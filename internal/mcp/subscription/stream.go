package subscription

import (
	"context"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// subscription is a single downstream subscription stream and its upstream
// fan-out. All writes to the SSEWriter go through the writer's own mutex, so
// the fan-in goroutines and the keep-alive goroutine never interleave frames.
type subscription struct {
	mgr    *Manager
	w      mcpproxy.SSEWriter
	params ListenParams

	// done is closed once to signal every goroutine (fan-in, keep-alive) to
	// stop. complete is closed by gracefulComplete to request the terminal
	// complete result before teardown.
	done       chan struct{}
	closeOnce  sync.Once
	complete   chan struct{}
	completeMu sync.Once

	// coalesce tracks the last time a (upstream,kind) list_changed was
	// forwarded so identical events within the debounce window are dropped
	// (HUB-229). resources/updated for distinct URIs is never coalesced.
	coalesceMu sync.Mutex
	lastSent   map[string]time.Time
}

// newSubscription constructs a subscription.
func newSubscription(mgr *Manager, w mcpproxy.SSEWriter, p ListenParams) *subscription {
	return &subscription{
		mgr:      mgr,
		w:        w,
		params:   p,
		done:     make(chan struct{}),
		complete: make(chan struct{}),
		lastSent: make(map[string]time.Time),
	}
}

// stop signals all goroutines to exit exactly once.
func (s *subscription) stop() {
	s.closeOnce.Do(func() { close(s.done) })
}

// gracefulComplete requests the terminal complete result (HUB-226). It signals
// the run loop, which writes the complete result then closes. It never blocks
// on the stream.
func (s *subscription) gracefulComplete() {
	s.completeMu.Do(func() { close(s.complete) })
}

// run drives the subscription: acknowledge, fan out, then block until the
// client disconnects (ctx), the manager shuts down (complete), or all upstream
// streams end. It returns after emitting the terminal complete result on a
// graceful path; an abrupt client disconnect returns without one (HUB-226).
func (s *subscription) run(ctx context.Context) error {
	ack, err := buildAcknowledged(s.params.SubscriptionID, s.params.Filter)
	if err != nil {
		return err
	}
	if werr := s.w.WriteEvent(eventMessage, ack); werr != nil {
		return werr
	}

	// A child context bounds every fan-out goroutine; canceling it on
	// return guarantees no goroutine outlives the subscription (leak-free).
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	s.fanOut(streamCtx, &wg)

	upstreamsDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(upstreamsDone)
	}()

	s.pump(ctx, streamCtx, cancel, upstreamsDone)
	// Ensure fan-out goroutines are joined before returning so the writer is
	// no longer referenced by any goroutine.
	<-upstreamsDone
	return nil
}

// eventMessage is the SSE event name for JSON-RPC payloads on the stream.
const eventMessage = "message"

// pump blocks handling keep-alive ticks and terminal signals until the
// subscription ends. It answers with a complete result on the graceful and
// upstream-teardown paths, but not on an abrupt client disconnect (HUB-226).
func (s *subscription) pump(
	ctx, streamCtx context.Context, cancel context.CancelFunc, upstreamsDone <-chan struct{},
) {
	ticker := time.NewTicker(s.mgr.cfg.KeepAlive)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Client disconnected (HUB-241): stop, emit nothing further.
			s.stop()
			cancel()
			return
		case <-s.complete:
			// Graceful shutdown (HUB-226): emit complete, then close.
			s.writeComplete()
			s.stop()
			cancel()
			return
		case <-upstreamsDone:
			// All upstream streams ended: treat as graceful teardown.
			s.writeComplete()
			s.stop()
			return
		case <-streamCtx.Done():
			return
		case <-ticker.C:
			if err := s.w.WriteComment("keep-alive"); err != nil {
				// Downstream gone: stop and tear down (HUB-241).
				s.stop()
				cancel()
				return
			}
		}
	}
}

// writeComplete emits the terminal complete result carrying the subscriptionId
// (HUB-226). Failures are logged, not fatal (the stream is closing anyway).
func (s *subscription) writeComplete() {
	raw, err := buildComplete(s.params.RequestID, s.params.SubscriptionID)
	if err != nil {
		s.mgr.logger.Debug("subscription: build complete failed", observability.Error(err))
		return
	}
	if werr := s.w.WriteEvent(eventMessage, raw); werr != nil {
		s.mgr.logger.Debug("subscription: write complete failed", observability.Error(werr))
	}
}

// fanOut opens an upstream subscription stream per configured upstream owning a
// requested type/URI (HUB-223). Each runs on its own goroutine and stops when
// streamCtx is canceled, guaranteeing no leak on client disconnect.
func (s *subscription) fanOut(streamCtx context.Context, wg *sync.WaitGroup) {
	req := s.buildUpstreamRequest()
	for _, upstreamID := range s.params.Upstreams {
		id := upstreamID
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler := func(ev mcpproxy.SSEEvent) error {
				return s.handleUpstreamEvent(streamCtx, id, ev)
			}
			if err := s.mgr.streamer.StreamUpstream(streamCtx, id, req, handler); err != nil {
				s.mgr.logger.Debug("subscription: upstream stream ended",
					observability.String("upstream", id), observability.Error(err))
			}
		}()
	}
}

// buildUpstreamRequest constructs the subscriptions/listen request sent to each
// upstream, de-namespacing the resourceSubscriptions URIs (HUB-223) and
// carrying the hub-built _meta.
func (s *subscription) buildUpstreamRequest() *jsonrpc.Request {
	params := map[string]any{
		"toolsListChanged":     s.params.Filter.ToolsListChanged,
		"promptsListChanged":   s.params.Filter.PromptsListChanged,
		"resourcesListChanged": s.params.Filter.ResourcesListChanged,
	}
	if uris := s.denamespaceURIs(); len(uris) > 0 {
		params["resourceSubscriptions"] = uris
	}
	if len(s.params.UpstreamMeta) > 0 {
		params["_meta"] = s.params.UpstreamMeta
	}
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		Method:  "subscriptions/listen",
		Params:  mustMarshal(params),
	}
}

// denamespaceURIs de-namespaces the client's resourceSubscriptions to upstream
// URIs (HUB-223). URIs that do not resolve to a known upstream are dropped.
func (s *subscription) denamespaceURIs() []string {
	var out []string
	for _, uri := range s.params.Filter.ResourceSubscriptions {
		if _, original, ok := s.mgr.mapper.Denamespace(uri); ok {
			out = append(out, original)
		}
	}
	return out
}

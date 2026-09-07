package gateway

import (
	"context"
	"net/http"
	"sync"
)

// progressRelayCtxKey is the request-context key carrying the lazy MRTR
// progress relay (HUB-244).
type progressRelayCtxKey struct{}

// progressRelay lazily originates a downstream SSE stream the first time an
// upstream notifications/progress event must be relayed, then reuses the same
// stream for subsequent progress events and the terminal result (HUB-244). It
// stays inert (no response head written) until the first progress event, so the
// JSON error paths — round/budget limits, invalid retry state — remain able to
// write their own status/body when no progress ever arrives.
type progressRelay struct {
	mu     sync.Mutex
	w      http.ResponseWriter
	sse    *sseResponseWriter
	opened bool
	failed bool
}

// newProgressRelay constructs an inert relay over the downstream writer.
func newProgressRelay(w http.ResponseWriter) *progressRelay {
	return &progressRelay{w: w}
}

// withProgressRelayContext attaches a lazy progress relay to the request
// context when the client is willing to receive an SSE stream (HUB-244).
// Otherwise the request is returned unchanged so single-JSON responses are
// unaffected.
func withProgressRelayContext(r *http.Request, w http.ResponseWriter) *http.Request {
	if !wantsSSE(r) {
		return r
	}
	relay := newProgressRelay(w)
	ctx := context.WithValue(r.Context(), progressRelayCtxKey{}, relay)
	return r.WithContext(ctx)
}

// progressRelayFromContext returns the relay attached to the request, or nil.
func progressRelayFromContext(r *http.Request) *progressRelay {
	relay, _ := r.Context().Value(progressRelayCtxKey{}).(*progressRelay)
	return relay
}

// writeProgress relays a raw notifications/progress payload as an SSE event,
// opening the downstream stream on first use (HUB-244).
func (p *progressRelay) writeProgress(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureOpenLocked(); err != nil {
		return err
	}
	return p.sse.WriteEvent(eventMessageName, raw)
}

// ensureOpenLocked opens the SSE writer once. The caller holds the lock.
func (p *progressRelay) ensureOpenLocked() error {
	if p.opened {
		if p.failed {
			return ErrSSEUnsupported
		}
		return nil
	}
	p.opened = true
	sse, err := newSSEResponseWriter(p.w)
	if err != nil {
		p.failed = true
		return err
	}
	p.sse = sse
	return nil
}

// active reports whether the relay has opened a downstream SSE stream, so the
// terminal result is written on the same stream rather than as a fresh JSON
// response (HUB-244).
func (p *progressRelay) active() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.opened && !p.failed
}

// writeTerminal writes the terminal JSON-RPC body as the final SSE event on the
// already-open stream. The caller must have confirmed active().
func (p *progressRelay) writeTerminal(body []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sse.WriteEvent(eventMessageName, body)
}

// eventMessageName is the SSE event name for MCP JSON-RPC payloads.
const eventMessageName = "message"

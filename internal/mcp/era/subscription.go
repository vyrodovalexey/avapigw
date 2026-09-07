package era

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// Legacy subscription method names (HUB-703). The modern hub speaks
// subscriptions/listen; a legacy upstream speaks resources/subscribe /
// resources/unsubscribe plus notifications on its SSE stream.
const (
	// MethodResourcesSubscribe subscribes to a single resource URI (legacy).
	MethodResourcesSubscribe = "resources/subscribe"
	// MethodResourcesUnsubscribe unsubscribes from a resource URI (legacy).
	MethodResourcesUnsubscribe = "resources/unsubscribe"
	// MethodSubscriptionsListen is the modern fan-out method the hub relays
	// downstream (mirrors subscription.MethodSubscriptionsListen).
	MethodSubscriptionsListen = "subscriptions/listen"
)

// SubscriptionEventSink receives legacy upstream notifications relayed toward a
// downstream subscription. It is the era package's view of the subscription
// manager's per-upstream SSE handler (mcpproxy.SSEEventHandler).
type SubscriptionEventSink = mcpproxy.SSEEventHandler

// LegacySubscriptionAdapter translates the hub's subscriptions/listen fan-out
// into legacy resources/subscribe / resources/unsubscribe calls and relays the
// upstream's notifications back to the subscription manager (HUB-703). It is a
// subscription.UpstreamStreamer for legacy upstreams: the manager calls
// StreamUpstream exactly as for a modern upstream, and this adapter bridges the
// legacy semantics behind that interface.
type LegacySubscriptionAdapter struct {
	pool *SessionPool
}

// NewLegacySubscriptionAdapter constructs a subscription adapter over the
// session pool.
func NewLegacySubscriptionAdapter(pool *SessionPool) (*LegacySubscriptionAdapter, error) {
	if pool == nil {
		return nil, fmt.Errorf("era: nil session pool")
	}
	return &LegacySubscriptionAdapter{pool: pool}, nil
}

// StreamUpstream honors a modern subscriptions/listen request against a legacy
// upstream (HUB-703): it acquires the pooled session, issues a legacy
// resources/subscribe for each requested resource URI, then relays the
// session's server notifications (resources/updated, *_list_changed) to handler
// until ctx is canceled. On return it best-effort unsubscribes so the upstream
// does not keep delivering notifications for a torn-down subscription.
//
// It satisfies subscription.UpstreamStreamer so the subscription Manager can
// fan out to legacy upstreams with no changes to its own code.
func (a *LegacySubscriptionAdapter) StreamUpstream(
	ctx context.Context, upstreamID string, req *jsonrpc.Request, handler mcpproxy.SSEEventHandler,
) error {
	sess, err := a.pool.Acquire(ctx, upstreamID)
	if err != nil {
		return fmt.Errorf("era: acquire legacy session: %w", err)
	}

	uris := resourceSubscriptionURIs(req)
	if err := a.subscribeAll(ctx, sess, uris); err != nil {
		return err
	}
	// The pooled session's SSE pump relays server events through the session's
	// EventDispatcher. Register this subscription's handler for the life of the
	// stream so upstream notifications reach this downstream subscription, then
	// unsubscribe and unregister on teardown (HUB-703).
	defer a.unsubscribeAll(context.WithoutCancel(ctx), sess, uris)

	dispatcher := sess.Dispatcher()
	if dispatcher == nil {
		// No SSE pump on this session: nothing to relay. Block until the
		// subscription is torn down so the manager's fan-out semantics hold.
		<-ctx.Done()
		return nil
	}
	token := dispatcher.registerRelay(handler)
	defer dispatcher.unregisterRelay(token)

	// Block until the downstream subscription is canceled; the dispatcher
	// delivers events to handler on the shared pump in the meantime.
	<-ctx.Done()
	return nil
}

// subscribeAll issues a legacy resources/subscribe for each URI, holding the
// upstream subscription open on the pooled session (HUB-703).
func (a *LegacySubscriptionAdapter) subscribeAll(
	ctx context.Context, sess *LegacySession, uris []string,
) error {
	for _, uri := range uris {
		req, err := buildResourceSubscribe(MethodResourcesSubscribe, uri)
		if err != nil {
			return err
		}
		if _, err := sess.PostRequest(ctx, req); err != nil {
			return fmt.Errorf("era: legacy resources/subscribe %q: %w", uri, err)
		}
	}
	return nil
}

// unsubscribeAll best-effort issues a legacy resources/unsubscribe for each URI
// on teardown. Errors are ignored: the stream is closing and the upstream drops
// the session's subscriptions on session loss anyway (HUB-703).
func (a *LegacySubscriptionAdapter) unsubscribeAll(
	ctx context.Context, sess *LegacySession, uris []string,
) {
	for _, uri := range uris {
		req, err := buildResourceSubscribe(MethodResourcesUnsubscribe, uri)
		if err != nil {
			continue
		}
		_, _ = sess.PostRequest(ctx, req)
	}
}

// resourceSubscriptionURIs extracts the resourceSubscriptions URIs from a
// modern subscriptions/listen request so they can be mapped to legacy
// per-resource subscribe calls (HUB-703). URIs are already de-namespaced by the
// subscription manager before StreamUpstream is called.
func resourceSubscriptionURIs(req *jsonrpc.Request) []string {
	if req == nil || len(req.Params) == 0 {
		return nil
	}
	var params struct {
		ResourceSubscriptions []string `json:"resourceSubscriptions"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil
	}
	return params.ResourceSubscriptions
}

// buildResourceSubscribe builds a legacy resources/(un)subscribe request for a
// single URI (HUB-703).
func buildResourceSubscribe(method, uri string) (*jsonrpc.Request, error) {
	raw, err := json.Marshal(map[string]string{"uri": uri})
	if err != nil {
		return nil, fmt.Errorf("era: encode %s params: %w", method, err)
	}
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		ID:      json.RawMessage(`"sub"`),
		Method:  method,
		Params:  raw,
	}, nil
}

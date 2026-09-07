package subscription

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// handleUpstreamEvent processes one relayed upstream SSE event: it parses the
// JSON-RPC notification, drops request-scoped notifications that must not flow
// on a subscription stream (HUB-227), rewrites subscriptionId to the downstream
// value and re-namespaces URIs (HUB-223), coalesces duplicate list_changed
// (HUB-229), fires the cache invalidation hook (HUB-185) and forwards the
// rewritten notification downstream.
func (s *subscription) handleUpstreamEvent(
	ctx context.Context, upstreamID string, ev mcpproxy.SSEEvent,
) error {
	select {
	case <-s.done:
		// Subscription is closing (client disconnect / shutdown): emit
		// nothing further (HUB-241).
		return context.Canceled
	default:
	}

	notif, ok := parseNotification(ev.Data)
	if !ok {
		return nil // non-notification frames are ignored on this stream
	}
	if isRequestScoped(notif.Method) {
		// HUB-227: progress/message never flow on a subscription stream.
		return nil
	}

	params := decodeParams(notif.Params)
	if s.coalesced(upstreamID, notif.Method) {
		return nil // duplicate list_changed within the debounce window
	}
	s.fireInvalidation(ctx, upstreamID, notif.Method, params)

	rewritten, err := s.rewriteNotification(upstreamID, notif, params)
	if err != nil {
		return err
	}
	return s.w.WriteEvent(eventMessage, rewritten)
}

// notification is a decoded JSON-RPC notification.
type notification struct {
	Method string
	Params json.RawMessage
}

// parseNotification decodes an SSE data payload as a JSON-RPC notification.
// Responses (with an id/result) are not notifications and are rejected.
func parseNotification(data []byte) (notification, bool) {
	var msg struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(data, &msg); err != nil || msg.Method == "" {
		return notification{}, false
	}
	return notification{Method: msg.Method, Params: msg.Params}, true
}

// decodeParams decodes a notification's params into a generic map.
func decodeParams(raw json.RawMessage) map[string]any {
	m := map[string]any{}
	if len(raw) == 0 {
		return m
	}
	_ = json.Unmarshal(raw, &m)
	return m
}

// requestScopedMethods are notifications that belong to a specific request's
// response stream and MUST NOT appear on a subscription stream (HUB-227).
var requestScopedMethods = map[string]bool{
	"notifications/progress": true,
	"notifications/message":  true,
}

// isRequestScoped reports whether a notification method is request-scoped.
func isRequestScoped(method string) bool {
	return requestScopedMethods[method]
}

// coalesced reports whether an identical list_changed from this upstream was
// forwarded within the debounce window (HUB-229). resources/updated is never
// coalesced (each distinct URI must be delivered). The check-and-record is
// performed under a single lock so there is no time-of-check/time-of-use race.
func (s *subscription) coalesced(upstreamID, method string) bool {
	if !isListChanged(method) {
		return false
	}
	key := upstreamID + "\x00" + method
	now := time.Now()

	s.coalesceMu.Lock()
	defer s.coalesceMu.Unlock()
	if last, ok := s.lastSent[key]; ok && now.Sub(last) < s.mgr.cfg.Debounce {
		return true
	}
	s.lastSent[key] = now
	return false
}

// isListChanged reports whether a method is a list_changed notification.
func isListChanged(method string) bool {
	switch method {
	case MethodToolsListChanged, MethodPromptsListChanged, MethodResourcesListChanged:
		return true
	default:
		return false
	}
}

// fireInvalidation calls the M3 cache invalidation hook for list_changed /
// resources/updated fan-in (HUB-185).
func (s *subscription) fireInvalidation(
	ctx context.Context, upstreamID, method string, params map[string]any,
) {
	switch method {
	case MethodToolsListChanged:
		s.mgr.invalidate(ctx, upstreamID, kindTools, "")
	case MethodPromptsListChanged:
		s.mgr.invalidate(ctx, upstreamID, kindPrompts, "")
	case MethodResourcesListChanged:
		s.mgr.invalidate(ctx, upstreamID, kindResources, "")
	case MethodResourcesUpdated:
		if uri, ok := params["uri"].(string); ok {
			s.mgr.invalidate(ctx, upstreamID, kindResources, uri)
		}
	}
}

// rewriteNotification rewrites the upstream notification for downstream
// delivery: it re-namespaces the resource URI (HUB-223) and stamps the
// downstream subscriptionId into _meta (HUB-223).
func (s *subscription) rewriteNotification(
	upstreamID string, notif notification, params map[string]any,
) (json.RawMessage, error) {
	s.renamespaceURI(upstreamID, params)
	s.stampSubscriptionID(params)

	out := map[string]any{
		"jsonrpc": "2.0",
		"method":  notif.Method,
		"params":  params,
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("subscription: encode notification: %w", err)
	}
	return raw, nil
}

// renamespaceURI re-namespaces a resources/updated URI back to its hub-visible
// form (HUB-223). A URI that cannot be namespaced is left unchanged.
func (s *subscription) renamespaceURI(upstreamID string, params map[string]any) {
	uri, ok := params["uri"].(string)
	if !ok || uri == "" {
		return
	}
	if ns, err := s.mgr.mapper.Namespace(upstreamID, uri); err == nil && ns != "" {
		params["uri"] = ns
	}
}

// stampSubscriptionID sets the downstream subscriptionId in the notification's
// _meta, overwriting any upstream value (HUB-223).
func (s *subscription) stampSubscriptionID(params map[string]any) {
	metaObj, ok := params["_meta"].(map[string]any)
	if !ok {
		metaObj = map[string]any{}
	}
	metaObj[protocol.MetaSubscriptionID] = rawSubscriptionID(s.params.SubscriptionID)
	params["_meta"] = metaObj
}

// rawSubscriptionID renders the subscriptionId JSON as a Go value so it embeds
// naturally in the params map.
func rawSubscriptionID(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(id, &v); err != nil {
		return string(id)
	}
	return v
}

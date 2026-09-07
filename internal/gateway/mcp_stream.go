package gateway

import (
	"context"
	"errors"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/lifecycle"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	mcpsub "github.com/vyrodovalexey/avapigw/internal/mcp/subscription"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// errUnknownUpstream indicates a subscription fan-out targeted an upstream that
// is not registered.
var errUnknownUpstream = errors.New("mcp: unknown subscription upstream")

// callContext derives the upstream-call context bounded by the per-method /
// per-tool timeout (HUB-243). The parent ctx is the request context so a
// downstream client disconnect still cancels the upstream call (HUB-241/242).
// The caller MUST defer the returned cancel.
func (h *MCPHandler) callContext(
	ctx context.Context, upstream config.MCPBackend, method string, params map[string]any,
) (context.Context, context.CancelFunc) {
	tool := h.denamespacedName(params, upstream.Name)
	return lifecycle.WithTimeout(ctx, upstream.Timeouts, method, tool)
}

// denamespacedName returns the de-namespaced primitive name for the request,
// used as the per-tool timeout key. It returns "" when the name is absent or
// not owned by the given upstream.
func (h *MCPHandler) denamespacedName(params map[string]any, upstreamID string) string {
	name := primitiveName(params)
	if name == "" {
		return ""
	}
	if id, original, ok := h.mapper.Denamespace(name); ok && id == upstreamID {
		return original
	}
	return ""
}

// writeUpstreamCallError converts an upstream call failure into a JSON-RPC
// error, distinguishing a timeout (HUB-243) and a client disconnect (HUB-241)
// from a generic upstream failure. On a client disconnect it emits nothing
// further, per HUB-241.
func (h *MCPHandler) writeUpstreamCallError(
	w http.ResponseWriter, mr *mcpReq, upstreamID, method, version string, err error,
) {
	if lifecycle.IsCancellation(err) {
		// Client disconnected: stop, emit no further messages (HUB-241).
		h.logger.Debug("mcp: request canceled by client",
			observability.String("method", method))
		return
	}
	h.metrics.RecordUpstreamFailure(upstreamID, method)
	if lifecycle.IsTimeout(err) {
		h.writeJSONRPCError(w, mr.id(), http.StatusGatewayTimeout, protocol.InternalError,
			"upstream call timed out", nil)
	} else {
		h.writeJSONRPCError(w, mr.id(), http.StatusBadGateway, protocol.InternalError,
			"upstream error: "+err.Error(), nil)
	}
	h.recordOutcome(upstreamID, method, name0(mr.params), version,
		resultTypeUnknown, mcpmetrics.OutcomeError, mr.start)
}

// mcpUpstreamStreamer adapts the hub client + resolver to the subscription
// package's UpstreamStreamer: it resolves an upstream id to its ServiceBackend
// and opens a subscriptions/listen SSE stream through the hub client.
type mcpUpstreamStreamer struct {
	handler *MCPHandler
}

// NewUpstreamStreamer returns a subscription UpstreamStreamer backed by this
// handler's hub client and upstream registry. It lets the subscription manager
// be constructed after the handler (avoiding a construction cycle) while still
// streaming through the handler's shared upstream infrastructure.
func (h *MCPHandler) NewUpstreamStreamer() mcpsub.UpstreamStreamer {
	return &mcpUpstreamStreamer{handler: h}
}

// AttachSubscriptionManager wires the subscription manager into the handler
// after construction (HUB-221..229). It is additive: without it, subscriptions/
// listen returns method-not-found. Wiring the manager also enables the graceful
// shutdown path (HUB-226) via Close.
func (h *MCPHandler) AttachSubscriptionManager(m *mcpsub.Manager) {
	h.mu.Lock()
	h.subManager = m
	h.mu.Unlock()
}

// StreamUpstream opens an upstream subscription stream and relays each SSE event
// to handler (HUB-223). It resolves the backend, applies the upstream MCP path,
// and never forwards a downstream credential upstream (the hub client strips
// them, HUB-303).
func (s *mcpUpstreamStreamer) StreamUpstream(
	ctx context.Context,
	upstreamID string,
	req *jsonrpc.Request,
	handler mcpproxy.SSEEventHandler,
) error {
	h := s.handler
	h.mu.RLock()
	upstream, ok := h.upstreams[upstreamID]
	h.mu.RUnlock()
	if !ok {
		return errUnknownUpstream
	}
	b, ok := h.backendRegistry.Get(upstream.Name)
	if !ok {
		return errUnknownUpstream
	}
	sb, ok := b.(*backend.ServiceBackend)
	if !ok {
		return errUnknownUpstream
	}
	// subscriptions/listen carries no primitive name; header derivation is
	// method-only.
	upHeaders := h.deriveHeaders(protocol.MethodSubscriptionsListen, nil, upstreamID)
	// Track the open upstream SSE relay stream for the SSEStreamsOpen gauge
	// (HUB-505). The gauge is decremented when the relay returns.
	h.metrics.IncSSEStreams(upstreamID)
	defer h.metrics.DecSSEStreams(upstreamID)
	return h.hub.Stream(ctx, sb, upstream.GetEffectivePath(), req, upHeaders, handler)
}

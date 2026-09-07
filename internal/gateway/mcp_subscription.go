package gateway

import (
	"encoding/json"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpsub "github.com/vyrodovalexey/avapigw/internal/mcp/subscription"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// serveSubscription handles subscriptions/listen (HUB-221..229). It originates
// a downstream SSE stream (HUB-107), delegates to the subscription manager to
// fan out and pump notifications, and blocks until the client disconnects or
// the manager shuts down. The stream is exempt from the request timeout: it is
// driven by r.Context() (client disconnect) only (HUB-243).
func (h *MCPHandler) serveSubscription(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, route *config.MCPRoute,
) {
	// Bound concurrent streams per principal (HUB-405). A principal already
	// at its limit is rejected before the SSE stream is originated.
	principalKey := subscriptionPrincipalKey(r)
	if !h.limiter.acquireStream(principalKey) {
		h.metrics.RecordAuthFailure(mr.method(), mcpmetrics.AuthClassScope)
		h.writeJSONRPCError(w, mr.id(), http.StatusTooManyRequests, protocol.InvalidRequest,
			"too many concurrent streams for principal", nil)
		return
	}
	defer h.limiter.releaseStream(principalKey)

	sw, err := newSSEResponseWriter(w)
	if err != nil {
		// The client must accept a stream for subscriptions; without flush
		// support we cannot serve one.
		h.writeJSONRPCError(w, mr.id(), http.StatusNotAcceptable, protocol.InvalidRequest,
			"subscriptions/listen requires a streaming (SSE-capable) client", nil)
		return
	}

	upstreamMeta := h.subscriptionUpstreamMeta(mr, route)
	params := mcpsub.ListenParams{
		SubscriptionID: mr.id(),
		RequestID:      mr.id(),
		Filter:         mcpsub.ParseFilter(mr.params),
		Upstreams:      routeUpstreams(route),
		UpstreamMeta:   upstreamMeta,
	}

	// r.Context() is canceled when the client disconnects, which the manager
	// treats as cancellation of the subscription (HUB-241).
	if lerr := h.subManager.Listen(r.Context(), sw, params); lerr != nil {
		h.logger.Debug("mcp: subscription ended",
			observability.String("method", mr.method()), observability.Error(lerr))
	}
	h.recordOutcome("", mr.method(), "", metaProtocolVersion(mr.params),
		protocol.ResultComplete, mcpmetrics.OutcomeSuccess, mr.start)
}

// subscriptionUpstreamMeta builds the _meta object forwarded to upstreams on
// the fan-out subscriptions/listen requests. It narrows client capabilities and
// carries the hub clientInfo like any other upstream request (HUB-124/125). On
// any failure it returns nil so the upstream request simply omits _meta.
func (h *MCPHandler) subscriptionUpstreamMeta(mr *mcpReq, route *config.MCPRoute) json.RawMessage {
	version := metaProtocolVersion(mr.params)
	negotiated := h.subscriptionNegotiatedVersion(route, version)

	downstreamMeta, err := meta.Decode(rawMeta(mr.params))
	if err != nil {
		return nil
	}
	upMeta, err := meta.BuildUpstreamMeta(downstreamMeta, meta.BuildUpstreamOptions{
		NegotiatedUpstreamVersion: negotiated,
		HubClientInfo:             h.hubClientInfo,
		BrokerableCaps:            brokerableCaps(),
	})
	if err != nil {
		return nil
	}
	raw, err := upMeta.Encode()
	if err != nil {
		return nil
	}
	return raw
}

// subscriptionNegotiatedVersion resolves the protocol version to send upstream
// on subscription fan-out, using the first configured upstream's pinned version
// when available.
func (h *MCPHandler) subscriptionNegotiatedVersion(route *config.MCPRoute, downstreamVersion string) string {
	ups := routeUpstreams(route)
	if len(ups) == 0 {
		return downstreamVersion
	}
	h.mu.RLock()
	upstream, ok := h.upstreams[ups[0]]
	h.mu.RUnlock()
	if !ok {
		return downstreamVersion
	}
	return negotiatedVersion(upstream, downstreamVersion)
}

// subscriptionPrincipalKey derives the per-principal limiter key for a
// subscription stream (HUB-405). It falls back to the remote address when no
// authenticated principal is present so an unauthenticated flood is still
// bounded per source.
func subscriptionPrincipalKey(r *http.Request) string {
	if p := mcpPrincipalFromContext(r); p != nil && p.Subject != "" {
		return p.Subject
	}
	return r.RemoteAddr
}

// compile-time assertion that the streamer adapter satisfies the subscription
// package's UpstreamStreamer interface.
var _ mcpsub.UpstreamStreamer = (*mcpUpstreamStreamer)(nil)

// compile-time assertion that the handler satisfies the subscription cache
// invalidator hook (InvalidateCache lives in mcp_cache.go).
var _ mcpsub.CacheInvalidator = (*MCPHandler)(nil)

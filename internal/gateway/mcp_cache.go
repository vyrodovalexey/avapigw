package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	mcpcache "github.com/vyrodovalexey/avapigw/internal/mcp/cache"
	"github.com/vyrodovalexey/avapigw/internal/mcp/discovery"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// serveReadFromCache serves a resources/read result from the cache when
// present, keyed by (upstream, uri, auth-context). Authorization has already
// been enforced earlier in ServeHTTP for the named primitive, so a cache hit is
// safe to return (HUB-183/307). It returns true when it served a response.
func (h *MCPHandler) serveReadFromCache(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, upstreamID string,
) bool {
	if h.cache == nil || mr.method() != protocol.MethodResourcesRead {
		return false
	}
	if !mcpcache.RequestCacheable(mr.params) {
		return false // MRTR-bearing request: never cached (HUB-184)
	}
	principal := mcpPrincipalFromContext(r)
	authCtx := authContextKey(principal)
	private := principal != nil
	parts := readKeyParts(upstreamID, mr.params)

	entry, ok := h.cache.Get(r.Context(), parts, authCtx, private)
	if !ok {
		return false
	}
	resp, err := jsonrpc.NewResponse(mr.id(), entry.Result)
	if err != nil {
		return false
	}
	h.writeJSON(w, http.StatusOK, resp)
	h.recordOutcome(upstreamID, mr.method(), name0(mr.params),
		metaProtocolVersion(mr.params), protocol.ResultComplete, mcpmetrics.OutcomeSuccess, mr.start)
	return true
}

// maybeCacheRead stores a successful resources/read result in the cache. It
// refuses to cache MRTR-bearing or input_required results (HUB-184).
func (h *MCPHandler) maybeCacheRead(
	r *http.Request, mr *mcpReq, resp *jsonrpc.Response, upstreamID string,
) {
	if h.cache == nil || mr.method() != protocol.MethodResourcesRead {
		return
	}
	if resp == nil || resp.Error != nil {
		return
	}
	if !mcpcache.RequestCacheable(mr.params) || !mcpcache.ResultCacheable(resp.Result) {
		return
	}

	principal := mcpPrincipalFromContext(r)
	authCtx := authContextKey(principal)
	scope := readCacheScope(resp.Result, principal != nil)
	entry := &mcpcache.Entry{
		Result:     append(json.RawMessage(nil), resp.Result...),
		TTLMs:      h.cache.ClampTTL(readTTLMs(resp.Result)),
		CacheScope: scope,
	}
	parts := readKeyParts(upstreamID, mr.params)
	if err := h.cache.Set(r.Context(), parts, authCtx, entry); err != nil {
		h.logger.Debug("mcp: store resources/read cache failed",
			observability.String("upstream", upstreamID), observability.Error(err))
	}
}

// readKeyParts builds the cache key parts for a resources/read request from the
// de-namespaced uri so the same underlying resource caches once per upstream.
func readKeyParts(upstreamID string, params map[string]any) mcpcache.KeyParts {
	uri := stringParam(params, "uri")
	return mcpcache.KeyParts{
		Upstream: upstreamID,
		Method:   protocol.MethodResourcesRead,
		Params:   uri,
	}
}

// readTTLMs reads a ttlMs hint from a result, defaulting to zero (which the
// clamp raises to the configured minimum).
func readTTLMs(result json.RawMessage) int64 {
	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(result, &obj); err != nil {
		return 0
	}
	if raw, ok := obj["ttlMs"]; ok {
		var ttl int64
		if err := json.Unmarshal(raw, &ttl); err == nil && ttl >= 0 {
			return ttl
		}
	}
	return 0
}

// readCacheScope resolves the cacheScope for a resources/read result: private
// when the upstream marked it private OR when the response was produced for an
// authenticated (per-caller) context (HUB-182).
func readCacheScope(result json.RawMessage, authenticated bool) string {
	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(result, &obj); err == nil {
		if raw, ok := obj["cacheScope"]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && s == mcpCacheScopePrivate {
				return mcpCacheScopePrivate
			}
		}
	}
	if authenticated {
		return mcpCacheScopePrivate
	}
	return "public"
}

// mcpcacheAuthContextKey exposes the cache package's auth-context key derivation
// to the gateway package (HUB-183).
func mcpcacheAuthContextKey(subject string, scopes []string) string {
	return mcpcache.AuthContextKey(subject, scopes)
}

// isCursorRestart reports whether an aggregation error is the
// invalid/expired-cursor sentinel that instructs the client to restart the list
// from the beginning (HUB-166).
func isCursorRestart(err error) bool {
	return errors.Is(err, discovery.ErrCursorRestart)
}

// InvalidateCache drops cached entries affected by an upstream list_changed or
// resources/updated notification (HUB-185). It is the hook the subscription
// fan-in path (M4) calls when it observes an upstream notification; it is a
// no-op when caching is disabled. ttlMs is never used as a polling interval;
// invalidation is event-driven.
func (h *MCPHandler) InvalidateCache(ctx context.Context, upstream, kind, uri string) {
	if h.cache == nil {
		return
	}
	h.cache.Invalidate(ctx, upstream, kind, uri)
}

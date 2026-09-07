package gateway

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpcache "github.com/vyrodovalexey/avapigw/internal/mcp/cache"
	"github.com/vyrodovalexey/avapigw/internal/mcp/discovery"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// MCPUpstreamResolver resolves an MCP upstream id to its ServiceBackend and
// config, implementing discovery.UpstreamResolver without depending on the
// handler, so the aggregator can be constructed before the handler and injected
// into it (avoiding a construction cycle).
//
// The upstream map is guarded by an RWMutex so a hot reload can swap it via
// Update while the aggregator concurrently reads it (G-1): without the swap the
// resolver kept a boot-time snapshot forever, hiding new/changed MCPBackends
// from discovery, and the bare map would additionally be a data race.
type MCPUpstreamResolver struct {
	registry BackendGetter

	mu        sync.RWMutex
	upstreams map[string]config.MCPBackend
}

// NewMCPUpstreamResolver constructs a resolver over the backend registry and
// the name-keyed upstream config map.
func NewMCPUpstreamResolver(
	registry BackendGetter, upstreams map[string]config.MCPBackend,
) *MCPUpstreamResolver {
	return &MCPUpstreamResolver{registry: registry, upstreams: upstreams}
}

// Update swaps the resolver's upstream config map under the write lock. It is
// called from every hot-reload path (file reload and operator apply) so the
// aggregator observes newly added/changed MCPBackends immediately instead of a
// stale boot-time snapshot (G-1).
func (r *MCPUpstreamResolver) Update(upstreams map[string]config.MCPBackend) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.upstreams = upstreams
	r.mu.Unlock()
}

// Resolve implements discovery.UpstreamResolver.
func (r *MCPUpstreamResolver) Resolve(
	upstreamID string,
) (*backend.ServiceBackend, config.MCPBackend, bool) {
	r.mu.RLock()
	cfg, exists := r.upstreams[upstreamID]
	r.mu.RUnlock()
	if !exists || r.registry == nil {
		return nil, config.MCPBackend{}, false
	}
	b, ok := r.registry.Get(cfg.Name)
	if !ok {
		return nil, config.MCPBackend{}, false
	}
	sb, ok := b.(*backend.ServiceBackend)
	if !ok {
		return nil, config.MCPBackend{}, false
	}
	return sb, cfg, true
}

// mcpCacheScopePrivate is the private cacheScope value the hub emits when a
// result is filtered by the caller's authorization (HUB-182).
const mcpCacheScopePrivate = "private"

// aggregatedMethods is the set of methods served by the discovery aggregator.
var aggregatedMethods = map[string]bool{
	protocol.MethodServerDiscover:        true,
	protocol.MethodToolsList:             true,
	protocol.MethodPromptsList:           true,
	protocol.MethodResourcesList:         true,
	protocol.MethodResourceTemplatesList: true,
}

// isAggregatedMethod reports whether a method is served by the aggregator.
func isAggregatedMethod(method string) bool {
	return aggregatedMethods[method]
}

// serveAggregated serves a discovery/list method through the aggregator and
// cache. It checks the cache first (per auth context), else aggregates across
// the route's upstreams, filters the merged items to the primitives the caller
// may see, stores the result and writes it downstream (HUB-161/164/181/307).
func (h *MCPHandler) serveAggregated(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, route *config.MCPRoute,
) {
	method := mr.method()
	upstreams := routeUpstreams(route)
	principal := mcpPrincipalFromContext(r)
	scopes := principalScopes(principal)

	cursor := stringParam(mr.params, "cursor")
	authCtx := authContextKey(principal)
	// Fold the route's upstream SET into the cache key so two routes with
	// different upstream sets never cross-serve each other's aggregate for the
	// same method/cursor/auth context (G-2). Without this discriminator a
	// partner route seeing 1 upstream could serve an internal route's 5-upstream
	// aggregate (or vice versa), exposing/hiding primitives outside its scope.
	upstreamSet := upstreamSetDigest(upstreams)

	if entry, ok := h.getAggregatedCache(r, method, cursor, upstreamSet, authCtx, scopes); ok {
		h.writeAggregatedEntry(w, mr, entry)
		return
	}

	result, err := h.aggregate(r, method, upstreams, cursor, scopes)
	if err != nil {
		h.writeAggregateError(w, mr, method, err)
		return
	}

	h.filterResultItems(r, method, route, principal, result)
	entry := h.buildEntry(result)
	// Only cache the filtered aggregate for the same auth context; a private
	// (auth-filtered) entry keys on the auth context so it never leaks across
	// authorization contexts (HUB-183).
	h.storeAggregatedCache(r, method, cursor, upstreamSet, authCtx, entry)
	h.writeAggregatedResult(w, mr, result, entry)
}

// upstreamSetDigest returns a stable, order-independent digest of a route's
// upstream id set, used as a cache-key discriminator (G-2). Sorting makes the
// digest independent of the configured order so it identifies the SET, not the
// sequence.
func upstreamSetDigest(upstreams []string) string {
	if len(upstreams) == 0 {
		return ""
	}
	sorted := append([]string(nil), upstreams...)
	sort.Strings(sorted)
	return strings.Join(sorted, "\x00")
}

// aggregate dispatches to the aggregator method for the given list/discover
// method.
func (h *MCPHandler) aggregate(
	r *http.Request, method string, upstreams []string, cursor string, scopes []string,
) (*discovery.DiscoverResult, error) {
	ctx := r.Context()
	switch method {
	case protocol.MethodServerDiscover:
		return h.aggregator.Discover(ctx, upstreams, scopes)
	case protocol.MethodToolsList:
		return h.aggregator.ListTools(ctx, upstreams, cursor, scopes)
	case protocol.MethodPromptsList:
		return h.aggregator.ListPrompts(ctx, upstreams, cursor, scopes)
	case protocol.MethodResourcesList:
		return h.aggregator.ListResources(ctx, upstreams, cursor, scopes)
	case protocol.MethodResourceTemplatesList:
		return h.aggregator.ListResourceTemplates(ctx, upstreams, cursor, scopes)
	default:
		return nil, discovery.ErrNilHub
	}
}

// filterResultItems drops merged primitives the caller's scopes/policy do not
// permit (HUB-306). Filtering marks the response private so the filtered view is
// never reused across authorization contexts. When no authorizer or principal
// is present, nothing is filtered (authorization is opt-in).
func (h *MCPHandler) filterResultItems(
	r *http.Request, method string, route *config.MCPRoute,
	principal *mcpauthzPrincipal, result *discovery.DiscoverResult,
) {
	if h.authorizer == nil || principal == nil || len(result.Items) == 0 {
		return
	}
	resolver := routeScopeResolver(route)
	filtered := result.Items[:0]
	for _, item := range result.Items {
		nsName := itemName(item)
		if nsName == "" || h.permitsPrimitive(r, principal, resolver, method, nsName) {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) != len(result.Items) {
		result.CacheScope = mcpCacheScopePrivate
	}
	result.Items = filtered
}

// itemName extracts the namespaced name/uri from a merged primitive item for
// authorization filtering.
func itemName(item json.RawMessage) string {
	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(item, &obj); err != nil {
		return ""
	}
	for _, field := range []string{"name", "uri", "uriTemplate"} {
		if raw, ok := obj[field]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && s != "" {
				return s
			}
		}
	}
	return ""
}

// getAggregatedCache looks up the cached aggregated result for the method,
// cursor, route upstream-set and auth context. The upstream-set digest is
// carried in KeyParts.Params so routes with different upstream sets never share
// entries (G-2). Private lookups fold in the auth context.
func (h *MCPHandler) getAggregatedCache(
	r *http.Request, method, cursor, upstreamSet, authCtx string, scopes []string,
) (*mcpcache.Entry, bool) {
	if h.cache == nil {
		return nil, false
	}
	parts := mcpcache.KeyParts{Method: method, Cursor: cursor, Params: upstreamSet}
	private := len(scopes) > 0
	return h.cache.Get(r.Context(), parts, authCtx, private)
}

// storeAggregatedCache stores the aggregated entry unless caching is disabled.
// The route upstream-set digest is folded into KeyParts.Params so the entry is
// scoped to the route's exact upstream set (G-2).
func (h *MCPHandler) storeAggregatedCache(
	r *http.Request, method, cursor, upstreamSet, authCtx string, entry *mcpcache.Entry,
) {
	if h.cache == nil || entry == nil {
		return
	}
	parts := mcpcache.KeyParts{Method: method, Cursor: cursor, Params: upstreamSet}
	if err := h.cache.Set(r.Context(), parts, authCtx, entry); err != nil {
		h.logger.Debug("mcp: store aggregated cache failed",
			observability.String("method", method), observability.Error(err))
	}
}

// buildEntry packages a DiscoverResult into a cache Entry carrying the
// aggregated ttlMs / cacheScope, clamped to the configured window (HUB-182).
func (h *MCPHandler) buildEntry(result *discovery.DiscoverResult) *mcpcache.Entry {
	ttl := result.TTLMs
	if h.cache != nil {
		ttl = h.cache.ClampTTL(ttl)
	}
	payload := h.encodeResultPayload(result)
	return &mcpcache.Entry{
		Result:     payload,
		TTLMs:      ttl,
		CacheScope: result.CacheScope,
	}
}

// encodeResultPayload encodes the merged result into the JSON-RPC result body,
// injecting the hub serverInfo and the cache hints (ttlMs / cacheScope).
func (h *MCPHandler) encodeResultPayload(result *discovery.DiscoverResult) json.RawMessage {
	obj := map[string]any{
		"ttlMs":      result.TTLMs,
		"cacheScope": result.CacheScope,
		"resultType": protocol.ResultComplete,
	}
	if len(result.Items) > 0 {
		obj[itemKeyForMethod(result.Method)] = result.Items
	}
	if result.Method == protocol.MethodServerDiscover {
		obj["supportedVersions"] = result.SupportedVersions
		if len(result.Capabilities) > 0 {
			obj["capabilities"] = result.Capabilities
		}
		if result.Instructions != "" {
			obj["instructions"] = result.Instructions
		}
	}
	if result.NextCursor != "" {
		obj["nextCursor"] = result.NextCursor
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	injected, err := meta.InjectServerInfo(raw, h.hubServerInfo)
	if err != nil {
		return raw
	}
	return injected
}

// writeAggregatedResult writes a freshly aggregated result downstream.
func (h *MCPHandler) writeAggregatedResult(
	w http.ResponseWriter, mr *mcpReq, result *discovery.DiscoverResult, entry *mcpcache.Entry,
) {
	resp, err := jsonrpc.NewResponse(mr.id(), entry.Result)
	if err != nil {
		h.writeJSONRPCError(w, mr.id(), http.StatusInternalServerError, protocol.InternalError,
			"encode aggregated result", nil)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
	outcome := mcpmetrics.OutcomeSuccess
	if result.Degraded {
		h.logger.Warn("mcp: served degraded discovery result",
			observability.String("method", mr.method()))
	}
	h.recordOutcome("", mr.method(), "", metaProtocolVersion(mr.params),
		protocol.ResultComplete, outcome, mr.start)
}

// writeAggregatedEntry writes a cached aggregated entry downstream.
func (h *MCPHandler) writeAggregatedEntry(w http.ResponseWriter, mr *mcpReq, entry *mcpcache.Entry) {
	resp, err := jsonrpc.NewResponse(mr.id(), entry.Result)
	if err != nil {
		h.writeJSONRPCError(w, mr.id(), http.StatusInternalServerError, protocol.InternalError,
			"encode cached result", nil)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
	h.recordOutcome("", mr.method(), "", metaProtocolVersion(mr.params),
		protocol.ResultComplete, mcpmetrics.OutcomeSuccess, mr.start)
}

// writeAggregateError converts an aggregation error into a JSON-RPC error. An
// invalid/expired pagination cursor is reported as invalid params so the client
// restarts the list from the beginning (HUB-166).
func (h *MCPHandler) writeAggregateError(w http.ResponseWriter, mr *mcpReq, method string, err error) {
	h.metrics.RecordUpstreamFailure("", method)
	code := protocol.InternalError
	status := http.StatusBadGateway
	if isCursorRestart(err) {
		code = protocol.InvalidParams
		status = http.StatusBadRequest
	}
	h.writeJSONRPCError(w, mr.id(), status, code, err.Error(), nil)
}

// itemKeyForMethod maps a list/discover method to the result array key.
func itemKeyForMethod(method string) string {
	switch method {
	case protocol.MethodToolsList:
		return "tools"
	case protocol.MethodPromptsList:
		return "prompts"
	case protocol.MethodResourcesList:
		return "resources"
	case protocol.MethodResourceTemplatesList:
		return "resourceTemplates"
	default:
		return "items"
	}
}

// routeUpstreams returns ALL configured upstream ids for a route, regardless of
// weight, so aggregation and subscription fan-out cover every candidate
// (weights only affect single-upstream selection, never fan-out).
func routeUpstreams(route *config.MCPRoute) []string {
	if route == nil {
		return nil
	}
	return route.UpstreamNames()
}

// stringParam returns a string param value, or "" when absent.
func stringParam(params map[string]any, key string) string {
	if v, ok := params[key].(string); ok {
		return v
	}
	return ""
}

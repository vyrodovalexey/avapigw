package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpauthz "github.com/vyrodovalexey/avapigw/internal/mcp/authz"
	mcpcache "github.com/vyrodovalexey/avapigw/internal/mcp/cache"
	"github.com/vyrodovalexey/avapigw/internal/mcp/discovery"
	"github.com/vyrodovalexey/avapigw/internal/mcp/era"
	"github.com/vyrodovalexey/avapigw/internal/mcp/headers"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	mcpmrtr "github.com/vyrodovalexey/avapigw/internal/mcp/mrtr"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/mcp/security"
	mcpsub "github.com/vyrodovalexey/avapigw/internal/mcp/subscription"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mcpChainScope namespaces MCP route names inside the shared
// RouteMiddlewareManager chain cache so an MCP route can never collide with an
// HTTP or GraphQL route of the same name (mirrors graphqlChainScope).
const mcpChainScope = "mcp:"

// mcpTracerName is the OTLP tracer name for the MCP broker path.
const mcpTracerName = "avapigw/mcp"

// resultTypeUnknown is the bounded result-type metric label used when the
// result type could not be determined.
const resultTypeUnknown = "unknown"

// BackendGetter resolves a backend by name. It is satisfied by
// *backend.Registry (Get returns the backend.Backend interface).
type BackendGetter interface {
	// Get returns a backend by name and whether it exists.
	Get(name string) (backend.Backend, bool)
}

// MCPRouteMiddleware applies per-route middleware chains to MCP route
// handling. It is satisfied by *RouteMiddlewareManager, so MCP routes reuse
// exactly the same middleware machinery as HTTP and GraphQL routes.
type MCPRouteMiddleware interface {
	// ApplyMiddleware wraps the handler with the route's middleware chain.
	ApplyMiddleware(handler http.Handler, route *config.Route) http.Handler
}

// MCPHandler serves the downstream MCP endpoint as a plain http.Handler so it
// composes INSIDE the gateway's global middleware chain exactly like the
// GraphQL handler. It enforces the modern MCP transport rules (HUB-101..148),
// selects an upstream, re-derives upstream headers and _meta, and brokers a
// single JSON-RPC request/response through the hub client.
//
// Discovery aggregation, caching, MRTR, subscriptions and full authorization
// are handled by later milestones; this handler covers the minimal
// request/response broker path.
type MCPHandler struct {
	logger          observability.Logger
	backendRegistry BackendGetter
	hub             mcpproxy.HubClient
	mapper          namespace.Mapper
	metrics         *mcpmetrics.Metrics
	routeMiddleware MCPRouteMiddleware
	hubClientInfo   meta.Info
	hubServerInfo   meta.Info

	// M3 components. Each is optional: a nil component degrades gracefully to
	// the M2 pass-through behavior (additive/opt-in).
	aggregator discovery.Aggregator
	cache      *mcpcache.ResultCache
	authorizer *mcpauthz.Authorizer

	// upstreamResolver is the aggregator's upstream resolver, held here so a
	// hot reload can refresh its upstream map alongside the handler's own map
	// (G-1). Optional: nil when the aggregator is disabled.
	upstreamResolver *MCPUpstreamResolver

	// M4 components. Each is optional: a nil component keeps the M3 behavior
	// (additive/opt-in). coordinator brokers MRTR (HUB-201..209); subManager
	// coordinates subscription streams (HUB-221..229).
	coordinator *mcpmrtr.Coordinator
	subManager  *mcpsub.Manager

	// M5 components. auditLogger records a tools/call audit trail (HUB-408);
	// dryRun enables shadow mode (HUB-507); limiter bounds concurrent
	// streams/upstream connections (HUB-405); healthChecker probes upstreams
	// (T-60). Each is optional/additive.
	auditLogger   audit.Logger
	dryRun        bool
	limiter       *mcpLimiter
	healthChecker *MCPHealthChecker

	// M6 components (HTTP dual-era bridging, HUB-701..707/721..724). Each is
	// optional/additive: when no legacy upstream is configured the era-aware
	// wrapper resolves modern and the modern path is unchanged. eraPool owns
	// pooled legacy sessions; eraBridge converts legacy server-initiated
	// requests to input_required (HUB-704).
	eraPool   *era.SessionPool
	eraBridge *era.ServerInitiatedBridge

	// mu guards the hot-reloadable configuration below.
	mu        sync.RWMutex
	routes    []config.MCPRoute
	upstreams map[string]config.MCPBackend
	mcpConfig *config.MCPConfig
}

// MCPHandlerOption is a functional option for MCPHandler.
type MCPHandlerOption func(*MCPHandler)

// WithMCPHandlerLogger sets the handler logger.
func WithMCPHandlerLogger(logger observability.Logger) MCPHandlerOption {
	return func(h *MCPHandler) {
		if logger != nil {
			h.logger = logger
		}
	}
}

// WithMCPHandlerBackendRegistry sets the backend registry used to resolve MCP
// upstreams by name.
func WithMCPHandlerBackendRegistry(reg BackendGetter) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.backendRegistry = reg
	}
}

// WithMCPHandlerHub sets the upstream hub client.
func WithMCPHandlerHub(hub mcpproxy.HubClient) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.hub = hub
	}
}

// WithMCPHandlerMapper sets the namespace mapper.
func WithMCPHandlerMapper(mapper namespace.Mapper) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.mapper = mapper
	}
}

// WithMCPHandlerMetrics sets the metrics recorder.
func WithMCPHandlerMetrics(m *mcpmetrics.Metrics) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.metrics = m
	}
}

// WithMCPHandlerRouteMiddleware sets the per-route middleware applier.
func WithMCPHandlerRouteMiddleware(rm MCPRouteMiddleware) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.routeMiddleware = rm
	}
}

// WithMCPHandlerConfig sets the initial routes, upstreams and MCP config.
func WithMCPHandlerConfig(
	routes []config.MCPRoute,
	upstreams map[string]config.MCPBackend,
	cfg *config.MCPConfig,
) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.routes = routes
		h.upstreams = upstreams
		h.mcpConfig = cfg
	}
}

// WithMCPHandlerClientInfo sets the hub's clientInfo sent upstream.
func WithMCPHandlerClientInfo(info meta.Info) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.hubClientInfo = info
	}
}

// WithMCPHandlerServerInfo sets the hub's serverInfo injected into results.
func WithMCPHandlerServerInfo(info meta.Info) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.hubServerInfo = info
	}
}

// WithMCPHandlerAggregator sets the discovery aggregator used for the
// server/discover and */list paths. A nil aggregator falls back to the M2
// single-upstream broker path.
func WithMCPHandlerAggregator(agg discovery.Aggregator) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.aggregator = agg
	}
}

// WithMCPHandlerUpstreamResolver registers the aggregator's upstream resolver
// with the handler so hot reloads refresh the resolver's upstream map in
// lock-step with the handler's own map (G-1). It is additive: nil keeps the
// prior behavior (no resolver refresh).
func WithMCPHandlerUpstreamResolver(r *MCPUpstreamResolver) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.upstreamResolver = r
	}
}

// WithMCPHandlerCache sets the MCP result cache. A nil cache disables caching
// (every discovery/list/read is served fresh).
func WithMCPHandlerCache(c *mcpcache.ResultCache) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.cache = c
	}
}

// WithMCPHandlerAuthorizer sets the MCP authorizer. A nil (or not-enabled)
// authorizer skips authentication/authorization enforcement (additive).
func WithMCPHandlerAuthorizer(a *mcpauthz.Authorizer) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.authorizer = a
	}
}

// WithMCPHandlerMRTRCoordinator sets the MRTR coordinator. A nil coordinator
// disables MRTR relay (input_required is forwarded verbatim as M3 did).
func WithMCPHandlerMRTRCoordinator(c *mcpmrtr.Coordinator) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.coordinator = c
	}
}

// WithMCPHandlerSubscriptionManager sets the subscription manager. A nil
// manager disables subscriptions/listen (it returns method-not-found).
func WithMCPHandlerSubscriptionManager(m *mcpsub.Manager) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.subManager = m
	}
}

// WithMCPHandlerAuditLogger sets the audit logger used to emit a tools/call
// audit trail (HUB-408). A nil logger disables MCP auditing (additive).
func WithMCPHandlerAuditLogger(l audit.Logger) MCPHandlerOption {
	return func(h *MCPHandler) {
		if l != nil {
			h.auditLogger = l
		}
	}
}

// WithMCPHandlerDryRun enables shadow mode: routing/policy/schema validation
// resolve a request WITHOUT invoking the upstream (HUB-507).
func WithMCPHandlerDryRun(enabled bool) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.dryRun = enabled
	}
}

// WithMCPHandlerLimits sets the concurrency limits for streams-per-principal
// and upstream connections (HUB-405). Non-positive bounds disable the
// corresponding limiter.
func WithMCPHandlerLimits(maxStreamsPerPrincipal, maxUpstreamConns int) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.limiter = newMCPLimiter(maxStreamsPerPrincipal, maxUpstreamConns)
	}
}

// WithMCPHandlerEra wires the HTTP dual-era bridging components (HUB-701..707,
// HUB-721..724): the legacy session pool and the server-initiated-request
// bridge. It is additive — a nil pool/bridge keeps the modern-only behavior.
// The caller is expected to have already wrapped the handler's hub client with
// an era.EraAwareHubClient so brokered calls route by era.
func WithMCPHandlerEra(pool *era.SessionPool, bridge *era.ServerInitiatedBridge) MCPHandlerOption {
	return func(h *MCPHandler) {
		h.eraPool = pool
		h.eraBridge = bridge
	}
}

// SetHub replaces the handler's hub client after construction. It is used to
// install the era-aware wrapper once the handler (which supplies the era
// interfaces) exists, avoiding a construction cycle. It MUST be called during
// wiring, before the handler serves traffic, so no concurrent request observes
// a mid-swap hub (the field is read without a lock on the hot path).
func (h *MCPHandler) SetHub(hub mcpproxy.HubClient) {
	if hub != nil {
		h.hub = hub
	}
}

// NewMCPHandler creates the MCP endpoint handler. The metrics recorder and
// mapper default to sane values when not supplied.
func NewMCPHandler(opts ...MCPHandlerOption) (*MCPHandler, error) {
	h := &MCPHandler{
		logger:    observability.NopLogger(),
		upstreams: make(map[string]config.MCPBackend),
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.metrics == nil {
		h.metrics = mcpmetrics.GetMetrics()
	}
	if h.mapper == nil {
		mapper, err := namespace.NewDefaultMapper("")
		if err != nil {
			return nil, err
		}
		h.mapper = mapper
	}
	h.registerUpstreamPrefixes()
	return h, nil
}

// registerUpstreamPrefixes registers each configured upstream's namespace
// prefix with the mapper so Denamespace/Namespace can resolve its primitives.
func (h *MCPHandler) registerUpstreamPrefixes() {
	dm, ok := h.mapper.(*namespace.DefaultMapper)
	if !ok {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for id := range h.upstreams {
		up := h.upstreams[id]
		_ = dm.Register(id, up.GetEffectiveNamespacePrefix())
	}
}

// UpdateConfig hot-reloads the routes, upstreams and MCP config (HUB-502). It
// swaps the configuration under the write lock and re-registers upstream
// namespace prefixes.
func (h *MCPHandler) UpdateConfig(
	routes []config.MCPRoute,
	upstreams map[string]config.MCPBackend,
	cfg *config.MCPConfig,
) {
	h.mu.Lock()
	h.routes = routes
	h.upstreams = upstreams
	h.mcpConfig = cfg
	h.mu.Unlock()
	// Refresh the aggregator's resolver so discovery observes the new upstream
	// set (added/changed MCPBackends) instead of a stale boot snapshot (G-1).
	if h.upstreamResolver != nil {
		h.upstreamResolver.Update(upstreams)
	}
	h.registerUpstreamPrefixes()
}

// AttachHealthChecker wires and starts a per-upstream MCP health checker
// (T-60). It is additive: without it the upstream-health gauge stays at its
// default and discovery is never degraded by probing. The checker is stopped by
// Close.
func (h *MCPHandler) AttachHealthChecker(ctx context.Context, hc *MCPHealthChecker) {
	if hc == nil {
		return
	}
	h.mu.Lock()
	h.healthChecker = hc
	h.mu.Unlock()
	hc.Start(ctx)
}

// Close releases handler resources. It answers every active subscription with
// a graceful complete result and closes the streams (HUB-226/509) so a
// draining shutdown never leaves clients hanging, and stops the upstream health
// checker. When no subscription manager is configured it is a no-op.
func (h *MCPHandler) Close() {
	if h.subManager != nil {
		h.subManager.Shutdown()
	}
	h.mu.RLock()
	hc := h.healthChecker
	pool := h.eraPool
	h.mu.RUnlock()
	if hc != nil {
		hc.Stop()
	}
	// Close pooled legacy sessions so their SSE pumps exit (no goroutine leak,
	// HUB-701/702).
	if pool != nil {
		pool.Close()
	}
}

// ServeHTTP implements http.Handler.
func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// HUB-103: only POST is served in modern mode; GET/DELETE are rejected.
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w)
		return
	}
	// HUB-106: validate Origin against the allowlist.
	if !h.originAllowed(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	h.serveRequest(w, r)
}

// writeMethodNotAllowed rejects non-POST requests (HUB-103).
func (h *MCPHandler) writeMethodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// originAllowed enforces the Origin allowlist (HUB-106). A same-origin request
// (no Origin header) is always allowed; an empty allowlist allows any origin.
func (h *MCPHandler) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	h.mu.RLock()
	cfg := h.mcpConfig
	h.mu.RUnlock()
	if cfg == nil || len(cfg.AllowedOrigins) == 0 {
		return true
	}
	for _, allowed := range cfg.AllowedOrigins {
		if allowed == "*" || strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

// mcpReq bundles the parsed JSON-RPC request, its decoded params and the
// per-request start time so broker helpers keep small signatures.
type mcpReq struct {
	req    *jsonrpc.Request
	params map[string]any
	start  time.Time
}

// id returns the JSON-RPC request id for error responses.
func (m *mcpReq) id() json.RawMessage { return m.req.ID }

// method returns the JSON-RPC method name.
func (m *mcpReq) method() string { return m.req.Method }

// serveRequest brokers a single MCP request end to end, recording metrics for
// every outcome.
func (h *MCPHandler) serveRequest(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.startSpan(r)
	defer span.End()
	// startSpan derives ctx from r.Context() (via the propagator's Extract);
	// re-stamping it onto the request propagates the span downstream.
	r = r.WithContext(ctx) //nolint:contextcheck // ctx derives from r.Context() in startSpan

	mr, ok := h.parseAndValidate(w, r)
	if !ok {
		return
	}
	span.SetAttributes(attribute.String(spanAttrMethod, mr.method()))
	annotateRequestSpan(r, mr.method(), name0(mr.params), metaProtocolVersion(mr.params))

	route := h.matchRoute(w, r, mr)
	if route == nil {
		return
	}
	r = withMCPRouteContext(r, route)

	// Authenticate + authorize early: resolve the principal, enforce required
	// scopes and consult the policy engine BEFORE any upstream call and before
	// returning cached results (HUB-305/306/307/310). When authorization is
	// not configured for the route this is a no-op.
	principal, ok := h.authorize(w, r, mr, route)
	if !ok {
		return
	}
	r = withMCPPrincipal(r, principal)

	terminal := h.brokerHandler(mr)
	h.applyRouteMiddleware(terminal, route).ServeHTTP(w, r)
}

// startSpan extracts inbound trace context and starts the per-request MCP
// span (mirrors proxy.doProxy).
func (h *MCPHandler) startSpan(r *http.Request) (context.Context, trace.Span) {
	propagator := otel.GetTextMapPropagator()
	ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	tracer := otel.Tracer(mcpTracerName)
	return tracer.Start(ctx, "mcp "+r.URL.Path,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("url.path", r.URL.Path)),
	)
}

// parseAndValidate reads the bounded body, parses the single JSON-RPC request,
// validates the _meta/protocol requirements (HUB-121..123) and the mirrored
// headers (HUB-141..143). It writes the appropriate error response and returns
// ok=false on any failure.
func (h *MCPHandler) parseAndValidate(w http.ResponseWriter, r *http.Request) (*mcpReq, bool) {
	req, ok := h.readRequest(w, r)
	if !ok {
		return nil, false
	}

	params, err := decodeParams(req.Params)
	if err != nil {
		h.writeJSONRPCError(w, req.ID, http.StatusBadRequest, protocol.InvalidParams, "invalid params object", nil)
		return nil, false
	}

	mr := &mcpReq{req: req, params: params, start: time.Now()}
	if ok := h.validateMeta(w, mr); !ok {
		return nil, false
	}
	if ok := h.validateHeaders(w, r, mr); !ok {
		return nil, false
	}
	return mr, true
}

// readRequest reads the body bounded by the configured max size, ignores
// session/resumption headers (HUB-104/105), and parses exactly one JSON-RPC
// request or notification (HUB-102).
func (h *MCPHandler) readRequest(w http.ResponseWriter, r *http.Request) (*jsonrpc.Request, bool) {
	// HUB-104/105: modern mode ignores session/resumption headers.
	r.Header.Del("Mcp-Session-Id")
	r.Header.Del("Last-Event-ID")

	limit := h.maxBodySize()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	req, err := jsonrpc.ParseSingleReader(r.Body)
	if err != nil {
		h.writeJSONRPCError(w, nil, http.StatusBadRequest, protocol.InvalidRequest, err.Error(), nil)
		return nil, false
	}
	return req, true
}

// validateMeta enforces the _meta discipline (HUB-121/123): params._meta MUST
// carry protocolVersion and clientCapabilities, and the requested version MUST
// be supported by the hub. The header/meta agreement (HUB-122) is checked in
// validateHeaders where the request headers are available.
func (h *MCPHandler) validateMeta(w http.ResponseWriter, mr *mcpReq) bool {
	metaObj := extractMeta(mr.params)
	version, _ := metaObj[protocol.MetaProtocolVersion].(string)
	_, hasCaps := metaObj[protocol.MetaClientCapabilities]

	if version == "" || !hasCaps {
		h.metrics.RecordSchemaRejection(mr.method())
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest, protocol.InvalidParams,
			"params._meta must carry protocolVersion and clientCapabilities", nil)
		return false
	}

	if !protocol.IsSupportedVersion(version) {
		h.metrics.RecordSchemaRejection(mr.method())
		data := map[string]any{
			"supported": protocol.HubSupportedVersions,
			"requested": version,
		}
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest,
			protocol.UnsupportedProtocolVersion, "unsupported protocol version", data)
		return false
	}
	return true
}

// validateHeaders enforces the MCP-Protocol-Version header agreement
// (HUB-122) and the mirrored Mcp-Method / Mcp-Name headers (HUB-141..143).
// The MCP-Protocol-Version header is REQUIRED: absence, an unsupported
// revision, or disagreement with _meta protocolVersion are all rejected with
// -32020 (HeaderMismatch) / HTTP 400 before any header-based policy runs
// (HUB-122/147). VersionGate gates enforcement on a revision that mandates
// header/body validation.
func (h *MCPHandler) validateHeaders(w http.ResponseWriter, r *http.Request, mr *mcpReq) bool {
	metaObj := extractMeta(mr.params)
	version, _ := metaObj[protocol.MetaProtocolVersion].(string)

	hdr := r.Header.Get(headers.HeaderMcpProtocolVersion)
	if hdr == "" {
		h.metrics.RecordHeaderMismatch(mr.method())
		h.logger.Debug("mcp: missing MCP-Protocol-Version header",
			observability.String("method", mr.method()))
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest, protocol.HeaderMismatch,
			"MCP-Protocol-Version header is required", nil)
		return false
	}
	if hdr != version {
		h.metrics.RecordHeaderMismatch(mr.method())
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest, protocol.HeaderMismatch,
			"MCP-Protocol-Version header does not match _meta protocolVersion", nil)
		return false
	}
	// HUB-147: the header must name a revision that mandates header/body
	// validation before any mirrored-header policy is trusted.
	if !headers.VersionGate(r) {
		h.metrics.RecordHeaderMismatch(mr.method())
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest, protocol.HeaderMismatch,
			"MCP-Protocol-Version does not mandate header validation", nil)
		return false
	}

	name := primitiveName(mr.params)
	if err := headers.ValidateHeaders(r, mr.method(), name, mr.params); err != nil {
		var he *headers.HeaderError
		code := protocol.HeaderMismatch
		if errors.As(err, &he) {
			code = he.Code
		}
		h.metrics.RecordHeaderMismatch(mr.method())
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest, code, err.Error(), nil)
		return false
	}
	return true
}

// matchRoute finds the MCP route matching the request. On no match it writes a
// JSON-RPC 404 error and returns nil.
func (h *MCPHandler) matchRoute(w http.ResponseWriter, r *http.Request, mr *mcpReq) *config.MCPRoute {
	h.mu.RLock()
	routes := h.routes
	h.mu.RUnlock()

	name := primitiveName(mr.params)
	route := matchMCPRoute(routes, r, mr.method(), name)
	if route == nil {
		h.writeJSONRPCError(w, mr.id(), http.StatusNotFound, protocol.MethodNotFound,
			"no matching MCP route", nil)
		return nil
	}
	return route
}

// brokerHandler returns the terminal handler that selects the upstream,
// de-namespaces the body, brokers the request via the hub, and writes the
// re-namespaced JSON response. Route middleware runs around it.
func (h *MCPHandler) brokerHandler(mr *mcpReq) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.broker(w, r, mr)
	})
}

// broker performs the upstream round-trip for a matched request. Discovery and
// list methods are served by the aggregator + cache path when configured;
// subscriptions/listen opens a fan-out SSE stream; MRTR-eligible methods route
// through the MRTR coordinator; other methods take the single-upstream broker
// path.
func (h *MCPHandler) broker(w http.ResponseWriter, r *http.Request, mr *mcpReq) {
	route := mcpRouteFromContext(r)

	// Shadow mode (HUB-507): resolve routing/policy without invoking the
	// upstream and return a synthetic resolution result.
	if h.dryRunRequested(r) {
		h.serveDryRun(w, r, mr, route)
		return
	}

	if h.aggregator != nil && isAggregatedMethod(mr.method()) {
		h.serveAggregated(w, r, mr, route)
		return
	}

	// subscriptions/listen opens a long-lived SSE stream exempt from the
	// request timeout (HUB-224/243).
	if h.subManager != nil && mr.method() == protocol.MethodSubscriptionsListen {
		h.serveSubscription(w, r, mr, route)
		return
	}

	upstreamID, upstream, ok := h.selectUpstream(w, mr, route)
	if !ok {
		return
	}

	sb, ok := h.resolveBackend(w, mr, upstream)
	if !ok {
		return
	}

	// MRTR-eligible methods (tools/call, resources/read, prompts/get) route
	// through the coordinator so input_required results are enveloped and
	// retries are verified (HUB-201..209).
	if h.coordinator != nil && mcpmrtr.IsMRTRMethod(mr.method()) {
		h.serveMRTR(w, r, mr, upstreamID, upstream, sb)
		return
	}

	version := metaProtocolVersion(mr.params)
	negotiated := negotiatedVersion(upstream, version)
	method := mr.method()

	// Serve resources/read from the cache when possible (per auth context),
	// enforcing authorization on the cache hit before returning (HUB-183/307).
	if h.serveReadFromCache(w, r, mr, upstreamID) {
		return
	}

	upstreamReq, err := h.buildUpstreamRequest(mr, negotiated)
	if err != nil {
		h.metrics.RecordUpstreamFailure(upstreamID, method)
		h.writeJSONRPCError(w, mr.id(), http.StatusBadGateway, protocol.InternalError, err.Error(), nil)
		return
	}

	upstreamHeaders := h.deriveHeaders(method, mr.params, upstreamID)

	// Bound concurrent upstream connections (HUB-405). A saturated pool is
	// reported as a retryable upstream failure rather than blocking.
	if !h.limiter.tryAcquireUpstream() {
		h.metrics.RecordUpstreamFailure(upstreamID, method)
		h.writeJSONRPCError(w, mr.id(), http.StatusServiceUnavailable, protocol.InternalError,
			"upstream connection pool exhausted", nil)
		return
	}
	defer h.limiter.releaseUpstream()

	h.metrics.IncInFlight(upstreamID, method)
	defer h.metrics.DecInFlight(upstreamID, method)

	// Bound the call by the per-method/per-tool timeout, converting an
	// upstream stall into a JSON-RPC error rather than a silent hang, while
	// still honoring client disconnect via r.Context() (HUB-241/243).
	callCtx, cancel := h.callContext(r.Context(), upstream, method, mr.params)
	defer cancel()

	resp, err := h.hub.Call(callCtx, sb, upstream.GetEffectivePath(), upstreamReq, upstreamHeaders)
	if err != nil {
		h.writeUpstreamCallError(w, mr, upstreamID, method, version, err)
		return
	}

	h.maybeCacheRead(r, mr, resp, upstreamID)
	resultType, outcome := brokeredSpanOutcome(resp)
	annotateOutcomeSpan(r, upstreamID, resultType, outcome)
	h.enforceBrokeredResultLimits(resp)
	h.writeBrokeredResponse(w, mr, resp, upstreamID, version)
	h.auditToolCall(r, mr, upstreamID, auditDecisionFor(resp), resultType, time.Since(mr.start))
}

// enforceBrokeredResultLimits logs a WARN when a brokered result exceeds the
// configured content-block count or total response size (HUB-405). The result
// is still returned (upstream response is already bounded by the hub client);
// this surfaces oversize results for observability.
func (h *MCPHandler) enforceBrokeredResultLimits(resp *jsonrpc.Response) {
	if resp == nil || resp.Error != nil {
		return
	}
	maxBlocks, maxSize := h.resultLimits()
	if err := enforceResultLimits(resp.Result, maxBlocks, maxSize); err != nil {
		h.logger.Warn("mcp: brokered result exceeds configured limits",
			observability.Error(err))
	}
}

// resultLimits returns the configured max content blocks and max response size.
func (h *MCPHandler) resultLimits() (maxBlocks int, maxSize int64) {
	h.mu.RLock()
	cfg := h.mcpConfig
	h.mu.RUnlock()
	if cfg == nil {
		return config.DefaultMCPMaxContentBlocks, config.DefaultMCPMaxResponseSize
	}
	return cfg.MaxContentBlocks, cfg.MaxResponseSize
}

// auditDecisionFor classifies a brokered response for the audit decision field.
func auditDecisionFor(resp *jsonrpc.Response) string {
	if resp != nil && resp.Error != nil {
		return "error"
	}
	return "allow"
}

// brokeredSpanOutcome classifies a brokered response for the request span.
func brokeredSpanOutcome(resp *jsonrpc.Response) (resultType, outcome string) {
	if resp != nil && resp.Error != nil {
		return resultTypeUnknown, mcpmetrics.OutcomeError
	}
	return protocol.ResultComplete, mcpmetrics.OutcomeSuccess
}

// selectUpstream resolves the upstream id and config for the request. When the
// primitive name is namespaced it is de-namespaced to its owning upstream
// (owner-pinning always wins so a namespaced primitive reaches its owner);
// otherwise (e.g. tools/call without a namespace prefix) one of the route's
// configured upstreams is chosen with stateless weighted-random selection over
// only the candidates present in the live upstreams map.
func (h *MCPHandler) selectUpstream(
	w http.ResponseWriter, mr *mcpReq, route *config.MCPRoute,
) (upstreamID string, upstream config.MCPBackend, ok bool) {
	h.mu.RLock()
	upstreams := h.upstreams
	h.mu.RUnlock()

	name := primitiveName(mr.params)
	if name != "" {
		if id, _, ok := h.mapper.Denamespace(name); ok {
			if up, exists := upstreams[id]; exists {
				return id, up, true
			}
		}
	}

	if id, up, picked := h.pickWeightedUpstream(route, upstreams); picked {
		return id, up, true
	}

	h.writeJSONRPCError(w, mr.id(), http.StatusNotFound, protocol.MethodNotFound,
		"no upstream configured for request", nil)
	return "", config.MCPBackend{}, false
}

// pickWeightedUpstream applies stateless weighted-random selection over the
// route's upstream refs, restricted to candidates that are present in the live
// upstreams map. Filtering to live candidates means a deleted or not-yet-applied
// first backend no longer 404s when healthy siblings exist. It returns the
// selected id/config and picked=true when a candidate was chosen.
func (h *MCPHandler) pickWeightedUpstream(
	route *config.MCPRoute, upstreams map[string]config.MCPBackend,
) (upstreamID string, upstream config.MCPBackend, picked bool) {
	if route == nil {
		return "", config.MCPBackend{}, false
	}
	refs := route.UpstreamRefs()
	candidates := make([]config.MCPUpstreamRef, 0, len(refs))
	for _, ref := range refs {
		if _, exists := upstreams[ref.Name]; exists {
			candidates = append(candidates, ref)
		}
	}
	selected, ok := selectWeightedUpstream(candidates)
	if !ok {
		return "", config.MCPBackend{}, false
	}
	up := upstreams[selected.Name]
	if h.metrics != nil && len(candidates) > 1 {
		h.metrics.RecordUpstreamSelected(route.Name, selected.Name)
	}
	h.logger.Debug("mcp: weighted upstream selected",
		observability.String("route", route.Name),
		observability.String("upstream", selected.Name),
		observability.Int("candidates", len(candidates)),
	)
	return selected.Name, up, true
}

// resolveBackend looks up the ServiceBackend for an upstream in the registry.
func (h *MCPHandler) resolveBackend(
	w http.ResponseWriter, mr *mcpReq, upstream config.MCPBackend,
) (*backend.ServiceBackend, bool) {
	if h.backendRegistry == nil {
		h.writeJSONRPCError(w, mr.id(), http.StatusBadGateway, protocol.InternalError,
			"backend registry unavailable", nil)
		return nil, false
	}
	b, exists := h.backendRegistry.Get(upstream.Name)
	if !exists {
		h.writeJSONRPCError(w, mr.id(), http.StatusBadGateway, protocol.InternalError,
			"upstream backend not found: "+upstream.Name, nil)
		return nil, false
	}
	sb, ok := b.(*backend.ServiceBackend)
	if !ok {
		h.writeJSONRPCError(w, mr.id(), http.StatusBadGateway, protocol.InternalError,
			"upstream backend type unsupported", nil)
		return nil, false
	}
	return sb, true
}

// buildUpstreamRequest de-namespaces the primitive name in the body and
// constructs a fresh upstream JSON-RPC request carrying the upstream _meta.
func (h *MCPHandler) buildUpstreamRequest(mr *mcpReq, negotiated string) (*jsonrpc.Request, error) {
	rewritten := denamespaceParams(h.mapper, mr.params)

	downstreamMeta, err := meta.Decode(rawMeta(mr.params))
	if err != nil {
		return nil, err
	}
	upMeta, err := meta.BuildUpstreamMeta(downstreamMeta, meta.BuildUpstreamOptions{
		NegotiatedUpstreamVersion: negotiated,
		HubClientInfo:             h.hubClientInfo,
		BrokerableCaps:            brokerableCaps(),
	})
	if err != nil {
		return nil, err
	}
	rawUpMeta, err := upMeta.Encode()
	if err != nil {
		return nil, err
	}
	rewritten["_meta"] = rawUpMeta

	newParams, err := json.Marshal(rewritten)
	if err != nil {
		return nil, err
	}
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		ID:      mr.id(),
		Method:  mr.method(),
		Params:  newParams,
	}, nil
}

// deriveHeaders re-derives the upstream Mcp-* headers after de-namespacing
// (HUB-143). The de-namespaced primitive name is used as Mcp-Name.
func (h *MCPHandler) deriveHeaders(method string, params map[string]any, upstreamID string) http.Header {
	name := primitiveName(params)
	original := name
	if id, orig, ok := h.mapper.Denamespace(name); ok && id == upstreamID {
		original = orig
	}
	return headers.DeriveUpstreamHeaders(method, original, params, nil)
}

// writeBrokeredResponse injects the hub serverInfo, re-namespaces result URIs,
// and writes the JSON-RPC response as application/json (HUB-126/163).
func (h *MCPHandler) writeBrokeredResponse(
	w http.ResponseWriter, mr *mcpReq, resp *jsonrpc.Response, upstreamID, version string,
) {
	outcome := mcpmetrics.OutcomeSuccess
	resultType := protocol.ResultComplete
	if resp.Error != nil {
		outcome = mcpmetrics.OutcomeError
		resultType = resultTypeUnknown
	} else {
		resp.Result = h.rewriteResult(resp.Result, upstreamID)
	}

	h.writeJSON(w, http.StatusOK, resp)
	h.recordOutcome(upstreamID, mr.method(), name0(mr.params), version, resultType, outcome, mr.start)
}

// rewriteResult injects hub serverInfo and re-namespaces result URIs,
// tolerating best-effort failures by returning the original result.
func (h *MCPHandler) rewriteResult(result json.RawMessage, upstreamID string) json.RawMessage {
	if len(result) == 0 {
		return result
	}
	injected, err := meta.InjectServerInfo(result, h.hubServerInfo)
	if err != nil {
		h.logger.Warn("mcp: inject serverInfo failed", observability.Error(err))
		injected = result
	}
	rewritten, err := h.mapper.RewriteResultURIs(upstreamID, injected)
	if err != nil {
		h.logger.Warn("mcp: rewrite result URIs failed", observability.Error(err))
		rewritten = injected
	}
	// Reject unsafe icon URI schemes; the hub never fetches icons (HUB-406).
	sanitized, dropped := security.SanitizeIcons(rewritten)
	if dropped > 0 {
		h.logger.Warn("mcp: dropped icons with unsafe URI scheme",
			observability.String("upstream", upstreamID),
			observability.Int("dropped", dropped))
	}
	return sanitized
}

// recordOutcome records the per-request metrics for a completed broker.
func (h *MCPHandler) recordOutcome(upstream, method, name, version, resultType, outcome string, start time.Time) {
	h.metrics.RecordRequest(upstream, method, name, version, resultType, outcome, time.Since(start))
}

// applyRouteMiddleware wraps the handler in the route's middleware chain,
// namespacing the chain cache key so MCP and other routes sharing a name never
// share a chain.
func (h *MCPHandler) applyRouteMiddleware(handler http.Handler, route *config.MCPRoute) http.Handler {
	if h.routeMiddleware == nil || route == nil {
		return handler
	}
	view := route.ToMiddlewareRoute()
	view.Name = mcpChainScope + view.Name
	return h.routeMiddleware.ApplyMiddleware(handler, view)
}

// maxBodySize returns the configured downstream body limit or the default.
func (h *MCPHandler) maxBodySize() int64 {
	h.mu.RLock()
	cfg := h.mcpConfig
	h.mu.RUnlock()
	if cfg != nil && cfg.MaxBodySize > 0 {
		return cfg.MaxBodySize
	}
	return config.DefaultMCPMaxBodySize
}

// writeJSONRPCError writes a JSON-RPC error response with the given HTTP status
// and JSON-RPC error code. The data argument, when non-nil, is embedded in the
// error object.
func (h *MCPHandler) writeJSONRPCError(
	w http.ResponseWriter, id json.RawMessage, status, code int, message string, data any,
) {
	rpcErr, err := jsonrpc.NewError(code, message, data)
	if err != nil {
		rpcErr = &jsonrpc.Error{Code: code, Message: message}
	}
	h.writeJSON(w, status, jsonrpc.NewErrorResponse(id, rpcErr))
}

// writeJSON marshals and writes a value as application/json.
func (h *MCPHandler) writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := jsonrpc.Encode(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	//nolint:gosec // G705: body is a marshaled JSON-RPC response served as application/json, not HTML
	if _, werr := w.Write(body); werr != nil {
		h.logger.Debug("mcp: write response failed", observability.Error(werr))
	}
}

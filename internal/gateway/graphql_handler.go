// Package gateway provides the core API Gateway functionality.
package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	graphqlmetrics "github.com/vyrodovalexey/avapigw/internal/graphql/metrics"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// GraphQLRouteMiddleware applies per-route middleware chains to GraphQL
// route handling. It is satisfied by *RouteMiddlewareManager, so GraphQL
// routes reuse exactly the same middleware machinery (authentication,
// authorization, rate limiting with memory/redis stores, CORS, security
// headers, caching, header manipulation) as HTTP routes.
type GraphQLRouteMiddleware interface {
	// GetMiddleware returns the middleware chain for a route config view.
	GetMiddleware(route *config.Route) []func(http.Handler) http.Handler

	// ApplyMiddleware wraps the handler with the route's middleware chain.
	ApplyMiddleware(handler http.Handler, route *config.Route) http.Handler
}

// GraphQLMetricsRecorder records GraphQL serving metrics. Satisfied by
// *graphqlmetrics.Metrics; injectable for tests.
type GraphQLMetricsRecorder interface {
	RecordRequest(backend, operationType string, statusCode int, duration time.Duration)
	RecordError(backend, operationType, errorType string)
}

// graphqlChainScope namespaces GraphQL route names inside the shared
// RouteMiddlewareManager chain cache (and derived scopes such as redis rate
// limit buckets and per-route metrics labels) so a GraphQL route can never
// collide with an HTTP route of the same name.
const graphqlChainScope = "graphql:"

// graphqlOpUnknown is the bounded operation-type label used for requests
// rejected before the operation type could be determined.
const graphqlOpUnknown = "unknown"

// graphqlOpSubscription is the operation type used to match and label
// WebSocket (graphql-ws) upgrade requests: the socket is the subscription
// transport, and upgrade requests carry no GraphQL body to inspect.
const graphqlOpSubscription = "subscription"

// GraphQL serving error types (bounded metric label values).
const (
	graphqlErrTransport    = "transport_error"
	graphqlErrAggregate    = "aggregate_error"
	graphqlErrSubscription = "subscription_error"
	graphqlErrNoRoute      = "route_not_found"
)

// graphqlErrorBody is the JSON error envelope used by the GraphQL endpoint,
// mirroring the GraphQL over HTTP response shape.
type graphqlErrorBody struct {
	Errors []graphqlErrorMessage `json:"errors"`
}

// graphqlErrorMessage is a single error entry in the error envelope.
type graphqlErrorMessage struct {
	Message string `json:"message"`
}

// GraphQLHandler serves the GraphQL endpoint as a plain http.Handler so it
// can be composed INSIDE the gateway's global middleware chain (recovery,
// request ID, logging, tracing, audit, metrics, CORS, max sessions, circuit
// breaker, global rate limit, global auth, body limit) exactly like proxied
// HTTP routes, and wraps every matched route's handling in that route's
// middleware chain.
//
// Serving order per request: parse (bounded read) -> match -> per-route
// middleware chain -> forward/aggregate. Parsing must precede the route
// chain because GraphQL route selection depends on the parsed operation;
// the read is bounded by maxBodySize so unauthenticated requests cannot
// buffer unbounded payloads before route-level auth runs.
type GraphQLHandler struct {
	router          *graphqlrouter.Router
	proxy           *graphqlproxy.Proxy
	subscriptions   *graphqlproxy.SubscriptionProxy
	aggregator      GraphQLAggregateHandler
	routeMiddleware GraphQLRouteMiddleware
	logger          observability.Logger
	metrics         GraphQLMetricsRecorder
	maxBodySize     int64

	// subscriptionOrigins is the WS origin allowlist forwarded to the
	// subscription proxy (empty keeps the permissive legacy behavior).
	subscriptionOrigins []string
}

// GraphQLHandlerOption is a functional option for GraphQLHandler.
type GraphQLHandlerOption func(*GraphQLHandler)

// WithGraphQLHandlerLogger sets the handler logger.
func WithGraphQLHandlerLogger(logger observability.Logger) GraphQLHandlerOption {
	return func(h *GraphQLHandler) {
		h.logger = logger
	}
}

// WithGraphQLHandlerAggregator sets the aggregate (fan-out) handler used for
// routes declaring an enabled aggregate config.
func WithGraphQLHandlerAggregator(aggregator GraphQLAggregateHandler) GraphQLHandlerOption {
	return func(h *GraphQLHandler) {
		h.aggregator = aggregator
	}
}

// WithGraphQLHandlerRouteMiddleware sets the per-route middleware applier.
// When configured, every matched GraphQL route's handling is wrapped in the
// route's middleware chain built from its middleware config fields
// (authentication, authorization, rateLimit, cors, security, cache, headers).
func WithGraphQLHandlerRouteMiddleware(rm GraphQLRouteMiddleware) GraphQLHandlerOption {
	return func(h *GraphQLHandler) {
		h.routeMiddleware = rm
	}
}

// WithGraphQLHandlerMaxBodySize sets the maximum GraphQL request body size.
func WithGraphQLHandlerMaxBodySize(maxBodySize int64) GraphQLHandlerOption {
	return func(h *GraphQLHandler) {
		if maxBodySize > 0 {
			h.maxBodySize = maxBodySize
		}
	}
}

// WithGraphQLHandlerMetrics sets the metrics recorder (defaults to the
// shared avapigw_graphql_* metrics singleton).
func WithGraphQLHandlerMetrics(metrics GraphQLMetricsRecorder) GraphQLHandlerOption {
	return func(h *GraphQLHandler) {
		h.metrics = metrics
	}
}

// WithGraphQLHandlerSubscriptionOrigins sets the WebSocket origin allowlist
// for GraphQL subscriptions (CSWSH protection). Empty keeps the permissive
// legacy behavior.
func WithGraphQLHandlerSubscriptionOrigins(origins []string) GraphQLHandlerOption {
	return func(h *GraphQLHandler) {
		h.subscriptionOrigins = origins
	}
}

// NewGraphQLHandler creates the GraphQL endpoint handler. Router and proxy
// are required; everything else is optional.
func NewGraphQLHandler(
	router *graphqlrouter.Router,
	proxy *graphqlproxy.Proxy,
	opts ...GraphQLHandlerOption,
) (*GraphQLHandler, error) {
	if router == nil || proxy == nil {
		return nil, fmt.Errorf("graphql handler requires a router and a proxy: %w", ErrNilConfig)
	}

	h := &GraphQLHandler{
		router:      router,
		proxy:       proxy,
		logger:      observability.NopLogger(),
		maxBodySize: defaultGraphQLMaxBodySize,
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.metrics == nil {
		h.metrics = graphqlmetrics.GetMetrics()
	}

	subOpts := []graphqlproxy.SubscriptionOption{
		graphqlproxy.WithSubscriptionLogger(h.logger),
	}
	if m, ok := h.metrics.(graphqlproxy.MetricsRecorder); ok {
		subOpts = append(subOpts, graphqlproxy.WithSubscriptionMetrics(m))
	}
	if len(h.subscriptionOrigins) > 0 {
		subOpts = append(subOpts, graphqlproxy.WithAllowedOrigins(h.subscriptionOrigins))
	}
	h.subscriptions = graphqlproxy.NewSubscriptionProxy(proxy, subOpts...)

	return h, nil
}

// Close releases handler resources (active subscription relays).
func (h *GraphQLHandler) Close() {
	if h.subscriptions != nil {
		h.subscriptions.Close()
	}
}

// ServeHTTP implements http.Handler.
func (h *GraphQLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case isWebSocketUpgradeRequest(r):
		// graphql-ws subscriptions: route middleware must run on the HTTP
		// upgrade request before the connection is hijacked.
		h.serveSubscription(w, r)
	case r.Method == http.MethodOptions:
		// CORS preflight: no GraphQL body to parse; match on path/headers
		// and let the route chain's CORS middleware answer it.
		h.servePreflight(w, r)
	default:
		h.serveRequest(w, r)
	}
}

// serveRequest handles regular (query/mutation) GraphQL HTTP requests and
// records the avapigw_graphql_* request metrics for every outcome.
func (h *GraphQLHandler) serveRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	recorder := util.NewStatusCapturingResponseWriter(w)

	backendLabel, opType := h.handleRequest(recorder, r)

	h.metrics.RecordRequest(backendLabel, opType, recorder.StatusCode, time.Since(start))
}

// handleRequest parses, matches, and serves a GraphQL request through the
// matched route's middleware chain. It returns the backend and operation
// type labels for metrics recording.
func (h *GraphQLHandler) handleRequest(w http.ResponseWriter, r *http.Request) (backendLabel, opType string) {
	gqlReq, ok := h.parseRequest(w, r)
	if !ok {
		return "", graphqlOpUnknown
	}

	match := h.router.Match(r, gqlReq)
	if match == nil {
		h.metrics.RecordError("", graphqlOpUnknown, graphqlErrNoRoute)
		h.writeError(w, http.StatusNotFound, "no matching GraphQL route")
		return "", graphqlOpUnknown
	}
	r = withGraphQLRouteContext(r, match.Route)

	terminal := h.terminalHandler(match)
	h.applyRouteMiddleware(terminal, match.Route).ServeHTTP(w, r)

	return match.BackendName, match.OperationType
}

// withGraphQLRouteContext stamps the matched GraphQL route name (namespaced
// with the graphql chain scope, mirroring the middleware chain cache keys)
// into the request context. Downstream middleware and the upstream metrics
// middleware's RouteHolder thereby label by matched route instead of
// "unmatched"/"unknown".
func withGraphQLRouteContext(r *http.Request, route *config.GraphQLRoute) *http.Request {
	if route == nil || route.Name == "" {
		return r
	}
	return r.WithContext(util.ContextWithRoute(r.Context(), graphqlChainScope+route.Name))
}

// parseRequest reads (bounded), validates, and restores the GraphQL request
// body. On failure it writes the error response and returns ok=false.
func (h *GraphQLHandler) parseRequest(w http.ResponseWriter, r *http.Request) (*graphqlrouter.GraphQLRequest, bool) {
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, h.maxBodySize+1))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return nil, false
	}
	if int64(len(bodyBytes)) > h.maxBodySize {
		h.writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}

	var gqlReq graphqlrouter.GraphQLRequest
	if err := json.Unmarshal(bodyBytes, &gqlReq); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid GraphQL request: %s", err.Error()))
		return nil, false
	}
	if gqlReq.Query == "" {
		h.writeError(w, http.StatusBadRequest, "GraphQL query is empty")
		return nil, false
	}

	// Restore the body for the route middleware chain and proxy forwarding.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	return &gqlReq, true
}

// terminalHandler returns the innermost handler for a matched route: the
// aggregate fan-out when configured and enabled, single-backend forwarding
// otherwise.
func (h *GraphQLHandler) terminalHandler(match *graphqlrouter.MatchResult) http.Handler {
	if h.aggregator != nil && match.Route != nil && match.Route.Aggregate.IsEnabled() {
		return h.aggregateHandler(match)
	}
	return h.forwardHandler(match)
}

// forwardHandler returns the terminal handler forwarding to the matched
// route's backend.
func (h *GraphQLHandler) forwardHandler(match *graphqlrouter.MatchResult) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := h.proxy.Forward(r.Context(), match.BackendName, r)
		if err != nil {
			h.logger.Error("GraphQL proxy error",
				observability.String("backend", match.BackendName),
				observability.Error(err),
			)
			h.metrics.RecordError(match.BackendName, match.OperationType, graphqlErrTransport)
			h.writeError(w, http.StatusBadGateway, fmt.Sprintf("backend error: %s", err.Error()))
			return
		}
		defer resp.Body.Close()

		// Copy response headers using Add to preserve multi-value headers
		// (e.g., Set-Cookie).
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			h.logger.Debug("failed to copy response body",
				observability.Error(err),
				observability.String("backend", match.BackendName),
			)
		}
	})
}

// aggregateHandler returns the terminal handler fanning the request out per
// the route's aggregate config.
func (h *GraphQLHandler) aggregateHandler(match *graphqlrouter.MatchResult) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.aggregator.ServeAggregate(w, r, match.Route.Aggregate); err != nil {
			h.logger.Warn("GraphQL aggregate fan-out failed",
				observability.String("route", match.Route.Name),
				observability.Error(err),
			)
			h.metrics.RecordError(match.BackendName, match.OperationType, graphqlErrAggregate)
			h.writeError(w, http.StatusBadGateway, fmt.Sprintf("aggregate error: %s", err.Error()))
		}
	})
}

// servePreflight answers CORS preflight requests on the GraphQL endpoint by
// running the matched route's middleware chain (whose CORS middleware
// short-circuits the preflight) around a No Content terminal. Preflights
// carry no GraphQL body, so matching uses path and headers only.
func (h *GraphQLHandler) servePreflight(w http.ResponseWriter, r *http.Request) {
	match := h.router.Match(r, &graphqlrouter.GraphQLRequest{})
	if match == nil {
		h.writeError(w, http.StatusNotFound, "no matching GraphQL route")
		return
	}
	r = withGraphQLRouteContext(r, match.Route)

	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Reached only when the route has no CORS middleware configured to
		// short-circuit the preflight; answer with No Content and no CORS
		// headers so browsers reject the cross-origin call.
		w.WriteHeader(http.StatusNoContent)
	})

	h.applyRouteMiddleware(terminal, match.Route).ServeHTTP(w, r)
}

// serveSubscription handles graphql-ws upgrade requests. The matched route's
// middleware chain runs on the HTTP upgrade request (authentication, rate
// limiting, CORS) BEFORE the connection is upgraded; the relay itself is
// handled by the subscription proxy and outlives the request.
func (h *GraphQLHandler) serveSubscription(w http.ResponseWriter, r *http.Request) {
	// Upgrade requests carry no GraphQL body; the socket transports
	// subscriptions, so match with the subscription operation type.
	match := h.router.Match(r, &graphqlrouter.GraphQLRequest{Query: graphqlOpSubscription})
	if match == nil {
		h.metrics.RecordError("", graphqlOpSubscription, graphqlErrNoRoute)
		h.writeError(w, http.StatusNotFound, "no matching GraphQL route")
		return
	}
	r = withGraphQLRouteContext(r, match.Route)

	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hw := newHijackTrackingResponseWriter(w)
		if err := h.subscriptions.HandleSubscription(r.Context(), hw, r, match.BackendName); err != nil {
			h.logger.Error("GraphQL subscription failed",
				observability.String("backend", match.BackendName),
				observability.Error(err),
			)
			h.metrics.RecordError(match.BackendName, graphqlOpSubscription, graphqlErrSubscription)
			// Only write an error response when the upgrader has not
			// already written one (it responds itself on handshake failure).
			if !hw.wroteOrHijacked() {
				h.writeError(w, http.StatusBadGateway, fmt.Sprintf("subscription error: %s", err.Error()))
			}
		}
	})

	h.applyRouteMiddleware(terminal, match.Route).ServeHTTP(w, r)
}

// applyRouteMiddleware wraps the handler in the route's middleware chain,
// namespacing the chain cache key so GraphQL and HTTP routes sharing a name
// never share a chain.
func (h *GraphQLHandler) applyRouteMiddleware(handler http.Handler, route *config.GraphQLRoute) http.Handler {
	if h.routeMiddleware == nil || route == nil {
		return handler
	}
	view := route.ToMiddlewareRoute()
	view.Name = graphqlChainScope + view.Name
	return h.routeMiddleware.ApplyMiddleware(handler, view)
}

// writeError writes the GraphQL JSON error envelope.
func (h *GraphQLHandler) writeError(w http.ResponseWriter, status int, message string) {
	body, err := json.Marshal(graphqlErrorBody{
		Errors: []graphqlErrorMessage{{Message: message}},
	})
	if err != nil {
		// Marshaling a flat string envelope cannot realistically fail;
		// degrade to a plain error to keep the status code correct.
		http.Error(w, message, status)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// isWebSocketUpgradeRequest reports whether the request is a WebSocket
// upgrade handshake (RFC 6455): Upgrade: websocket plus Connection: upgrade.
func isWebSocketUpgradeRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// hijackTrackingResponseWriter tracks whether a response has been written or
// the connection hijacked, while preserving http.Hijacker support required
// by the WebSocket upgrader. It must NOT embed StatusCapturingResponseWriter
// (which lacks Hijack) because gorilla/websocket type-asserts the writer.
type hijackTrackingResponseWriter struct {
	http.ResponseWriter
	wrote    bool
	hijacked bool
}

// newHijackTrackingResponseWriter wraps w with write/hijack tracking.
func newHijackTrackingResponseWriter(w http.ResponseWriter) *hijackTrackingResponseWriter {
	return &hijackTrackingResponseWriter{ResponseWriter: w}
}

// WriteHeader marks the response as written.
func (w *hijackTrackingResponseWriter) WriteHeader(code int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

// Write marks the response as written.
func (w *hijackTrackingResponseWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// Hijack delegates to the underlying writer's Hijacker and marks the
// connection as hijacked.
func (w *hijackTrackingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return conn, rw, err
}

// wroteOrHijacked reports whether a response was written or the connection
// hijacked (upgrade succeeded).
func (w *hijackTrackingResponseWriter) wroteOrHijacked() bool {
	return w.wrote || w.hijacked
}

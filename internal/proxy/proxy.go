// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// hopHeaders are headers that should not be forwarded.
// Using a map for O(1) lookup instead of iterating a slice.
var hopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// RouteMiddlewareApplier applies per-route middleware to a handler.
// This interface decouples the proxy from the gateway package to avoid
// import cycles.
type RouteMiddlewareApplier interface {
	// GetMiddleware returns the middleware chain for a specific route config.
	GetMiddleware(route *config.Route) []func(http.Handler) http.Handler

	// ApplyMiddleware wraps the handler with per-route middleware.
	ApplyMiddleware(handler http.Handler, route *config.Route) http.Handler
}

// ReverseProxy handles proxying requests to backend services.
type ReverseProxy struct {
	router                *router.Router
	backendRegistry       *backend.Registry
	circuitBreakerManager *backend.CircuitBreakerManager
	globalCircuitBreaker  *backend.CircuitBreakerManager
	logger                observability.Logger
	transport             http.RoundTripper
	errorHandler          func(http.ResponseWriter, *http.Request, error)
	modifyResponse        func(*http.Response) error
	flushInterval         time.Duration
	metricsRegistry       *prometheus.Registry
	routeMiddleware       RouteMiddlewareApplier
}

// ProxyOption is a functional option for configuring the proxy.
type ProxyOption func(*ReverseProxy)

// WithProxyLogger sets the logger for the proxy.
func WithProxyLogger(logger observability.Logger) ProxyOption {
	return func(p *ReverseProxy) {
		p.logger = logger
	}
}

// WithTransport sets the transport for the proxy.
func WithTransport(transport http.RoundTripper) ProxyOption {
	return func(p *ReverseProxy) {
		p.transport = transport
	}
}

// WithErrorHandler sets the error handler for the proxy.
func WithErrorHandler(handler func(http.ResponseWriter, *http.Request, error)) ProxyOption {
	return func(p *ReverseProxy) {
		p.errorHandler = handler
	}
}

// WithModifyResponse sets the response modifier for the proxy.
func WithModifyResponse(modifier func(*http.Response) error) ProxyOption {
	return func(p *ReverseProxy) {
		p.modifyResponse = modifier
	}
}

// WithFlushInterval sets the flush interval for streaming responses.
func WithFlushInterval(interval time.Duration) ProxyOption {
	return func(p *ReverseProxy) {
		p.flushInterval = interval
	}
}

// WithCircuitBreakerManager sets the backend circuit breaker manager.
func WithCircuitBreakerManager(manager *backend.CircuitBreakerManager) ProxyOption {
	return func(p *ReverseProxy) {
		p.circuitBreakerManager = manager
	}
}

// WithGlobalCircuitBreaker sets the global circuit breaker manager.
func WithGlobalCircuitBreaker(manager *backend.CircuitBreakerManager) ProxyOption {
	return func(p *ReverseProxy) {
		p.globalCircuitBreaker = manager
	}
}

// WithMetricsRegistry sets the Prometheus registry for proxy metrics.
// When provided, proxy and WebSocket metrics are registered with this
// registry instead of the default global registerer, ensuring they
// appear on the gateway's /metrics endpoint.
func WithMetricsRegistry(registry *prometheus.Registry) ProxyOption {
	return func(p *ReverseProxy) {
		p.metricsRegistry = registry
	}
}

// WithRouteMiddleware sets the per-route middleware applier.
// When configured, per-route middleware (cache, transform, encoding, headers)
// is applied around the proxying logic for each matched route.
func WithRouteMiddleware(rm RouteMiddlewareApplier) ProxyOption {
	return func(p *ReverseProxy) {
		p.routeMiddleware = rm
	}
}

// NewReverseProxy creates a new reverse proxy.
func NewReverseProxy(r *router.Router, registry *backend.Registry, opts ...ProxyOption) *ReverseProxy {
	p := &ReverseProxy{
		router:          r,
		backendRegistry: registry,
		logger:          observability.NopLogger(),
		flushInterval:   -1, // Immediate flush
	}

	for _, opt := range opts {
		opt(p)
	}

	// Initialize proxy and WebSocket metrics with the configured
	// registry so they appear on the gateway's /metrics endpoint.
	// When metricsRegistry is nil the metrics fall back to the
	// default global registerer (e.g. in tests).
	initProxyMetrics(p.metricsRegistry)
	initWebSocketMetrics(p.metricsRegistry)

	if p.errorHandler == nil {
		p.errorHandler = p.defaultErrorHandler
	}

	return p
}

// ServeHTTP implements http.Handler.
func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Match route
	result, err := p.router.Match(r)
	if err != nil {
		p.handleRouteNotFound(w, r, err)
		return
	}

	route := result.Route

	// Add path params to context
	if len(result.PathParams) > 0 {
		ctx = util.ContextWithPathParams(ctx, result.PathParams)
		r = r.WithContext(ctx)
	}

	// Add route name to context
	ctx = util.ContextWithRoute(ctx, route.Name)
	r = r.WithContext(ctx)

	// Handle direct response
	if route.Config.DirectResponse != nil {
		p.handleDirectResponse(w, route.Config.DirectResponse)
		return
	}

	// Handle redirect
	if route.Config.Redirect != nil {
		p.handleRedirect(w, r, route.Config.Redirect)
		return
	}

	// Proxy to backend
	p.proxyRequest(w, r, route)
}

// proxyTracerName is the OpenTelemetry tracer name for proxy operations.
const proxyTracerName = "avapigw/proxy"

// URL scheme constants to avoid duplicated string literals.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// proxyRequest proxies the request to a backend.
func (p *ReverseProxy) proxyRequest(
	w http.ResponseWriter,
	r *http.Request,
	route *router.CompiledRoute,
) {
	if len(route.Config.Route) == 0 {
		p.errorHandler(w, r, NewNoDestinationError(route.Name))
		return
	}

	// Apply per-route middleware if configured and the route has any
	if p.routeMiddleware != nil {
		middlewares := p.routeMiddleware.GetMiddleware(&route.Config)
		if len(middlewares) > 0 {
			// Create a handler that performs the actual proxying
			proxyHandler := http.HandlerFunc(func(innerW http.ResponseWriter, innerR *http.Request) {
				p.doProxy(innerW, innerR, route)
			})
			// Wrap the proxy handler with per-route middleware
			handler := p.routeMiddleware.ApplyMiddleware(proxyHandler, &route.Config)
			handler.ServeHTTP(w, r)
			return
		}
	}

	// No per-route middleware — proxy directly
	p.doProxy(w, r, route)
}

// doProxy performs the actual proxying logic: destination selection, backend
// resolution, target URL building, and reverse proxy execution.
func (p *ReverseProxy) doProxy(
	w http.ResponseWriter,
	r *http.Request,
	route *router.CompiledRoute,
) {
	// Extract incoming trace context and start a proxy span
	propagator := otel.GetTextMapPropagator()
	ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	tracer := otel.Tracer(proxyTracerName)
	ctx, span := tracer.Start(ctx, "proxy "+r.Method+" "+route.Name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("url.path", r.URL.Path),
			attribute.String("proxy.route", route.Name),
		),
	)
	defer span.End()
	r = r.WithContext(ctx)

	// Select destination using weighted random selection
	dest := p.selectDestination(route.Config.Route)
	if dest == nil {
		p.errorHandler(w, r, NewNoDestinationAvailableError(route.Name))
		return
	}

	span.SetAttributes(attribute.String("proxy.backend", dest.Destination.Host))

	// Get backend and resolve target host
	serviceBackend := p.getServiceBackend(dest.Destination.Host)

	var backendHost *backend.Host
	if serviceBackend != nil {
		var hostErr error
		backendHost, hostErr = serviceBackend.GetAvailableHost()
		if hostErr != nil {
			p.logger.Warn("no available hosts for backend",
				observability.String("backend", dest.Destination.Host),
				observability.String("route", route.Name),
				observability.Error(hostErr),
			)
			span.SetAttributes(attribute.String("proxy.host_error", hostErr.Error()))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, jsonErrNoAvailableHosts)
			return
		}
		defer serviceBackend.ReleaseHost(backendHost)
	}

	target, err := p.buildTargetURL(dest, serviceBackend, backendHost)
	if err != nil {
		p.errorHandler(w, r, NewInvalidTargetError(
			route.Name, dest.Destination.Host, err,
		))
		return
	}

	// Record the actual target host for observability
	targetLabel := dest.Destination.Host
	if backendHost != nil {
		actualTarget := net.JoinHostPort(backendHost.Address, strconv.Itoa(backendHost.Port))
		span.SetAttributes(
			attribute.String("proxy.target_host", actualTarget),
		)
		targetLabel = dest.Destination.Host + "/" + actualTarget
	}

	// Apply URL rewriting
	if route.Config.Rewrite != nil {
		r = p.applyRewrite(r, route.Config.Rewrite)
	}

	// Create and execute reverse proxy with duration tracking
	proxy := p.createReverseProxy(
		target, r, dest.Destination.Host, serviceBackend,
	)
	r, cancel := p.applyTimeout(r, route.Config.Timeout.Duration())
	defer cancel()

	backendStart := time.Now()
	p.executeProxy(w, r, proxy, dest.Destination.Host, target)
	duration := time.Since(backendStart)
	getProxyMetrics().backendDuration.WithLabelValues(
		targetLabel,
	).Observe(duration.Seconds())

	// Set span attributes for the response
	span.SetAttributes(attribute.Float64("proxy.backend_duration_ms", float64(duration.Milliseconds())))
}

// getServiceBackend retrieves the service backend from the registry.
func (p *ReverseProxy) getServiceBackend(host string) *backend.ServiceBackend {
	if p.backendRegistry == nil {
		return nil
	}
	b, ok := p.backendRegistry.Get(host)
	if !ok {
		return nil
	}
	sb, _ := b.(*backend.ServiceBackend)
	return sb
}

// buildTargetURL constructs the target URL for the backend.
// When a backendHost is provided (from the backend's load balancer), its Address
// and Port are used instead of the route destination's Host and Port.
func (p *ReverseProxy) buildTargetURL(
	dest *config.RouteDestination,
	serviceBackend *backend.ServiceBackend,
	backendHost *backend.Host,
) (*url.URL, error) {
	scheme := schemeHTTP
	if serviceBackend != nil && serviceBackend.IsTLSEnabled() {
		scheme = schemeHTTPS
	}

	host := dest.Destination.Host
	port := dest.Destination.Port
	if backendHost != nil {
		host = backendHost.Address
		port = backendHost.Port
	}

	targetURL := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	return url.Parse(targetURL)
}

// createReverseProxy creates a configured reverse proxy.
func (p *ReverseProxy) createReverseProxy(
	target *url.URL,
	originalReq *http.Request,
	backendHost string,
	serviceBackend *backend.ServiceBackend,
) *httputil.ReverseProxy {
	// Use the backend's transport when TLS is enabled, so that the
	// backend's TLS config (including client certs for mTLS and
	// InsecureSkipVerify) is applied to the connection.
	transport := p.transport
	if serviceBackend != nil && serviceBackend.IsTLSEnabled() {
		transport = serviceBackend.HTTPClient().Transport
	}

	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			p.director(req, target, originalReq)
			if serviceBackend != nil {
				if err := serviceBackend.ApplyAuth(req.Context(), req); err != nil {
					p.logger.Error("failed to apply backend authentication",
						observability.String("backend", backendHost),
						observability.Error(err),
					)
				}
			}
		},
		Transport:      transport,
		FlushInterval:  p.flushInterval,
		ErrorHandler:   p.errorHandler,
		ModifyResponse: p.modifyResponse,
	}
}

// applyTimeout applies timeout to the request context if configured.
// It returns the modified request and a cancel function that must be deferred by the caller.
func (p *ReverseProxy) applyTimeout(r *http.Request, timeout time.Duration) (*http.Request, context.CancelFunc) {
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		return r.WithContext(ctx), cancel
	}
	// Return a no-op cancel function when no timeout is applied
	return r, func() { /* no-op: no timeout context was created */ }
}

// executeProxy executes the proxy request with optional circuit breaker protection.
// The target URL is passed through for WebSocket message-level proxying.
func (p *ReverseProxy) executeProxy(
	w http.ResponseWriter,
	r *http.Request,
	proxy *httputil.ReverseProxy,
	backendName string,
	target *url.URL,
) {
	cb := p.getCircuitBreaker(backendName)

	// WebSocket upgrades require direct access to the underlying connection (Hijacker)
	// and cannot be wrapped by the circuit breaker's response recorder.
	// The gorilla/websocket message-level proxy is used for per-message metrics.
	if isWebSocketRequest(r) {
		p.executeWebSocket(w, r, backendName, target)
		return
	}

	if cb != nil {
		p.executeWithCircuitBreaker(w, r, proxy, cb, backendName)
	} else {
		proxy.ServeHTTP(w, r)
	}
}

// executeWebSocket executes a WebSocket proxy request with message-level metrics and tracing.
// It uses gorilla/websocket for bidirectional message relay, enabling per-message counting.
func (p *ReverseProxy) executeWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	backendName string,
	target *url.URL,
) {
	wsMetrics := getWebSocketMetrics()
	wsMetrics.connectionsTotal.WithLabelValues(backendName).Inc()
	wsMetrics.connectionsActive.WithLabelValues(backendName).Inc()
	connStart := time.Now()
	defer func() {
		wsMetrics.connectionsActive.WithLabelValues(backendName).Dec()
		wsMetrics.connectionDuration.WithLabelValues(backendName).Observe(
			time.Since(connStart).Seconds(),
		)
	}()

	// Start a tracing span for the WebSocket connection
	tracer := otel.Tracer(proxyTracerName)
	ctx, span := tracer.Start(r.Context(), "websocket "+r.URL.Path,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("websocket.backend", backendName),
			attribute.String("url.path", r.URL.Path),
			attribute.String("network.protocol.name", "websocket"),
		),
	)
	defer span.End()
	r = r.WithContext(ctx)

	p.logger.Debug("websocket connection established",
		observability.String("backend", backendName),
		observability.String("path", r.URL.Path),
	)

	// Use message-level WebSocket proxy for metrics tracking
	wp := &websocketProxy{logger: p.logger}
	sent, received, wsErr := wp.proxyWebSocket(w, r, target, p.transport)

	// Record message metrics
	if sent > 0 {
		wsMetrics.messagesSentTotal.WithLabelValues(backendName).Add(float64(sent))
	}
	if received > 0 {
		wsMetrics.messagesReceivedTotal.WithLabelValues(backendName).Add(float64(received))
	}

	// Record span attributes for message counts
	span.SetAttributes(
		attribute.Int64("websocket.messages_sent", sent),
		attribute.Int64("websocket.messages_received", received),
	)

	if wsErr != nil {
		wsMetrics.errorsTotal.WithLabelValues(backendName, "proxy_error").Inc()
		// Only log at debug level - WebSocket close is normal
		p.logger.Debug("websocket proxy completed",
			observability.String("backend", backendName),
			observability.Error(wsErr),
			observability.Int64("messages_sent", sent),
			observability.Int64("messages_received", received),
		)
	}
}

// isWebSocketRequest checks if the request is a WebSocket upgrade request.
func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// getCircuitBreaker returns the circuit breaker for a backend.
// It first checks for a backend-specific circuit breaker, then falls back to global.
func (p *ReverseProxy) getCircuitBreaker(backendName string) *backend.CircuitBreakerManager {
	// Check for backend-specific circuit breaker
	if p.circuitBreakerManager != nil {
		if cb := p.circuitBreakerManager.Get(backendName); cb != nil {
			return p.circuitBreakerManager
		}
	}

	// Fall back to global circuit breaker
	return p.globalCircuitBreaker
}

// executeWithCircuitBreaker executes the proxy request with circuit breaker protection.
func (p *ReverseProxy) executeWithCircuitBreaker(
	w http.ResponseWriter,
	r *http.Request,
	proxy *httputil.ReverseProxy,
	cbManager *backend.CircuitBreakerManager,
	backendName string,
) {
	// Create a response recorder to capture the response
	recorder := util.NewStatusCapturingResponseWriter(w)

	_, err := cbManager.Execute(backendName, func() (interface{}, error) {
		proxy.ServeHTTP(recorder, r)

		// Return error for 5xx responses to trigger circuit breaker
		if recorder.StatusCode >= http.StatusInternalServerError {
			return nil, util.NewServerError(recorder.StatusCode)
		}
		return nil, nil
	})

	if err != nil {
		// Check if it's a circuit breaker error (not a server error from the backend)
		var srvErr *util.ServerError
		if !errors.As(err, &srvErr) {
			p.logger.Warn("circuit breaker rejected request",
				observability.String("backend", backendName),
				observability.String("path", r.URL.Path),
				observability.Error(err),
			)

			// Only write error response if we haven't written anything yet
			if !recorder.HeaderWritten {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, jsonErrServiceUnavailable)
			}
		}
		// For server errors, the response was already written by the proxy
	}
}

// director modifies the request before forwarding.
func (p *ReverseProxy) director(req *http.Request, target *url.URL, originalReq *http.Request) {
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host

	// Inject trace context into outgoing request headers for distributed tracing
	otel.GetTextMapPropagator().Inject(originalReq.Context(), propagation.HeaderCarrier(req.Header))

	// Set the path from the original request only when the outgoing request
	// has no path (e.g., the request was constructed without one). When a
	// rewrite has been applied, req.URL.Path is already set to the rewritten
	// value and should not be overridden.
	if req.URL.Path == "" {
		req.URL.Path = originalReq.URL.Path
	}

	// Preserve query string
	if originalReq.URL.RawQuery != "" {
		req.URL.RawQuery = originalReq.URL.RawQuery
	}

	// Remove hop-by-hop headers, but preserve Upgrade and Connection
	// headers so that httputil.ReverseProxy can detect WebSocket
	// upgrade requests and handle protocol switching (101 Switching Protocols).
	// ReverseProxy.ServeHTTP checks upgradeType(outreq.Header) AFTER Director
	// returns, then strips hop-by-hop headers itself and re-adds Upgrade/Connection
	// if an upgrade was detected.
	for h := range hopHeaders {
		if h == "Upgrade" || h == "Connection" {
			continue
		}
		req.Header.Del(h)
	}

	// Set X-Forwarded headers
	if clientIP, _, err := net.SplitHostPort(originalReq.RemoteAddr); err == nil {
		if prior := originalReq.Header.Get("X-Forwarded-For"); prior != "" {
			clientIP = prior + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	if originalReq.TLS != nil {
		req.Header.Set("X-Forwarded-Proto", schemeHTTPS)
	} else {
		req.Header.Set("X-Forwarded-Proto", schemeHTTP)
	}

	req.Header.Set("X-Forwarded-Host", originalReq.Host)

	// Set Host header
	req.Host = target.Host
}

// selectDestination selects a destination based on weights using weighted random selection.
func (p *ReverseProxy) selectDestination(destinations []config.RouteDestination) *config.RouteDestination {
	if len(destinations) == 0 {
		return nil
	}

	if len(destinations) == 1 {
		return &destinations[0]
	}

	// Calculate total weight
	totalWeight := 0
	for _, dest := range destinations {
		weight := dest.Weight
		if weight == 0 {
			weight = 1 // Default weight
		}
		totalWeight += weight
	}

	// Generate a cryptographically secure random number
	randomValue := secureRandomInt(totalWeight)

	// Select destination based on weighted random selection
	cumulativeWeight := 0
	for i := range destinations {
		weight := destinations[i].Weight
		if weight == 0 {
			weight = 1
		}
		cumulativeWeight += weight
		if randomValue < cumulativeWeight {
			return &destinations[i]
		}
	}

	// Fallback to first destination (should not reach here)
	return &destinations[0]
}

// secureRandomInt returns a cryptographically secure random integer in [0, maxVal).
func secureRandomInt(maxVal int) int {
	if maxVal <= 0 {
		return 0
	}

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to math/rand/v2 on crypto/rand failure
		observability.GetGlobalLogger().Warn("crypto/rand failure, falling back to math/rand",
			observability.Error(err),
		)
		getProxyMetrics().cryptoRandFailures.Inc()
		return mathrand.IntN(maxVal) //nolint:gosec // fallback when crypto/rand is unavailable
	}

	// Convert to uint64 and take modulo
	n := binary.LittleEndian.Uint64(b[:])
	return int(n % uint64(maxVal)) //nolint:gosec // maxVal is validated above
}

// applyRewrite applies URL rewriting to the request.
// It clones the URL before modifying to avoid mutating shared state.
func (p *ReverseProxy) applyRewrite(r *http.Request, rewrite *config.RewriteConfig) *http.Request {
	// Clone the URL to avoid mutating the original request's URL,
	// which could be shared with other middleware or logging.
	clonedURL := *r.URL
	r.URL = &clonedURL

	if rewrite.URI != "" {
		// Get path params from context
		params := util.PathParamsFromContext(r.Context())

		// Replace path parameters in rewrite URI
		newPath := rewrite.URI
		for key, value := range params {
			newPath = strings.ReplaceAll(newPath, "{"+key+"}", value)
		}

		r.URL.Path = newPath
	}

	if rewrite.Authority != "" {
		r.Host = rewrite.Authority
	}

	return r
}

// handleDirectResponse handles direct response configuration.
func (p *ReverseProxy) handleDirectResponse(w http.ResponseWriter, dr *config.DirectResponseConfig) {
	// Set headers
	for key, value := range dr.Headers {
		w.Header().Set(key, value)
	}

	// Set status code
	status := dr.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	// Write body
	if dr.Body != "" {
		_, _ = io.WriteString(w, dr.Body)
	}
}

// handleRedirect handles redirect configuration.
func (p *ReverseProxy) handleRedirect(w http.ResponseWriter, r *http.Request, redirect *config.RedirectConfig) {
	// Build redirect URL
	redirectURL := *r.URL

	if redirect.Scheme != "" {
		redirectURL.Scheme = redirect.Scheme
	}

	if redirect.Host != "" {
		redirectURL.Host = redirect.Host
	}

	if redirect.Port != 0 {
		host := redirectURL.Hostname()
		redirectURL.Host = fmt.Sprintf("%s:%d", host, redirect.Port)
	}

	if redirect.URI != "" {
		redirectURL.Path = redirect.URI
	}

	if redirect.StripQuery {
		redirectURL.RawQuery = ""
	}

	// Validate redirect URL to prevent open redirect attacks
	if !isRedirectSafe(&redirectURL) {
		p.logger.Warn("blocked potentially unsafe redirect",
			observability.String("redirect_url", redirectURL.String()),
			observability.String("scheme", redirectURL.Scheme),
			observability.String("path", r.URL.Path),
			observability.String("remote_addr", r.RemoteAddr),
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, jsonErrBadRedirect)
		return
	}

	// Determine status code
	code := redirect.Code
	if code == 0 {
		code = http.StatusFound // 302
	}

	http.Redirect(w, r, redirectURL.String(), code)
}

// isRedirectSafe validates that a redirect URL is safe and not an open redirect attack.
// Only http and https schemes are allowed. Dangerous schemes like javascript:, data:,
// vbscript:, etc. are rejected.
func isRedirectSafe(u *url.URL) bool {
	// Allow empty scheme (relative redirects)
	if u.Scheme == "" {
		return true
	}

	scheme := strings.ToLower(u.Scheme)
	return scheme == schemeHTTP || scheme == schemeHTTPS
}

// handleRouteNotFound handles route not found errors.
func (p *ReverseProxy) handleRouteNotFound(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.Debug("route not found",
		observability.String("path", r.URL.Path),
		observability.String("method", r.Method),
		observability.Error(err),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, jsonErrNotFound)
}

// defaultErrorHandler is the default error handler.
func (p *ReverseProxy) defaultErrorHandler(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	p.logger.Error("proxy error",
		observability.String("path", r.URL.Path),
		observability.String("method", r.Method),
		observability.Error(err),
	)

	getProxyMetrics().errorsTotal.WithLabelValues(
		"unknown", "proxy_error",
	).Inc()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, jsonErrBadGateway)
}

// Handler returns an http.Handler for the proxy.
func (p *ReverseProxy) Handler() http.Handler {
	return p
}

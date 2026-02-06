// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// hopHeaders are headers that should not be forwarded.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
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

// proxyRequest proxies the request to a backend.
func (p *ReverseProxy) proxyRequest(w http.ResponseWriter, r *http.Request, route *router.CompiledRoute) {
	if len(route.Config.Route) == 0 {
		p.errorHandler(w, r, NewNoDestinationError(route.Name))
		return
	}

	// Select destination using weighted random selection
	dest := p.selectDestination(route.Config.Route)
	if dest == nil {
		p.errorHandler(w, r, NewNoDestinationAvailableError(route.Name))
		return
	}

	// Get backend and target URL
	serviceBackend := p.getServiceBackend(dest.Destination.Host)
	target, err := p.buildTargetURL(dest, serviceBackend)
	if err != nil {
		p.errorHandler(w, r, NewInvalidTargetError(route.Name, dest.Destination.Host, err))
		return
	}

	// Apply URL rewriting
	if route.Config.Rewrite != nil {
		r = p.applyRewrite(r, route.Config.Rewrite)
	}

	// Create and execute reverse proxy
	proxy := p.createReverseProxy(target, r, dest.Destination.Host, serviceBackend)
	r, cancel := p.applyTimeout(r, route.Config.Timeout.Duration())
	defer cancel()
	p.executeProxy(w, r, proxy, dest.Destination.Host)
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
func (p *ReverseProxy) buildTargetURL(
	dest *config.RouteDestination,
	serviceBackend *backend.ServiceBackend,
) (*url.URL, error) {
	scheme := "http"
	if serviceBackend != nil && serviceBackend.IsTLSEnabled() {
		scheme = "https"
	}
	targetURL := scheme + "://" + net.JoinHostPort(dest.Destination.Host, strconv.Itoa(dest.Destination.Port))
	return url.Parse(targetURL)
}

// createReverseProxy creates a configured reverse proxy.
func (p *ReverseProxy) createReverseProxy(
	target *url.URL,
	originalReq *http.Request,
	backendHost string,
	serviceBackend *backend.ServiceBackend,
) *httputil.ReverseProxy {
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
		Transport:      p.transport,
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
func (p *ReverseProxy) executeProxy(
	w http.ResponseWriter,
	r *http.Request,
	proxy *httputil.ReverseProxy,
	backendName string,
) {
	cb := p.getCircuitBreaker(backendName)

	// WebSocket upgrades require direct access to the underlying connection (Hijacker)
	// and cannot be wrapped by the circuit breaker's response recorder
	if isWebSocketRequest(r) {
		p.executeWebSocket(w, r, proxy, backendName)
		return
	}

	if cb != nil {
		p.executeWithCircuitBreaker(w, r, proxy, cb, backendName)
	} else {
		proxy.ServeHTTP(w, r)
	}
}

// executeWebSocket executes a WebSocket proxy request with metrics tracking.
func (p *ReverseProxy) executeWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	proxy *httputil.ReverseProxy,
	backendName string,
) {
	wsMetrics := getWebSocketMetrics()
	wsMetrics.connectionsTotal.WithLabelValues(backendName).Inc()
	wsMetrics.connectionsActive.WithLabelValues(backendName).Inc()
	defer wsMetrics.connectionsActive.WithLabelValues(backendName).Dec()

	p.logger.Debug("websocket connection established",
		observability.String("backend", backendName),
		observability.String("path", r.URL.Path),
	)

	proxy.ServeHTTP(w, r)
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

	// Preserve the original path if not rewritten
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
	for _, h := range hopHeaders {
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
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
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
		// Fallback to 0 on error (will select first destination)
		return 0
	}

	// Convert to uint64 and take modulo
	n := binary.LittleEndian.Uint64(b[:])
	return int(n % uint64(maxVal)) //nolint:gosec // maxVal is validated above
}

// applyRewrite applies URL rewriting to the request.
func (p *ReverseProxy) applyRewrite(r *http.Request, rewrite *config.RewriteConfig) *http.Request {
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
	return scheme == "http" || scheme == "https"
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
func (p *ReverseProxy) defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.Error("proxy error",
		observability.String("path", r.URL.Path),
		observability.String("method", r.Method),
		observability.Error(err),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, jsonErrBadGateway)
}

// Handler returns an http.Handler for the proxy.
func (p *ReverseProxy) Handler() http.Handler {
	return p
}

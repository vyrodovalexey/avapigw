// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	router          *router.Router
	backendRegistry *backend.Registry
	logger          observability.Logger
	transport       http.RoundTripper
	errorHandler    func(http.ResponseWriter, *http.Request, error)
	modifyResponse  func(*http.Response) error
	flushInterval   time.Duration
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
		p.errorHandler(w, r, fmt.Errorf("no destinations configured for route %s", route.Name))
		return
	}

	// Select destination (for now, use first destination or weighted selection)
	dest := p.selectDestination(route.Config.Route)
	if dest == nil {
		p.errorHandler(w, r, fmt.Errorf("no destination available for route %s", route.Name))
		return
	}

	// Get backend host
	targetURL := fmt.Sprintf("http://%s:%d", dest.Destination.Host, dest.Destination.Port)
	target, err := url.Parse(targetURL)
	if err != nil {
		p.errorHandler(w, r, fmt.Errorf("invalid target URL: %w", err))
		return
	}

	// Apply URL rewriting
	if route.Config.Rewrite != nil {
		r = p.applyRewrite(r, route.Config.Rewrite)
	}

	// Create reverse proxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			p.director(req, target, r)
		},
		Transport:      p.transport,
		FlushInterval:  p.flushInterval,
		ErrorHandler:   p.errorHandler,
		ModifyResponse: p.modifyResponse,
	}

	// Apply timeout if configured
	if route.Config.Timeout.Duration() > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), route.Config.Timeout.Duration())
		defer cancel()
		r = r.WithContext(ctx)
	}

	proxy.ServeHTTP(w, r)
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

	// Remove hop-by-hop headers
	for _, h := range hopHeaders {
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

// selectDestination selects a destination based on weights.
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
			weight = 1
		}
		totalWeight += weight
	}

	// Simple weighted selection (for production, use proper random)
	// This is a simplified version - in production, use crypto/rand
	for i := range destinations {
		return &destinations[i]
	}

	return &destinations[0]
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

	// Determine status code
	code := redirect.Code
	if code == 0 {
		code = http.StatusFound // 302
	}

	http.Redirect(w, r, redirectURL.String(), code)
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
	_, _ = io.WriteString(w, `{"error":"not found","message":"no matching route"}`)
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
	_, _ = io.WriteString(w, `{"error":"bad gateway","message":"failed to proxy request"}`)
}

// Handler returns an http.Handler for the proxy.
func (p *ReverseProxy) Handler() http.Handler {
	return p
}

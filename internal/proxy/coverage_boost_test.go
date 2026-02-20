package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// ============================================================================
// WithMetricsRegistry and WithRouteMiddleware functional options
// ============================================================================

func TestWithMetricsRegistry(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	promRegistry := prometheus.NewRegistry()

	proxy := NewReverseProxy(r, registry, WithMetricsRegistry(promRegistry))

	assert.NotNil(t, proxy)
	assert.Equal(t, promRegistry, proxy.metricsRegistry)
}

// mockRouteMiddlewareApplier implements RouteMiddlewareApplier for testing.
type mockRouteMiddlewareApplier struct {
	middlewares []func(http.Handler) http.Handler
}

func (m *mockRouteMiddlewareApplier) GetMiddleware(route *config.Route) []func(http.Handler) http.Handler {
	return m.middlewares
}

func (m *mockRouteMiddlewareApplier) ApplyMiddleware(handler http.Handler, route *config.Route) http.Handler {
	h := handler
	for i := len(m.middlewares) - 1; i >= 0; i-- {
		h = m.middlewares[i](h)
	}
	return h
}

func TestWithRouteMiddleware(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	rm := &mockRouteMiddlewareApplier{}
	proxy := NewReverseProxy(r, registry, WithRouteMiddleware(rm))

	assert.NotNil(t, proxy)
	assert.Equal(t, rm, proxy.routeMiddleware)
}

// ============================================================================
// NewNoAvailableHostsError
// ============================================================================

func TestNewNoAvailableHostsError(t *testing.T) {
	t.Parallel()

	cause := errors.New("all hosts unhealthy")
	err := NewNoAvailableHostsError("my-route", "my-backend", cause)

	require.NotNil(t, err)
	assert.Equal(t, "get_available_host", err.Op)
	assert.Equal(t, "my-route", err.Route)
	assert.Equal(t, "my-backend", err.Target)
	assert.Equal(t, "no available backend hosts", err.Message)
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "my-route")
	assert.Contains(t, err.Error(), "my-backend")
}

func TestNewNoAvailableHostsError_NilCause(t *testing.T) {
	t.Parallel()

	err := NewNoAvailableHostsError("route1", "backend1", nil)

	require.NotNil(t, err)
	assert.Equal(t, "get_available_host", err.Op)
	assert.Nil(t, err.Cause)
	assert.Contains(t, err.Error(), "no available backend hosts")
}

// ============================================================================
// buildBackendWSURL with HTTPS scheme and query strings
// ============================================================================

func TestBuildBackendWSURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		targetURL   string
		requestPath string
		rawQuery    string
		expectedURL string
	}{
		{
			name:        "HTTP target becomes ws",
			targetURL:   "http://backend:8080",
			requestPath: "/ws/chat",
			expectedURL: "ws://backend:8080/ws/chat",
		},
		{
			name:        "HTTPS target becomes wss",
			targetURL:   "https://backend:443",
			requestPath: "/ws/chat",
			expectedURL: "wss://backend:443/ws/chat",
		},
		{
			name:        "with query string",
			targetURL:   "http://backend:8080",
			requestPath: "/ws/chat",
			rawQuery:    "token=abc123&room=general",
			expectedURL: "ws://backend:8080/ws/chat?token=abc123&room=general",
		},
		{
			name:        "HTTPS with query string",
			targetURL:   "https://backend:443",
			requestPath: "/ws/stream",
			rawQuery:    "format=json",
			expectedURL: "wss://backend:443/ws/stream?format=json",
		},
		{
			name:        "empty query string",
			targetURL:   "http://backend:9090",
			requestPath: "/ws",
			rawQuery:    "",
			expectedURL: "ws://backend:9090/ws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wp := &websocketProxy{logger: observability.NopLogger()}

			target, err := url.Parse(tt.targetURL)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			if tt.rawQuery != "" {
				req.URL.RawQuery = tt.rawQuery
			}

			result := wp.buildBackendWSURL(target, req)
			assert.Equal(t, tt.expectedURL, result)
		})
	}
}

// ============================================================================
// buildResponseHeaders
// ============================================================================

func TestBuildResponseHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		resp            *http.Response
		expectedHeaders map[string]string
		excludedHeaders []string
		expectNil       bool
	}{
		{
			name:      "nil response returns nil",
			resp:      nil,
			expectNil: true,
		},
		{
			name: "filters WebSocket protocol headers",
			resp: &http.Response{
				Header: http.Header{
					"Upgrade":              {"websocket"},
					"Connection":           {"Upgrade"},
					"Sec-Websocket-Accept": {"abc123"},
					"X-Custom-Header":      {"custom-value"},
					"Content-Type":         {"application/json"},
				},
			},
			expectedHeaders: map[string]string{
				"X-Custom-Header": "custom-value",
				"Content-Type":    "application/json",
			},
			excludedHeaders: []string{
				"Upgrade",
				"Connection",
				"Sec-Websocket-Accept",
			},
		},
		{
			name: "empty response headers",
			resp: &http.Response{
				Header: http.Header{},
			},
			expectedHeaders: map[string]string{},
		},
		{
			name: "only WebSocket headers - returns empty",
			resp: &http.Response{
				Header: http.Header{
					"Upgrade":              {"websocket"},
					"Connection":           {"Upgrade"},
					"Sec-Websocket-Accept": {"abc123"},
				},
			},
			excludedHeaders: []string{
				"Upgrade",
				"Connection",
				"Sec-Websocket-Accept",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wp := &websocketProxy{logger: observability.NopLogger()}
			result := wp.buildResponseHeaders(tt.resp)

			if tt.expectNil {
				assert.Nil(t, result)
				return
			}

			for key, value := range tt.expectedHeaders {
				assert.Equal(t, value, result.Get(key), "header %s", key)
			}

			for _, key := range tt.excludedHeaders {
				assert.Empty(t, result.Get(key), "header %s should be excluded", key)
			}
		})
	}
}

// ============================================================================
// buildRequestHeaders
// ============================================================================

func TestBuildRequestHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		requestHeaders  map[string]string
		expectedHeaders map[string]string
		excludedHeaders []string
	}{
		{
			name: "filters WebSocket and hop-by-hop headers",
			requestHeaders: map[string]string{
				"Upgrade":                  "websocket",
				"Connection":               "Upgrade",
				"Sec-Websocket-Key":        "dGhlIHNhbXBsZSBub25jZQ==",
				"Sec-Websocket-Version":    "13",
				"Sec-Websocket-Extensions": "permessage-deflate",
				"Sec-Websocket-Protocol":   "chat",
				"Authorization":            "Bearer token123",
				"X-Custom":                 "value",
			},
			expectedHeaders: map[string]string{
				"Authorization": "Bearer token123",
				"X-Custom":      "value",
			},
			excludedHeaders: []string{
				"Upgrade",
				"Connection",
				"Sec-Websocket-Key",
				"Sec-Websocket-Version",
				"Sec-Websocket-Extensions",
				"Sec-Websocket-Protocol",
			},
		},
		{
			name:            "empty request headers",
			requestHeaders:  map[string]string{},
			expectedHeaders: map[string]string{},
		},
		{
			name: "preserves non-WebSocket headers",
			requestHeaders: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "text/html",
				"X-Request-Id": "req-123",
			},
			expectedHeaders: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "text/html",
				"X-Request-Id": "req-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wp := &websocketProxy{logger: observability.NopLogger()}

			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			for k, v := range tt.requestHeaders {
				req.Header.Set(k, v)
			}

			result := wp.buildRequestHeaders(req)

			for key, value := range tt.expectedHeaders {
				assert.Equal(t, value, result.Get(key), "header %s", key)
			}

			for _, key := range tt.excludedHeaders {
				assert.Empty(t, result.Get(key), "header %s should be excluded", key)
			}
		})
	}
}

// ============================================================================
// proxyRequest with route middleware path
// ============================================================================

func TestReverseProxy_ProxyRequest_WithRouteMiddleware(t *testing.T) {
	t.Parallel()

	// Create a backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Middleware-Applied", r.Header.Get("X-Middleware-Applied"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 80
	if backendURL.Port() != "" {
		_, _ = parsePort(backendURL.Port(), &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Create a middleware that adds a header
	middlewareApplied := false
	rm := &mockRouteMiddlewareApplier{
		middlewares: []func(http.Handler) http.Handler{
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					middlewareApplied = true
					r.Header.Set("X-Middleware-Applied", "true")
					next.ServeHTTP(w, r)
				})
			},
		},
	}

	route := config.Route{
		Name: "middleware-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/middleware",
				},
			},
		},
		Route: []config.RouteDestination{
			{
				Destination: config.Destination{
					Host: backendURL.Hostname(),
					Port: port,
				},
			},
		},
	}
	err = r.AddRoute(route)
	require.NoError(t, err)

	proxy := NewReverseProxy(r, registry, WithRouteMiddleware(rm))

	req := httptest.NewRequest(http.MethodGet, "/middleware/test", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, middlewareApplied, "route middleware should have been applied")
}

func TestReverseProxy_ProxyRequest_WithRouteMiddleware_EmptyMiddlewares(t *testing.T) {
	t.Parallel()

	// Create a backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("direct"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 80
	if backendURL.Port() != "" {
		_, _ = parsePort(backendURL.Port(), &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Route middleware applier that returns empty middlewares
	rm := &mockRouteMiddlewareApplier{
		middlewares: nil, // Empty - should fall through to direct proxy
	}

	route := config.Route{
		Name: "empty-middleware-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/empty-mw",
				},
			},
		},
		Route: []config.RouteDestination{
			{
				Destination: config.Destination{
					Host: backendURL.Hostname(),
					Port: port,
				},
			},
		},
	}
	err = r.AddRoute(route)
	require.NoError(t, err)

	proxy := NewReverseProxy(r, registry, WithRouteMiddleware(rm))

	req := httptest.NewRequest(http.MethodGet, "/empty-mw/test", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "direct")
}

// ============================================================================
// getServiceBackend with nil registry
// ============================================================================

func TestReverseProxy_GetServiceBackend_NilRegistry(t *testing.T) {
	t.Parallel()

	r := router.New()
	proxy := NewReverseProxy(r, nil) // nil registry

	result := proxy.getServiceBackend("any-host")
	assert.Nil(t, result)
}

func TestReverseProxy_GetServiceBackend_NotFound(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	proxy := NewReverseProxy(r, registry)

	result := proxy.getServiceBackend("nonexistent-host")
	assert.Nil(t, result)
}

// ============================================================================
// handleDialError
// ============================================================================

func TestHandleDialError_WithResponse(t *testing.T) {
	t.Parallel()

	wp := &websocketProxy{logger: observability.NopLogger()}

	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header: http.Header{
			"X-Error-Reason": {"forbidden"},
		},
		Body: http.NoBody,
	}

	rec := httptest.NewRecorder()
	wp.handleDialError(rec, resp, errors.New("dial failed"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "forbidden", rec.Header().Get("X-Error-Reason"))
}

func TestHandleDialError_NilResponse(t *testing.T) {
	t.Parallel()

	wp := &websocketProxy{logger: observability.NopLogger()}

	rec := httptest.NewRecorder()
	wp.handleDialError(rec, nil, errors.New("dial failed"))

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

// ============================================================================
// ProxyError formatting tests
// ============================================================================

func TestProxyError_FormatBasic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *ProxyError
		expected string
	}{
		{
			name: "basic with cause",
			err: &ProxyError{
				Op:      "test_op",
				Message: "something failed",
				Cause:   errors.New("root cause"),
			},
			expected: "proxy error [test_op]: something failed: root cause",
		},
		{
			name: "basic without cause",
			err: &ProxyError{
				Op:      "test_op",
				Message: "something failed",
			},
			expected: "proxy error [test_op]: something failed",
		},
		{
			name: "with route and cause",
			err: &ProxyError{
				Op:      "test_op",
				Route:   "my-route",
				Message: "route error",
				Cause:   errors.New("cause"),
			},
			expected: "proxy error [test_op] route=my-route: route error: cause",
		},
		{
			name: "with route without cause",
			err: &ProxyError{
				Op:      "test_op",
				Route:   "my-route",
				Message: "route error",
			},
			expected: "proxy error [test_op] route=my-route: route error",
		},
		{
			name: "with route and target and cause",
			err: &ProxyError{
				Op:      "test_op",
				Route:   "my-route",
				Target:  "http://backend:8080",
				Message: "target error",
				Cause:   errors.New("cause"),
			},
			expected: "proxy error [test_op] route=my-route target=http://backend:8080: target error: cause",
		},
		{
			name: "with route and target without cause",
			err: &ProxyError{
				Op:      "test_op",
				Route:   "my-route",
				Target:  "http://backend:8080",
				Message: "target error",
			},
			expected: "proxy error [test_op] route=my-route target=http://backend:8080: target error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestProxyError_FormatVariants(t *testing.T) {
	t.Parallel()

	// Test Is with ProxyError target
	err1 := &ProxyError{Op: "test", Cause: ErrNoDestination}
	err2 := &ProxyError{Op: "other", Cause: ErrNoDestination}
	assert.True(t, errors.Is(err1, err2))
	assert.True(t, errors.Is(err1, ErrNoDestination))
	assert.False(t, errors.Is(err1, ErrRouteNotFound))
}

// ============================================================================
// Helper
// ============================================================================

func parsePort(portStr string, port *int) (int, error) {
	n := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid port")
		}
		n = n*10 + int(c-'0')
	}
	*port = n
	return n, nil
}

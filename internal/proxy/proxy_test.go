package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

func TestNewReverseProxy(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	proxy := NewReverseProxy(r, registry)

	assert.NotNil(t, proxy)
	assert.Equal(t, r, proxy.router)
	assert.Equal(t, registry, proxy.backendRegistry)
}

func TestNewReverseProxy_WithOptions(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	proxy := NewReverseProxy(r, registry,
		WithProxyLogger(logger),
		WithFlushInterval(100*time.Millisecond),
	)

	assert.NotNil(t, proxy)
	assert.Equal(t, logger, proxy.logger)
	assert.Equal(t, 100*time.Millisecond, proxy.flushInterval)
}

func TestNewReverseProxy_WithTransport(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	transport := &http.Transport{}

	proxy := NewReverseProxy(r, registry, WithTransport(transport))

	assert.Equal(t, transport, proxy.transport)
}

func TestNewReverseProxy_WithErrorHandler(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
	}

	proxy := NewReverseProxy(r, registry, WithErrorHandler(errorHandler))

	assert.NotNil(t, proxy.errorHandler)
}

func TestNewReverseProxy_WithModifyResponse(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	modifier := func(resp *http.Response) error {
		return nil
	}

	proxy := NewReverseProxy(r, registry, WithModifyResponse(modifier))

	assert.NotNil(t, proxy.modifyResponse)
}

func TestReverseProxy_ServeHTTP_RouteNotFound(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "not found")
}

func TestReverseProxy_ServeHTTP_DirectResponse(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Add a route with direct response
	route := config.Route{
		Name: "direct-response",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Exact: "/direct",
				},
			},
		},
		DirectResponse: &config.DirectResponseConfig{
			Status: 200,
			Body:   `{"message":"direct response"}`,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/direct", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "direct response")
}

func TestReverseProxy_ServeHTTP_Redirect(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Add a route with redirect
	route := config.Route{
		Name: "redirect",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Exact: "/old-path",
				},
			},
		},
		Redirect: &config.RedirectConfig{
			URI:  "/new-path",
			Code: 301,
		},
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/old-path", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMovedPermanently, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/new-path")
}

func TestReverseProxy_HandleDirectResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *config.DirectResponseConfig
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "with status and body",
			config: &config.DirectResponseConfig{
				Status: 201,
				Body:   "created",
			},
			expectedStatus: 201,
			expectedBody:   "created",
		},
		{
			name: "with headers",
			config: &config.DirectResponseConfig{
				Status: 200,
				Body:   "ok",
				Headers: map[string]string{
					"X-Custom": "value",
				},
			},
			expectedStatus: 200,
			expectedBody:   "ok",
		},
		{
			name: "zero status defaults to 200",
			config: &config.DirectResponseConfig{
				Status: 0,
				Body:   "default",
			},
			expectedStatus: 200,
			expectedBody:   "default",
		},
		{
			name: "empty body",
			config: &config.DirectResponseConfig{
				Status: 204,
			},
			expectedStatus: 204,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := router.New()
			logger := observability.NopLogger()
			registry := backend.NewRegistry(logger)
			proxy := NewReverseProxy(r, registry)

			rec := httptest.NewRecorder()
			proxy.handleDirectResponse(rec, tt.config)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, tt.expectedBody, rec.Body.String())
		})
	}
}

func TestReverseProxy_HandleRedirect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *config.RedirectConfig
		requestURL     string
		expectedStatus int
		expectedPath   string
	}{
		{
			name: "simple redirect",
			config: &config.RedirectConfig{
				URI:  "/new-path",
				Code: 302,
			},
			requestURL:     "/old-path",
			expectedStatus: 302,
			expectedPath:   "/new-path",
		},
		{
			name: "redirect with scheme change",
			config: &config.RedirectConfig{
				Scheme: "https",
				Code:   301,
			},
			requestURL:     "http://example.com/path",
			expectedStatus: 301,
		},
		{
			name: "redirect with host change",
			config: &config.RedirectConfig{
				Host: "new-host.com",
				Code: 301,
			},
			requestURL:     "http://old-host.com/path",
			expectedStatus: 301,
		},
		{
			name: "redirect with port change",
			config: &config.RedirectConfig{
				Port: 8080,
				Code: 301,
			},
			requestURL:     "http://example.com/path",
			expectedStatus: 301,
		},
		{
			name: "redirect with strip query",
			config: &config.RedirectConfig{
				URI:        "/new-path",
				StripQuery: true,
				Code:       302,
			},
			requestURL:     "/old-path?foo=bar",
			expectedStatus: 302,
		},
		{
			name: "default redirect code",
			config: &config.RedirectConfig{
				URI:  "/new-path",
				Code: 0, // Should default to 302
			},
			requestURL:     "/old-path",
			expectedStatus: 302,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := router.New()
			logger := observability.NopLogger()
			registry := backend.NewRegistry(logger)
			proxy := NewReverseProxy(r, registry)

			req := httptest.NewRequest(http.MethodGet, tt.requestURL, nil)
			rec := httptest.NewRecorder()

			proxy.handleRedirect(rec, req, tt.config)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedPath != "" {
				assert.Contains(t, rec.Header().Get("Location"), tt.expectedPath)
			}
		})
	}
}

func TestReverseProxy_SelectDestination(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	tests := []struct {
		name         string
		destinations []config.RouteDestination
		expectNil    bool
	}{
		{
			name:         "empty destinations",
			destinations: []config.RouteDestination{},
			expectNil:    true,
		},
		{
			name: "single destination",
			destinations: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: "localhost",
						Port: 8080,
					},
				},
			},
			expectNil: false,
		},
		{
			name: "multiple destinations",
			destinations: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "host1", Port: 8080},
					Weight:      50,
				},
				{
					Destination: config.Destination{Host: "host2", Port: 8080},
					Weight:      50,
				},
			},
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := proxy.selectDestination(tt.destinations)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestReverseProxy_Handler(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	handler := proxy.Handler()

	assert.NotNil(t, handler)
	assert.Equal(t, proxy, handler)
}

func TestReverseProxy_DefaultErrorHandler(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	proxy.defaultErrorHandler(rec, req, assert.AnError)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "bad gateway")
}

func TestReverseProxy_HandleRouteNotFound(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	proxy.handleRouteNotFound(rec, req, assert.AnError)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "not found")
}

func TestReverseProxy_ProxyToBackend(t *testing.T) {
	t.Parallel()

	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "test")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backendServer.Close()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Add a route that proxies to the backend
	route := config.Route{
		Name: "proxy-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/api",
				},
			},
		},
		Route: []config.RouteDestination{
			{
				Destination: config.Destination{
					Host: "127.0.0.1",
					Port: 9999, // Will fail but tests the flow
				},
			},
		},
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// Will get bad gateway since backend is not reachable
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestHopHeaders(t *testing.T) {
	t.Parallel()

	expectedHeaders := []string{
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

	assert.Equal(t, expectedHeaders, hopHeaders)
}

func TestReverseProxy_ApplyRewrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rewrite      *config.RewriteConfig
		requestPath  string
		pathParams   map[string]string
		expectedPath string
		expectedHost string
	}{
		{
			name: "rewrite URI",
			rewrite: &config.RewriteConfig{
				URI: "/new-path",
			},
			requestPath:  "/old-path",
			expectedPath: "/new-path",
		},
		{
			name: "rewrite URI with path params",
			rewrite: &config.RewriteConfig{
				URI: "/users/{id}/profile",
			},
			requestPath:  "/api/users/123",
			pathParams:   map[string]string{"id": "123"},
			expectedPath: "/users/123/profile",
		},
		{
			name: "rewrite authority",
			rewrite: &config.RewriteConfig{
				Authority: "new-host.example.com",
			},
			requestPath:  "/path",
			expectedPath: "/path",
			expectedHost: "new-host.example.com",
		},
		{
			name: "rewrite both URI and authority",
			rewrite: &config.RewriteConfig{
				URI:       "/new-path",
				Authority: "new-host.example.com",
			},
			requestPath:  "/old-path",
			expectedPath: "/new-path",
			expectedHost: "new-host.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := router.New()
			logger := observability.NopLogger()
			registry := backend.NewRegistry(logger)
			proxy := NewReverseProxy(r, registry)

			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)

			// Add path params to context if provided
			if tt.pathParams != nil {
				ctx := util.ContextWithPathParams(req.Context(), tt.pathParams)
				req = req.WithContext(ctx)
			}

			result := proxy.applyRewrite(req, tt.rewrite)

			assert.Equal(t, tt.expectedPath, result.URL.Path)
			if tt.expectedHost != "" {
				assert.Equal(t, tt.expectedHost, result.Host)
			}
		})
	}
}

func TestReverseProxy_Director(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		targetURL       string
		originalPath    string
		originalQuery   string
		originalHeaders map[string]string
		remoteAddr      string
		useTLS          bool
		reqPath         string // Path on the request being modified (empty triggers path copy)
		expectedScheme  string
		expectedHost    string
		expectedPath    string
		expectedQuery   string
		expectedXFF     string
		expectedXFP     string
		expectedXFH     string
	}{
		{
			name:           "basic director with empty req path",
			targetURL:      "http://backend:8080",
			originalPath:   "/api/users",
			originalQuery:  "page=1",
			remoteAddr:     "192.168.1.1:12345",
			reqPath:        "", // Empty path triggers copy from original
			expectedScheme: "http",
			expectedHost:   "backend:8080",
			expectedPath:   "/api/users",
			expectedQuery:  "page=1",
			expectedXFF:    "192.168.1.1",
			expectedXFP:    "http",
		},
		{
			name:           "with TLS",
			targetURL:      "https://backend:443",
			originalPath:   "/secure",
			remoteAddr:     "10.0.0.1:54321",
			useTLS:         true,
			reqPath:        "", // Empty path triggers copy from original
			expectedScheme: "https",
			expectedHost:   "backend:443",
			expectedPath:   "/secure",
			expectedXFF:    "10.0.0.1",
			expectedXFP:    "https",
		},
		{
			name:         "with existing X-Forwarded-For",
			targetURL:    "http://backend:8080",
			originalPath: "/api",
			remoteAddr:   "192.168.1.1:12345",
			reqPath:      "", // Empty path triggers copy from original
			originalHeaders: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			expectedScheme: "http",
			expectedHost:   "backend:8080",
			expectedPath:   "/api",
			expectedXFF:    "10.0.0.1, 192.168.1.1",
			expectedXFP:    "http",
		},
		{
			name:           "req path already set - not overwritten",
			targetURL:      "http://backend:8080",
			originalPath:   "/original/path",
			remoteAddr:     "192.168.1.1:12345",
			reqPath:        "/already/set", // Non-empty path is preserved
			expectedScheme: "http",
			expectedHost:   "backend:8080",
			expectedPath:   "/already/set",
			expectedXFP:    "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := router.New()
			logger := observability.NopLogger()
			registry := backend.NewRegistry(logger)
			proxy := NewReverseProxy(r, registry)

			target, err := url.Parse(tt.targetURL)
			require.NoError(t, err)

			// Create original request
			originalReq := httptest.NewRequest(http.MethodGet, tt.originalPath, nil)
			if tt.originalQuery != "" {
				originalReq.URL.RawQuery = tt.originalQuery
			}
			originalReq.RemoteAddr = tt.remoteAddr
			originalReq.Host = "original-host.com"

			// Add original headers
			for k, v := range tt.originalHeaders {
				originalReq.Header.Set(k, v)
			}

			// Simulate TLS
			if tt.useTLS {
				originalReq.TLS = &tls.ConnectionState{}
			}

			// Create request to be modified by director
			// Use the specified reqPath (empty string means path will be copied from original)
			reqURL := "http://example.com"
			if tt.reqPath != "" {
				reqURL = "http://example.com" + tt.reqPath
			}
			req, _ := http.NewRequest(http.MethodGet, reqURL, nil)
			if tt.reqPath == "" {
				req.URL.Path = "" // Explicitly set empty path
			}
			// Copy headers from original
			for k, v := range originalReq.Header {
				req.Header[k] = v
			}

			proxy.director(req, target, originalReq)

			assert.Equal(t, tt.expectedScheme, req.URL.Scheme)
			assert.Equal(t, tt.expectedHost, req.URL.Host)
			if tt.expectedPath != "" {
				assert.Equal(t, tt.expectedPath, req.URL.Path)
			}
			if tt.expectedQuery != "" {
				assert.Equal(t, tt.expectedQuery, req.URL.RawQuery)
			}
			if tt.expectedXFF != "" {
				assert.Equal(t, tt.expectedXFF, req.Header.Get("X-Forwarded-For"))
			}
			assert.Equal(t, tt.expectedXFP, req.Header.Get("X-Forwarded-Proto"))
			assert.Equal(t, "original-host.com", req.Header.Get("X-Forwarded-Host"))
		})
	}
}

func TestReverseProxy_Director_RemovesHopHeaders(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	target, err := url.Parse("http://backend:8080")
	require.NoError(t, err)

	originalReq := httptest.NewRequest(http.MethodGet, "/api", nil)
	originalReq.RemoteAddr = "192.168.1.1:12345"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Add hop-by-hop headers
	for _, h := range hopHeaders {
		req.Header.Set(h, "some-value")
	}

	proxy.director(req, target, originalReq)

	// Verify hop headers are removed, except Upgrade and Connection
	// which are preserved for WebSocket support (httputil.ReverseProxy
	// handles them after Director returns, checking for protocol upgrades first).
	for _, h := range hopHeaders {
		if h == "Upgrade" || h == "Connection" {
			assert.NotEmpty(t, req.Header.Get(h),
				"hop header %s should be preserved for WebSocket support", h)
			continue
		}
		assert.Empty(t, req.Header.Get(h), "hop header %s should be removed", h)
	}
}

func TestReverseProxy_ProxyRequest_NoDestinations(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Add a route with no destinations
	route := config.Route{
		Name: "no-dest-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/no-dest",
				},
			},
		},
		Route: []config.RouteDestination{}, // Empty destinations
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/no-dest/test", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, rec.Body.String(), "bad gateway")
}

func TestReverseProxy_ProxyRequest_WithTimeout(t *testing.T) {
	t.Parallel()

	// Create a slow backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	// Parse backend URL
	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 80
	if backendURL.Port() != "" {
		fmt.Sscanf(backendURL.Port(), "%d", &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Add a route with short timeout
	route := config.Route{
		Name: "timeout-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/timeout",
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
		Timeout: config.Duration(50 * time.Millisecond),
	}
	err = r.AddRoute(route)
	require.NoError(t, err)

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/timeout/test", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// Should get bad gateway due to timeout
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestReverseProxy_ProxyRequest_WithRewrite(t *testing.T) {
	t.Parallel()

	// Create a backend server that echoes the path
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	// Parse backend URL
	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 80
	if backendURL.Port() != "" {
		fmt.Sscanf(backendURL.Port(), "%d", &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Add a route with rewrite
	route := config.Route{
		Name: "rewrite-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/old",
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
		Rewrite: &config.RewriteConfig{
			URI: "/new",
		},
	}
	err = r.AddRoute(route)
	require.NoError(t, err)

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/old/path", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestReverseProxy_ProxyRequest_SuccessfulProxy(t *testing.T) {
	t.Parallel()

	// Create a backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "test")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backendServer.Close()

	// Parse backend URL
	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 80
	if backendURL.Port() != "" {
		fmt.Sscanf(backendURL.Port(), "%d", &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Add a route
	route := config.Route{
		Name: "success-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/success",
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

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/success/test", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test", rec.Header().Get("X-Backend"))
	assert.Contains(t, rec.Body.String(), "backend response")
}

func TestReverseProxy_ServeHTTP_WithPathParams(t *testing.T) {
	t.Parallel()

	// Create a backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	// Parse backend URL
	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 80
	if backendURL.Port() != "" {
		fmt.Sscanf(backendURL.Port(), "%d", &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Add a route with path parameter
	route := config.Route{
		Name: "param-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Regex: `/users/(?P<id>\d+)`,
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

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/users/123", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestReverseProxy_SelectDestination_WithZeroWeight(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	destinations := []config.RouteDestination{
		{
			Destination: config.Destination{Host: "host1", Port: 8080},
			Weight:      0, // Zero weight should be treated as 1
		},
		{
			Destination: config.Destination{Host: "host2", Port: 8080},
			Weight:      0,
		},
	}

	result := proxy.selectDestination(destinations)
	assert.NotNil(t, result)
}

func TestWithCircuitBreakerManager(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	cbManager := backend.NewCircuitBreakerManager(logger)

	proxy := NewReverseProxy(r, registry, WithCircuitBreakerManager(cbManager))

	assert.Equal(t, cbManager, proxy.circuitBreakerManager)
}

func TestWithGlobalCircuitBreaker(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	cbManager := backend.NewCircuitBreakerManager(logger)

	proxy := NewReverseProxy(r, registry, WithGlobalCircuitBreaker(cbManager))

	assert.Equal(t, cbManager, proxy.globalCircuitBreaker)
}

func TestReverseProxy_GetCircuitBreaker_NoManagers(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	cb := proxy.getCircuitBreaker("test-backend")
	assert.Nil(t, cb)
}

func TestReverseProxy_GetCircuitBreaker_WithGlobalOnly(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	cbManager := backend.NewCircuitBreakerManager(logger)

	proxy := NewReverseProxy(r, registry, WithGlobalCircuitBreaker(cbManager))

	cb := proxy.getCircuitBreaker("test-backend")
	assert.Equal(t, cbManager, cb)
}

func TestReverseProxy_GetCircuitBreaker_WithBackendSpecific(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	backendCBManager := backend.NewCircuitBreakerManager(logger)
	globalCBManager := backend.NewCircuitBreakerManager(logger)

	// Create a backend with circuit breaker config
	backendCfg := &config.Backend{
		Name: "test-backend",
		CircuitBreaker: &config.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
			Timeout:   config.Duration(30 * time.Second),
		},
	}
	backendCBManager.GetOrCreate(backendCfg)

	proxy := NewReverseProxy(r, registry,
		WithCircuitBreakerManager(backendCBManager),
		WithGlobalCircuitBreaker(globalCBManager),
	)

	cb := proxy.getCircuitBreaker("test-backend")
	assert.Equal(t, backendCBManager, cb)
}

func TestReverseProxy_GetCircuitBreaker_FallbackToGlobal(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	backendCBManager := backend.NewCircuitBreakerManager(logger)
	globalCBManager := backend.NewCircuitBreakerManager(logger)

	// Backend manager has no circuit breaker for "other-backend"
	proxy := NewReverseProxy(r, registry,
		WithCircuitBreakerManager(backendCBManager),
		WithGlobalCircuitBreaker(globalCBManager),
	)

	cb := proxy.getCircuitBreaker("other-backend")
	assert.Equal(t, globalCBManager, cb)
}

func TestReverseProxy_ExecuteWithCircuitBreaker_Success(t *testing.T) {
	t.Parallel()

	// Create a backend server that returns 200
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 80
	if backendURL.Port() != "" {
		fmt.Sscanf(backendURL.Port(), "%d", &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	cbManager := backend.NewCircuitBreakerManager(logger)
	backendCfg := &config.Backend{
		Name: "test-backend",
		CircuitBreaker: &config.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
			Timeout:   config.Duration(30 * time.Second),
		},
	}
	cbManager.GetOrCreate(backendCfg)

	route := config.Route{
		Name: "cb-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/cb-test",
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

	proxy := NewReverseProxy(r, registry, WithGlobalCircuitBreaker(cbManager))

	req := httptest.NewRequest(http.MethodGet, "/cb-test", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestReverseProxy_ExecuteWithCircuitBreaker_ServerError(t *testing.T) {
	t.Parallel()

	// Create a backend server that returns 500
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 80
	if backendURL.Port() != "" {
		fmt.Sscanf(backendURL.Port(), "%d", &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	cbManager := backend.NewCircuitBreakerManager(logger)
	backendCfg := &config.Backend{
		Name: "test-backend",
		CircuitBreaker: &config.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
			Timeout:   config.Duration(30 * time.Second),
		},
	}
	cbManager.GetOrCreate(backendCfg)

	route := config.Route{
		Name: "cb-error-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/cb-error",
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

	proxy := NewReverseProxy(r, registry, WithGlobalCircuitBreaker(cbManager))

	req := httptest.NewRequest(http.MethodGet, "/cb-error", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// Should still return 500 from backend
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSecureRandomInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		maxVal int
	}{
		{"zero max", 0},
		{"negative max", -1},
		{"small max", 10},
		{"large max", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := secureRandomInt(tt.maxVal)

			if tt.maxVal <= 0 {
				assert.Equal(t, 0, result)
			} else {
				assert.GreaterOrEqual(t, result, 0)
				assert.Less(t, result, tt.maxVal)
			}
		})
	}
}

func TestSecureRandomInt_Distribution(t *testing.T) {
	t.Parallel()

	// Test that secureRandomInt produces a reasonable distribution
	maxVal := 10
	counts := make(map[int]int)

	for i := 0; i < 1000; i++ {
		result := secureRandomInt(maxVal)
		counts[result]++
	}

	// Each value should appear at least once in 1000 iterations
	for i := 0; i < maxVal; i++ {
		assert.Greater(t, counts[i], 0, "value %d should appear at least once", i)
	}
}

func TestReverseProxy_SelectDestination_WeightedDistribution(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)
	proxy := NewReverseProxy(r, registry)

	destinations := []config.RouteDestination{
		{
			Destination: config.Destination{Host: "host1", Port: 8080},
			Weight:      80,
		},
		{
			Destination: config.Destination{Host: "host2", Port: 8080},
			Weight:      20,
		},
	}

	counts := make(map[string]int)
	for i := 0; i < 1000; i++ {
		result := proxy.selectDestination(destinations)
		require.NotNil(t, result)
		counts[result.Destination.Host]++
	}

	// host1 should be selected more often than host2
	assert.Greater(t, counts["host1"], counts["host2"])
}

func TestReverseProxy_ProxyRequest_TLSSchemeSelection(t *testing.T) {
	t.Parallel()

	// Create a backend server (using TLS)
	backendServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Scheme", r.URL.Scheme)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tls ok"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	require.NoError(t, err)

	port := 443
	if backendURL.Port() != "" {
		fmt.Sscanf(backendURL.Port(), "%d", &port)
	}

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	// Create a backend with TLS enabled
	backendCfg := config.Backend{
		Name: backendURL.Hostname(),
		Hosts: []config.BackendHost{
			{Address: backendURL.Hostname(), Port: port},
		},
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		},
	}
	b, err := backend.NewBackend(backendCfg, backend.WithBackendLogger(logger))
	require.NoError(t, err)
	err = registry.Register(b)
	require.NoError(t, err)

	// Add a route pointing to the TLS backend
	route := config.Route{
		Name: "tls-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{
					Prefix: "/tls-test",
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

	// Use the TLS client from the test server
	proxy := NewReverseProxy(r, registry,
		WithProxyLogger(logger),
		WithTransport(backendServer.Client().Transport),
	)

	req := httptest.NewRequest(http.MethodGet, "/tls-test/path", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// The proxy should have used https:// scheme
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "tls ok")
}

func TestReverseProxy_ProxyErrors(t *testing.T) {
	t.Parallel()

	r := router.New()
	logger := observability.NopLogger()
	registry := backend.NewRegistry(logger)

	tests := []struct {
		name         string
		routeName    string
		destinations []config.RouteDestination
		expectError  bool
	}{
		{
			name:         "no destination error",
			routeName:    "no-dest",
			destinations: []config.RouteDestination{},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := config.Route{
				Name: tt.routeName,
				Match: []config.RouteMatch{
					{
						URI: &config.URIMatch{
							Prefix: "/" + tt.routeName,
						},
					},
				},
				Route: tt.destinations,
			}
			err := r.AddRoute(route)
			require.NoError(t, err)

			proxy := NewReverseProxy(r, registry)

			req := httptest.NewRequest(http.MethodGet, "/"+tt.routeName+"/test", nil)
			rec := httptest.NewRecorder()

			proxy.ServeHTTP(rec, req)

			if tt.expectError {
				assert.Equal(t, http.StatusBadGateway, rec.Code)
			}
		})
	}
}

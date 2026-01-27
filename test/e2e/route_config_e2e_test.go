//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_RouteConfig_RequestLimits(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("full gateway with route-level RequestLimits", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "route-limits-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18110, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "small-limit-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api/v1/small"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
						RequestLimits: &config.RequestLimitsConfig{
							MaxBodySize: 1024, // 1KB
						},
					},
					{
						Name: "default-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				RequestLimits: &config.RequestLimitsConfig{
					MaxBodySize: 10 * 1024 * 1024, // 10MB global
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		// Apply body limit middleware
		handler := middleware.BodyLimitFromRequestLimits(cfg.Spec.RequestLimits, logger)(p)

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18110"

		// Test request within global limit
		smallBody := strings.Repeat("a", 500)
		resp, err := client.Post(baseURL+"/api/v1/items", "application/json", strings.NewReader(smallBody))
		require.NoError(t, err)
		resp.Body.Close()
		// Should succeed (within global limit) - not 413 (Request Entity Too Large)
		assert.NotEqual(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "request within limit should not return 413")
	})

	t.Run("request exceeding route body limit returns 413", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "body-limit-413-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18111, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "test-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				RequestLimits: &config.RequestLimitsConfig{
					MaxBodySize: 100, // Very small limit
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		handler := middleware.BodyLimitFromRequestLimits(cfg.Spec.RequestLimits, logger)(p)

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18111"

		// Request exceeding limit
		largeBody := strings.Repeat("a", 500)
		resp, err := client.Post(baseURL+"/api/test", "application/json", strings.NewReader(largeBody))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})
}

func TestE2E_RouteConfig_CORS(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("full gateway with route-level CORS", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "cors-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18112, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "cors-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				CORS: &config.CORSConfig{
					AllowOrigins:     []string{"https://example.com"},
					AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
					AllowHeaders:     []string{"Content-Type", "Authorization"},
					AllowCredentials: true,
					MaxAge:           3600,
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		handler := middleware.CORSFromConfig(cfg.Spec.CORS)(p)

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18112"

		// CORS preflight request
		req, err := http.NewRequest(http.MethodOptions, baseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Equal(t, "https://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	})

	t.Run("CORS preflight with route-specific origins", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "cors-specific-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18113, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "cors-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				CORS: &config.CORSConfig{
					AllowOrigins: []string{"https://allowed.example.com"},
					AllowMethods: []string{"GET"},
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		handler := middleware.CORSFromConfig(cfg.Spec.CORS)(p)

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18113"

		// Allowed origin
		req, err := http.NewRequest(http.MethodOptions, baseURL+"/api/test", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://allowed.example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")

		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, "https://allowed.example.com", resp.Header.Get("Access-Control-Allow-Origin"))

		// Disallowed origin
		req, err = http.NewRequest(http.MethodOptions, baseURL+"/api/test", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://disallowed.example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")

		resp, err = client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		// Should not have the disallowed origin in response
		assert.NotEqual(t, "https://disallowed.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	})
}

func TestE2E_RouteConfig_Security(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("full gateway with route-level Security headers", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "security-headers-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18114, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "secure-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		// Add security headers
		securityHeaders := middleware.HeadersConfig{
			ResponseSet: map[string]string{
				"X-Frame-Options":        "DENY",
				"X-Content-Type-Options": "nosniff",
				"X-XSS-Protection":       "1; mode=block",
				"Referrer-Policy":        "strict-origin-when-cross-origin",
			},
		}
		handler := middleware.Headers(securityHeaders)(p)

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18114"

		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify security headers
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
		assert.Equal(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
	})

	t.Run("security headers present in response", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "security-response-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18115, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "test-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		// Add HSTS and CSP headers
		securityHeaders := middleware.HeadersConfig{
			ResponseSet: map[string]string{
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"Content-Security-Policy":   "default-src 'self'",
			},
		}
		handler := middleware.Headers(securityHeaders)(p)

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18115"

		resp, err := client.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
		assert.Equal(t, "default-src 'self'", resp.Header.Get("Content-Security-Policy"))
	})
}

func TestE2E_RouteConfig_Combined(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway with all route configurations", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "combined-config-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18116, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "full-config-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				RequestLimits: &config.RequestLimitsConfig{
					MaxBodySize: 5 * 1024 * 1024, // 5MB
				},
				CORS: &config.CORSConfig{
					AllowOrigins: []string{"https://example.com"},
					AllowMethods: []string{"GET", "POST"},
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		// Build middleware chain
		handler := middleware.BodyLimitFromRequestLimits(cfg.Spec.RequestLimits, logger)(
			middleware.CORSFromConfig(cfg.Spec.CORS)(
				middleware.Headers(middleware.HeadersConfig{
					ResponseSet: map[string]string{
						"X-Frame-Options": "DENY",
					},
				})(p),
			),
		)

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18116"

		// Test CORS
		req, err := http.NewRequest(http.MethodOptions, baseURL+"/api/test", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")

		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, "https://example.com", resp.Header.Get("Access-Control-Allow-Origin"))

		// Test security headers
		resp, err = client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))

		// Test body limit
		largeBody := bytes.Repeat([]byte("a"), 6*1024*1024) // 6MB
		resp, err = client.Post(baseURL+"/api/test", "application/json", bytes.NewReader(largeBody))
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})
}

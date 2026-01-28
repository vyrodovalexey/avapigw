//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"net/http"
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

func TestE2E_CircuitBreaker(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("circuit breaker allows requests when closed", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "circuit-breaker-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18093, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "test-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        5,
					Timeout:          config.Duration(30 * time.Second),
					HalfOpenRequests: 3,
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
		cbMiddleware := middleware.CircuitBreakerFromConfig(cfg.Spec.CircuitBreaker, logger)
		handler := cbMiddleware(p)

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
		baseURL := "http://127.0.0.1:18093"

		// Requests should succeed when circuit breaker is closed
		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should succeed (circuit breaker is closed)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("circuit breaker with healthy backend", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "circuit-breaker-healthy-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18094, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "test-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        10,
					Timeout:          config.Duration(30 * time.Second),
					HalfOpenRequests: 3,
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
		cbMiddleware := middleware.CircuitBreakerFromConfig(cfg.Spec.CircuitBreaker, logger)
		handler := cbMiddleware(p)

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
		baseURL := "http://127.0.0.1:18094"

		// Multiple requests should succeed
		successCount := 0
		for i := 0; i < 10; i++ {
			resp, err := client.Get(baseURL + "/api/v1/items")
			if err == nil {
				if resp.StatusCode == http.StatusOK {
					successCount++
				}
				resp.Body.Close()
			}
		}

		// All requests should succeed with healthy backend
		assert.Equal(t, 10, successCount, "All requests should succeed with healthy backend")
	})
}

func TestE2E_CircuitBreaker_Disabled(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("disabled circuit breaker passes all requests", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "circuit-breaker-disabled-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18095, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "test-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled: false,
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
		cbMiddleware := middleware.CircuitBreakerFromConfig(cfg.Spec.CircuitBreaker, logger)
		handler := cbMiddleware(p)

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
		baseURL := "http://127.0.0.1:18095"

		// All requests should pass through
		successCount := 0
		for i := 0; i < 10; i++ {
			resp, err := client.Get(baseURL + "/api/v1/items")
			if err == nil {
				if resp.StatusCode == http.StatusOK {
					successCount++
				}
				resp.Body.Close()
			}
		}

		assert.Equal(t, 10, successCount, "All requests should succeed when circuit breaker is disabled")
	})
}

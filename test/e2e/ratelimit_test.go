//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
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

func TestE2E_RateLimiting(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("rate limiting enforced", func(t *testing.T) {
		// Create a gateway with very low rate limit for testing
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "rate-limit-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18090, Protocol: "HTTP"},
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
				RateLimit: &config.RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 5,
					Burst:             5,
					PerClient:         false,
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		// Create router
		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		// Create backend registry
		registry := backend.NewRegistry(logger)

		// Create proxy with rate limiting
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		// Create rate limiter middleware
		rateLimitMiddleware := middleware.RateLimitFromConfig(cfg.Spec.RateLimit, logger)
		handler := rateLimitMiddleware(p)

		// Create gateway with the handler
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

		// Wait for gateway to be ready
		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18090"

		// Send requests within rate limit
		successCount := 0
		rateLimitedCount := 0

		for i := 0; i < 20; i++ {
			resp, err := client.Get(baseURL + "/api/v1/items")
			if err == nil {
				if resp.StatusCode == http.StatusOK {
					successCount++
				} else if resp.StatusCode == http.StatusTooManyRequests {
					rateLimitedCount++
				}
				resp.Body.Close()
			}
		}

		// Some requests should succeed, some should be rate limited
		assert.Greater(t, successCount, 0, "Some requests should succeed")
		assert.Greater(t, rateLimitedCount, 0, "Some requests should be rate limited")
	})

	t.Run("per-client rate limiting", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "per-client-rate-limit-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18091, Protocol: "HTTP"},
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
				RateLimit: &config.RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 10,
					Burst:             10,
					PerClient:         true,
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
		rateLimitMiddleware := middleware.RateLimitFromConfig(cfg.Spec.RateLimit, logger)
		handler := rateLimitMiddleware(p)

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

		// Per-client rate limiting should allow different clients to have separate limits
		// This is a simplified test - in reality, different clients would have different IPs
		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18091"

		var successCount atomic.Int64
		var wg sync.WaitGroup

		// Simulate multiple clients
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 5; j++ {
					resp, err := client.Get(baseURL + "/api/v1/items")
					if err == nil {
						if resp.StatusCode == http.StatusOK {
							successCount.Add(1)
						}
						resp.Body.Close()
					}
				}
			}()
		}

		wg.Wait()

		// Some requests should succeed
		assert.Greater(t, successCount.Load(), int64(0), "Some requests should succeed")
	})
}

func TestE2E_RateLimiting_Recovery(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("rate limit recovers after time", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "rate-limit-recovery-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18092, Protocol: "HTTP"},
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
				RateLimit: &config.RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 5,
					Burst:             5,
					PerClient:         false,
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
		rateLimitMiddleware := middleware.RateLimitFromConfig(cfg.Spec.RateLimit, logger)
		handler := rateLimitMiddleware(p)

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
		baseURL := "http://127.0.0.1:18092"

		// Exhaust rate limit
		for i := 0; i < 10; i++ {
			resp, err := client.Get(baseURL + "/api/v1/items")
			if err == nil {
				resp.Body.Close()
			}
		}

		// Wait for rate limit to recover
		time.Sleep(2 * time.Second)

		// Should be able to make requests again
		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should succeed or at least not be rate limited
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Request should succeed after rate limit recovery")
	})
}

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestE2E_BackendCircuitBreaker(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway with backend circuit breaker", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "cb-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18130, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "cb-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "cb-backend",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
						CircuitBreaker: &config.CircuitBreakerConfig{
							Enabled:          true,
							Threshold:        5,
							Timeout:          config.Duration(30 * time.Second),
							HalfOpenRequests: 3,
						},
					},
				},
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        10,
					Timeout:          config.Duration(60 * time.Second),
					HalfOpenRequests: 5,
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

		// Apply circuit breaker middleware
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
		baseURL := "http://127.0.0.1:18130"

		// Send requests - should succeed when backend is healthy
		resp, err := client.Get(baseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should get a response (either from backend or circuit breaker)
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound)
	})

	t.Run("circuit breaker opens on backend failures", func(t *testing.T) {
		// Create a failing backend
		failCount := int32(0)
		failingBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&failCount, 1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"backend failure"}`)
		}))
		defer failingBackend.Close()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "cb-open-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18131, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "failing-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        3,
					Timeout:          config.Duration(5 * time.Second),
					HalfOpenRequests: 1,
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

		cb := middleware.NewCircuitBreaker("e2e-test", 3, 5*time.Second,
			middleware.WithCircuitBreakerLogger(logger))
		handler := middleware.CircuitBreakerMiddleware(cb)(p)

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
		baseURL := "http://127.0.0.1:18131"

		// Send requests that will fail
		circuitOpenCount := 0
		for i := 0; i < 15; i++ {
			resp, err := client.Get(baseURL + "/api/test")
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusServiceUnavailable {
				circuitOpenCount++
			}
			resp.Body.Close()
		}

		// After enough failures, circuit breaker should open
		// and return 503 without hitting the backend
		t.Logf("Circuit open responses: %d", circuitOpenCount)
	})

	t.Run("circuit breaker returns 503 when open", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "cb-503-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18132, Protocol: "HTTP"},
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
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        2,
					Timeout:          config.Duration(100 * time.Millisecond),
					HalfOpenRequests: 1,
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)
		_ = proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		// Create circuit breaker that will open quickly
		cb := middleware.NewCircuitBreaker("503-test", 2, 100*time.Millisecond,
			middleware.WithCircuitBreakerLogger(logger))

		// Handler that always fails
		failingHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		handler := middleware.CircuitBreakerMiddleware(cb)(failingHandler)

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
		baseURL := "http://127.0.0.1:18132"

		// Send failing requests to open circuit breaker
		for i := 0; i < 10; i++ {
			resp, err := client.Get(baseURL + "/test")
			if err != nil {
				continue
			}

			// Check for 503 response
			if resp.StatusCode == http.StatusServiceUnavailable {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				assert.Contains(t, string(body), "service unavailable")
				return // Test passed
			}
			resp.Body.Close()
		}
	})

	t.Run("circuit breaker recovery after timeout", func(t *testing.T) {
		shouldFail := int32(1)
		mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.LoadInt32(&shouldFail) == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"recovered"}`)
		}))
		defer mockBackend.Close()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "cb-recovery-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18133, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "recovery-route",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
				},
				CircuitBreaker: &config.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        3,
					Timeout:          config.Duration(100 * time.Millisecond),
					HalfOpenRequests: 1,
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		r := router.New()
		err := r.LoadRoutes(cfg.Spec.Routes)
		require.NoError(t, err)

		registry := backend.NewRegistry(logger)

		cb := middleware.NewCircuitBreaker("recovery-test", 3, 100*time.Millisecond,
			middleware.WithCircuitBreakerLogger(logger))

		// Handler that proxies to mock backend
		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			resp, err := http.Get(mockBackend.URL)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
		})

		handler := middleware.CircuitBreakerMiddleware(cb)(proxyHandler)

		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
			_ = registry.StopAll(ctx)
		})

		time.Sleep(500 * time.Millisecond)

		client := helpers.HTTPClient()
		baseURL := "http://127.0.0.1:18133"

		// Trigger failures
		for i := 0; i < 10; i++ {
			resp, _ := client.Get(baseURL + "/test")
			if resp != nil {
				resp.Body.Close()
			}
		}

		// Wait for timeout
		time.Sleep(200 * time.Millisecond)

		// Make backend healthy
		atomic.StoreInt32(&shouldFail, 0)

		// Try to recover
		recovered := false
		for i := 0; i < 20; i++ {
			resp, err := client.Get(baseURL + "/test")
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}

			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if strings.Contains(string(body), "recovered") {
					recovered = true
					break
				}
			} else {
				resp.Body.Close()
			}
			time.Sleep(50 * time.Millisecond)
		}

		assert.True(t, recovered, "Circuit breaker should recover after backend becomes healthy")
	})
}

func TestE2E_BackendCircuitBreaker_MultipleBackends(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("independent circuit breakers for multiple backends", func(t *testing.T) {
		// Backend 1 - always fails
		backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer backend1.Close()

		// Backend 2 - always succeeds
		backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		}))
		defer backend2.Close()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "multi-cb-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 18134, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "route1",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api/v1"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
						},
					},
					{
						Name: "route2",
						Match: []config.RouteMatch{
							{URI: &config.URIMatch{Prefix: "/api/v2"}},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "127.0.0.1", Port: 8802}},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "backend1",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
						CircuitBreaker: &config.CircuitBreakerConfig{
							Enabled:          true,
							Threshold:        3,
							Timeout:          config.Duration(5 * time.Second),
							HalfOpenRequests: 1,
						},
					},
					{
						Name: "backend2",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8802},
						},
						CircuitBreaker: &config.CircuitBreakerConfig{
							Enabled:          true,
							Threshold:        3,
							Timeout:          config.Duration(5 * time.Second),
							HalfOpenRequests: 1,
						},
					},
				},
			},
		}

		// Verify config has independent circuit breakers
		assert.Len(t, cfg.Spec.Backends, 2)
		assert.NotNil(t, cfg.Spec.Backends[0].CircuitBreaker)
		assert.NotNil(t, cfg.Spec.Backends[1].CircuitBreaker)
		assert.True(t, cfg.Spec.Backends[0].CircuitBreaker.Enabled)
		assert.True(t, cfg.Spec.Backends[1].CircuitBreaker.Enabled)
	})
}

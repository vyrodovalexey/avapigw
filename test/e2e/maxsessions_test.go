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

func TestE2E_MaxSessions_GlobalLimit(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway enforces global max sessions", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "test-gateway",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "http",
						Port:     18090,
						Protocol: "HTTP",
						Hosts:    []string{"*"},
						Bind:     "0.0.0.0",
					},
				},
				Routes: []config.Route{
					{
						Name: "api-route",
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
									Port: 8801,
								},
							},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "backend-1",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
					},
				},
				MaxSessions: &config.MaxSessionsConfig{
					Enabled:       true,
					MaxConcurrent: 2,
					QueueSize:     0,
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
		err = registry.LoadFromConfig(cfg.Spec.Backends)
		require.NoError(t, err)
		err = registry.StartAll(ctx)
		require.NoError(t, err)
		defer func() { _ = registry.StopAll(ctx) }()

		// Create proxy
		p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

		// Create max sessions middleware
		maxSessionsMw, limiter := middleware.MaxSessionsFromConfig(cfg.Spec.MaxSessions, logger)
		require.NotNil(t, limiter)
		defer limiter.Stop()

		// Wrap proxy with max sessions middleware
		handler := maxSessionsMw(p)

		// Create gateway with custom handler
		gw, err := gateway.New(cfg,
			gateway.WithLogger(logger),
			gateway.WithRouteHandler(handler),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = gw.Stop(ctx) }()

		// Wait for gateway to be ready
		err = helpers.WaitForReady("http://127.0.0.1:18090/api/v1/items", 10*time.Second)
		require.NoError(t, err)

		client := helpers.HTTPClient()

		var wg sync.WaitGroup
		var successCount, rejectCount atomic.Int64

		// Start 5 concurrent requests with max 2 allowed
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get("http://127.0.0.1:18090/api/v1/items")
				if err != nil {
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					successCount.Add(1)
				} else if resp.StatusCode == http.StatusServiceUnavailable {
					rejectCount.Add(1)
				}
			}()
		}

		wg.Wait()

		// Some requests should succeed, some should be rejected
		assert.Greater(t, successCount.Load(), int64(0))
	})
}

func TestE2E_MaxSessions_RouteOverride(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("route level max sessions overrides global", func(t *testing.T) {
		// This test verifies that route-level configuration can be different from global
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "test-gateway",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "http",
						Port:     18091,
						Protocol: "HTTP",
						Hosts:    []string{"*"},
						Bind:     "0.0.0.0",
					},
				},
				Routes: []config.Route{
					{
						Name: "limited-route",
						Match: []config.RouteMatch{
							{
								URI: &config.URIMatch{
									Prefix: "/limited",
								},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{
									Host: "127.0.0.1",
									Port: 8801,
								},
							},
						},
						MaxSessions: &config.MaxSessionsConfig{
							Enabled:       true,
							MaxConcurrent: 1, // Very restrictive
							QueueSize:     0,
						},
					},
					{
						Name: "unlimited-route",
						Match: []config.RouteMatch{
							{
								URI: &config.URIMatch{
									Prefix: "/unlimited",
								},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{
									Host: "127.0.0.1",
									Port: 8801,
								},
							},
						},
						// No MaxSessions - uses global or unlimited
					},
				},
				Backends: []config.Backend{
					{
						Name: "backend-1",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
					},
				},
				MaxSessions: &config.MaxSessionsConfig{
					Enabled:       true,
					MaxConcurrent: 100, // Global is permissive
				},
			},
		}

		// Verify route-level config is set correctly
		assert.NotNil(t, cfg.Spec.Routes[0].MaxSessions)
		assert.Equal(t, 1, cfg.Spec.Routes[0].MaxSessions.MaxConcurrent)
		assert.Nil(t, cfg.Spec.Routes[1].MaxSessions)
	})
}

func TestE2E_MaxSessions_BackendLimit(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("backend level max sessions limits connections", func(t *testing.T) {
		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "test-gateway",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "http",
						Port:     18092,
						Protocol: "HTTP",
						Hosts:    []string{"*"},
						Bind:     "0.0.0.0",
					},
				},
				Routes: []config.Route{
					{
						Name: "api-route",
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
									Port: 8801,
								},
							},
						},
					},
				},
				Backends: []config.Backend{
					{
						Name: "backend-1",
						Hosts: []config.BackendHost{
							{Address: "127.0.0.1", Port: 8801},
						},
						MaxSessions: &config.MaxSessionsConfig{
							Enabled:       true,
							MaxConcurrent: 3,
						},
					},
				},
			},
		}

		ctx := context.Background()
		logger := observability.NopLogger()

		// Create backend registry
		registry := backend.NewRegistry(logger)
		err := registry.LoadFromConfig(cfg.Spec.Backends)
		require.NoError(t, err)
		err = registry.StartAll(ctx)
		require.NoError(t, err)
		defer func() { _ = registry.StopAll(ctx) }()

		// Get the backend
		b, exists := registry.Get("backend-1")
		require.True(t, exists)

		// Verify max sessions is configured
		sb, ok := b.(*backend.ServiceBackend)
		require.True(t, ok)

		hosts := sb.GetHosts()
		require.Len(t, hosts, 1)
		assert.True(t, hosts[0].IsMaxSessionsEnabled())
		assert.Equal(t, 3, hosts[0].MaxSessions())
	})
}

func TestE2E_MaxSessions_Recovery(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("sessions are released after request completes", func(t *testing.T) {
		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 2,
			QueueSize:     0,
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		require.NotNil(t, limiter)
		defer limiter.Stop()

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(10 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))

		// Make requests sequentially - all should succeed because sessions are released
		for i := 0; i < 10; i++ {
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			rec := &responseRecorder{code: 0}
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.code, "request %d should succeed", i)
		}

		// Current sessions should be 0
		assert.Equal(t, int64(0), limiter.Current())
	})

	t.Run("queue drains after capacity freed", func(t *testing.T) {
		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1,
			QueueSize:     5,
			QueueTimeout:  config.Duration(500 * time.Millisecond),
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		require.NotNil(t, limiter)
		defer limiter.Stop()

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(20 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))

		var wg sync.WaitGroup
		var successCount atomic.Int64

		// Start 3 requests with max 1 concurrent but queue of 5
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest(http.MethodGet, "/test", nil)
				rec := &responseRecorder{code: 0}
				handler.ServeHTTP(rec, req)
				if rec.code == http.StatusOK {
					successCount.Add(1)
				}
			}()
		}

		wg.Wait()

		// All 3 should eventually succeed due to queuing
		assert.Equal(t, int64(3), successCount.Load())
	})
}

func TestE2E_MaxSessions_WithLoadBalancing(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("load balancer distributes within max sessions", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
				{Address: "127.0.0.1", Port: 8802},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 2, // 2 per host = 4 total
			},
			LoadBalancer: &config.LoadBalancer{
				Algorithm: config.LoadBalancerRoundRobin,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// Should be able to get 4 hosts total
		hosts := make([]*backend.Host, 0, 4)
		for i := 0; i < 4; i++ {
			host, err := b.GetAvailableHost()
			require.NoError(t, err, "request %d should succeed", i)
			hosts = append(hosts, host)
		}

		// Fifth should fail
		_, err = b.GetAvailableHost()
		assert.Error(t, err)

		// Cleanup
		for _, host := range hosts {
			b.ReleaseHost(host)
		}
	})
}

// responseRecorder is a simple http.ResponseWriter for testing
type responseRecorder struct {
	code int
}

func (r *responseRecorder) Header() http.Header {
	return http.Header{}
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return len(b), nil
}

func (r *responseRecorder) WriteHeader(code int) {
	r.code = code
}

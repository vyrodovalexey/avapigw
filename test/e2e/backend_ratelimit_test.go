//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_BackendRateLimit_Enforcement(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("backend rate limit enforces request limits", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				Burst:             3,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		var successCount, failCount atomic.Int64

		// Make requests - first 3 should succeed (burst), rest should fail
		for i := 0; i < 10; i++ {
			host, err := b.GetHost()
			if err != nil {
				failCount.Add(1)
			} else {
				successCount.Add(1)
				b.ReleaseHost(host)
			}
		}

		// Burst of 3 should succeed
		assert.Equal(t, int64(3), successCount.Load())
		// Rest should fail
		assert.Equal(t, int64(7), failCount.Load())
	})

	t.Run("rate limit with multiple backends", func(t *testing.T) {
		testCfg := helpers.GetTestConfig()
		helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
				{Address: "127.0.0.1", Port: 8802},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				Burst:             2, // 2 per host = 4 total burst
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

		var successCount atomic.Int64

		// Make requests - should get 4 total (2 per host)
		for i := 0; i < 10; i++ {
			host, err := b.GetAvailableHost()
			if err == nil {
				successCount.Add(1)
				b.ReleaseHost(host)
			}
		}

		// Should get 4 successful requests (2 burst per host)
		assert.Equal(t, int64(4), successCount.Load())
	})
}

func TestE2E_BackendRateLimit_Recovery(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("rate limit recovers after waiting", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 20, // 20 RPS = 1 token per 50ms
				Burst:             2,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// Exhaust burst
		for i := 0; i < 2; i++ {
			host, err := b.GetHost()
			require.NoError(t, err)
			b.ReleaseHost(host)
		}

		// Should be rate limited
		_, err = b.GetHost()
		assert.Error(t, err)

		// Wait for recovery
		time.Sleep(100 * time.Millisecond)

		// Should succeed now
		host, err := b.GetHost()
		require.NoError(t, err)
		b.ReleaseHost(host)
	})

	t.Run("sustained rate within limit", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100, // 100 RPS
				Burst:             10,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		var successCount atomic.Int64

		// Make requests at a rate below the limit
		for i := 0; i < 20; i++ {
			host, err := b.GetHost()
			if err == nil {
				successCount.Add(1)
				b.ReleaseHost(host)
			}
			time.Sleep(15 * time.Millisecond) // ~66 RPS, below 100 RPS limit
		}

		// Most requests should succeed
		assert.GreaterOrEqual(t, successCount.Load(), int64(15))
	})
}

func TestE2E_BackendRateLimit_ConcurrentLoad(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("concurrent requests respect rate limit", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             20,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		var wg sync.WaitGroup
		var successCount, failCount atomic.Int64

		// Start 50 concurrent requests with burst of 20
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				host, err := b.GetHost()
				if err != nil {
					failCount.Add(1)
				} else {
					successCount.Add(1)
					b.ReleaseHost(host)
				}
			}()
		}

		wg.Wait()

		// At least burst amount should succeed
		assert.GreaterOrEqual(t, successCount.Load(), int64(20))
		// Some should fail
		assert.Greater(t, failCount.Load(), int64(0))
	})
}

func TestE2E_BackendRateLimit_WithMaxSessions(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("both constraints enforced together", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 10,
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             5, // Rate limit is more restrictive
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		var successCount atomic.Int64

		// Rate limit (burst=5) should kick in before max sessions (10)
		for i := 0; i < 15; i++ {
			host, err := b.GetHost()
			if err == nil {
				successCount.Add(1)
				b.ReleaseHost(host)
			}
		}

		// Should be limited by rate limit burst
		assert.Equal(t, int64(5), successCount.Load())
	})
}

func TestE2E_BackendRateLimit_FullGatewayFlow(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("rate limit in full gateway configuration", func(t *testing.T) {
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
						Port:     18095,
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
						RateLimit: &config.RateLimitConfig{
							Enabled:           true,
							RequestsPerSecond: 50,
							Burst:             10,
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

		// Verify backend has rate limiting configured
		b, exists := registry.Get("backend-1")
		require.True(t, exists)

		sb, ok := b.(*backend.ServiceBackend)
		require.True(t, ok)

		hosts := sb.GetHosts()
		require.Len(t, hosts, 1)
		assert.True(t, hosts[0].IsRateLimitEnabled())
	})
}

func TestE2E_BackendRateLimit_DisabledBehavior(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("disabled rate limit allows all requests", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           false,
				RequestsPerSecond: 1,
				Burst:             1,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		var successCount atomic.Int64

		// All requests should succeed
		for i := 0; i < 20; i++ {
			host, err := b.GetHost()
			if err == nil {
				successCount.Add(1)
				b.ReleaseHost(host)
			}
		}

		assert.Equal(t, int64(20), successCount.Load())
	})

	t.Run("nil rate limit config allows all requests", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			// RateLimit is nil
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		var successCount atomic.Int64

		// All requests should succeed
		for i := 0; i < 20; i++ {
			host, err := b.GetHost()
			if err == nil {
				successCount.Add(1)
				b.ReleaseHost(host)
			}
		}

		assert.Equal(t, int64(20), successCount.Load())
	})
}

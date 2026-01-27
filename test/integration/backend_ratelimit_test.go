//go:build integration
// +build integration

package integration

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
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_BackendRateLimit_WithRealBackends(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("backend rate limit restricts requests", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 5,
				Burst:             2,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// First two requests should succeed (burst)
		host1, err := b.GetHost()
		require.NoError(t, err)
		b.ReleaseHost(host1)

		host2, err := b.GetHost()
		require.NoError(t, err)
		b.ReleaseHost(host2)

		// Third request should be rate limited
		_, err = b.GetHost()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "rate limited")
	})

	t.Run("rate limit replenishes over time", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				Burst:             1,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// First request should succeed
		host1, err := b.GetHost()
		require.NoError(t, err)
		b.ReleaseHost(host1)

		// Second request should be rate limited
		_, err = b.GetHost()
		assert.Error(t, err)

		// Wait for token replenishment
		time.Sleep(150 * time.Millisecond)

		// Should succeed now
		host2, err := b.GetHost()
		require.NoError(t, err)
		b.ReleaseHost(host2)
	})

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

		// All requests should succeed
		for i := 0; i < 10; i++ {
			host, err := b.GetHost()
			require.NoError(t, err, "request %d should succeed", i)
			b.ReleaseHost(host)
		}
	})
}

func TestIntegration_BackendRateLimit_LoadBalancerIntegration(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("load balancer tries next host when rate limited", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
				{Address: "127.0.0.1", Port: 8802},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				Burst:             1, // Very low burst per host
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

		// With 2 hosts and burst of 1 each, we should get 2 requests through
		host1, err := b.GetAvailableHost()
		require.NoError(t, err)
		b.ReleaseHost(host1)

		host2, err := b.GetAvailableHost()
		require.NoError(t, err)
		b.ReleaseHost(host2)

		// Third request should fail (both hosts rate limited)
		_, err = b.GetAvailableHost()
		assert.Error(t, err)
	})

	t.Run("rate limit per host is independent", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
				{Address: "127.0.0.1", Port: 8802},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             5,
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

		// Should be able to get 10 hosts (5 per host)
		hosts := make([]*backend.Host, 0, 10)
		for i := 0; i < 10; i++ {
			host, err := b.GetAvailableHost()
			require.NoError(t, err, "request %d should succeed", i)
			hosts = append(hosts, host)
			b.ReleaseHost(host)
		}

		assert.Len(t, hosts, 10)
	})
}

func TestIntegration_BackendRateLimit_ConcurrentRequests(t *testing.T) {
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
				Burst:             10,
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

		// Start 20 concurrent requests with burst of 10
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				host, err := b.GetHost()
				if err != nil {
					failCount.Add(1)
					return
				}

				successCount.Add(1)
				b.ReleaseHost(host)
			}()
		}

		wg.Wait()

		// At least burst amount should succeed
		assert.GreaterOrEqual(t, successCount.Load(), int64(10))
		// Some should fail due to rate limiting
		assert.Greater(t, failCount.Load(), int64(0))
	})
}

func TestIntegration_BackendRateLimit_RealHTTPRequests(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("make real HTTP requests with rate limiting", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 50,
				Burst:             5,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		client := helpers.HTTPClient()

		var successCount atomic.Int64

		// Make requests within burst limit
		for i := 0; i < 5; i++ {
			host, err := b.GetHost()
			if err != nil {
				continue
			}

			resp, err := client.Get(host.URL() + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					successCount.Add(1)
				}
			}

			b.ReleaseHost(host)
		}

		// All 5 should succeed (within burst)
		assert.Equal(t, int64(5), successCount.Load())
	})
}

func TestIntegration_BackendRateLimit_CombinedWithMaxSessions(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("both rate limit and max sessions enforced", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 5,
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             3, // Lower than max sessions
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// Rate limit (burst=3) should kick in before max sessions (5)
		hosts := make([]*backend.Host, 0, 5)

		for i := 0; i < 5; i++ {
			host, err := b.GetHost()
			if err != nil {
				// Should fail due to rate limiting after 3 requests
				assert.GreaterOrEqual(t, i, 3)
				break
			}
			hosts = append(hosts, host)
		}

		// Should have gotten at most 3 hosts (rate limit burst)
		assert.LessOrEqual(t, len(hosts), 3)

		// Cleanup
		for _, host := range hosts {
			b.ReleaseHost(host)
		}
	})

	t.Run("max sessions kicks in when rate limit allows", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 2, // Lower than rate limit burst
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             10,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// Get hosts up to max sessions
		host1, err := b.GetAvailableHost()
		require.NoError(t, err)

		host2, err := b.GetAvailableHost()
		require.NoError(t, err)

		// Third should fail due to max sessions (not rate limit)
		_, err = b.GetAvailableHost()
		assert.Error(t, err)

		// Cleanup
		b.ReleaseHost(host1)
		b.ReleaseHost(host2)
	})
}

func TestIntegration_BackendRateLimit_Recovery(t *testing.T) {
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
		host1, err := b.GetHost()
		require.NoError(t, err)
		b.ReleaseHost(host1)

		host2, err := b.GetHost()
		require.NoError(t, err)
		b.ReleaseHost(host2)

		// Should be rate limited
		_, err = b.GetHost()
		assert.Error(t, err)

		// Wait for recovery (at least 50ms for 1 token at 20 RPS)
		time.Sleep(100 * time.Millisecond)

		// Should succeed now
		host3, err := b.GetHost()
		require.NoError(t, err)
		b.ReleaseHost(host3)
	})
}

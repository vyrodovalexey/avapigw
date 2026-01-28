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

func TestIntegration_MaxSessions_WithRealBackends(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("backend with max sessions limits connections", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 2,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// Get first host
		host1, err := b.GetAvailableHost()
		require.NoError(t, err)
		assert.NotNil(t, host1)

		// Get second host (same host, second connection)
		host2, err := b.GetAvailableHost()
		require.NoError(t, err)
		assert.NotNil(t, host2)

		// Third attempt should fail (at capacity)
		_, err = b.GetAvailableHost()
		assert.Error(t, err)

		// Release one
		b.ReleaseHost(host1)

		// Now should succeed
		host3, err := b.GetAvailableHost()
		require.NoError(t, err)
		assert.NotNil(t, host3)

		// Cleanup
		b.ReleaseHost(host2)
		b.ReleaseHost(host3)
	})

	t.Run("backend without max sessions allows unlimited connections", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			// No MaxSessions config
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// Should be able to get many hosts
		hosts := make([]*backend.Host, 0, 10)
		for i := 0; i < 10; i++ {
			host, err := b.GetHost()
			require.NoError(t, err)
			hosts = append(hosts, host)
		}

		// Cleanup
		for _, host := range hosts {
			b.ReleaseHost(host)
		}
	})
}

func TestIntegration_MaxSessions_ConcurrentRequests(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("concurrent requests respect max sessions", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 5,
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

		// Start 20 concurrent requests
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				host, err := b.GetAvailableHost()
				if err != nil {
					failCount.Add(1)
					return
				}

				successCount.Add(1)

				// Simulate some work
				time.Sleep(10 * time.Millisecond)

				b.ReleaseHost(host)
			}()
		}

		wg.Wait()

		// Some requests should have failed (20 concurrent > 5 max)
		assert.Greater(t, failCount.Load(), int64(0))

		// Some requests should have succeeded
		assert.Greater(t, successCount.Load(), int64(0))
	})

	t.Run("concurrent requests with multiple hosts", func(t *testing.T) {
		testCfg := helpers.GetTestConfig()
		helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

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
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		var wg sync.WaitGroup
		var successCount atomic.Int64

		// Start 10 concurrent requests
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				host, err := b.GetAvailableHost()
				if err != nil {
					return
				}

				successCount.Add(1)
				time.Sleep(10 * time.Millisecond)
				b.ReleaseHost(host)
			}()
		}

		wg.Wait()

		// With 2 hosts and 2 max sessions each, we should get at least 4 concurrent
		assert.GreaterOrEqual(t, successCount.Load(), int64(4))
	})
}

func TestIntegration_MaxSessions_QueueBehavior(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("requests queue and eventually succeed", func(t *testing.T) {
		// Note: Queue behavior is at the middleware level, not backend level
		// Backend level max sessions just limits concurrent connections per host
		// This test verifies the backend correctly tracks connections

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		// Get the only slot
		host1, err := b.GetAvailableHost()
		require.NoError(t, err)

		// Second request should fail
		_, err = b.GetAvailableHost()
		assert.Error(t, err)

		// Release the slot
		b.ReleaseHost(host1)

		// Now should succeed
		host2, err := b.GetAvailableHost()
		require.NoError(t, err)
		b.ReleaseHost(host2)
	})
}

func TestIntegration_MaxSessions_LoadBalancerIntegration(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("load balancer skips hosts at capacity", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
				{Address: "127.0.0.1", Port: 8802},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1,
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

		// Get first host
		host1, err := b.GetAvailableHost()
		require.NoError(t, err)

		// Get second host (should be different due to round robin)
		host2, err := b.GetAvailableHost()
		require.NoError(t, err)

		// Both hosts should be at capacity now
		_, err = b.GetAvailableHost()
		assert.Error(t, err)

		// Release one
		b.ReleaseHost(host1)

		// Should be able to get a host again
		host3, err := b.GetAvailableHost()
		require.NoError(t, err)

		// Cleanup
		b.ReleaseHost(host2)
		b.ReleaseHost(host3)
	})

	t.Run("least connections considers max sessions", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
				{Address: "127.0.0.1", Port: 8802},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 5,
			},
			LoadBalancer: &config.LoadBalancer{
				Algorithm: config.LoadBalancerLeastConn,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		hosts := make([]*backend.Host, 0, 10)

		// Get 10 hosts - should distribute based on least connections
		for i := 0; i < 10; i++ {
			host, err := b.GetAvailableHost()
			require.NoError(t, err)
			hosts = append(hosts, host)
		}

		// Count connections per host
		hostConnections := make(map[string]int64)
		for _, host := range hosts {
			key := host.URL()
			hostConnections[key]++
		}

		// Should be roughly balanced
		for _, count := range hostConnections {
			assert.LessOrEqual(t, count, int64(5))
		}

		// Cleanup
		for _, host := range hosts {
			b.ReleaseHost(host)
		}
	})
}

func TestIntegration_MaxSessions_RealHTTPRequests(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("make real HTTP requests with max sessions", func(t *testing.T) {
		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 3,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = b.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = b.Stop(ctx) }()

		client := helpers.HTTPClient()

		var wg sync.WaitGroup
		var successCount atomic.Int64

		// Make concurrent HTTP requests
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				host, err := b.GetAvailableHost()
				if err != nil {
					return
				}
				defer b.ReleaseHost(host)

				resp, err := client.Get(host.URL() + "/health")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						successCount.Add(1)
					}
				}
			}()
		}

		wg.Wait()

		// At least some requests should succeed
		assert.Greater(t, successCount.Load(), int64(0))
	})
}

func TestIntegration_MaxSessions_HostAvailability(t *testing.T) {
	t.Parallel()

	t.Run("host availability checks all constraints", func(t *testing.T) {
		t.Parallel()

		host := backend.NewHost("127.0.0.1", 8801, 1)
		host.SetMaxSessions(2)

		// Initially unknown status - should be available
		assert.True(t, host.IsAvailable())

		// Set healthy - should be available
		host.SetStatus(backend.StatusHealthy)
		assert.True(t, host.IsAvailable())

		// Add connections
		host.IncrementConnections()
		assert.True(t, host.IsAvailable())

		host.IncrementConnections()
		assert.False(t, host.IsAvailable()) // At capacity

		// Set unhealthy - should not be available
		host.SetStatus(backend.StatusUnhealthy)
		assert.False(t, host.IsAvailable())

		// Even with capacity, unhealthy is not available
		host.DecrementConnections()
		assert.False(t, host.IsAvailable())

		// Set healthy again
		host.SetStatus(backend.StatusHealthy)
		assert.True(t, host.IsAvailable())
	})
}

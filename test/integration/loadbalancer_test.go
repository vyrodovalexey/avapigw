//go:build integration
// +build integration

package integration

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_LoadBalancer_Distribution(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("round robin distribution", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		lb := backend.NewRoundRobinBalancer(hosts)

		// Track which hosts are selected
		hostCounts := make(map[string]int)
		for i := 0; i < 100; i++ {
			host := lb.Next()
			require.NotNil(t, host)
			hostCounts[host.URL()]++
		}

		// Should be roughly equal distribution
		assert.Len(t, hostCounts, 2)
		for _, count := range hostCounts {
			assert.Equal(t, 50, count, "Round robin should distribute evenly")
		}
	})

	t.Run("weighted distribution", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 3), // 75%
			backend.NewHost("127.0.0.1", 8802, 1), // 25%
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		lb := backend.NewWeightedBalancer(hosts)

		// Track which hosts are selected
		hostCounts := make(map[string]int)
		iterations := 1000
		for i := 0; i < iterations; i++ {
			host := lb.Next()
			require.NotNil(t, host)
			hostCounts[host.URL()]++
		}

		// Should be roughly 75/25 distribution (with some variance)
		host1Count := hostCounts["http://127.0.0.1:8801"]
		host2Count := hostCounts["http://127.0.0.1:8802"]

		// Allow 15% variance
		assert.InDelta(t, float64(iterations)*0.75, float64(host1Count), float64(iterations)*0.15)
		assert.InDelta(t, float64(iterations)*0.25, float64(host2Count), float64(iterations)*0.15)
	})

	t.Run("least connections distribution", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		lb := backend.NewLeastConnBalancer(hosts)

		// Simulate connections on first host
		hosts[0].IncrementConnections()
		hosts[0].IncrementConnections()
		hosts[0].IncrementConnections()

		// Next should select second host (fewer connections)
		host := lb.Next()
		require.NotNil(t, host)
		assert.Equal(t, "http://127.0.0.1:8802", host.URL())
	})

	t.Run("random distribution", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		lb := backend.NewRandomBalancer(hosts)

		// Track which hosts are selected
		hostCounts := make(map[string]int)
		iterations := 1000
		for i := 0; i < iterations; i++ {
			host := lb.Next()
			require.NotNil(t, host)
			hostCounts[host.URL()]++
		}

		// Both hosts should be selected at least some times
		assert.Greater(t, hostCounts["http://127.0.0.1:8801"], 0)
		assert.Greater(t, hostCounts["http://127.0.0.1:8802"], 0)
	})

	t.Run("skip unhealthy hosts", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark first host as unhealthy
		hosts[0].SetStatus(backend.StatusUnhealthy)
		hosts[1].SetStatus(backend.StatusHealthy)

		lb := backend.NewRoundRobinBalancer(hosts)

		// Should only select healthy host
		for i := 0; i < 10; i++ {
			host := lb.Next()
			require.NotNil(t, host)
			assert.Equal(t, "http://127.0.0.1:8802", host.URL())
		}
	})

	t.Run("no healthy hosts returns nil", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark all hosts as unhealthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusUnhealthy)
		}

		lb := backend.NewRoundRobinBalancer(hosts)
		host := lb.Next()
		assert.Nil(t, host)
	})

	t.Run("concurrent access", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		lb := backend.NewRoundRobinBalancer(hosts)

		var wg sync.WaitGroup
		var successCount atomic.Int64

		// Concurrent access
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				host := lb.Next()
				if host != nil {
					successCount.Add(1)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, int64(100), successCount.Load())
	})
}

func TestIntegration_LoadBalancer_FromConfig(t *testing.T) {
	t.Parallel()

	t.Run("create load balancer from config", func(t *testing.T) {
		t.Parallel()

		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Test different algorithms
		algorithms := []string{
			config.LoadBalancerRoundRobin,
			config.LoadBalancerWeighted,
			config.LoadBalancerLeastConn,
			config.LoadBalancerRandom,
		}

		for _, algo := range algorithms {
			lb := backend.NewLoadBalancer(algo, hosts)
			assert.NotNil(t, lb, "Algorithm %s should create load balancer", algo)
		}
	})

	t.Run("default algorithm is round robin", func(t *testing.T) {
		t.Parallel()

		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
		}
		hosts[0].SetStatus(backend.StatusHealthy)

		lb := backend.NewLoadBalancer("", hosts)
		assert.NotNil(t, lb)

		// Should work like round robin
		host := lb.Next()
		assert.NotNil(t, host)
	})
}

func TestIntegration_LoadBalancer_RealBackends(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("distribute requests to real backends", func(t *testing.T) {
		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		lb := backend.NewRoundRobinBalancer(hosts)

		// Make requests to both backends
		client := helpers.HTTPClient()
		successCount := 0

		for i := 0; i < 10; i++ {
			host := lb.Next()
			require.NotNil(t, host)

			resp, err := client.Get(host.URL() + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					successCount++
				}
			}
		}

		assert.Equal(t, 10, successCount, "All requests should succeed")
	})
}

func TestIntegration_LoadBalancer_SkipsHostsAtCapacity(t *testing.T) {
	t.Parallel()

	t.Run("round robin skips hosts at max sessions capacity", func(t *testing.T) {
		t.Parallel()

		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		// Set max sessions on first host
		hosts[0].SetMaxSessions(1)
		hosts[1].SetMaxSessions(1)

		lb := backend.NewRoundRobinBalancer(hosts)

		// First available host
		host1 := lb.NextAvailable()
		require.NotNil(t, host1)
		host1.IncrementConnections()

		// Second available host (should be different)
		host2 := lb.NextAvailable()
		require.NotNil(t, host2)
		host2.IncrementConnections()

		// Third should return nil (both at capacity)
		host3 := lb.NextAvailable()
		assert.Nil(t, host3)

		// Release one
		host1.DecrementConnections()

		// Now should get a host
		host4 := lb.NextAvailable()
		assert.NotNil(t, host4)
	})

	t.Run("weighted balancer skips hosts at capacity", func(t *testing.T) {
		t.Parallel()

		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 3),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		// Set max sessions
		hosts[0].SetMaxSessions(2)
		hosts[1].SetMaxSessions(2)

		lb := backend.NewWeightedBalancer(hosts)

		// Get hosts until capacity
		gotHosts := make([]*backend.Host, 0, 4)
		for i := 0; i < 10; i++ {
			host := lb.NextAvailable()
			if host == nil {
				break
			}
			host.IncrementConnections()
			gotHosts = append(gotHosts, host)
		}

		// Should have gotten 4 hosts (2 per host)
		assert.Equal(t, 4, len(gotHosts))

		// Cleanup
		for _, h := range gotHosts {
			h.DecrementConnections()
		}
	})

	t.Run("least conn balancer skips hosts at capacity", func(t *testing.T) {
		t.Parallel()

		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		// Set max sessions
		hosts[0].SetMaxSessions(1)
		hosts[1].SetMaxSessions(1)

		lb := backend.NewLeastConnBalancer(hosts)

		// Get first host
		host1 := lb.NextAvailable()
		require.NotNil(t, host1)
		host1.IncrementConnections()

		// Get second host (should be the other one with fewer connections)
		host2 := lb.NextAvailable()
		require.NotNil(t, host2)
		host2.IncrementConnections()

		// Third should return nil
		host3 := lb.NextAvailable()
		assert.Nil(t, host3)

		// Cleanup
		host1.DecrementConnections()
		host2.DecrementConnections()
	})

	t.Run("random balancer skips hosts at capacity", func(t *testing.T) {
		t.Parallel()

		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		// Set max sessions
		hosts[0].SetMaxSessions(1)
		hosts[1].SetMaxSessions(1)

		lb := backend.NewRandomBalancer(hosts)

		// Get hosts until capacity
		gotHosts := make([]*backend.Host, 0, 2)
		for i := 0; i < 10; i++ {
			host := lb.NextAvailable()
			if host == nil {
				break
			}
			host.IncrementConnections()
			gotHosts = append(gotHosts, host)
		}

		// Should have gotten 2 hosts
		assert.Equal(t, 2, len(gotHosts))

		// Cleanup
		for _, h := range gotHosts {
			h.DecrementConnections()
		}
	})
}

func TestIntegration_LoadBalancer_ConsidersRateLimit(t *testing.T) {
	t.Parallel()

	t.Run("load balancer considers rate limit in availability", func(t *testing.T) {
		t.Parallel()

		hosts := []*backend.Host{
			backend.NewHost("127.0.0.1", 8801, 1),
			backend.NewHost("127.0.0.1", 8802, 1),
		}

		// Mark hosts as healthy
		for _, h := range hosts {
			h.SetStatus(backend.StatusHealthy)
		}

		// Set rate limit with low burst
		hosts[0].SetRateLimiter(10, 1)
		hosts[1].SetRateLimiter(10, 1)

		lb := backend.NewRoundRobinBalancer(hosts)

		// First request to each host should succeed
		host1 := lb.NextAvailable()
		require.NotNil(t, host1)
		assert.True(t, host1.AllowRequest())

		host2 := lb.NextAvailable()
		require.NotNil(t, host2)
		assert.True(t, host2.AllowRequest())

		// Both hosts should now be rate limited
		// Note: NextAvailable doesn't check rate limit, only IsAvailable
		// Rate limit is checked separately via AllowRequest
		host3 := lb.NextAvailable()
		require.NotNil(t, host3)
		assert.False(t, host3.AllowRequest()) // Rate limited
	})

	t.Run("host availability does not include rate limit check", func(t *testing.T) {
		t.Parallel()

		host := backend.NewHost("127.0.0.1", 8801, 1)
		host.SetStatus(backend.StatusHealthy)
		host.SetRateLimiter(10, 1)

		// Exhaust rate limit
		assert.True(t, host.AllowRequest())
		assert.False(t, host.AllowRequest())

		// IsAvailable should still return true (rate limit is separate check)
		assert.True(t, host.IsAvailable())
	})
}

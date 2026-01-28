//go:build functional
// +build functional

package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestFunctional_BackendRateLimit_Config(t *testing.T) {
	t.Parallel()

	t.Run("backend rate limit config structure", func(t *testing.T) {
		t.Parallel()

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8080},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
			},
		}

		assert.NotNil(t, cfg.RateLimit)
		assert.True(t, cfg.RateLimit.Enabled)
		assert.Equal(t, 100, cfg.RateLimit.RequestsPerSecond)
		assert.Equal(t, 200, cfg.RateLimit.Burst)
	})

	t.Run("backend with rate limit creates rate limited hosts", func(t *testing.T) {
		t.Parallel()

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8080},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				Burst:             5,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		hosts := b.GetHosts()
		require.Len(t, hosts, 1)

		// Host should have rate limiting enabled
		assert.True(t, hosts[0].IsRateLimitEnabled())
	})

	t.Run("disabled rate limit does not limit hosts", func(t *testing.T) {
		t.Parallel()

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8080},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           false,
				RequestsPerSecond: 10,
				Burst:             5,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		hosts := b.GetHosts()
		require.Len(t, hosts, 1)

		// Host should not have rate limiting enabled
		assert.False(t, hosts[0].IsRateLimitEnabled())
	})

	t.Run("nil rate limit config does not limit hosts", func(t *testing.T) {
		t.Parallel()

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8080},
			},
			// RateLimit is nil
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		hosts := b.GetHosts()
		require.Len(t, hosts, 1)

		// Host should not have rate limiting enabled
		assert.False(t, hosts[0].IsRateLimitEnabled())
	})
}

func TestFunctional_BackendRateLimit_Validation(t *testing.T) {
	t.Parallel()

	t.Run("valid rate limit config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
		}

		assert.True(t, cfg.Enabled)
		assert.Equal(t, 100, cfg.RequestsPerSecond)
		assert.Equal(t, 200, cfg.Burst)
	})

	t.Run("burst defaults to RPS when zero", func(t *testing.T) {
		t.Parallel()

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8080},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 50,
				Burst:             0, // Should default to RPS
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		hosts := b.GetHosts()
		require.Len(t, hosts, 1)
		assert.True(t, hosts[0].IsRateLimitEnabled())
	})

	t.Run("rate limit with per client flag", func(t *testing.T) {
		t.Parallel()

		cfg := &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
			PerClient:         true,
		}

		assert.True(t, cfg.PerClient)
	})
}

func TestFunctional_BackendRateLimit_HostBehavior(t *testing.T) {
	t.Parallel()

	t.Run("host rate limiter allows burst requests", func(t *testing.T) {
		t.Parallel()

		host := backend.NewHost("127.0.0.1", 8080, 1)
		host.SetRateLimiter(10, 5) // 10 RPS, burst of 5

		assert.True(t, host.IsRateLimitEnabled())

		// Should allow burst requests
		for i := 0; i < 5; i++ {
			assert.True(t, host.AllowRequest(), "request %d should be allowed", i)
		}

		// Next request should be denied (burst exhausted)
		assert.False(t, host.AllowRequest())
	})

	t.Run("host rate limiter replenishes tokens", func(t *testing.T) {
		t.Parallel()

		host := backend.NewHost("127.0.0.1", 8080, 1)
		host.SetRateLimiter(10, 2) // 10 RPS, burst of 2

		// Exhaust burst
		assert.True(t, host.AllowRequest())
		assert.True(t, host.AllowRequest())
		assert.False(t, host.AllowRequest())

		// Wait for token replenishment (100ms = 1 token at 10 RPS)
		time.Sleep(150 * time.Millisecond)

		// Should allow another request
		assert.True(t, host.AllowRequest())
	})

	t.Run("host without rate limiter allows all requests", func(t *testing.T) {
		t.Parallel()

		host := backend.NewHost("127.0.0.1", 8080, 1)

		assert.False(t, host.IsRateLimitEnabled())

		// All requests should be allowed
		for i := 0; i < 100; i++ {
			assert.True(t, host.AllowRequest())
		}
	})
}

func TestFunctional_BackendRateLimit_MultipleHosts(t *testing.T) {
	t.Parallel()

	t.Run("each host has independent rate limiter", func(t *testing.T) {
		t.Parallel()

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8080},
				{Address: "127.0.0.1", Port: 8081},
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				Burst:             2,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		hosts := b.GetHosts()
		require.Len(t, hosts, 2)

		// Both hosts should have rate limiting enabled
		assert.True(t, hosts[0].IsRateLimitEnabled())
		assert.True(t, hosts[1].IsRateLimitEnabled())

		// Exhaust first host's burst
		assert.True(t, hosts[0].AllowRequest())
		assert.True(t, hosts[0].AllowRequest())
		assert.False(t, hosts[0].AllowRequest())

		// Second host should still have its burst available
		assert.True(t, hosts[1].AllowRequest())
		assert.True(t, hosts[1].AllowRequest())
		assert.False(t, hosts[1].AllowRequest())
	})
}

func TestFunctional_BackendRateLimit_CombinedWithMaxSessions(t *testing.T) {
	t.Parallel()

	t.Run("backend with both rate limit and max sessions", func(t *testing.T) {
		t.Parallel()

		cfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8080},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 10,
			},
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             50,
			},
		}

		b, err := backend.NewBackend(cfg)
		require.NoError(t, err)

		hosts := b.GetHosts()
		require.Len(t, hosts, 1)

		// Both features should be enabled
		assert.True(t, hosts[0].IsMaxSessionsEnabled())
		assert.True(t, hosts[0].IsRateLimitEnabled())
		assert.Equal(t, 10, hosts[0].MaxSessions())
	})

	t.Run("host availability considers both constraints", func(t *testing.T) {
		t.Parallel()

		host := backend.NewHost("127.0.0.1", 8080, 1)
		host.SetStatus(backend.StatusHealthy)
		host.SetMaxSessions(2)
		host.SetRateLimiter(10, 2)

		// Initially available
		assert.True(t, host.IsAvailable())

		// Add connections up to max
		host.IncrementConnections()
		host.IncrementConnections()

		// Should not be available (at max sessions)
		assert.False(t, host.IsAvailable())

		// Release one connection
		host.DecrementConnections()

		// Should be available again
		assert.True(t, host.IsAvailable())
	})
}

func TestFunctional_BackendRateLimit_HostRateLimiter(t *testing.T) {
	t.Parallel()

	t.Run("new host rate limiter initialization", func(t *testing.T) {
		t.Parallel()

		rl := backend.NewHostRateLimiter(100, 50)
		require.NotNil(t, rl)

		// Should allow burst requests
		for i := 0; i < 50; i++ {
			assert.True(t, rl.Allow(), "request %d should be allowed", i)
		}

		// Next request should be denied
		assert.False(t, rl.Allow())
	})

	t.Run("rate limiter with high RPS", func(t *testing.T) {
		t.Parallel()

		rl := backend.NewHostRateLimiter(1000, 100)
		require.NotNil(t, rl)

		// Should allow burst
		for i := 0; i < 100; i++ {
			assert.True(t, rl.Allow())
		}

		// Should be rate limited
		assert.False(t, rl.Allow())

		// Wait for replenishment
		time.Sleep(10 * time.Millisecond) // Should get ~10 tokens at 1000 RPS

		// Should allow some more requests
		allowed := 0
		for i := 0; i < 20; i++ {
			if rl.Allow() {
				allowed++
			}
		}
		assert.Greater(t, allowed, 0)
	})
}

func TestFunctional_BackendRateLimit_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("zero RPS does not enable rate limiting", func(t *testing.T) {
		t.Parallel()

		host := backend.NewHost("127.0.0.1", 8080, 1)
		host.SetRateLimiter(0, 10) // Zero RPS

		// Rate limiting should not be enabled
		assert.False(t, host.IsRateLimitEnabled())
	})

	t.Run("negative values handled gracefully", func(t *testing.T) {
		t.Parallel()

		host := backend.NewHost("127.0.0.1", 8080, 1)
		host.SetRateLimiter(-1, -1) // Negative values

		// Rate limiting should not be enabled
		assert.False(t, host.IsRateLimitEnabled())
	})
}

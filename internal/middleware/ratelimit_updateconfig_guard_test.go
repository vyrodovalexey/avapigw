// UpdateConfig guard tests: hot-reload paths must reject invalid rate
// limiting parameters (rps < 1 or burst < 1) instead of applying a
// configuration that turns the token bucket into a permanent silent deny.
package middleware

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestValidRateLimitParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rps   int
		burst int
		want  bool
	}{
		{name: "valid minimal", rps: 1, burst: 1, want: true},
		{name: "valid typical", rps: 100, burst: 200, want: true},
		{name: "zero burst", rps: 100, burst: 0, want: false},
		{name: "negative burst", rps: 100, burst: -1, want: false},
		{name: "zero rps", rps: 0, burst: 10, want: false},
		{name: "negative rps", rps: -1, burst: 10, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := validRateLimitParams(&config.RateLimitConfig{
				RequestsPerSecond: tt.rps,
				Burst:             tt.burst,
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRateLimiter_UpdateConfig_RejectsInvalidParams(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(10, 5, false, WithRateLimiterLogger(observability.NopLogger()))
	defer rl.Stop()

	invalidConfigs := []*config.RateLimitConfig{
		{Enabled: true, RequestsPerSecond: 100, Burst: 0},
		{Enabled: true, RequestsPerSecond: 0, Burst: 10},
		{Enabled: true, RequestsPerSecond: -1, Burst: -1},
	}

	for _, cfg := range invalidConfigs {
		rl.UpdateConfig(cfg)

		rl.mu.RLock()
		rps, burst := rl.rps, rl.burst
		rl.mu.RUnlock()

		assert.Equal(t, 10, rps, "invalid update must not change rps")
		assert.Equal(t, 5, burst, "invalid update must not change burst")
	}

	// The limiter keeps working with the previous parameters.
	assert.True(t, rl.Allow("10.0.0.1"), "limiter must keep previous working config")

	// A valid update still applies.
	rl.UpdateConfig(&config.RateLimitConfig{Enabled: true, RequestsPerSecond: 20, Burst: 40})
	rl.mu.RLock()
	rps, burst := rl.rps, rl.burst
	rl.mu.RUnlock()
	assert.Equal(t, 20, rps)
	assert.Equal(t, 40, burst)
}

func TestRedisRateLimiter_UpdateConfig_RejectsInvalidParams(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             5,
		Store:             config.RateLimitStoreRedis,
		Redis:             &config.RateLimitRedisConfig{URL: "redis://" + mr.Addr()},
	}

	rl, err := NewRedisRateLimiter(
		context.Background(), cfg, "guard-test", observability.NopLogger(),
		WithRedisRateLimiterClient(client),
	)
	require.NoError(t, err)
	t.Cleanup(rl.Stop)

	// Reject zero burst: with the redis store a zero-capacity Lua bucket
	// would permanently deny every request.
	rl.UpdateConfig(&config.RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 0})

	rl.mu.RLock()
	rps, burst := rl.rps, rl.burst
	rl.mu.RUnlock()
	assert.Equal(t, 10, rps, "invalid update must not change rps")
	assert.Equal(t, 5, burst, "invalid update must not change burst")

	// Requests are still admitted with the previous valid parameters —
	// not silently denied.
	assert.True(t, rl.Allow(context.Background(), "10.0.0.2"),
		"limiter must keep admitting requests after a rejected update")

	// Reject zero rps as well.
	rl.UpdateConfig(&config.RateLimitConfig{Enabled: true, RequestsPerSecond: 0, Burst: 10})
	rl.mu.RLock()
	rps, burst = rl.rps, rl.burst
	rl.mu.RUnlock()
	assert.Equal(t, 10, rps)
	assert.Equal(t, 5, burst)

	// A valid update still applies.
	rl.UpdateConfig(&config.RateLimitConfig{
		Enabled: true, RequestsPerSecond: 25, Burst: 50, PerClient: true,
	})
	rl.mu.RLock()
	rps, burst, perClient := rl.rps, rl.burst, rl.perClient
	rl.mu.RUnlock()
	assert.Equal(t, 25, rps)
	assert.Equal(t, 50, burst)
	assert.True(t, perClient)
}

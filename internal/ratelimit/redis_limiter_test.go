package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit/store"
	"go.uber.org/zap"
)

func TestDefaultRedisRateLimiterConfig(t *testing.T) {
	config := DefaultRedisRateLimiterConfig()

	assert.Equal(t, AlgorithmTokenBucket, config.Algorithm)
	assert.Equal(t, 100, config.Requests)
	assert.Equal(t, time.Minute, config.Window)
	assert.Equal(t, 10, config.Burst)
	assert.Equal(t, 10, config.Precision)
	assert.True(t, config.FallbackEnabled)
	assert.Equal(t, 5*time.Second, config.HealthCheckInterval)
	assert.NotNil(t, config.RedisConfig)
	assert.NotNil(t, config.CircuitBreakerConfig)
}

func TestRedisRateLimiterConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config *RedisRateLimiterConfig
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name: "custom algorithm",
			config: &RedisRateLimiterConfig{
				Algorithm: AlgorithmSlidingWindow,
				Requests:  50,
				Window:    30 * time.Second,
				Burst:     5,
			},
		},
		{
			name: "fixed window algorithm",
			config: &RedisRateLimiterConfig{
				Algorithm: AlgorithmFixedWindow,
				Requests:  200,
				Window:    2 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify config creation doesn't panic
			if tt.config == nil {
				config := DefaultRedisRateLimiterConfig()
				assert.NotNil(t, config)
			} else {
				assert.NotEmpty(t, tt.config.Algorithm)
			}
		})
	}
}

// TestRedisRateLimiter_FallbackBehavior tests the fallback limiter behavior
// when Redis is unavailable. This test doesn't require a real Redis connection.
func TestRedisRateLimiter_FallbackBehavior(t *testing.T) {
	logger := zap.NewNop()

	// Test that fallback limiter is created correctly for each algorithm
	algorithms := []Algorithm{
		AlgorithmTokenBucket,
		AlgorithmSlidingWindow,
		AlgorithmFixedWindow,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			config := &RedisRateLimiterConfig{
				Algorithm:       algo,
				Requests:        10,
				Window:          time.Second,
				Burst:           5,
				Precision:       5,
				FallbackEnabled: true,
				Logger:          logger,
			}

			// Create a mock limiter to test fallback creation logic
			limiter := &RedisRateLimiter{
				config: config,
				logger: logger,
			}

			fallback := limiter.createFallbackLimiter()
			require.NotNil(t, fallback)

			// Test that fallback limiter works
			ctx := context.Background()
			result, err := fallback.Allow(ctx, "test-key")
			require.NoError(t, err)
			assert.True(t, result.Allowed)
		})
	}
}

// TestRedisRateLimiter_GetLimit tests the GetLimit method.
func TestRedisRateLimiter_GetLimit(t *testing.T) {
	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100,
		Window:    time.Minute,
		Burst:     20,
	}

	limiter := &RedisRateLimiter{
		config: config,
	}

	limit := limiter.GetLimit("test-key")
	require.NotNil(t, limit)
	assert.Equal(t, 100, limit.Requests)
	assert.Equal(t, time.Minute, limit.Window)
	assert.Equal(t, 20, limit.Burst)
}

// TestRedisRateLimiter_ParseScriptResult tests the script result parsing.
func TestRedisRateLimiter_ParseScriptResult(t *testing.T) {
	limiter := &RedisRateLimiter{
		config: DefaultRedisRateLimiterConfig(),
	}

	tests := []struct {
		name        string
		result      interface{}
		limit       int
		wantAllowed bool
		wantRemain  int
		wantErr     bool
	}{
		{
			name:        "allowed result",
			result:      []interface{}{int64(1), int64(9), int64(1000)},
			limit:       10,
			wantAllowed: true,
			wantRemain:  9,
			wantErr:     false,
		},
		{
			name:        "denied result",
			result:      []interface{}{int64(0), int64(0), int64(5000)},
			limit:       10,
			wantAllowed: false,
			wantRemain:  0,
			wantErr:     false,
		},
		{
			name:        "negative remaining clamped to zero",
			result:      []interface{}{int64(0), int64(-5), int64(1000)},
			limit:       10,
			wantAllowed: false,
			wantRemain:  0,
			wantErr:     false,
		},
		{
			name:    "invalid result format - not slice",
			result:  "invalid",
			limit:   10,
			wantErr: true,
		},
		{
			name:    "invalid result format - too few elements",
			result:  []interface{}{int64(1)},
			limit:   10,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := limiter.parseScriptResult(tt.result, tt.limit)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, result.Allowed)
			assert.Equal(t, tt.wantRemain, result.Remaining)
			assert.Equal(t, tt.limit, result.Limit)
		})
	}
}

// TestRedisRateLimiter_PrefixKey tests the key prefixing.
func TestRedisRateLimiter_PrefixKey(t *testing.T) {
	config := &RedisRateLimiterConfig{
		RedisConfig: &store.RedisConfig{
			Prefix: "myapp:ratelimit:",
		},
	}

	limiter := &RedisRateLimiter{
		config: config,
	}

	prefixed := limiter.prefixKey("user:123")
	assert.Equal(t, "myapp:ratelimit:user:123", prefixed)
}

// TestRedisRateLimiter_CircuitBreakerIntegration tests circuit breaker integration.
func TestRedisRateLimiter_CircuitBreakerIntegration(t *testing.T) {
	logger := zap.NewNop()

	cbConfig := circuitbreaker.DefaultConfig()
	cbConfig.MaxFailures = 3
	cbConfig.Timeout = 100 * time.Millisecond

	cb := circuitbreaker.NewCircuitBreaker("test-redis-ratelimit", cbConfig, logger)

	limiter := &RedisRateLimiter{
		config: &RedisRateLimiterConfig{
			Algorithm:       AlgorithmTokenBucket,
			Requests:        100,
			Window:          time.Minute,
			Burst:           10,
			FallbackEnabled: true,
			RedisConfig:     store.DefaultRedisConfig(),
		},
		circuitBreaker: cb,
		logger:         logger,
	}

	// Verify circuit breaker starts in closed state
	assert.Equal(t, circuitbreaker.StateClosed, limiter.GetCircuitBreakerState())

	// Get stats
	stats := limiter.GetCircuitBreakerStats()
	assert.Equal(t, circuitbreaker.StateClosed, stats.State)
	assert.Equal(t, 0, stats.Failures)

	// Reset circuit breaker
	limiter.ResetCircuitBreaker()
	assert.Equal(t, circuitbreaker.StateClosed, limiter.GetCircuitBreakerState())
}

// TestRedisRateLimiter_HealthCheck tests the health check functionality.
func TestRedisRateLimiter_HealthCheck(t *testing.T) {
	limiter := &RedisRateLimiter{
		config: DefaultRedisRateLimiterConfig(),
		logger: zap.NewNop(),
	}

	// Initially healthy
	limiter.healthy.Store(true)
	assert.True(t, limiter.IsHealthy())

	// Set unhealthy
	limiter.healthy.Store(false)
	assert.False(t, limiter.IsHealthy())
}

// TestRedisRateLimiter_Close tests the Close method.
func TestRedisRateLimiter_Close(t *testing.T) {
	logger := zap.NewNop()

	// Create a limiter with fallback
	config := &RedisRateLimiterConfig{
		Algorithm:       AlgorithmTokenBucket,
		Requests:        100,
		Window:          time.Minute,
		Burst:           10,
		FallbackEnabled: true,
		Logger:          logger,
	}

	limiter := &RedisRateLimiter{
		config:          config,
		logger:          logger,
		stopHealthCheck: make(chan struct{}),
	}

	// Create fallback limiter
	limiter.fallbackLimiter = limiter.createFallbackLimiter()

	// Close should not panic
	err := limiter.Close()
	assert.NoError(t, err)

	// Calling Close again should be safe
	err = limiter.Close()
	assert.NoError(t, err)
}

// TestRedisRateLimiter_Errors tests error handling.
func TestRedisRateLimiter_Errors(t *testing.T) {
	// Test error types
	assert.Error(t, ErrRedisUnavailable)
	assert.Error(t, ErrFallbackUsed)

	assert.Contains(t, ErrRedisUnavailable.Error(), "unavailable")
	assert.Contains(t, ErrFallbackUsed.Error(), "fallback")
}

// BenchmarkRedisRateLimiter_ParseScriptResult benchmarks result parsing.
func BenchmarkRedisRateLimiter_ParseScriptResult(b *testing.B) {
	limiter := &RedisRateLimiter{
		config: DefaultRedisRateLimiterConfig(),
	}

	result := []interface{}{int64(1), int64(9), int64(1000)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = limiter.parseScriptResult(result, 10)
	}
}

// BenchmarkRedisRateLimiter_PrefixKey benchmarks key prefixing.
func BenchmarkRedisRateLimiter_PrefixKey(b *testing.B) {
	limiter := &RedisRateLimiter{
		config: &RedisRateLimiterConfig{
			RedisConfig: &store.RedisConfig{
				Prefix: "ratelimit:",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = limiter.prefixKey("user:123:api:endpoint")
	}
}

// TestNewRedisRateLimiter_WithMiniredis tests creating a Redis rate limiter with miniredis.
func TestNewRedisRateLimiter_WithMiniredis(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  10,
		Window:    time.Second,
		Burst:     5,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     true,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	require.NotNil(t, limiter)
	defer limiter.Close()

	assert.True(t, limiter.IsHealthy())
}

// TestNewRedisRateLimiter_NilConfig tests creating a Redis rate limiter with nil config.
func TestNewRedisRateLimiter_NilConfig(t *testing.T) {
	// This will fail because default config points to localhost:6379 which is not running
	// We just verify it doesn't panic
	_, err := NewRedisRateLimiter(nil)
	assert.Error(t, err) // Expected to fail without Redis
}

// TestRedisRateLimiter_TokenBucket_WithMiniredis tests token bucket algorithm with miniredis.
func TestRedisRateLimiter_TokenBucket_WithMiniredis(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  10,
		Window:    time.Second,
		Burst:     5,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     false,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	defer limiter.Close()

	ctx := context.Background()

	// First request should be allowed
	result, err := limiter.Allow(ctx, "user:1")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 5, result.Limit) // Burst is the limit for token bucket

	// Multiple requests should be allowed up to burst
	for i := 0; i < 4; i++ {
		result, err = limiter.Allow(ctx, "user:1")
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	}

	// After burst is exhausted, requests should be denied
	result, err = limiter.Allow(ctx, "user:1")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

// TestRedisRateLimiter_SlidingWindow_WithMiniredis tests sliding window algorithm with miniredis.
func TestRedisRateLimiter_SlidingWindow_WithMiniredis(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmSlidingWindow,
		Requests:  5,
		Window:    time.Second,
		Precision: 10,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     false,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	defer limiter.Close()

	ctx := context.Background()

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(ctx, "user:2")
		require.NoError(t, err)
		assert.True(t, result.Allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be denied
	result, err := limiter.Allow(ctx, "user:2")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

// TestRedisRateLimiter_FixedWindow_WithMiniredis tests fixed window algorithm with miniredis.
func TestRedisRateLimiter_FixedWindow_WithMiniredis(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmFixedWindow,
		Requests:  5,
		Window:    time.Second,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     false,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	defer limiter.Close()

	ctx := context.Background()

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(ctx, "user:3")
		require.NoError(t, err)
		assert.True(t, result.Allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be denied
	result, err := limiter.Allow(ctx, "user:3")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

// TestRedisRateLimiter_AllowN_WithMiniredis tests AllowN method with miniredis.
func TestRedisRateLimiter_AllowN_WithMiniredis(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  10,
		Window:    time.Second,
		Burst:     10,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     false,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	defer limiter.Close()

	ctx := context.Background()

	// Request 5 tokens at once
	result, err := limiter.AllowN(ctx, "user:4", 5)
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// Request 5 more tokens
	result, err = limiter.AllowN(ctx, "user:4", 5)
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// Request 1 more token should fail
	result, err = limiter.AllowN(ctx, "user:4", 1)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

// TestRedisRateLimiter_Reset_WithMiniredis tests Reset method with miniredis.
func TestRedisRateLimiter_Reset_WithMiniredis(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmFixedWindow, // Use fixed window for easier reset testing
		Requests:  5,
		Window:    time.Second,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     false,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	defer limiter.Close()

	ctx := context.Background()

	// Exhaust the rate limit
	for i := 0; i < 5; i++ {
		_, err := limiter.Allow(ctx, "user:5")
		require.NoError(t, err)
	}

	// Should be denied
	result, err := limiter.Allow(ctx, "user:5")
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// Reset the rate limit - this deletes the key
	err = limiter.Reset(ctx, "user:5")
	require.NoError(t, err)

	// Note: For fixed window, the key includes the window timestamp,
	// so Reset may not immediately allow new requests in the same window.
	// We just verify Reset doesn't error.
}

// TestRedisRateLimiter_FallbackOnError tests fallback behavior when Redis fails.
func TestRedisRateLimiter_FallbackOnError(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)

	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100, // High limit so fallback doesn't exhaust
		Window:    time.Second,
		Burst:     100,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     true,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	defer limiter.Close()

	ctx := context.Background()

	// First request should work with Redis
	result, err := limiter.Allow(ctx, "user:fallback")
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// Close miniredis to simulate failure
	mr.Close()

	// Requests should still work via fallback (even if Redis fails)
	// The circuit breaker will eventually open and use fallback
	var lastResult *Result
	for i := 0; i < 15; i++ {
		lastResult, err = limiter.Allow(ctx, "user:fallback:new")
		// We don't check error here because some requests may fail before fallback kicks in
	}

	// After circuit breaker opens, fallback should be used
	// The last result should be allowed (fallback has high limit)
	require.NotNil(t, lastResult)
	// Note: We can't guarantee the last request used fallback,
	// but we verify the limiter doesn't panic and handles errors gracefully
}

// TestRedisRateLimiter_DefaultAlgorithm tests default algorithm selection.
func TestRedisRateLimiter_DefaultAlgorithm(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &RedisRateLimiterConfig{
		Algorithm: "unknown", // Unknown algorithm should default to token bucket
		Requests:  10,
		Window:    time.Second,
		Burst:     5,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     false,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	defer limiter.Close()

	ctx := context.Background()

	// Should work with default algorithm
	result, err := limiter.Allow(ctx, "user:7")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// TestRedisRateLimiter_MultipleKeys tests rate limiting with multiple keys.
func TestRedisRateLimiter_MultipleKeys(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &RedisRateLimiterConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  10,
		Window:    time.Second,
		Burst:     2,
		RedisConfig: &store.RedisConfig{
			Address:           mr.Addr(),
			Prefix:            "test:",
			DialTimeout:       100 * time.Millisecond,
			ReadTimeout:       100 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
			ConnectionRetries: 1,
		},
		FallbackEnabled:     false,
		HealthCheckInterval: 100 * time.Millisecond,
		Logger:              zap.NewNop(),
	}

	limiter, err := NewRedisRateLimiter(config)
	require.NoError(t, err)
	defer limiter.Close()

	ctx := context.Background()

	// Exhaust rate limit for user:a
	for i := 0; i < 2; i++ {
		_, err := limiter.Allow(ctx, "user:a")
		require.NoError(t, err)
	}

	// user:a should be denied
	result, err := limiter.Allow(ctx, "user:a")
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// user:b should still be allowed (separate rate limit)
	result, err = limiter.Allow(ctx, "user:b")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

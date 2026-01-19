package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Cases for Algorithm Constants
// ============================================================================

func TestAlgorithmConstants(t *testing.T) {
	assert.Equal(t, Algorithm("token_bucket"), AlgorithmTokenBucket)
	assert.Equal(t, Algorithm("sliding_window"), AlgorithmSlidingWindow)
	assert.Equal(t, Algorithm("fixed_window"), AlgorithmFixedWindow)
}

// ============================================================================
// Test Cases for Limit Struct
// ============================================================================

func TestLimit_Fields(t *testing.T) {
	limit := &Limit{
		Requests: 100,
		Window:   time.Minute,
		Burst:    10,
	}

	assert.Equal(t, 100, limit.Requests)
	assert.Equal(t, time.Minute, limit.Window)
	assert.Equal(t, 10, limit.Burst)
}

func TestLimit_ZeroValues(t *testing.T) {
	limit := &Limit{}

	assert.Equal(t, 0, limit.Requests)
	assert.Equal(t, time.Duration(0), limit.Window)
	assert.Equal(t, 0, limit.Burst)
}

// ============================================================================
// Test Cases for Result Struct
// ============================================================================

func TestResult_Fields(t *testing.T) {
	result := &Result{
		Allowed:    true,
		Limit:      100,
		Remaining:  50,
		ResetAfter: time.Second * 30,
		RetryAfter: time.Duration(0),
	}

	assert.True(t, result.Allowed)
	assert.Equal(t, 100, result.Limit)
	assert.Equal(t, 50, result.Remaining)
	assert.Equal(t, time.Second*30, result.ResetAfter)
	assert.Equal(t, time.Duration(0), result.RetryAfter)
}

func TestResult_Denied(t *testing.T) {
	result := &Result{
		Allowed:    false,
		Limit:      100,
		Remaining:  0,
		ResetAfter: time.Second * 30,
		RetryAfter: time.Second * 30,
	}

	assert.False(t, result.Allowed)
	assert.Equal(t, 0, result.Remaining)
	assert.True(t, result.RetryAfter > 0)
}

// ============================================================================
// Test Cases for Config Struct
// ============================================================================

func TestConfig_Fields(t *testing.T) {
	config := &Config{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100,
		Window:    time.Minute,
		Burst:     10,
		Precision: 20,
	}

	assert.Equal(t, AlgorithmTokenBucket, config.Algorithm)
	assert.Equal(t, 100, config.Requests)
	assert.Equal(t, time.Minute, config.Window)
	assert.Equal(t, 10, config.Burst)
	assert.Equal(t, 20, config.Precision)
}

// ============================================================================
// Test Cases for DefaultConfig
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	require.NotNil(t, config)
	assert.Equal(t, AlgorithmTokenBucket, config.Algorithm)
	assert.Equal(t, 100, config.Requests)
	assert.Equal(t, time.Minute, config.Window)
	assert.Equal(t, 10, config.Burst)
	assert.Equal(t, 10, config.Precision)
}

// ============================================================================
// Test Cases for NoopLimiter
// ============================================================================

func TestNoopLimiter_NewNoopLimiter(t *testing.T) {
	limiter := NewNoopLimiter()
	require.NotNil(t, limiter)
}

func TestNoopLimiter_Allow(t *testing.T) {
	limiter := NewNoopLimiter()
	ctx := context.Background()

	// Should always allow
	for i := 0; i < 100; i++ {
		result, err := limiter.Allow(ctx, "test-key")
		require.NoError(t, err)
		assert.True(t, result.Allowed)
		assert.Equal(t, 0, result.Limit)
		assert.Equal(t, 0, result.Remaining)
		assert.Equal(t, time.Duration(0), result.ResetAfter)
		assert.Equal(t, time.Duration(0), result.RetryAfter)
	}
}

func TestNoopLimiter_AllowN(t *testing.T) {
	limiter := NewNoopLimiter()
	ctx := context.Background()

	tests := []struct {
		name string
		n    int
	}{
		{"single request", 1},
		{"multiple requests", 10},
		{"large number", 1000000},
		{"zero requests", 0},
		{"negative requests", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := limiter.AllowN(ctx, "test-key", tt.n)
			require.NoError(t, err)
			assert.True(t, result.Allowed)
		})
	}
}

func TestNoopLimiter_GetLimit(t *testing.T) {
	limiter := NewNoopLimiter()

	limit := limiter.GetLimit("any-key")
	assert.Nil(t, limit)
}

func TestNoopLimiter_Reset(t *testing.T) {
	limiter := NewNoopLimiter()
	ctx := context.Background()

	err := limiter.Reset(ctx, "test-key")
	require.NoError(t, err)
}

func TestNoopLimiter_DifferentKeys(t *testing.T) {
	limiter := NewNoopLimiter()
	ctx := context.Background()

	keys := []string{"key1", "key2", "key3", "", "special-key!@#$%"}

	for _, key := range keys {
		result, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
		assert.True(t, result.Allowed, "key %q should be allowed", key)
	}
}

func TestNoopLimiter_CancelledContext(t *testing.T) {
	limiter := NewNoopLimiter()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should still work even with cancelled context
	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestNoopLimiter_NilContext(t *testing.T) {
	limiter := NewNoopLimiter()

	// Should work with nil context
	result, err := limiter.Allow(nil, "test-key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// ============================================================================
// Test Cases for Limiter Interface Compliance
// ============================================================================

func TestLimiterInterface_NoopLimiter(t *testing.T) {
	var limiter Limiter = NewNoopLimiter()
	assert.NotNil(t, limiter)

	ctx := context.Background()

	// Test all interface methods
	result, err := limiter.Allow(ctx, "key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	result, err = limiter.AllowN(ctx, "key", 5)
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	limit := limiter.GetLimit("key")
	assert.Nil(t, limit)

	err = limiter.Reset(ctx, "key")
	require.NoError(t, err)
}

func TestLimiterInterface_TokenBucketLimiter(t *testing.T) {
	var limiter Limiter = NewTokenBucketLimiter(nil, 10, 5, nil)
	defer limiter.(*TokenBucketLimiter).Close()

	assert.NotNil(t, limiter)

	ctx := context.Background()

	// Test all interface methods
	result, err := limiter.Allow(ctx, "key")
	require.NoError(t, err)
	assert.NotNil(t, result)

	result, err = limiter.AllowN(ctx, "key", 2)
	require.NoError(t, err)
	assert.NotNil(t, result)

	limit := limiter.GetLimit("key")
	assert.NotNil(t, limit)

	err = limiter.Reset(ctx, "key")
	require.NoError(t, err)
}

func TestLimiterInterface_SlidingWindowLimiter(t *testing.T) {
	var limiter Limiter = NewSlidingWindowLimiter(nil, 10, time.Minute, nil)
	assert.NotNil(t, limiter)

	ctx := context.Background()

	// Test all interface methods
	result, err := limiter.Allow(ctx, "key")
	require.NoError(t, err)
	assert.NotNil(t, result)

	result, err = limiter.AllowN(ctx, "key", 2)
	require.NoError(t, err)
	assert.NotNil(t, result)

	limit := limiter.GetLimit("key")
	assert.NotNil(t, limit)

	err = limiter.Reset(ctx, "key")
	require.NoError(t, err)
}

func TestLimiterInterface_FixedWindowLimiter(t *testing.T) {
	var limiter Limiter = NewFixedWindowLimiter(nil, 10, time.Minute, nil)
	assert.NotNil(t, limiter)

	ctx := context.Background()

	// Test all interface methods
	result, err := limiter.Allow(ctx, "key")
	require.NoError(t, err)
	assert.NotNil(t, result)

	result, err = limiter.AllowN(ctx, "key", 2)
	require.NoError(t, err)
	assert.NotNil(t, result)

	limit := limiter.GetLimit("key")
	assert.NotNil(t, limit)

	err = limiter.Reset(ctx, "key")
	require.NoError(t, err)
}

// ============================================================================
// Test Cases for Result Behavior
// ============================================================================

func TestResult_AllowedBehavior(t *testing.T) {
	tests := []struct {
		name       string
		allowed    bool
		remaining  int
		retryAfter time.Duration
	}{
		{
			name:       "allowed with remaining",
			allowed:    true,
			remaining:  5,
			retryAfter: 0,
		},
		{
			name:       "allowed with zero remaining",
			allowed:    true,
			remaining:  0,
			retryAfter: 0,
		},
		{
			name:       "denied with retry",
			allowed:    false,
			remaining:  0,
			retryAfter: time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{
				Allowed:    tt.allowed,
				Remaining:  tt.remaining,
				RetryAfter: tt.retryAfter,
			}

			if tt.allowed {
				assert.True(t, result.Allowed)
				assert.Equal(t, time.Duration(0), result.RetryAfter)
			} else {
				assert.False(t, result.Allowed)
				assert.True(t, result.RetryAfter > 0)
			}
		})
	}
}

// ============================================================================
// Test Cases for Config Validation
// ============================================================================

func TestConfig_DifferentAlgorithms(t *testing.T) {
	algorithms := []Algorithm{
		AlgorithmTokenBucket,
		AlgorithmSlidingWindow,
		AlgorithmFixedWindow,
	}

	for _, algo := range algorithms {
		config := &Config{
			Algorithm: algo,
			Requests:  100,
			Window:    time.Minute,
			Burst:     10,
			Precision: 10,
		}

		assert.Equal(t, algo, config.Algorithm)
	}
}

func TestConfig_EdgeValues(t *testing.T) {
	tests := []struct {
		name      string
		requests  int
		window    time.Duration
		burst     int
		precision int
	}{
		{
			name:      "zero values",
			requests:  0,
			window:    0,
			burst:     0,
			precision: 0,
		},
		{
			name:      "large values",
			requests:  1000000,
			window:    24 * time.Hour,
			burst:     10000,
			precision: 100,
		},
		{
			name:      "negative values",
			requests:  -1,
			window:    -time.Second,
			burst:     -1,
			precision: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Algorithm: AlgorithmTokenBucket,
				Requests:  tt.requests,
				Window:    tt.window,
				Burst:     tt.burst,
				Precision: tt.precision,
			}

			assert.Equal(t, tt.requests, config.Requests)
			assert.Equal(t, tt.window, config.Window)
			assert.Equal(t, tt.burst, config.Burst)
			assert.Equal(t, tt.precision, config.Precision)
		})
	}
}

// ============================================================================
// Test Cases for Limit Struct Usage
// ============================================================================

func TestLimit_Usage(t *testing.T) {
	// Test that Limit struct can be used to configure limiters
	limit := &Limit{
		Requests: 100,
		Window:   time.Minute,
		Burst:    10,
	}

	// Create a limiter using the limit values
	limiter := NewTokenBucketLimiter(nil, float64(limit.Requests)/limit.Window.Seconds(), limit.Burst, nil)
	defer limiter.Close()

	ctx := context.Background()

	// Verify the limiter respects the burst limit
	for i := 0; i < limit.Burst; i++ {
		result, err := limiter.Allow(ctx, "test-key")
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	}

	// Next request should be denied (burst exhausted)
	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

// ============================================================================
// Test Cases for Algorithm String Conversion
// ============================================================================

func TestAlgorithm_StringConversion(t *testing.T) {
	tests := []struct {
		algorithm Algorithm
		expected  string
	}{
		{AlgorithmTokenBucket, "token_bucket"},
		{AlgorithmSlidingWindow, "sliding_window"},
		{AlgorithmFixedWindow, "fixed_window"},
		{Algorithm("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.algorithm))
		})
	}
}

func TestAlgorithm_FromString(t *testing.T) {
	tests := []struct {
		input    string
		expected Algorithm
	}{
		{"token_bucket", AlgorithmTokenBucket},
		{"sliding_window", AlgorithmSlidingWindow},
		{"fixed_window", AlgorithmFixedWindow},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			algo := Algorithm(tt.input)
			assert.Equal(t, tt.expected, algo)
		})
	}
}

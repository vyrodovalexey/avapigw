package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Test Cases for DefaultFactoryConfig
// ============================================================================

func TestDefaultFactoryConfig(t *testing.T) {
	config := DefaultFactoryConfig()

	require.NotNil(t, config)
	assert.Equal(t, AlgorithmTokenBucket, config.Algorithm)
	assert.Equal(t, 100, config.Requests)
	assert.Equal(t, time.Minute, config.Window)
	assert.Equal(t, 10, config.Burst)
	assert.Equal(t, 10, config.Precision)
	assert.Equal(t, "memory", config.StoreType)
	assert.Equal(t, "ratelimit:", config.RedisPrefix)
	assert.True(t, config.FallbackEnabled)
	assert.Equal(t, 5*time.Second, config.HealthCheckInterval)
}

// ============================================================================
// Test Cases for NewLimiter - Different Algorithms
// ============================================================================

func TestNewLimiter_TokenBucket(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100,
		Window:    time.Minute,
		Burst:     10,
		StoreType: "memory",
		Logger:    zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	// Verify it's a token bucket limiter by checking behavior
	_, ok := limiter.(*TokenBucketLimiter)
	assert.True(t, ok, "expected TokenBucketLimiter")

	// Clean up
	if closer, ok := limiter.(*TokenBucketLimiter); ok {
		closer.Close()
	}
}

func TestNewLimiter_SlidingWindow(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: AlgorithmSlidingWindow,
		Requests:  100,
		Window:    time.Minute,
		Precision: 20,
		StoreType: "memory",
		Logger:    zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	_, ok := limiter.(*SlidingWindowLimiter)
	assert.True(t, ok, "expected SlidingWindowLimiter")
}

func TestNewLimiter_FixedWindow(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: AlgorithmFixedWindow,
		Requests:  100,
		Window:    time.Minute,
		StoreType: "memory",
		Logger:    zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	_, ok := limiter.(*FixedWindowLimiter)
	assert.True(t, ok, "expected FixedWindowLimiter")
}

func TestNewLimiter_DefaultAlgorithm(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: "", // Empty should default to token bucket
		Requests:  100,
		Window:    time.Minute,
		Burst:     10,
		StoreType: "memory",
		Logger:    zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	_, ok := limiter.(*TokenBucketLimiter)
	assert.True(t, ok, "expected TokenBucketLimiter for empty algorithm")

	// Clean up
	if closer, ok := limiter.(*TokenBucketLimiter); ok {
		closer.Close()
	}
}

func TestNewLimiter_UnknownAlgorithm(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: "unknown_algorithm",
		Requests:  100,
		Window:    time.Minute,
		StoreType: "memory",
		Logger:    zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	assert.Error(t, err)
	assert.Nil(t, limiter)
	assert.Contains(t, err.Error(), "unknown algorithm")
}

// ============================================================================
// Test Cases for NewLimiter - Store Types
// ============================================================================

func TestNewLimiter_MemoryStore(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100,
		Window:    time.Minute,
		Burst:     10,
		StoreType: "memory",
		Logger:    zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	// Clean up
	if closer, ok := limiter.(*TokenBucketLimiter); ok {
		closer.Close()
	}
}

func TestNewLimiter_EmptyStoreType(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100,
		Window:    time.Minute,
		Burst:     10,
		StoreType: "", // Empty should default to memory
		Logger:    zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	// Clean up
	if closer, ok := limiter.(*TokenBucketLimiter); ok {
		closer.Close()
	}
}

func TestNewLimiter_UnknownStoreType(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100,
		Window:    time.Minute,
		Burst:     10,
		StoreType: "unknown_store",
		Logger:    zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	assert.Error(t, err)
	assert.Nil(t, limiter)
	assert.Contains(t, err.Error(), "unknown store type")
}

func TestNewLimiter_RedisStore_InvalidAddress(t *testing.T) {
	config := &FactoryConfig{
		Algorithm:    AlgorithmTokenBucket,
		Requests:     100,
		Window:       time.Minute,
		Burst:        10,
		StoreType:    "redis",
		RedisAddress: "", // Invalid address
		Logger:       zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	assert.Error(t, err)
	assert.Nil(t, limiter)
	assert.Contains(t, err.Error(), "failed to create Redis store")
}

// ============================================================================
// Test Cases for NewLimiter - Nil Config
// ============================================================================

func TestNewLimiter_NilConfig(t *testing.T) {
	limiter, err := NewLimiter(nil)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	// Should use default config (token bucket)
	_, ok := limiter.(*TokenBucketLimiter)
	assert.True(t, ok, "expected TokenBucketLimiter for nil config")

	// Clean up
	if closer, ok := limiter.(*TokenBucketLimiter); ok {
		closer.Close()
	}
}

// ============================================================================
// Test Cases for NewLimiterFromEnv
// ============================================================================

func TestNewLimiterFromEnv_TokenBucket(t *testing.T) {
	limiter, err := NewLimiterFromEnv(
		"token_bucket",
		100,
		time.Minute,
		10,
		"memory",
		"",
		"",
		0,
		zap.NewNop(),
	)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	_, ok := limiter.(*TokenBucketLimiter)
	assert.True(t, ok)

	// Clean up
	if closer, ok := limiter.(*TokenBucketLimiter); ok {
		closer.Close()
	}
}

func TestNewLimiterFromEnv_SlidingWindow(t *testing.T) {
	limiter, err := NewLimiterFromEnv(
		"sliding_window",
		100,
		time.Minute,
		10,
		"memory",
		"",
		"",
		0,
		zap.NewNop(),
	)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	_, ok := limiter.(*SlidingWindowLimiter)
	assert.True(t, ok)
}

func TestNewLimiterFromEnv_FixedWindow(t *testing.T) {
	limiter, err := NewLimiterFromEnv(
		"fixed_window",
		100,
		time.Minute,
		10,
		"memory",
		"",
		"",
		0,
		zap.NewNop(),
	)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	_, ok := limiter.(*FixedWindowLimiter)
	assert.True(t, ok)
}

func TestNewLimiterFromEnv_InvalidAlgorithm(t *testing.T) {
	limiter, err := NewLimiterFromEnv(
		"invalid",
		100,
		time.Minute,
		10,
		"memory",
		"",
		"",
		0,
		zap.NewNop(),
	)
	assert.Error(t, err)
	assert.Nil(t, limiter)
}

// ============================================================================
// Test Cases for MustNewLimiter
// ============================================================================

func TestMustNewLimiter_Success(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: AlgorithmTokenBucket,
		Requests:  100,
		Window:    time.Minute,
		Burst:     10,
		StoreType: "memory",
		Logger:    zap.NewNop(),
	}

	assert.NotPanics(t, func() {
		limiter := MustNewLimiter(config)
		require.NotNil(t, limiter)

		// Clean up
		if closer, ok := limiter.(*TokenBucketLimiter); ok {
			closer.Close()
		}
	})
}

func TestMustNewLimiter_Panic(t *testing.T) {
	config := &FactoryConfig{
		Algorithm: "invalid_algorithm",
		Requests:  100,
		Window:    time.Minute,
		StoreType: "memory",
		Logger:    zap.NewNop(),
	}

	assert.Panics(t, func() {
		MustNewLimiter(config)
	})
}

func TestMustNewLimiter_NilConfig(t *testing.T) {
	assert.NotPanics(t, func() {
		limiter := MustNewLimiter(nil)
		require.NotNil(t, limiter)

		// Clean up
		if closer, ok := limiter.(*TokenBucketLimiter); ok {
			closer.Close()
		}
	})
}

// ============================================================================
// Test Cases for Configuration Validation
// ============================================================================

func TestNewLimiter_ConfigurationValues(t *testing.T) {
	tests := []struct {
		name      string
		config    *FactoryConfig
		expectErr bool
	}{
		{
			name: "valid config",
			config: &FactoryConfig{
				Algorithm: AlgorithmTokenBucket,
				Requests:  100,
				Window:    time.Minute,
				Burst:     10,
				StoreType: "memory",
			},
			expectErr: false,
		},
		{
			name: "zero requests",
			config: &FactoryConfig{
				Algorithm: AlgorithmTokenBucket,
				Requests:  0,
				Window:    time.Minute,
				Burst:     10,
				StoreType: "memory",
			},
			expectErr: false, // Zero is valid (will deny all)
		},
		{
			name: "zero window",
			config: &FactoryConfig{
				Algorithm: AlgorithmTokenBucket,
				Requests:  100,
				Window:    0,
				Burst:     10,
				StoreType: "memory",
			},
			expectErr: false, // Zero window is handled
		},
		{
			name: "zero burst",
			config: &FactoryConfig{
				Algorithm: AlgorithmTokenBucket,
				Requests:  100,
				Window:    time.Minute,
				Burst:     0,
				StoreType: "memory",
			},
			expectErr: false, // Zero burst is valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter, err := NewLimiter(tt.config)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, limiter)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, limiter)

				// Clean up
				if closer, ok := limiter.(*TokenBucketLimiter); ok {
					closer.Close()
				}
			}
		})
	}
}

// ============================================================================
// Test Cases for Limiter Functionality After Creation
// ============================================================================

func TestNewLimiter_FunctionalityAfterCreation(t *testing.T) {
	tests := []struct {
		name      string
		algorithm Algorithm
	}{
		{
			name:      "token bucket functionality",
			algorithm: AlgorithmTokenBucket,
		},
		{
			name:      "sliding window functionality",
			algorithm: AlgorithmSlidingWindow,
		},
		{
			name:      "fixed window functionality",
			algorithm: AlgorithmFixedWindow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &FactoryConfig{
				Algorithm: tt.algorithm,
				Requests:  5,
				Window:    time.Minute,
				Burst:     5,
				Precision: 10,
				StoreType: "memory",
				Logger:    zap.NewNop(),
			}

			limiter, err := NewLimiter(config)
			require.NoError(t, err)
			require.NotNil(t, limiter)

			// Clean up token bucket limiter
			defer func() {
				if closer, ok := limiter.(*TokenBucketLimiter); ok {
					closer.Close()
				}
			}()

			// Test Allow
			ctx := context.Background()
			result, err := limiter.Allow(ctx, "test-key")
			require.NoError(t, err)
			assert.True(t, result.Allowed)

			// Test GetLimit
			limit := limiter.GetLimit("test-key")
			assert.NotNil(t, limit)

			// Test Reset
			err = limiter.Reset(ctx, "test-key")
			require.NoError(t, err)
		})
	}
}

// ============================================================================
// Test Cases for Redis Distributed Limiter
// ============================================================================

func TestNewLimiter_RedisDistributed_InvalidConfig(t *testing.T) {
	config := &FactoryConfig{
		Algorithm:    AlgorithmTokenBucket,
		Requests:     100,
		Window:       time.Minute,
		Burst:        10,
		StoreType:    "redis_distributed",
		RedisAddress: "", // Invalid address
		Logger:       zap.NewNop(),
	}

	limiter, err := NewLimiter(config)
	assert.Error(t, err)
	assert.Nil(t, limiter)
}

// ============================================================================
// Test Cases for Factory Config Fields
// ============================================================================

func TestFactoryConfig_AllFields(t *testing.T) {
	config := &FactoryConfig{
		Algorithm:           AlgorithmSlidingWindow,
		Requests:            200,
		Window:              2 * time.Minute,
		Burst:               20,
		Precision:           15,
		StoreType:           "memory",
		RedisAddress:        "localhost:6379",
		RedisPassword:       "secret",
		RedisDB:             1,
		RedisPrefix:         "custom:",
		FallbackEnabled:     true,
		HealthCheckInterval: 10 * time.Second,
		Logger:              zap.NewNop(),
	}

	assert.Equal(t, AlgorithmSlidingWindow, config.Algorithm)
	assert.Equal(t, 200, config.Requests)
	assert.Equal(t, 2*time.Minute, config.Window)
	assert.Equal(t, 20, config.Burst)
	assert.Equal(t, 15, config.Precision)
	assert.Equal(t, "memory", config.StoreType)
	assert.Equal(t, "localhost:6379", config.RedisAddress)
	assert.Equal(t, "secret", config.RedisPassword)
	assert.Equal(t, 1, config.RedisDB)
	assert.Equal(t, "custom:", config.RedisPrefix)
	assert.True(t, config.FallbackEnabled)
	assert.Equal(t, 10*time.Second, config.HealthCheckInterval)
	assert.NotNil(t, config.Logger)
}

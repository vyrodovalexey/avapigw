package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestRedisStore_Get_ContextCancelled tests that Get returns immediately
// when the context is cancelled before the operation starts.
func TestRedisStore_Get_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Create a mock store that checks context before operation
	// Since we can't easily mock Redis without a running instance,
	// we test the context check behavior directly
	store := &RedisStore{
		prefix: "test:",
	}

	_, err := store.Get(ctx, "test-key")

	// Should return context error
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got %v", err)
}

// TestRedisStore_Set_ContextCancelled tests that Set returns immediately
// when the context is cancelled before the operation starts.
func TestRedisStore_Set_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	store := &RedisStore{
		prefix: "test:",
	}

	err := store.Set(ctx, "test-key", 100, time.Minute)

	// Should return context error
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got %v", err)
}

// TestRedisStore_Increment_ContextCancelled tests that Increment returns immediately
// when the context is cancelled before the operation starts.
func TestRedisStore_Increment_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	store := &RedisStore{
		prefix: "test:",
	}

	_, err := store.Increment(ctx, "test-key", 1)

	// Should return context error
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got %v", err)
}

// TestRedisStore_IncrementWithExpiry_ContextCancelled tests that IncrementWithExpiry
// returns immediately when the context is cancelled before the operation starts.
func TestRedisStore_IncrementWithExpiry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	store := &RedisStore{
		prefix: "test:",
	}

	_, err := store.IncrementWithExpiry(ctx, "test-key", 1, time.Minute)

	// Should return context error
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got %v", err)
}

// TestRedisStore_Delete_ContextCancelled tests that Delete returns immediately
// when the context is cancelled before the operation starts.
func TestRedisStore_Delete_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	store := &RedisStore{
		prefix: "test:",
	}

	err := store.Delete(ctx, "test-key")

	// Should return context error
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got %v", err)
}

// TestRedisStore_Get_ContextDeadlineExceeded tests that Get returns immediately
// when the context deadline is exceeded before the operation starts.
func TestRedisStore_Get_ContextDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	// Wait for deadline to pass
	time.Sleep(time.Millisecond)

	store := &RedisStore{
		prefix: "test:",
	}

	_, err := store.Get(ctx, "test-key")

	// Should return context error
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "expected context.DeadlineExceeded, got %v", err)
}

// TestRedisStore_PrefixKey tests that prefixKey correctly adds the prefix to keys.
func TestRedisStore_PrefixKey(t *testing.T) {
	store := &RedisStore{
		prefix: "ratelimit:",
	}

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "simple key",
			key:      "test",
			expected: "ratelimit:test",
		},
		{
			name:     "key with path",
			key:      "user/123/requests",
			expected: "ratelimit:user/123/requests",
		},
		{
			name:     "empty key",
			key:      "",
			expected: "ratelimit:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.prefixKey(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDefaultRedisConfig tests that DefaultRedisConfig returns sensible defaults.
func TestDefaultRedisConfig(t *testing.T) {
	config := DefaultRedisConfig()

	assert.Equal(t, "localhost:6379", config.Address)
	assert.Equal(t, "", config.Password)
	assert.Equal(t, 0, config.DB)
	assert.Equal(t, "ratelimit:", config.Prefix)
	assert.Equal(t, 10, config.PoolSize)
	assert.Equal(t, 2, config.MinIdleConns)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 5*time.Second, config.DialTimeout)
	assert.Equal(t, 3*time.Second, config.ReadTimeout)
	assert.Equal(t, 3*time.Second, config.WriteTimeout)
	assert.Equal(t, 100*time.Millisecond, config.InitialBackoff)
	assert.Equal(t, 10*time.Second, config.MaxBackoff)
	assert.Equal(t, 5, config.ConnectionRetries)
}

// TestDecorrelatedJitterBackoff_Next tests the backoff calculation.
func TestDecorrelatedJitterBackoff_Next(t *testing.T) {
	backoff := newDecorrelatedJitterBackoff(100*time.Millisecond, 10*time.Second)

	// First attempt should return initial backoff
	first := backoff.next(0)
	assert.Equal(t, 100*time.Millisecond, first)

	// Subsequent attempts should increase (with jitter)
	// We can't test exact values due to jitter, but we can verify bounds
	for i := 1; i < 10; i++ {
		next := backoff.next(i)
		assert.LessOrEqual(t, next, 10*time.Second, "backoff should not exceed max")
		assert.GreaterOrEqual(t, next, 100*time.Millisecond, "backoff should not be less than initial")
	}
}

// TestDecorrelatedJitterBackoff_MaxCap tests that backoff is capped at max.
func TestDecorrelatedJitterBackoff_MaxCap(t *testing.T) {
	backoff := newDecorrelatedJitterBackoff(1*time.Second, 5*time.Second)

	// After many iterations, should be capped at max
	for i := 0; i < 100; i++ {
		backoff.next(i)
	}

	// Final value should not exceed max
	final := backoff.next(100)
	assert.LessOrEqual(t, final, 5*time.Second)
}

// ============================================================================
// Tests using miniredis for full Redis store functionality
// ============================================================================

// TestNewRedisStore tests the basic constructor.
func TestNewRedisStore(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	assert.Equal(t, "test:", store.prefix)
	assert.NotNil(t, store.client)
}

// TestNewRedisStore_DefaultPrefix tests that empty prefix uses default.
func TestNewRedisStore_DefaultPrefix(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "")
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	// Empty prefix should use default "ratelimit:"
	assert.Equal(t, "ratelimit:", store.prefix)
}

// TestNewRedisStoreWithConfig_NilConfig tests that nil config uses defaults.
func TestNewRedisStoreWithConfig_NilConfig(t *testing.T) {
	mr := miniredis.RunT(t)

	// Create config with miniredis address but pass nil to test default handling
	// We need to actually connect, so we'll test the nil config path differently
	config := DefaultRedisConfig()
	config.Address = mr.Addr()

	store, err := NewRedisStoreWithConfig(config)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()
}

// TestNewRedisStoreWithConfig_CustomConfig tests constructor with custom config.
func TestNewRedisStoreWithConfig_CustomConfig(t *testing.T) {
	mr := miniredis.RunT(t)

	config := &RedisConfig{
		Address:           mr.Addr(),
		Password:          "",
		DB:                0,
		Prefix:            "custom:",
		PoolSize:          5,
		MinIdleConns:      1,
		MaxRetries:        2,
		DialTimeout:       2 * time.Second,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		InitialBackoff:    50 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		ConnectionRetries: 3,
		Logger:            zap.NewNop(),
	}

	store, err := NewRedisStoreWithConfig(config)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	assert.Equal(t, "custom:", store.prefix)
}

// TestNewRedisStoreWithConfig_ZeroBackoffValues tests that zero backoff values use defaults.
func TestNewRedisStoreWithConfig_ZeroBackoffValues(t *testing.T) {
	mr := miniredis.RunT(t)

	config := &RedisConfig{
		Address:           mr.Addr(),
		Password:          "",
		DB:                0,
		Prefix:            "test:",
		PoolSize:          5,
		MinIdleConns:      1,
		MaxRetries:        2,
		DialTimeout:       2 * time.Second,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		InitialBackoff:    0, // Should use default
		MaxBackoff:        0, // Should use default
		ConnectionRetries: 0, // Should use default
	}

	store, err := NewRedisStoreWithConfig(config)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()
}

// TestNewRedisStoreWithConfig_ConnectionFailure tests connection failure after max retries.
func TestNewRedisStoreWithConfig_ConnectionFailure(t *testing.T) {
	config := &RedisConfig{
		Address:           "localhost:59999", // Non-existent port
		Password:          "",
		DB:                0,
		Prefix:            "test:",
		PoolSize:          1,
		MinIdleConns:      0,
		MaxRetries:        1,
		DialTimeout:       100 * time.Millisecond,
		ReadTimeout:       100 * time.Millisecond,
		WriteTimeout:      100 * time.Millisecond,
		InitialBackoff:    10 * time.Millisecond,
		MaxBackoff:        50 * time.Millisecond,
		ConnectionRetries: 1, // Only 1 retry to speed up test
		Logger:            zap.NewNop(),
	}

	store, err := NewRedisStoreWithConfig(config)
	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "failed to connect to Redis")
}

// TestRedisStore_Get_Success tests successful Get operation.
func TestRedisStore_Get_Success(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	// Set up test data directly in miniredis
	mr.Set("test:mykey", "42")

	ctx := context.Background()
	val, err := store.Get(ctx, "mykey")
	require.NoError(t, err)
	assert.Equal(t, int64(42), val)
}

// TestRedisStore_Get_KeyNotFound tests Get with non-existent key.
func TestRedisStore_Get_KeyNotFound(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	_, err = store.Get(ctx, "nonexistent")
	assert.Error(t, err)
	assert.True(t, IsKeyNotFound(err))
}

// TestRedisStore_Get_ParseError tests Get with invalid value.
func TestRedisStore_Get_ParseError(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	// Set a non-numeric value
	mr.Set("test:badkey", "not-a-number")

	ctx := context.Background()
	_, err = store.Get(ctx, "badkey")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse value")
}

// TestRedisStore_Set_Success tests successful Set operation.
func TestRedisStore_Set_Success(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	err = store.Set(ctx, "mykey", 100, time.Minute)
	require.NoError(t, err)

	// Verify the value was set
	val, err := mr.Get("test:mykey")
	require.NoError(t, err)
	assert.Equal(t, "100", val)
}

// TestRedisStore_Set_WithExpiration tests Set with expiration.
func TestRedisStore_Set_WithExpiration(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	err = store.Set(ctx, "mykey", 100, time.Minute)
	require.NoError(t, err)

	// Check TTL is set
	ttl := mr.TTL("test:mykey")
	assert.Greater(t, ttl, time.Duration(0))
	assert.LessOrEqual(t, ttl, time.Minute)
}

// TestRedisStore_Increment_Success tests successful Increment operation.
func TestRedisStore_Increment_Success(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Increment non-existent key
	val, err := store.Increment(ctx, "counter", 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), val)

	// Increment again
	val, err = store.Increment(ctx, "counter", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(6), val)
}

// TestRedisStore_Increment_NegativeDelta tests Increment with negative delta.
func TestRedisStore_Increment_NegativeDelta(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Set initial value
	mr.Set("test:counter", "10")

	// Decrement
	val, err := store.Increment(ctx, "counter", -3)
	require.NoError(t, err)
	assert.Equal(t, int64(7), val)
}

// TestRedisStore_IncrementWithExpiry_Success tests successful IncrementWithExpiry.
func TestRedisStore_IncrementWithExpiry_Success(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// First increment should set expiry
	val, err := store.IncrementWithExpiry(ctx, "counter", 1, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), val)

	// Check TTL is set
	ttl := mr.TTL("test:counter")
	assert.Greater(t, ttl, time.Duration(0))

	// Second increment should not change expiry
	val, err = store.IncrementWithExpiry(ctx, "counter", 5, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(6), val)
}

// TestRedisStore_IncrementWithExpiry_ShortExpiration tests with very short expiration.
func TestRedisStore_IncrementWithExpiry_ShortExpiration(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Expiration less than 1 second should be set to 1 second
	val, err := store.IncrementWithExpiry(ctx, "counter", 1, 100*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(1), val)

	// TTL should be at least 1 second
	ttl := mr.TTL("test:counter")
	assert.GreaterOrEqual(t, ttl, time.Second)
}

// TestRedisStore_Delete_Success tests successful Delete operation.
func TestRedisStore_Delete_Success(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	// Set up test data
	mr.Set("test:mykey", "42")

	ctx := context.Background()
	err = store.Delete(ctx, "mykey")
	require.NoError(t, err)

	// Verify key is deleted
	assert.False(t, mr.Exists("test:mykey"))
}

// TestRedisStore_Delete_NonExistent tests Delete on non-existent key.
func TestRedisStore_Delete_NonExistent(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	// Deleting non-existent key should not error
	err = store.Delete(ctx, "nonexistent")
	require.NoError(t, err)
}

// TestRedisStore_Close_Success tests successful Close operation.
func TestRedisStore_Close_Success(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)

	err = store.Close()
	require.NoError(t, err)
	assert.True(t, store.closed)
}

// TestRedisStore_Close_Idempotent tests that Close is idempotent.
func TestRedisStore_Close_Idempotent(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)

	// First close
	err = store.Close()
	require.NoError(t, err)

	// Second close should also succeed
	err = store.Close()
	require.NoError(t, err)
}

// TestRedisStore_Client tests the Client accessor.
func TestRedisStore_Client(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	client := store.Client()
	assert.NotNil(t, client)
	assert.Equal(t, store.client, client)
}

// TestRedisStore_SetGet_Integration tests Set and Get together.
func TestRedisStore_SetGet_Integration(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Set a value
	err = store.Set(ctx, "key1", 100, time.Minute)
	require.NoError(t, err)

	// Get the value
	val, err := store.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(100), val)
}

// TestRedisStore_TableDriven_Get tests Get with various scenarios.
func TestRedisStore_TableDriven_Get(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	tests := []struct {
		name        string
		setup       func()
		key         string
		expected    int64
		expectError bool
		errorCheck  func(error) bool
	}{
		{
			name: "existing key with positive value",
			setup: func() {
				mr.Set("test:positive", "42")
			},
			key:         "positive",
			expected:    42,
			expectError: false,
		},
		{
			name: "existing key with zero value",
			setup: func() {
				mr.Set("test:zero", "0")
			},
			key:         "zero",
			expected:    0,
			expectError: false,
		},
		{
			name: "existing key with negative value",
			setup: func() {
				mr.Set("test:negative", "-10")
			},
			key:         "negative",
			expected:    -10,
			expectError: false,
		},
		{
			name:        "non-existent key",
			setup:       func() {},
			key:         "nonexistent_table",
			expected:    0,
			expectError: true,
			errorCheck:  IsKeyNotFound,
		},
		{
			name: "invalid value",
			setup: func() {
				mr.Set("test:invalid", "abc")
			},
			key:         "invalid",
			expected:    0,
			expectError: true,
			errorCheck: func(err error) bool {
				return err != nil && !IsKeyNotFound(err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			ctx := context.Background()
			val, err := store.Get(ctx, tt.key)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCheck != nil {
					assert.True(t, tt.errorCheck(err), "error check failed for: %v", err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, val)
			}
		})
	}
}

// TestRedisStore_TableDriven_Set tests Set with various scenarios.
func TestRedisStore_TableDriven_Set(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	tests := []struct {
		name       string
		key        string
		value      int64
		expiration time.Duration
	}{
		{
			name:       "positive value with expiration",
			key:        "set_pos",
			value:      100,
			expiration: time.Minute,
		},
		{
			name:       "zero value",
			key:        "set_zero",
			value:      0,
			expiration: time.Minute,
		},
		{
			name:       "negative value",
			key:        "set_neg",
			value:      -50,
			expiration: time.Minute,
		},
		{
			name:       "no expiration",
			key:        "set_no_exp",
			value:      200,
			expiration: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := store.Set(ctx, tt.key, tt.value, tt.expiration)
			require.NoError(t, err)

			// Verify value was set
			val, err := store.Get(ctx, tt.key)
			require.NoError(t, err)
			assert.Equal(t, tt.value, val)
		})
	}
}

// TestRedisStore_TableDriven_Increment tests Increment with various scenarios.
func TestRedisStore_TableDriven_Increment(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	tests := []struct {
		name     string
		setup    func()
		key      string
		delta    int64
		expected int64
	}{
		{
			name:     "increment new key",
			setup:    func() {},
			key:      "incr_new",
			delta:    5,
			expected: 5,
		},
		{
			name: "increment existing key",
			setup: func() {
				mr.Set("test:incr_existing", "10")
			},
			key:      "incr_existing",
			delta:    3,
			expected: 13,
		},
		{
			name: "decrement existing key",
			setup: func() {
				mr.Set("test:decr_existing", "10")
			},
			key:      "decr_existing",
			delta:    -4,
			expected: 6,
		},
		{
			name:     "increment by zero",
			setup:    func() {},
			key:      "incr_zero",
			delta:    0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			ctx := context.Background()
			val, err := store.Increment(ctx, tt.key, tt.delta)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}

// TestRedisStore_ConcurrentAccess tests concurrent access to the store.
func TestRedisStore_ConcurrentAccess(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Concurrent increments
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			_, _ = store.Increment(ctx, "concurrent_counter", 1)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Check final value
	val, err := store.Get(ctx, "concurrent_counter")
	require.NoError(t, err)
	assert.Equal(t, int64(100), val)
}

// TestNewRedisStoreWithConfig_WithLogger tests that logger is properly set.
func TestNewRedisStoreWithConfig_WithLogger(t *testing.T) {
	mr := miniredis.RunT(t)

	logger := zap.NewNop()
	config := &RedisConfig{
		Address:           mr.Addr(),
		Password:          "",
		DB:                0,
		Prefix:            "test:",
		PoolSize:          5,
		MinIdleConns:      1,
		MaxRetries:        2,
		DialTimeout:       2 * time.Second,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		InitialBackoff:    50 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		ConnectionRetries: 3,
		Logger:            logger,
	}

	store, err := NewRedisStoreWithConfig(config)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	assert.Equal(t, logger, store.logger)
}

// TestNewRedisStoreWithConfig_NilLogger tests that nil logger uses nop logger.
func TestNewRedisStoreWithConfig_NilLogger(t *testing.T) {
	mr := miniredis.RunT(t)

	config := &RedisConfig{
		Address:           mr.Addr(),
		Password:          "",
		DB:                0,
		Prefix:            "test:",
		PoolSize:          5,
		MinIdleConns:      1,
		MaxRetries:        2,
		DialTimeout:       2 * time.Second,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		InitialBackoff:    50 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		ConnectionRetries: 3,
		Logger:            nil, // Nil logger
	}

	store, err := NewRedisStoreWithConfig(config)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	// Logger should be set to nop logger
	assert.NotNil(t, store.logger)
}

// TestDecorrelatedJitterBackoff_FirstAttempt tests first attempt returns initial.
func TestDecorrelatedJitterBackoff_FirstAttempt(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := newDecorrelatedJitterBackoff(initial, max)

	// First attempt (attempt 0) should return initial
	result := backoff.next(0)
	assert.Equal(t, initial, result)
	assert.Equal(t, initial, backoff.current)
}

// TestDecorrelatedJitterBackoff_SubsequentAttempts tests subsequent attempts.
func TestDecorrelatedJitterBackoff_SubsequentAttempts(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := newDecorrelatedJitterBackoff(initial, max)

	// First attempt
	backoff.next(0)

	// Subsequent attempts should be between initial and max
	for i := 1; i < 20; i++ {
		result := backoff.next(i)
		assert.GreaterOrEqual(t, result, initial, "attempt %d: backoff should be >= initial", i)
		assert.LessOrEqual(t, result, max, "attempt %d: backoff should be <= max", i)
	}
}

// TestDecorrelatedJitterBackoff_SmallMax tests when max is close to initial.
func TestDecorrelatedJitterBackoff_SmallMax(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 150 * time.Millisecond

	backoff := newDecorrelatedJitterBackoff(initial, max)

	// All attempts should be capped at max
	for i := 0; i < 10; i++ {
		result := backoff.next(i)
		assert.LessOrEqual(t, result, max)
	}
}

// TestNewRedisStoreWithConfig_ConnectionRetrySuccess tests successful connection after retry.
func TestNewRedisStoreWithConfig_ConnectionRetrySuccess(t *testing.T) {
	// Start miniredis and get the address before closing
	mr := miniredis.RunT(t)
	addr := mr.Addr()

	// Close it to simulate initial failure
	mr.Close()

	// Start a goroutine to restart miniredis after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		mr.Restart()
	}()

	config := &RedisConfig{
		Address:           addr,
		Password:          "",
		DB:                0,
		Prefix:            "test:",
		PoolSize:          1,
		MinIdleConns:      0,
		MaxRetries:        1,
		DialTimeout:       100 * time.Millisecond,
		ReadTimeout:       100 * time.Millisecond,
		WriteTimeout:      100 * time.Millisecond,
		InitialBackoff:    10 * time.Millisecond,
		MaxBackoff:        50 * time.Millisecond,
		ConnectionRetries: 5, // Allow multiple retries
		Logger:            zap.NewNop(),
	}

	store, err := NewRedisStoreWithConfig(config)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()
}

// TestRedisStore_Get_RedisError tests Get when Redis returns an error.
func TestRedisStore_Get_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	// Close miniredis to simulate connection error
	mr.Close()

	ctx := context.Background()
	_, err = store.Get(ctx, "key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis get error")
}

// TestRedisStore_Set_RedisError tests Set when Redis returns an error.
func TestRedisStore_Set_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	// Close miniredis to simulate connection error
	mr.Close()

	ctx := context.Background()
	err = store.Set(ctx, "key", 100, time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis set error")
}

// TestRedisStore_Increment_RedisError tests Increment when Redis returns an error.
func TestRedisStore_Increment_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	// Close miniredis to simulate connection error
	mr.Close()

	ctx := context.Background()
	_, err = store.Increment(ctx, "key", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis incr error")
}

// TestRedisStore_IncrementWithExpiry_RedisError tests IncrementWithExpiry when Redis returns an error.
func TestRedisStore_IncrementWithExpiry_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	// Close miniredis to simulate connection error
	mr.Close()

	ctx := context.Background()
	_, err = store.IncrementWithExpiry(ctx, "key", 1, time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis script error")
}

// TestRedisStore_Delete_RedisError tests Delete when Redis returns an error.
func TestRedisStore_Delete_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)

	store, err := NewRedisStore(mr.Addr(), "", 0, "test:")
	require.NoError(t, err)
	defer store.Close()

	// Close miniredis to simulate connection error
	mr.Close()

	ctx := context.Background()
	err = store.Delete(ctx, "key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis del error")
}

// TestNewRedisStoreWithConfig_NilConfigUsesDefaults tests that nil config uses defaults.
func TestNewRedisStoreWithConfig_NilConfigUsesDefaults(t *testing.T) {
	// This test verifies the nil config path, but we can't actually connect
	// without a running Redis, so we just verify it attempts to connect
	// to the default address
	store, err := NewRedisStoreWithConfig(nil)
	// Should fail because localhost:6379 is not running
	assert.Error(t, err)
	assert.Nil(t, store)
}

// TestNewRedisStoreWithConfig_TotalTimeoutCap tests that total timeout is capped at 2 minutes.
func TestNewRedisStoreWithConfig_TotalTimeoutCap(t *testing.T) {
	config := &RedisConfig{
		Address:           "localhost:59999", // Non-existent port
		Password:          "",
		DB:                0,
		Prefix:            "test:",
		PoolSize:          1,
		MinIdleConns:      0,
		MaxRetries:        1,
		DialTimeout:       10 * time.Minute, // Very long dial timeout
		ReadTimeout:       100 * time.Millisecond,
		WriteTimeout:      100 * time.Millisecond,
		InitialBackoff:    10 * time.Millisecond,
		MaxBackoff:        50 * time.Millisecond,
		ConnectionRetries: 100, // Many retries
		Logger:            zap.NewNop(),
	}

	// This should fail but the total timeout should be capped at 2 minutes
	start := time.Now()
	store, err := NewRedisStoreWithConfig(config)
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Nil(t, store)
	// Should complete in reasonable time (not 100 * 10 minutes)
	assert.Less(t, elapsed, 3*time.Minute)
}

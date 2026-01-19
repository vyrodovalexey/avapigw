package ratelimit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit/store"
	"go.uber.org/zap"
)

// ============================================================================
// Test Cases for SlidingWindowLimiter - Basic Functionality
// ============================================================================

func TestSlidingWindowLimiter_NewSlidingWindowLimiter(t *testing.T) {
	tests := []struct {
		name   string
		store  store.Store
		limit  int
		window time.Duration
		logger *zap.Logger
	}{
		{
			name:   "with nil store and nil logger",
			store:  nil,
			limit:  100,
			window: time.Minute,
			logger: nil,
		},
		{
			name:   "with memory store",
			store:  store.NewMemoryStore(),
			limit:  50,
			window: time.Second * 30,
			logger: zap.NewNop(),
		},
		{
			name:   "with zero limit",
			store:  nil,
			limit:  0,
			window: time.Minute,
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewSlidingWindowLimiter(tt.store, tt.limit, tt.window, tt.logger)
			require.NotNil(t, limiter)
			assert.Equal(t, tt.limit, limiter.limit)
			assert.Equal(t, tt.window, limiter.window)
			assert.Equal(t, 10, limiter.precision) // default precision
		})
	}
}

func TestSlidingWindowLimiter_NewSlidingWindowLimiterWithPrecision(t *testing.T) {
	tests := []struct {
		name              string
		precision         int
		expectedPrecision int
	}{
		{
			name:              "valid precision",
			precision:         20,
			expectedPrecision: 20,
		},
		{
			name:              "zero precision defaults to 10",
			precision:         0,
			expectedPrecision: 10,
		},
		{
			name:              "negative precision defaults to 10",
			precision:         -5,
			expectedPrecision: 10,
		},
		{
			name:              "precision of 1",
			precision:         1,
			expectedPrecision: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewSlidingWindowLimiterWithPrecision(nil, 100, time.Minute, tt.precision, nil)
			require.NotNil(t, limiter)
			assert.Equal(t, tt.expectedPrecision, limiter.precision)
		})
	}
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Allow/AllowN Methods
// ============================================================================

func TestSlidingWindowLimiter_Allow(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, time.Minute, nil)
	ctx := context.Background()
	key := "test-key"

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
		assert.True(t, result.Allowed, "request %d should be allowed", i+1)
		assert.Equal(t, 5, result.Limit)
		assert.Equal(t, 5-i-1, result.Remaining)
	}

	// 6th request should be denied
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed, "6th request should be denied")
	assert.Equal(t, 0, result.Remaining)
}

func TestSlidingWindowLimiter_AllowN(t *testing.T) {
	tests := []struct {
		name            string
		limit           int
		n               int
		expectedAllowed bool
		expectedRemain  int
	}{
		{
			name:            "allow single request",
			limit:           10,
			n:               1,
			expectedAllowed: true,
			expectedRemain:  9,
		},
		{
			name:            "allow multiple requests within limit",
			limit:           10,
			n:               5,
			expectedAllowed: true,
			expectedRemain:  5,
		},
		{
			name:            "allow exact limit",
			limit:           10,
			n:               10,
			expectedAllowed: true,
			expectedRemain:  0,
		},
		{
			name:            "deny requests exceeding limit",
			limit:           10,
			n:               11,
			expectedAllowed: false,
			expectedRemain:  0,
		},
		{
			name:            "zero limit denies all",
			limit:           0,
			n:               1,
			expectedAllowed: false,
			expectedRemain:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewSlidingWindowLimiter(nil, tt.limit, time.Minute, nil)
			ctx := context.Background()

			result, err := limiter.AllowN(ctx, "test-key", tt.n)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAllowed, result.Allowed)
			if tt.expectedAllowed {
				assert.Equal(t, tt.expectedRemain, result.Remaining)
			}
		})
	}
}

func TestSlidingWindowLimiter_AllowN_Sequential(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 10, time.Minute, nil)
	ctx := context.Background()
	key := "test-key"

	// First batch: 5 requests
	result, err := limiter.AllowN(ctx, key, 5)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 5, result.Remaining)

	// Second batch: 3 requests
	result, err = limiter.AllowN(ctx, key, 3)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 2, result.Remaining)

	// Third batch: 3 requests (should fail, only 2 remaining)
	result, err = limiter.AllowN(ctx, key, 3)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Window Boundaries
// ============================================================================

func TestSlidingWindowLimiter_WindowExpiration(t *testing.T) {
	// Use a very short window for testing
	limiter := NewSlidingWindowLimiter(nil, 2, 100*time.Millisecond, nil)
	ctx := context.Background()
	key := "test-key"

	// Exhaust the limit
	for i := 0; i < 2; i++ {
		result, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	}

	// Should be denied
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	result, err = limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestSlidingWindowLimiter_ResetAfterCalculation(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, time.Second, nil)
	ctx := context.Background()
	key := "test-key"

	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// ResetAfter should be approximately the window duration
	assert.True(t, result.ResetAfter > 0)
	assert.True(t, result.ResetAfter <= time.Second)
}

func TestSlidingWindowLimiter_RetryAfterCalculation(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 1, time.Second, nil)
	ctx := context.Background()
	key := "test-key"

	// First request allowed
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, time.Duration(0), result.RetryAfter)

	// Second request denied
	result, err = limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.True(t, result.RetryAfter > 0)
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Different Keys
// ============================================================================

func TestSlidingWindowLimiter_DifferentKeys(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 2, time.Minute, nil)
	ctx := context.Background()

	// Exhaust key1
	for i := 0; i < 2; i++ {
		result, err := limiter.Allow(ctx, "key1")
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	}

	// key1 should be exhausted
	result, err := limiter.Allow(ctx, "key1")
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// key2 should still have capacity
	result, err = limiter.Allow(ctx, "key2")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - GetLimit
// ============================================================================

func TestSlidingWindowLimiter_GetLimit(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 100, time.Minute, nil)

	limit := limiter.GetLimit("any-key")
	require.NotNil(t, limit)
	assert.Equal(t, 100, limit.Requests)
	assert.Equal(t, time.Minute, limit.Window)
	assert.Equal(t, 100, limit.Burst)
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Reset
// ============================================================================

func TestSlidingWindowLimiter_Reset(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, time.Minute, nil)
	ctx := context.Background()
	key := "test-key"

	// Exhaust the limit
	for i := 0; i < 5; i++ {
		_, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
	}

	// Verify exhausted
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// Reset
	err = limiter.Reset(ctx, key)
	require.NoError(t, err)

	// Should be allowed again
	result, err = limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 4, result.Remaining)
}

func TestSlidingWindowLimiter_Reset_NonExistentKey(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, time.Minute, nil)
	ctx := context.Background()

	// Reset non-existent key should not error
	err := limiter.Reset(ctx, "non-existent-key")
	require.NoError(t, err)
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Cleanup
// ============================================================================

func TestSlidingWindowLimiter_Cleanup(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, 50*time.Millisecond, nil)
	ctx := context.Background()

	// Create some window states
	for i := 0; i < 5; i++ {
		_, err := limiter.Allow(ctx, "key-"+string(rune('a'+i)))
		require.NoError(t, err)
	}

	// Wait for requests to become old
	time.Sleep(100 * time.Millisecond)

	// Cleanup with short maxAge should remove all
	limiter.Cleanup(10 * time.Millisecond)

	// After cleanup, new requests should be allowed with full capacity
	result, err := limiter.Allow(ctx, "key-a")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 4, result.Remaining)
}

func TestSlidingWindowLimiter_Cleanup_KeepsRecentRequests(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, time.Minute, nil)
	ctx := context.Background()

	// Make some requests
	for i := 0; i < 3; i++ {
		_, err := limiter.Allow(ctx, "test-key")
		require.NoError(t, err)
	}

	// Cleanup with long maxAge should keep recent requests
	limiter.Cleanup(time.Hour)

	// Should still have the same remaining count
	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 1, result.Remaining) // 5 - 3 - 1 = 1
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Concurrent Access
// ============================================================================

func TestSlidingWindowLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 100, time.Minute, nil)
	ctx := context.Background()
	key := "concurrent-key"

	var wg sync.WaitGroup
	var allowedCount atomic.Int32
	numGoroutines := 50
	requestsPerGoroutine := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				result, err := limiter.Allow(ctx, key)
				if err == nil && result.Allowed {
					allowedCount.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	// Should have allowed exactly 100 requests (the limit)
	assert.Equal(t, int32(100), allowedCount.Load())
}

func TestSlidingWindowLimiter_ConcurrentDifferentKeys(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 10, time.Minute, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	numKeys := 10
	requestsPerKey := 10

	results := make([]atomic.Int32, numKeys)

	for i := 0; i < numKeys; i++ {
		wg.Add(1)
		go func(keyIndex int) {
			defer wg.Done()
			key := "key-" + string(rune('a'+keyIndex))
			for j := 0; j < requestsPerKey; j++ {
				result, err := limiter.Allow(ctx, key)
				if err == nil && result.Allowed {
					results[keyIndex].Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	// Each key should have allowed exactly 10 requests
	for i := 0; i < numKeys; i++ {
		assert.Equal(t, int32(10), results[i].Load(), "key %d should have 10 allowed requests", i)
	}
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Distributed Mode with Store
// ============================================================================

func TestSlidingWindowLimiter_Distributed_Allow(t *testing.T) {
	memStore := store.NewMemoryStore()
	defer memStore.Close()

	limiter := NewSlidingWindowLimiter(memStore, 5, time.Minute, nil)
	ctx := context.Background()
	key := "distributed-key"

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
		assert.True(t, result.Allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be denied
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestSlidingWindowLimiter_Distributed_Reset(t *testing.T) {
	memStore := store.NewMemoryStore()
	defer memStore.Close()

	limiter := NewSlidingWindowLimiter(memStore, 5, time.Minute, nil)
	ctx := context.Background()
	key := "distributed-key"

	// Exhaust the limit
	for i := 0; i < 5; i++ {
		_, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
	}

	// Verify exhausted
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// Reset
	err = limiter.Reset(ctx, key)
	require.NoError(t, err)

	// Should be allowed again
	result, err = limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Edge Cases
// ============================================================================

func TestSlidingWindowLimiter_ZeroLimit(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 0, time.Minute, nil)
	ctx := context.Background()

	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, 0, result.Limit)
	assert.Equal(t, 0, result.Remaining)
}

func TestSlidingWindowLimiter_NegativeN(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 10, time.Minute, nil)
	ctx := context.Background()

	// Negative n should be treated as allowing (since -1 + 10 > 10 is false)
	result, err := limiter.AllowN(ctx, "test-key", -1)
	require.NoError(t, err)
	// With negative n, the check currentCount + n <= limit becomes 0 + (-1) <= 10 which is true
	assert.True(t, result.Allowed)
}

func TestSlidingWindowLimiter_VeryLargeN(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 10, time.Minute, nil)
	ctx := context.Background()

	result, err := limiter.AllowN(ctx, "test-key", 1000000)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestSlidingWindowLimiter_EmptyKey(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, time.Minute, nil)
	ctx := context.Background()

	result, err := limiter.Allow(ctx, "")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestSlidingWindowLimiter_VeryShortWindow(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, time.Millisecond, nil)
	ctx := context.Background()
	key := "test-key"

	// Make a request
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// Wait for window to expire
	time.Sleep(5 * time.Millisecond)

	// Should be allowed again with full capacity
	result, err = limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// ============================================================================
// Test Cases for SlidingWindowLimiter - Store Errors
// ============================================================================

func TestSlidingWindowLimiter_Distributed_StoreGetError(t *testing.T) {
	mockStore := &slidingWindowMockStore{
		getFunc: func(ctx context.Context, key string) (int64, error) {
			return 0, errors.New("store get error")
		},
	}

	limiter := NewSlidingWindowLimiter(mockStore, 5, time.Minute, nil)
	ctx := context.Background()

	_, err := limiter.Allow(ctx, "test-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "store get error")
}

func TestSlidingWindowLimiter_Distributed_StoreIncrementError(t *testing.T) {
	mockStore := &slidingWindowMockStore{
		getFunc: func(ctx context.Context, key string) (int64, error) {
			return 0, &store.ErrKeyNotFound{Key: key}
		},
		incrementWithExpiryFunc: func(ctx context.Context, key string, delta int64, expiration time.Duration) (int64, error) {
			return 0, errors.New("store increment error")
		},
	}

	limiter := NewSlidingWindowLimiter(mockStore, 5, time.Minute, zap.NewNop())
	ctx := context.Background()

	// Should still return result (error is logged but not returned)
	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// ============================================================================
// Mock Store for Testing
// ============================================================================

type slidingWindowMockStore struct {
	getFunc                 func(ctx context.Context, key string) (int64, error)
	setFunc                 func(ctx context.Context, key string, value int64, expiration time.Duration) error
	incrementFunc           func(ctx context.Context, key string, delta int64) (int64, error)
	incrementWithExpiryFunc func(ctx context.Context, key string, delta int64, expiration time.Duration) (int64, error)
	deleteFunc              func(ctx context.Context, key string) error
}

func (m *slidingWindowMockStore) Get(ctx context.Context, key string) (int64, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, key)
	}
	return 0, &store.ErrKeyNotFound{Key: key}
}

func (m *slidingWindowMockStore) Set(ctx context.Context, key string, value int64, expiration time.Duration) error {
	if m.setFunc != nil {
		return m.setFunc(ctx, key, value, expiration)
	}
	return nil
}

func (m *slidingWindowMockStore) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	if m.incrementFunc != nil {
		return m.incrementFunc(ctx, key, delta)
	}
	return delta, nil
}

func (m *slidingWindowMockStore) IncrementWithExpiry(ctx context.Context, key string, delta int64, expiration time.Duration) (int64, error) {
	if m.incrementWithExpiryFunc != nil {
		return m.incrementWithExpiryFunc(ctx, key, delta, expiration)
	}
	return delta, nil
}

func (m *slidingWindowMockStore) Delete(ctx context.Context, key string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, key)
	}
	return nil
}

func (m *slidingWindowMockStore) Close() error {
	return nil
}

// ============================================================================
// Additional Test Cases for Edge Cases
// ============================================================================

func TestSlidingWindowLimiter_Distributed_ResetWithDeleteError(t *testing.T) {
	mockStore := &slidingWindowMockStore{
		deleteFunc: func(ctx context.Context, key string) error {
			return errors.New("delete error")
		},
	}

	limiter := NewSlidingWindowLimiter(mockStore, 5, time.Minute, zap.NewNop())
	ctx := context.Background()

	// Reset should not return error (error is logged)
	err := limiter.Reset(ctx, "test-key")
	require.NoError(t, err)
}

func TestSlidingWindowLimiter_Distributed_NegativeRemaining(t *testing.T) {
	// Simulate a case where count exceeds limit (race condition scenario)
	mockStore := &slidingWindowMockStore{
		getFunc: func(ctx context.Context, key string) (int64, error) {
			// Return count higher than limit
			return 100, nil
		},
	}

	limiter := NewSlidingWindowLimiter(mockStore, 5, time.Minute, nil)
	ctx := context.Background()

	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, 0, result.Remaining) // Should be clamped to 0
}

func TestSlidingWindowLimiter_Distributed_AllowN_ExceedsLimit(t *testing.T) {
	mockStore := &slidingWindowMockStore{
		getFunc: func(ctx context.Context, key string) (int64, error) {
			return 3, nil // Already have 3 requests
		},
	}

	limiter := NewSlidingWindowLimiter(mockStore, 5, time.Minute, nil)
	ctx := context.Background()

	// Try to allow 5 more (3 + 5 > 5)
	result, err := limiter.AllowN(ctx, "test-key", 5)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.True(t, result.RetryAfter > 0)
}

func TestSlidingWindowLimiter_Local_EmptyRequests(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 5, time.Minute, nil)
	ctx := context.Background()

	// First request - no previous requests
	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, time.Minute, result.ResetAfter) // Should be window duration when no old requests
}

func TestSlidingWindowLimiter_Local_RetryAfterCalculation_EdgeCase(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 2, 100*time.Millisecond, nil)
	ctx := context.Background()
	key := "test-key"

	// Exhaust the limit
	for i := 0; i < 2; i++ {
		_, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
	}

	// Try to allow more than remaining
	result, err := limiter.AllowN(ctx, key, 3)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	// RetryAfter should be calculated based on when enough requests expire
	assert.True(t, result.RetryAfter >= 0)
}

func TestSlidingWindowLimiter_Local_ExcessRequestsExceedsWindowSize(t *testing.T) {
	limiter := NewSlidingWindowLimiter(nil, 2, 100*time.Millisecond, nil)
	ctx := context.Background()
	key := "test-key"

	// Exhaust the limit
	for i := 0; i < 2; i++ {
		_, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
	}

	// Try to allow way more than the limit (excessRequests > len(ws.requests))
	result, err := limiter.AllowN(ctx, key, 10)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	// RetryAfter should be 0 when excessRequests > len(ws.requests)
	assert.Equal(t, time.Duration(0), result.RetryAfter)
}

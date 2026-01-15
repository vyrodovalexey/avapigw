package ratelimit

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenBucketLimiter_Allow(t *testing.T) {
	// Create a limiter with 10 requests per second and burst of 5
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	ctx := context.Background()
	key := "test-key"

	// First 5 requests should be allowed (burst)
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
		assert.True(t, result.Allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be denied (burst exhausted)
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed, "6th request should be denied")
	assert.GreaterOrEqual(t, result.RetryAfter, time.Duration(0), "retry after should be non-negative")
}

func TestTokenBucketLimiter_AllowN(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 10, nil)

	ctx := context.Background()
	key := "test-key"

	// Request 5 tokens
	result, err := limiter.AllowN(ctx, key, 5)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 5, result.Remaining)

	// Request 6 more tokens (should fail)
	result, err = limiter.AllowN(ctx, key, 6)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestTokenBucketLimiter_Refill(t *testing.T) {
	// Create a limiter with 100 requests per second and burst of 1
	limiter := NewTokenBucketLimiter(nil, 100, 1, nil)

	ctx := context.Background()
	key := "test-key"

	// First request should be allowed
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// Second request should be denied
	result, err = limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// Wait for refill (10ms for 1 token at 100/s)
	time.Sleep(15 * time.Millisecond)

	// Third request should be allowed
	result, err = limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestTokenBucketLimiter_Reset(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	ctx := context.Background()
	key := "test-key"

	// Exhaust the bucket
	for i := 0; i < 5; i++ {
		_, err := limiter.Allow(ctx, key)
		require.NoError(t, err)
	}

	// Verify bucket is exhausted
	result, err := limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// Reset the bucket
	err = limiter.Reset(ctx, key)
	require.NoError(t, err)

	// Should be allowed again
	result, err = limiter.Allow(ctx, key)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestTokenBucketLimiter_DifferentKeys(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 2, nil)

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

	// key2 should still have tokens
	result, err = limiter.Allow(ctx, "key2")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestTokenBucketLimiter_GetLimit(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	limit := limiter.GetLimit("any-key")
	assert.NotNil(t, limit)
	assert.Equal(t, 10, limit.Requests)
	assert.Equal(t, 5, limit.Burst)
}

func TestTokenBucketLimiter_ContextCancellation(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)
	defer limiter.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should still work (local limiter doesn't use context for storage)
	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// ============================================================================
// Test Cases for Token Bucket Context Cancellation (TASK-008)
// ============================================================================

func TestTokenBucketLimiter_ContextCancellation_Distributed(t *testing.T) {
	// Create a mock store that respects context cancellation
	store := &mockStore{
		getFunc: func(ctx context.Context, key string) (int64, error) {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
				return 0, &mockKeyNotFoundError{key: key}
			}
		},
		setFunc: func(ctx context.Context, key string, value int64, expiration time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
	}

	limiter := NewTokenBucketLimiter(store, 10, 5, nil)
	defer limiter.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should return context.Canceled error for distributed limiter
	_, err := limiter.Allow(ctx, "test-key")
	assert.Equal(t, context.Canceled, err)
}

func TestTokenBucketLimiter_ContextCancellation_DuringGetTokens(t *testing.T) {
	// Create a mock store that blocks on Get until context is cancelled
	store := &mockStore{
		getFunc: func(ctx context.Context, key string) (int64, error) {
			// Simulate slow operation
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(100 * time.Millisecond):
				return 5000, nil // Return 5 tokens (stored as millis)
			}
		},
		setFunc: func(ctx context.Context, key string, value int64, expiration time.Duration) error {
			return nil
		},
	}

	limiter := NewTokenBucketLimiter(store, 10, 5, nil)
	defer limiter.Stop()

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	// Should return context.Canceled error
	_, err := limiter.Allow(ctx, "test-key")
	assert.Equal(t, context.Canceled, err)
}

func TestTokenBucketLimiter_ContextCancellation_DuringSet(t *testing.T) {
	// Create a mock store that succeeds on Get but blocks on Set
	// The store needs to return valid data for Get operations so we reach the Set phase
	store := &mockStore{
		getFunc: func(ctx context.Context, key string) (int64, error) {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
				// Return valid token count (5000 = 5 tokens in millis)
				if key == "tb:test-key:tokens" {
					return 5000, nil
				}
				// Return current time for time key
				return time.Now().UnixMilli(), nil
			}
		},
		setFunc: func(ctx context.Context, key string, value int64, expiration time.Duration) error {
			// Block until context is cancelled
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
				return nil
			}
		},
	}

	limiter := NewTokenBucketLimiter(store, 10, 5, nil)
	defer limiter.Stop()

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay (after Get succeeds but during Set)
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	// Should return context.Canceled error
	_, err := limiter.Allow(ctx, "test-key")
	assert.Equal(t, context.Canceled, err)
}

func TestTokenBucketLimiter_Stop(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	// Stop should not panic
	limiter.Stop()

	// Calling Stop multiple times should not panic
	limiter.Stop()
	limiter.Stop()
}

func TestTokenBucketLimiter_Cleanup(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)
	defer limiter.Stop()

	ctx := context.Background()

	// Create some buckets
	for i := 0; i < 5; i++ {
		_, err := limiter.Allow(ctx, "key-"+string(rune('a'+i)))
		require.NoError(t, err)
	}

	// Cleanup with very short TTL should remove all buckets
	limiter.Cleanup(0)

	// After cleanup, buckets should be recreated with full tokens
	result, err := limiter.Allow(ctx, "key-a")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 4, result.Remaining) // 5 burst - 1 = 4
}

func TestTokenBucketLimiter_WithTTL(t *testing.T) {
	limiter := NewTokenBucketLimiterWithTTL(nil, 10, 5, 100*time.Millisecond, 200*time.Millisecond, nil)
	defer limiter.Stop()

	ctx := context.Background()

	// Should work normally
	result, err := limiter.Allow(ctx, "test-key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// ============================================================================
// Mock Store Implementation for Testing
// ============================================================================

type mockStore struct {
	getFunc       func(ctx context.Context, key string) (int64, error)
	setFunc       func(ctx context.Context, key string, value int64, expiration time.Duration) error
	incrementFunc func(ctx context.Context, key string, delta int64) (int64, error)
	deleteFunc    func(ctx context.Context, key string) error
}

func (m *mockStore) Get(ctx context.Context, key string) (int64, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, key)
	}
	return 0, &mockKeyNotFoundError{key: key}
}

func (m *mockStore) Set(ctx context.Context, key string, value int64, expiration time.Duration) error {
	if m.setFunc != nil {
		return m.setFunc(ctx, key, value, expiration)
	}
	return nil
}

func (m *mockStore) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	if m.incrementFunc != nil {
		return m.incrementFunc(ctx, key, delta)
	}
	return delta, nil
}

func (m *mockStore) IncrementWithExpiry(ctx context.Context, key string, delta int64, expiration time.Duration) (int64, error) {
	if m.incrementFunc != nil {
		return m.incrementFunc(ctx, key, delta)
	}
	return delta, nil
}

func (m *mockStore) Delete(ctx context.Context, key string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, key)
	}
	return nil
}

func (m *mockStore) Close() error {
	return nil
}

type mockKeyNotFoundError struct {
	key string
}

func (e *mockKeyNotFoundError) Error() string {
	return "key not found: " + e.key
}

// ============================================================================
// Test Cases for TokenBucketLimiter io.Closer Implementation (Bug Fixes)
// ============================================================================

// Test 1: Implements io.Closer
func TestTokenBucketLimiter_ImplementsCloser(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)
	defer limiter.Close()

	var closer io.Closer = limiter
	assert.NotNil(t, closer)
}

// Test 2: Close Returns No Error
func TestTokenBucketLimiter_CloseReturnsNoError(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	err := limiter.Close()
	assert.NoError(t, err)
}

// Test 3: Multiple Close Calls Safe
func TestTokenBucketLimiter_MultipleCloseCalls(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	// Multiple closes should not panic
	assert.NotPanics(t, func() {
		limiter.Close()
		limiter.Close()
		limiter.Close()
	})
}

// Test 4: Stop Still Works (Backward Compatibility)
func TestTokenBucketLimiter_StopBackwardCompatibility(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	// Stop should still work
	assert.NotPanics(t, func() {
		limiter.Stop()
	})
}

// Test 5: Close After Stop
func TestTokenBucketLimiter_CloseAfterStop(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	// Stop first
	limiter.Stop()

	// Close should not panic
	assert.NotPanics(t, func() {
		err := limiter.Close()
		assert.NoError(t, err)
	})
}

// Test 6: Stop After Close
func TestTokenBucketLimiter_StopAfterClose(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	// Close first
	err := limiter.Close()
	assert.NoError(t, err)

	// Stop should not panic
	assert.NotPanics(t, func() {
		limiter.Stop()
	})
}

// Test 7: Limiter Works After Creation
func TestTokenBucketLimiter_WorksAfterCreation(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)
	defer limiter.Close()

	ctx := context.Background()
	result, err := limiter.Allow(ctx, "test-key")

	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// Test 8: Concurrent Close Calls
func TestTokenBucketLimiter_ConcurrentClose(t *testing.T) {
	limiter := NewTokenBucketLimiter(nil, 10, 5, nil)

	done := make(chan bool, 10)

	// Multiple goroutines calling Close concurrently
	for i := 0; i < 10; i++ {
		go func() {
			err := limiter.Close()
			assert.NoError(t, err)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

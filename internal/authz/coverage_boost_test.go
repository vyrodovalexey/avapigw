package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// AuthzError.Is() — AuthzError-to-AuthzError comparison
// ============================================================================

func TestAuthzError_Is_AuthzErrorToAuthzError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *AuthzError
		target   error
		expected bool
	}{
		{
			name:     "same wrapped error matches",
			err:      &AuthzError{Err: ErrAccessDenied},
			target:   &AuthzError{Err: ErrAccessDenied},
			expected: true,
		},
		{
			name:     "different wrapped errors do not match",
			err:      &AuthzError{Err: ErrAccessDenied},
			target:   &AuthzError{Err: ErrPolicyNotFound},
			expected: false,
		},
		{
			name:     "both nil wrapped errors match",
			err:      &AuthzError{},
			target:   &AuthzError{},
			expected: true,
		},
		{
			name:     "nil vs non-nil wrapped error does not match",
			err:      &AuthzError{},
			target:   &AuthzError{Err: ErrAccessDenied},
			expected: false,
		},
		{
			name:     "non-nil vs nil wrapped error does not match",
			err:      &AuthzError{Err: ErrAccessDenied},
			target:   &AuthzError{},
			expected: false,
		},
		{
			name:     "same ErrNoIdentity matches",
			err:      &AuthzError{Err: ErrNoIdentity},
			target:   &AuthzError{Err: ErrNoIdentity},
			expected: true,
		},
		{
			name:     "same ErrExternalAuthzFailed matches",
			err:      &AuthzError{Err: ErrExternalAuthzFailed},
			target:   &AuthzError{Err: ErrExternalAuthzFailed},
			expected: true,
		},
		{
			name:     "different fields but same Err matches",
			err:      &AuthzError{Err: ErrAccessDenied, Subject: "user1", Resource: "/api"},
			target:   &AuthzError{Err: ErrAccessDenied, Subject: "user2", Resource: "/other"},
			expected: true,
		},
		{
			name:     "AuthzError matches plain sentinel error",
			err:      &AuthzError{Err: ErrAccessDenied},
			target:   ErrAccessDenied,
			expected: true,
		},
		{
			name:     "AuthzError does not match different plain sentinel error",
			err:      &AuthzError{Err: ErrAccessDenied},
			target:   ErrPolicyNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := errors.Is(tt.err, tt.target)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Batch eviction with larger cache (maxSize=20)
// ============================================================================

func TestMemoryDecisionCache_BatchEviction_LargerCache(t *testing.T) {
	t.Parallel()

	// Create cache with maxSize=20 to exercise the 10% batch eviction path
	// (evictCount = 20/10 = 2, so 2 entries should be evicted per batch)
	maxSize := 20
	cache := NewMemoryDecisionCache(5*time.Minute, maxSize)
	defer cache.Close()

	ctx := context.Background()

	// Fill the cache to capacity with entries that have staggered timestamps
	for i := 0; i < maxSize; i++ {
		key := &CacheKey{
			Subject:  fmt.Sprintf("user%d", i),
			Resource: "/api/resource",
			Action:   "GET",
		}
		cache.Set(ctx, key, &CachedDecision{
			Allowed: true,
			Reason:  fmt.Sprintf("reason-%d", i),
		})
		// Small sleep to ensure different CachedAt timestamps for ordering
		time.Sleep(time.Millisecond)
	}

	// Now add one more entry, which should trigger eviction
	overflowKey := &CacheKey{
		Subject:  "overflow-user",
		Resource: "/api/resource",
		Action:   "GET",
	}
	cache.Set(ctx, overflowKey, &CachedDecision{
		Allowed: true,
		Reason:  "overflow",
	})

	// Verify the overflow entry was stored
	retrieved, ok := cache.Get(ctx, overflowKey)
	require.True(t, ok)
	assert.Equal(t, "overflow", retrieved.Reason)

	// Verify that some of the oldest entries were evicted
	// The first 2 entries (10% of 20) should have been evicted
	// We can't guarantee exact eviction order due to map iteration,
	// but we can verify the cache size is within bounds
	memCache := cache.(*memoryDecisionCache)
	memCache.mu.RLock()
	entryCount := len(memCache.entries)
	memCache.mu.RUnlock()

	// After evicting 2 entries and adding 1, we should have maxSize - 2 + 1 = 19
	assert.LessOrEqual(t, entryCount, maxSize,
		"cache should not exceed maxSize after eviction")
}

func TestMemoryDecisionCache_BatchEviction_WithExpiredEntries(t *testing.T) {
	t.Parallel()

	// Create cache with a generous TTL so the newly added entry survives its
	// own retrieval. Expiry of the initial entries is forced deterministically
	// below by mutating ExpiresAt, avoiding race-prone short-TTL timing.
	maxSize := 20
	cache := NewMemoryDecisionCache(5*time.Minute, maxSize)
	defer cache.Close()

	ctx := context.Background()

	// Fill the cache to capacity, keeping references to the stored pointers.
	decisions := make([]*CachedDecision, 0, maxSize)
	for i := 0; i < maxSize; i++ {
		key := &CacheKey{
			Subject:  fmt.Sprintf("user%d", i),
			Resource: "/api/resource",
			Action:   "GET",
		}
		d := &CachedDecision{Allowed: true}
		cache.Set(ctx, key, d)
		decisions = append(decisions, d)
	}

	// Force the initial entries to be expired. Set stores the same pointer we
	// passed in, so mutating ExpiresAt here marks them expired for the eviction
	// scan (IsExpired is time.Now().After(ExpiresAt)).
	for _, d := range decisions {
		d.ExpiresAt = time.Now().Add(-time.Hour)
	}

	// Add a new entry - should trigger eviction of the expired entries first.
	newKey := &CacheKey{
		Subject:  "new-user",
		Resource: "/api/resource",
		Action:   "GET",
	}
	cache.Set(ctx, newKey, &CachedDecision{
		Allowed: true,
		Reason:  "new-entry",
	})

	// The new entry (with the generous TTL) should be retrievable.
	retrieved, ok := cache.Get(ctx, newKey)
	require.True(t, ok)
	assert.Equal(t, "new-entry", retrieved.Reason)
}

func TestMemoryDecisionCache_BatchEviction_SmallCache(t *testing.T) {
	t.Parallel()

	// Test with maxSize=5 where evictCount = max(5/10, 1) = 1
	maxSize := 5
	cache := NewMemoryDecisionCache(5*time.Minute, maxSize)
	defer cache.Close()

	ctx := context.Background()

	// Fill to capacity
	for i := 0; i < maxSize; i++ {
		key := &CacheKey{
			Subject:  fmt.Sprintf("user%d", i),
			Resource: "/api/resource",
			Action:   "GET",
		}
		cache.Set(ctx, key, &CachedDecision{Allowed: true})
		time.Sleep(time.Millisecond)
	}

	// Add one more to trigger eviction
	overflowKey := &CacheKey{
		Subject:  "overflow",
		Resource: "/api/resource",
		Action:   "GET",
	}
	cache.Set(ctx, overflowKey, &CachedDecision{Allowed: true, Reason: "overflow"})

	// Verify overflow entry exists
	retrieved, ok := cache.Get(ctx, overflowKey)
	require.True(t, ok)
	assert.Equal(t, "overflow", retrieved.Reason)
}

// ============================================================================
// WithMemoryCacheMetrics option test
// ============================================================================

func TestNewMemoryDecisionCache_WithMetrics(t *testing.T) {
	t.Parallel()

	metrics := &Metrics{}
	cache := NewMemoryDecisionCache(
		5*time.Minute,
		1000,
		WithMemoryCacheMetrics(metrics),
	)
	require.NotNil(t, cache)

	err := cache.Close()
	assert.NoError(t, err)
}

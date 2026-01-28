package authz

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestCacheKey_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  *CacheKey
	}{
		{
			name: "basic key",
			key: &CacheKey{
				Subject:  "user123",
				Resource: "/api/users",
				Action:   "GET",
			},
		},
		{
			name: "key with roles",
			key: &CacheKey{
				Subject:  "user123",
				Resource: "/api/users",
				Action:   "GET",
				Roles:    []string{"admin", "user"},
			},
		},
		{
			name: "key with groups",
			key: &CacheKey{
				Subject:  "user123",
				Resource: "/api/users",
				Action:   "GET",
				Groups:   []string{"engineering", "platform"},
			},
		},
		{
			name: "key with roles and groups",
			key: &CacheKey{
				Subject:  "user123",
				Resource: "/api/users",
				Action:   "GET",
				Roles:    []string{"admin"},
				Groups:   []string{"engineering"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyStr := tt.key.String()
			assert.NotEmpty(t, keyStr)
			// Key should be a hex-encoded SHA256 hash (64 characters)
			assert.Len(t, keyStr, 64)
		})
	}
}

func TestCacheKey_String_Deterministic(t *testing.T) {
	t.Parallel()

	key := &CacheKey{
		Subject:  "user123",
		Resource: "/api/users",
		Action:   "GET",
		Roles:    []string{"admin", "user"},
		Groups:   []string{"engineering"},
	}

	// Same key should produce same hash
	hash1 := key.String()
	hash2 := key.String()
	assert.Equal(t, hash1, hash2)
}

func TestCacheKey_String_Different(t *testing.T) {
	t.Parallel()

	key1 := &CacheKey{
		Subject:  "user123",
		Resource: "/api/users",
		Action:   "GET",
	}

	key2 := &CacheKey{
		Subject:  "user456",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Different keys should produce different hashes
	assert.NotEqual(t, key1.String(), key2.String())
}

func TestCachedDecision_IsExpired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(time.Hour),
			expected:  false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-time.Hour),
			expected:  true,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-time.Millisecond),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision := &CachedDecision{
				Allowed:   true,
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.expected, decision.IsExpired())
		})
	}
}

func TestNewMemoryDecisionCache(t *testing.T) {
	t.Parallel()

	cache := NewMemoryDecisionCache(5*time.Minute, 1000)
	require.NotNil(t, cache)

	err := cache.Close()
	assert.NoError(t, err)
}

func TestNewMemoryDecisionCache_WithOptions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cache := NewMemoryDecisionCache(
		5*time.Minute,
		1000,
		WithMemoryCacheLogger(logger),
	)
	require.NotNil(t, cache)

	err := cache.Close()
	assert.NoError(t, err)
}

func TestMemoryDecisionCache_SetAndGet(t *testing.T) {
	t.Parallel()

	cache := NewMemoryDecisionCache(5*time.Minute, 1000)
	defer cache.Close()

	ctx := context.Background()
	key := &CacheKey{
		Subject:  "user123",
		Resource: "/api/users",
		Action:   "GET",
	}

	decision := &CachedDecision{
		Allowed: true,
		Reason:  "test reason",
		Policy:  "test-policy",
	}

	// Set the decision
	cache.Set(ctx, key, decision)

	// Get the decision
	retrieved, ok := cache.Get(ctx, key)
	require.True(t, ok)
	assert.True(t, retrieved.Allowed)
	assert.Equal(t, "test reason", retrieved.Reason)
	assert.Equal(t, "test-policy", retrieved.Policy)
	assert.False(t, retrieved.CachedAt.IsZero())
	assert.False(t, retrieved.ExpiresAt.IsZero())
}

func TestMemoryDecisionCache_Get_NotFound(t *testing.T) {
	t.Parallel()

	cache := NewMemoryDecisionCache(5*time.Minute, 1000)
	defer cache.Close()

	ctx := context.Background()
	key := &CacheKey{
		Subject:  "user123",
		Resource: "/api/users",
		Action:   "GET",
	}

	retrieved, ok := cache.Get(ctx, key)
	assert.False(t, ok)
	assert.Nil(t, retrieved)
}

func TestMemoryDecisionCache_Get_Expired(t *testing.T) {
	t.Parallel()

	// Create cache with very short TTL
	cache := NewMemoryDecisionCache(1*time.Millisecond, 1000)
	defer cache.Close()

	ctx := context.Background()
	key := &CacheKey{
		Subject:  "user123",
		Resource: "/api/users",
		Action:   "GET",
	}

	decision := &CachedDecision{
		Allowed: true,
	}

	cache.Set(ctx, key, decision)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Should not find expired entry
	retrieved, ok := cache.Get(ctx, key)
	assert.False(t, ok)
	assert.Nil(t, retrieved)
}

func TestMemoryDecisionCache_Delete(t *testing.T) {
	t.Parallel()

	cache := NewMemoryDecisionCache(5*time.Minute, 1000)
	defer cache.Close()

	ctx := context.Background()
	key := &CacheKey{
		Subject:  "user123",
		Resource: "/api/users",
		Action:   "GET",
	}

	decision := &CachedDecision{
		Allowed: true,
	}

	cache.Set(ctx, key, decision)

	// Verify it exists
	_, ok := cache.Get(ctx, key)
	require.True(t, ok)

	// Delete it
	cache.Delete(ctx, key)

	// Verify it's gone
	_, ok = cache.Get(ctx, key)
	assert.False(t, ok)
}

func TestMemoryDecisionCache_Clear(t *testing.T) {
	t.Parallel()

	cache := NewMemoryDecisionCache(5*time.Minute, 1000)
	defer cache.Close()

	ctx := context.Background()

	// Add multiple entries
	for i := 0; i < 10; i++ {
		key := &CacheKey{
			Subject:  "user123",
			Resource: "/api/users",
			Action:   "GET",
			Roles:    []string{string(rune('a' + i))},
		}
		cache.Set(ctx, key, &CachedDecision{Allowed: true})
	}

	// Clear all
	cache.Clear(ctx)

	// Verify all are gone
	key := &CacheKey{
		Subject:  "user123",
		Resource: "/api/users",
		Action:   "GET",
		Roles:    []string{"a"},
	}
	_, ok := cache.Get(ctx, key)
	assert.False(t, ok)
}

func TestMemoryDecisionCache_Eviction(t *testing.T) {
	t.Parallel()

	// Create cache with max size of 2
	cache := NewMemoryDecisionCache(5*time.Minute, 2)
	defer cache.Close()

	ctx := context.Background()

	// Add 3 entries
	for i := 0; i < 3; i++ {
		key := &CacheKey{
			Subject:  "user123",
			Resource: "/api/users",
			Action:   "GET",
			Roles:    []string{string(rune('a' + i))},
		}
		cache.Set(ctx, key, &CachedDecision{Allowed: true})
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// The oldest entry should have been evicted
	// We can't easily verify which one was evicted, but we can verify
	// that the cache is working and not panicking
}

func TestNewNoopDecisionCache(t *testing.T) {
	t.Parallel()

	cache := NewNoopDecisionCache()
	require.NotNil(t, cache)

	ctx := context.Background()
	key := &CacheKey{
		Subject:  "user123",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Set should be a no-op
	cache.Set(ctx, key, &CachedDecision{Allowed: true})

	// Get should always return false
	retrieved, ok := cache.Get(ctx, key)
	assert.False(t, ok)
	assert.Nil(t, retrieved)

	// Delete should be a no-op
	cache.Delete(ctx, key)

	// Clear should be a no-op
	cache.Clear(ctx)

	// Close should return nil
	err := cache.Close()
	assert.NoError(t, err)
}

func TestCachedDecision_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	decision := &CachedDecision{
		Allowed:   true,
		Reason:    "test reason",
		Policy:    "test-policy",
		CachedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}

	assert.True(t, decision.Allowed)
	assert.Equal(t, "test reason", decision.Reason)
	assert.Equal(t, "test-policy", decision.Policy)
	assert.Equal(t, now, decision.CachedAt)
	assert.Equal(t, now.Add(time.Hour), decision.ExpiresAt)
}

func TestMemoryDecisionCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	cache := NewMemoryDecisionCache(5*time.Minute, 1000)
	defer cache.Close()

	ctx := context.Background()
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(idx int) {
			key := &CacheKey{
				Subject:  "user123",
				Resource: "/api/users",
				Action:   "GET",
				Roles:    []string{string(rune('a' + idx))},
			}
			cache.Set(ctx, key, &CachedDecision{Allowed: true})
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(idx int) {
			key := &CacheKey{
				Subject:  "user123",
				Resource: "/api/users",
				Action:   "GET",
				Roles:    []string{string(rune('a' + idx))},
			}
			cache.Get(ctx, key)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestExternalCacheOptions(t *testing.T) {
	t.Parallel()

	// Test that options are properly applied
	// Note: We can't fully test external cache without a real cache implementation
	// but we can test the option functions

	logger := observability.NopLogger()

	// These should not panic
	opt1 := WithExternalCacheLogger(logger)
	assert.NotNil(t, opt1)

	opt2 := WithExternalCachePrefix("custom:")
	assert.NotNil(t, opt2)
}

// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func newTestMemoryCache(t *testing.T, maxEntries int, ttl time.Duration) *memoryCache {
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		MaxEntries: maxEntries,
		TTL:        config.Duration(ttl),
	}

	cache, err := newMemoryCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	return cache
}

func TestMemoryCache_SetAndGet(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Set a value
	err := cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	require.NoError(t, err)

	// Get the value
	value, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), value)
}

func TestMemoryCache_Get_Miss(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Get non-existent key
	_, err := cache.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestMemoryCache_Get_Expired(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Set a value with very short TTL
	err := cache.Set(ctx, "key1", []byte("value1"), time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Get should return miss
	_, err = cache.Get(ctx, "key1")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestMemoryCache_Set_Update(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Set initial value
	err := cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	require.NoError(t, err)

	// Update value
	err = cache.Set(ctx, "key1", []byte("value2"), time.Minute)
	require.NoError(t, err)

	// Get should return updated value
	value, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("value2"), value)
}

func TestMemoryCache_Set_DefaultTTL(t *testing.T) {
	cache := newTestMemoryCache(t, 100, time.Hour)
	defer cache.Close()

	ctx := context.Background()

	// Set with zero TTL - should use default
	err := cache.Set(ctx, "key1", []byte("value1"), 0)
	require.NoError(t, err)

	// Value should be retrievable
	value, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), value)
}

func TestMemoryCache_Delete(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Set a value
	err := cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	require.NoError(t, err)

	// Delete the value
	err = cache.Delete(ctx, "key1")
	require.NoError(t, err)

	// Get should return miss
	_, err = cache.Get(ctx, "key1")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestMemoryCache_Delete_NonExistent(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Delete non-existent key should not error
	err := cache.Delete(ctx, "nonexistent")
	assert.NoError(t, err)
}

func TestMemoryCache_Exists(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Check non-existent key
	exists, err := cache.Exists(ctx, "key1")
	require.NoError(t, err)
	assert.False(t, exists)

	// Set a value
	err = cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	require.NoError(t, err)

	// Check existing key
	exists, err = cache.Exists(ctx, "key1")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMemoryCache_Exists_Expired(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Set a value with very short TTL
	err := cache.Set(ctx, "key1", []byte("value1"), time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Exists should return false
	exists, err := cache.Exists(ctx, "key1")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestMemoryCache_Close(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)

	ctx := context.Background()

	// Set some values
	_ = cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	_ = cache.Set(ctx, "key2", []byte("value2"), time.Minute)

	// Close the cache
	err := cache.Close()
	require.NoError(t, err)

	// Cache should be empty after close
	stats := cache.Stats()
	assert.Equal(t, int64(0), stats.Size)
}

func TestMemoryCache_Stats(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Initial stats
	stats := cache.Stats()
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, int64(0), stats.Misses)
	assert.Equal(t, int64(0), stats.Size)

	// Set some values
	_ = cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	_ = cache.Set(ctx, "key2", []byte("value2"), time.Minute)

	// Check size
	stats = cache.Stats()
	assert.Equal(t, int64(2), stats.Size)

	// Get existing key - hit
	_, _ = cache.Get(ctx, "key1")
	stats = cache.Stats()
	assert.Equal(t, int64(1), stats.Hits)

	// Get non-existing key - miss
	_, _ = cache.Get(ctx, "nonexistent")
	stats = cache.Stats()
	assert.Equal(t, int64(1), stats.Misses)
}

func TestMemoryCache_Eviction(t *testing.T) {
	cache := newTestMemoryCache(t, 3, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Fill the cache
	_ = cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	_ = cache.Set(ctx, "key2", []byte("value2"), time.Minute)
	_ = cache.Set(ctx, "key3", []byte("value3"), time.Minute)

	// Add one more - should evict oldest
	_ = cache.Set(ctx, "key4", []byte("value4"), time.Minute)

	// Check size
	stats := cache.Stats()
	assert.Equal(t, int64(3), stats.Size)

	// key1 should be evicted (oldest)
	_, err := cache.Get(ctx, "key1")
	assert.ErrorIs(t, err, ErrCacheMiss)

	// key4 should exist
	value, err := cache.Get(ctx, "key4")
	require.NoError(t, err)
	assert.Equal(t, []byte("value4"), value)
}

func TestMemoryCache_LRU(t *testing.T) {
	cache := newTestMemoryCache(t, 3, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Fill the cache
	_ = cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	_ = cache.Set(ctx, "key2", []byte("value2"), time.Minute)
	_ = cache.Set(ctx, "key3", []byte("value3"), time.Minute)

	// Access key1 to make it recently used
	_, _ = cache.Get(ctx, "key1")

	// Add one more - should evict key2 (least recently used)
	_ = cache.Set(ctx, "key4", []byte("value4"), time.Minute)

	// key1 should still exist (was accessed)
	value, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), value)

	// key2 should be evicted
	_, err = cache.Get(ctx, "key2")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestMemoryCache_Concurrent(t *testing.T) {
	cache := newTestMemoryCache(t, 1000, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "key" + string(rune('0'+i%10))
			_ = cache.Set(ctx, key, []byte("value"), time.Minute)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "key" + string(rune('0'+i%10))
			_, _ = cache.Get(ctx, key)
		}(i)
	}

	// Concurrent deletes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "key" + string(rune('0'+i%10))
			_ = cache.Delete(ctx, key)
		}(i)
	}

	wg.Wait()

	// Should not panic or deadlock
}

func TestMemoryCache_DefaultMaxEntries(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		MaxEntries: 0, // Should use default
		TTL:        config.Duration(5 * time.Minute),
	}

	cache, err := newMemoryCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer cache.Close()

	// Should use default max entries (10000)
	assert.Equal(t, 10000, cache.maxEntries)
}

func TestMemoryCache_NoExpiration(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 0) // No default TTL
	defer cache.Close()

	ctx := context.Background()

	// Set with no TTL
	err := cache.Set(ctx, "key1", []byte("value1"), 0)
	require.NoError(t, err)

	// Value should be retrievable
	value, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), value)
}

func TestMemoryCache_UpdateMovesToFront(t *testing.T) {
	cache := newTestMemoryCache(t, 3, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Fill the cache
	_ = cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	_ = cache.Set(ctx, "key2", []byte("value2"), time.Minute)
	_ = cache.Set(ctx, "key3", []byte("value3"), time.Minute)

	// Update key1 - should move to front
	_ = cache.Set(ctx, "key1", []byte("updated"), time.Minute)

	// Add one more - should evict key2 (now oldest)
	_ = cache.Set(ctx, "key4", []byte("value4"), time.Minute)

	// key1 should still exist
	value, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("updated"), value)

	// key2 should be evicted
	_, err = cache.Get(ctx, "key2")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestMemoryCache_MultipleOperations(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Set multiple values
	for i := 0; i < 50; i++ {
		key := "key" + string(rune('A'+i))
		value := []byte("value" + string(rune('A'+i)))
		err := cache.Set(ctx, key, value, time.Minute)
		require.NoError(t, err)
	}

	// Verify all values
	for i := 0; i < 50; i++ {
		key := "key" + string(rune('A'+i))
		expectedValue := []byte("value" + string(rune('A'+i)))
		value, err := cache.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, expectedValue, value)
	}

	// Delete half
	for i := 0; i < 25; i++ {
		key := "key" + string(rune('A'+i))
		err := cache.Delete(ctx, key)
		require.NoError(t, err)
	}

	// Verify deleted
	for i := 0; i < 25; i++ {
		key := "key" + string(rune('A'+i))
		_, err := cache.Get(ctx, key)
		assert.ErrorIs(t, err, ErrCacheMiss)
	}

	// Verify remaining
	for i := 25; i < 50; i++ {
		key := "key" + string(rune('A'+i))
		_, err := cache.Get(ctx, key)
		require.NoError(t, err)
	}

	// Check stats
	stats := cache.Stats()
	assert.Equal(t, int64(25), stats.Size)
}

func TestMemoryCache_Cleanup(t *testing.T) {
	// Create cache with very short TTL
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		MaxEntries: 100,
		TTL:        config.Duration(10 * time.Millisecond),
	}

	cache, err := newMemoryCache(cfg, observability.NopLogger())
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()

	// Set some values
	for i := 0; i < 5; i++ {
		key := "cleanup-key-" + string(rune('A'+i))
		err := cache.Set(ctx, key, []byte("value"), 10*time.Millisecond)
		require.NoError(t, err)
	}

	// Verify values exist
	stats := cache.Stats()
	assert.Equal(t, int64(5), stats.Size)

	// Wait for expiration
	time.Sleep(50 * time.Millisecond)

	// Manually trigger cleanup
	cache.cleanup()

	// Verify values are cleaned up
	stats = cache.Stats()
	assert.Equal(t, int64(0), stats.Size)
}

func TestMemoryCache_CleanupLoop(t *testing.T) {
	// Create cache
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		MaxEntries: 100,
		TTL:        config.Duration(5 * time.Minute),
	}

	cache, err := newMemoryCache(cfg, observability.NopLogger())
	require.NoError(t, err)

	// Close should stop the cleanup loop
	err = cache.Close()
	assert.NoError(t, err)
}

func TestMemoryCache_CleanupWithNoExpiredEntries(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Set values with long TTL
	for i := 0; i < 5; i++ {
		key := "long-ttl-key-" + string(rune('A'+i))
		err := cache.Set(ctx, key, []byte("value"), time.Hour)
		require.NoError(t, err)
	}

	// Trigger cleanup
	cache.cleanup()

	// All values should still exist
	stats := cache.Stats()
	assert.Equal(t, int64(5), stats.Size)
}

func TestMemoryCache_EvictOldest(t *testing.T) {
	cache := newTestMemoryCache(t, 3, 5*time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Fill cache to capacity
	_ = cache.Set(ctx, "key1", []byte("value1"), time.Minute)
	_ = cache.Set(ctx, "key2", []byte("value2"), time.Minute)
	_ = cache.Set(ctx, "key3", []byte("value3"), time.Minute)

	// Verify size
	stats := cache.Stats()
	assert.Equal(t, int64(3), stats.Size)

	// Add one more - should evict oldest
	_ = cache.Set(ctx, "key4", []byte("value4"), time.Minute)

	// Verify size is still 3
	stats = cache.Stats()
	assert.Equal(t, int64(3), stats.Size)

	// key1 should be evicted
	_, err := cache.Get(ctx, "key1")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestMemoryCache_NegativeTTL(t *testing.T) {
	cache := newTestMemoryCache(t, 100, 0) // No default TTL
	defer cache.Close()

	ctx := context.Background()

	// Set with negative TTL (should be treated as no expiration)
	err := cache.Set(ctx, "key", []byte("value"), -1*time.Second)
	require.NoError(t, err)

	// Value should be retrievable
	value, err := cache.Get(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, []byte("value"), value)
}

//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify cache logic in isolation without external dependencies.
package functional

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestFunctional_Cache_MemoryOperations tests basic memory cache operations.
func TestFunctional_Cache_MemoryOperations(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(5 * time.Minute),
		MaxEntries: 100,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	t.Run("set_and_get", func(t *testing.T) {
		key := "test-key-1"
		value := []byte("test-value-1")

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("get_nonexistent_key", func(t *testing.T) {
		_, err := c.Get(ctx, "nonexistent-key")
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("delete_key", func(t *testing.T) {
		key := "test-key-delete"
		value := []byte("test-value")

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		err = c.Delete(ctx, key)
		require.NoError(t, err)

		_, err = c.Get(ctx, key)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("exists_check", func(t *testing.T) {
		key := "test-key-exists"
		value := []byte("test-value")

		exists, err := c.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)

		err = c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		exists, err = c.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("overwrite_existing_key", func(t *testing.T) {
		key := "test-key-overwrite"
		value1 := []byte("value-1")
		value2 := []byte("value-2")

		err := c.Set(ctx, key, value1, 0)
		require.NoError(t, err)

		err = c.Set(ctx, key, value2, 0)
		require.NoError(t, err)

		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value2, result)
	})
}

// TestFunctional_Cache_TTLExpiration tests cache TTL expiration.
func TestFunctional_Cache_TTLExpiration(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(100 * time.Millisecond),
		MaxEntries: 100,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	t.Run("entry_expires_after_ttl", func(t *testing.T) {
		key := "ttl-test-key"
		value := []byte("ttl-test-value")

		err := c.Set(ctx, key, value, 50*time.Millisecond)
		require.NoError(t, err)

		// Should exist immediately
		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Should be expired
		_, err = c.Get(ctx, key)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("custom_ttl_overrides_default", func(t *testing.T) {
		key := "custom-ttl-key"
		value := []byte("custom-ttl-value")

		// Set with longer TTL than default
		err := c.Set(ctx, key, value, 500*time.Millisecond)
		require.NoError(t, err)

		// Wait past default TTL
		time.Sleep(150 * time.Millisecond)

		// Should still exist
		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("zero_ttl_uses_default", func(t *testing.T) {
		key := "zero-ttl-key"
		value := []byte("zero-ttl-value")

		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)

		// Should exist immediately
		result, err := c.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, result)

		// Wait past default TTL
		time.Sleep(150 * time.Millisecond)

		// Should be expired (using default TTL of 100ms)
		_, err = c.Get(ctx, key)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})
}

// TestFunctional_Cache_KeyGeneration tests cache key generation.
func TestFunctional_Cache_KeyGeneration(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name     string
		cfg      *config.CacheKeyConfig
		method   string
		path     string
		expected string
	}{
		{
			name: "method_and_path",
			cfg: &config.CacheKeyConfig{
				IncludeMethod: true,
				IncludePath:   true,
			},
			method:   "GET",
			path:     "/api/users",
			expected: "GET:/api/users",
		},
		{
			name: "path_only",
			cfg: &config.CacheKeyConfig{
				IncludeMethod: false,
				IncludePath:   true,
			},
			method:   "GET",
			path:     "/api/users",
			expected: "/api/users",
		},
		{
			name: "method_only",
			cfg: &config.CacheKeyConfig{
				IncludeMethod: true,
				IncludePath:   false,
			},
			method:   "GET",
			path:     "/api/users",
			expected: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kg, err := cache.NewKeyGenerator(tt.cfg, logger)
			require.NoError(t, err)

			// Create a real HTTP request using httptest
			req := httptest.NewRequest(tt.method, tt.path, nil)
			key, err := kg.GenerateKey(req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, key)
		})
	}
}

// TestFunctional_Cache_MaxEntries tests cache max entries eviction.
func TestFunctional_Cache_MaxEntries(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	maxEntries := 5
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(5 * time.Minute),
		MaxEntries: maxEntries,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	// Fill cache to capacity
	for i := 0; i < maxEntries; i++ {
		key := keyForIndex(i)
		value := valueForIndex(i)
		err := c.Set(ctx, key, value, 0)
		require.NoError(t, err)
	}

	// Add one more entry to trigger eviction
	err = c.Set(ctx, "new-key", []byte("new-value"), 0)
	require.NoError(t, err)

	// The newest entry should exist
	_, err = c.Get(ctx, "new-key")
	require.NoError(t, err)

	// At least one of the original entries should be evicted
	// (LRU eviction - oldest entry should be gone)
	_, err = c.Get(ctx, keyForIndex(0))
	assert.ErrorIs(t, err, cache.ErrCacheMiss, "oldest entry should be evicted")
}

// TestFunctional_Cache_ConcurrentAccess tests concurrent cache access.
func TestFunctional_Cache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(5 * time.Minute),
		MaxEntries: 1000,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()
	numGoroutines := 10
	numOperations := 100

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				key := keyForIndex(id*numOperations + j)
				value := valueForIndex(id*numOperations + j)

				// Set
				err := c.Set(ctx, key, value, 0)
				if err != nil {
					t.Errorf("Set failed: %v", err)
				}

				// Get
				_, _ = c.Get(ctx, key)

				// Exists
				_, _ = c.Exists(ctx, key)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestFunctional_Cache_DisabledCache tests disabled cache behavior.
func TestFunctional_Cache_DisabledCache(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled: false,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	// All operations should return ErrCacheDisabled
	_, err = c.Get(ctx, "key")
	assert.ErrorIs(t, err, cache.ErrCacheDisabled)

	err = c.Set(ctx, "key", []byte("value"), 0)
	assert.ErrorIs(t, err, cache.ErrCacheDisabled)

	err = c.Delete(ctx, "key")
	assert.ErrorIs(t, err, cache.ErrCacheDisabled)

	_, err = c.Exists(ctx, "key")
	assert.ErrorIs(t, err, cache.ErrCacheDisabled)
}

// TestFunctional_Cache_Stats tests cache statistics.
func TestFunctional_Cache_Stats(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       config.CacheTypeMemory,
		TTL:        config.Duration(5 * time.Minute),
		MaxEntries: 100,
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	// Cast to CacheWithStats
	cws, ok := c.(cache.CacheWithStats)
	require.True(t, ok, "cache should implement CacheWithStats")

	// Initial stats
	stats := cws.Stats()
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, int64(0), stats.Misses)
	assert.Equal(t, int64(0), stats.Size)

	// Add some entries
	for i := 0; i < 5; i++ {
		err := c.Set(ctx, keyForIndex(i), valueForIndex(i), 0)
		require.NoError(t, err)
	}

	stats = cws.Stats()
	assert.Equal(t, int64(5), stats.Size)

	// Generate some hits
	for i := 0; i < 5; i++ {
		_, err := c.Get(ctx, keyForIndex(i))
		require.NoError(t, err)
	}

	stats = cws.Stats()
	assert.Equal(t, int64(5), stats.Hits)

	// Generate some misses
	for i := 10; i < 15; i++ {
		_, _ = c.Get(ctx, keyForIndex(i))
	}

	stats = cws.Stats()
	assert.Equal(t, int64(5), stats.Misses)

	// Check hit rate
	assert.Equal(t, 50.0, stats.HitRate())
}

// TestFunctional_Cache_CacheEntry tests CacheEntry methods.
func TestFunctional_Cache_CacheEntry(t *testing.T) {
	t.Parallel()

	t.Run("entry_not_expired", func(t *testing.T) {
		entry := &cache.CacheEntry{
			Value:     []byte("test"),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		assert.False(t, entry.IsExpired())
		assert.True(t, entry.TTL() > 0)
	})

	t.Run("entry_expired", func(t *testing.T) {
		entry := &cache.CacheEntry{
			Value:     []byte("test"),
			CreatedAt: time.Now().Add(-2 * time.Hour),
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		assert.True(t, entry.IsExpired())
		assert.Equal(t, time.Duration(0), entry.TTL())
	})

	t.Run("entry_no_expiration", func(t *testing.T) {
		entry := &cache.CacheEntry{
			Value:     []byte("test"),
			CreatedAt: time.Now(),
			ExpiresAt: time.Time{}, // Zero time = no expiration
		}

		assert.False(t, entry.IsExpired())
		assert.Equal(t, time.Duration(0), entry.TTL())
	})
}

// TestFunctional_Cache_KeyHelpers tests cache key helper functions.
func TestFunctional_Cache_KeyHelpers(t *testing.T) {
	t.Parallel()

	t.Run("generate_simple_key", func(t *testing.T) {
		key := cache.GenerateSimpleKey("GET", "/api/users")
		assert.Equal(t, "GET:/api/users", key)
	})

	t.Run("hash_key", func(t *testing.T) {
		key := "some-long-key-that-needs-hashing"
		hashed := cache.HashKey(key)

		// Should be a hex string of SHA256 (64 characters)
		assert.Len(t, hashed, 64)

		// Same input should produce same hash
		assert.Equal(t, hashed, cache.HashKey(key))
	})

	t.Run("sanitize_key", func(t *testing.T) {
		key := "key with spaces\nand\tnewlines"
		sanitized := cache.SanitizeKey(key)

		assert.NotContains(t, sanitized, " ")
		assert.NotContains(t, sanitized, "\n")
		assert.NotContains(t, sanitized, "\t")
	})
}

// Helper functions

func keyForIndex(i int) string {
	return "key-" + string(rune('0'+i%10)) + string(rune('0'+i/10))
}

func valueForIndex(i int) []byte {
	return []byte("value-" + string(rune('0'+i%10)) + string(rune('0'+i/10)))
}

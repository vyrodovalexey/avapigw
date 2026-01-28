//go:build integration
// +build integration

package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_Cache_Redis_BasicOperations tests basic Redis cache operations (Get, Set, Delete, Exists).
func TestIntegration_Cache_Redis_BasicOperations(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("basic_ops")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
		},
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("Set and Get", func(t *testing.T) {
		testKey := "test-key-1"
		testValue := []byte("test-value-1")

		// Test Set
		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Test Get
		value, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, value)
	})

	t.Run("Exists returns true for existing key", func(t *testing.T) {
		testKey := "test-key-exists"
		testValue := []byte("test-value-exists")

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		exists, err := c.Exists(ctx, testKey)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("Exists returns false for non-existing key", func(t *testing.T) {
		exists, err := c.Exists(ctx, "non-existing-key")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Delete removes key", func(t *testing.T) {
		testKey := "test-key-delete"
		testValue := []byte("test-value-delete")

		// Set the key
		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Verify it exists
		exists, err := c.Exists(ctx, testKey)
		require.NoError(t, err)
		assert.True(t, exists)

		// Delete the key
		err = c.Delete(ctx, testKey)
		require.NoError(t, err)

		// Verify it's deleted
		exists, err = c.Exists(ctx, testKey)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Get returns cache miss for non-existing key", func(t *testing.T) {
		_, err := c.Get(ctx, "non-existing-key-get")
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("Delete non-existing key does not error", func(t *testing.T) {
		err := c.Delete(ctx, "non-existing-key-delete")
		assert.NoError(t, err)
	})
}

// TestIntegration_Cache_Redis_TTLExpiration tests Redis cache TTL expiration.
func TestIntegration_Cache_Redis_TTLExpiration(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("ttl_exp")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(1 * time.Second), // Short TTL for testing
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
		},
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("Key expires after TTL", func(t *testing.T) {
		testKey := "ttl-test-key"
		testValue := []byte("ttl-test-value")
		shortTTL := 1 * time.Second

		// Set with short TTL
		err := c.Set(ctx, testKey, testValue, shortTTL)
		require.NoError(t, err)

		// Verify it exists immediately
		value, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, value)

		// Wait for TTL to expire
		time.Sleep(shortTTL + 500*time.Millisecond)

		// Verify it's expired
		_, err = c.Get(ctx, testKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("Key with zero TTL uses default", func(t *testing.T) {
		testKey := "zero-ttl-key"
		testValue := []byte("zero-ttl-value")

		// Set with zero TTL (should use default)
		err := c.Set(ctx, testKey, testValue, 0)
		require.NoError(t, err)

		// Verify it exists
		value, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, value)
	})
}

// TestIntegration_Cache_Redis_ConcurrentAccess tests Redis cache concurrent access.
func TestIntegration_Cache_Redis_ConcurrentAccess(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("concurrent")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
			PoolSize:  10,
		},
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("Concurrent writes to same key", func(t *testing.T) {
		testKey := "concurrent-write-key"
		numGoroutines := 10
		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				value := []byte("value-" + string(rune('0'+idx)))
				err := c.Set(ctx, testKey, value, 5*time.Minute)
				assert.NoError(t, err)
			}(i)
		}

		wg.Wait()

		// Verify key exists (value will be one of the written values)
		exists, err := c.Exists(ctx, testKey)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("Concurrent reads and writes", func(t *testing.T) {
		testKey := "concurrent-rw-key"
		testValue := []byte("initial-value")
		numGoroutines := 20

		// Set initial value
		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				if idx%2 == 0 {
					// Read
					_, err := c.Get(ctx, testKey)
					if err != nil && err != cache.ErrCacheMiss {
						errors <- err
					}
				} else {
					// Write
					value := []byte("updated-value-" + string(rune('0'+idx)))
					if err := c.Set(ctx, testKey, value, 5*time.Minute); err != nil {
						errors <- err
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	})

	t.Run("Concurrent operations on different keys", func(t *testing.T) {
		numGoroutines := 50
		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines*2)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				key := "key-" + string(rune('a'+idx%26)) + string(rune('0'+idx/26))
				value := []byte("value-" + key)

				// Set
				if err := c.Set(ctx, key, value, 5*time.Minute); err != nil {
					errors <- err
					return
				}

				// Get
				retrieved, err := c.Get(ctx, key)
				if err != nil {
					errors <- err
					return
				}

				if string(retrieved) != string(value) {
					errors <- assert.AnError
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	})
}

// TestIntegration_Cache_Redis_ConnectionHandling tests Redis cache connection handling.
func TestIntegration_Cache_Redis_ConnectionHandling(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("conn_handling")

	t.Run("Cache works with connection pool", func(t *testing.T) {
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       helpers.GetRedisURL(),
				KeyPrefix: keyPrefix,
				PoolSize:  5,
			},
		}

		c, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c.Close()

		// Perform multiple operations to use connection pool
		for i := 0; i < 20; i++ {
			key := "pool-test-" + string(rune('0'+i%10))
			value := []byte("pool-value-" + key)

			err := c.Set(ctx, key, value, 5*time.Minute)
			require.NoError(t, err)

			retrieved, err := c.Get(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, value, retrieved)
		}
	})

	t.Run("Cache handles close and reopen", func(t *testing.T) {
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       helpers.GetRedisURL(),
				KeyPrefix: keyPrefix + "reopen:",
			},
		}

		// First cache instance
		c1, err := cache.New(cfg, logger)
		require.NoError(t, err)

		testKey := "reopen-test-key"
		testValue := []byte("reopen-test-value")

		err = c1.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Close first instance
		err = c1.Close()
		require.NoError(t, err)

		// Create second instance
		c2, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c2.Close()

		// Data should still be accessible
		retrieved, err := c2.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)
	})

	t.Run("Invalid Redis URL returns error", func(t *testing.T) {
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       "invalid://url",
				KeyPrefix: keyPrefix,
			},
		}

		_, err := cache.New(cfg, logger)
		assert.Error(t, err)
	})
}

// TestIntegration_Cache_Redis_KeyPrefix tests Redis cache key prefix functionality.
func TestIntegration_Cache_Redis_KeyPrefix(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	// Create two caches with different prefixes
	prefix1 := helpers.GenerateTestKeyPrefix("prefix1")
	prefix2 := helpers.GenerateTestKeyPrefix("prefix2")

	cfg1 := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: prefix1,
		},
	}

	cfg2 := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: prefix2,
		},
	}

	c1, err := cache.New(cfg1, logger)
	require.NoError(t, err)
	defer c1.Close()

	c2, err := cache.New(cfg2, logger)
	require.NoError(t, err)
	defer c2.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, prefix1)
		_ = helpers.CleanupRedis(redisClient, prefix2)
	}()

	t.Run("Keys are isolated by prefix", func(t *testing.T) {
		testKey := "shared-key"
		value1 := []byte("value-from-cache-1")
		value2 := []byte("value-from-cache-2")

		// Set same key in both caches
		err := c1.Set(ctx, testKey, value1, 5*time.Minute)
		require.NoError(t, err)

		err = c2.Set(ctx, testKey, value2, 5*time.Minute)
		require.NoError(t, err)

		// Get from each cache - should get different values
		retrieved1, err := c1.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, value1, retrieved1)

		retrieved2, err := c2.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, value2, retrieved2)
	})

	t.Run("Delete in one cache does not affect other", func(t *testing.T) {
		testKey := "delete-isolation-key"
		value1 := []byte("value-1")
		value2 := []byte("value-2")

		// Set in both caches
		err := c1.Set(ctx, testKey, value1, 5*time.Minute)
		require.NoError(t, err)

		err = c2.Set(ctx, testKey, value2, 5*time.Minute)
		require.NoError(t, err)

		// Delete from cache 1
		err = c1.Delete(ctx, testKey)
		require.NoError(t, err)

		// Cache 1 should not have the key
		_, err = c1.Get(ctx, testKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// Cache 2 should still have the key
		retrieved2, err := c2.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, value2, retrieved2)
	})
}

// TestIntegration_Cache_Redis_LargeValues tests Redis cache with large values.
func TestIntegration_Cache_Redis_LargeValues(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("large_values")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
		},
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("Store and retrieve 1KB value", func(t *testing.T) {
		testKey := "large-1kb"
		testValue := make([]byte, 1024)
		for i := range testValue {
			testValue[i] = byte(i % 256)
		}

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		retrieved, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)
	})

	t.Run("Store and retrieve 100KB value", func(t *testing.T) {
		testKey := "large-100kb"
		testValue := make([]byte, 100*1024)
		for i := range testValue {
			testValue[i] = byte(i % 256)
		}

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		retrieved, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)
	})

	t.Run("Store and retrieve 1MB value", func(t *testing.T) {
		testKey := "large-1mb"
		testValue := make([]byte, 1024*1024)
		for i := range testValue {
			testValue[i] = byte(i % 256)
		}

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		retrieved, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)
	})

	t.Run("Store empty value", func(t *testing.T) {
		testKey := "empty-value"
		testValue := []byte{}

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		retrieved, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)
	})
}

// TestIntegration_Cache_Redis_ErrorHandling tests Redis cache error handling.
func TestIntegration_Cache_Redis_ErrorHandling(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("error_handling")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
		},
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("Get non-existing key returns cache miss", func(t *testing.T) {
		_, err := c.Get(ctx, "definitely-not-existing-key-12345")
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("Context cancellation is handled", func(t *testing.T) {
		canceledCtx, cancelFunc := context.WithCancel(context.Background())
		cancelFunc() // Cancel immediately

		_, err := c.Get(canceledCtx, "any-key")
		assert.Error(t, err)
	})

	t.Run("Context timeout is handled", func(t *testing.T) {
		timeoutCtx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancelFunc()

		// Wait a bit to ensure timeout
		time.Sleep(1 * time.Millisecond)

		_, err := c.Get(timeoutCtx, "any-key")
		assert.Error(t, err)
	})

	t.Run("Special characters in key are handled", func(t *testing.T) {
		specialKeys := []string{
			"key:with:colons",
			"key/with/slashes",
			"key.with.dots",
			"key-with-dashes",
			"key_with_underscores",
			"key with spaces",
		}

		for _, key := range specialKeys {
			value := []byte("value-for-" + key)

			err := c.Set(ctx, key, value, 5*time.Minute)
			require.NoError(t, err, "Failed to set key: %s", key)

			retrieved, err := c.Get(ctx, key)
			require.NoError(t, err, "Failed to get key: %s", key)
			assert.Equal(t, value, retrieved, "Value mismatch for key: %s", key)
		}
	})
}

// TestIntegration_Cache_Redis_Statistics tests Redis cache statistics.
func TestIntegration_Cache_Redis_Statistics(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("stats")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
		},
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	// Check if cache supports statistics
	cacheWithStats, ok := c.(cache.CacheWithStats)
	if !ok {
		t.Skip("Cache does not support statistics")
	}

	t.Run("Statistics track hits and misses", func(t *testing.T) {
		testKey := "stats-test-key"
		testValue := []byte("stats-test-value")

		// Initial stats
		initialStats := cacheWithStats.Stats()

		// Cause a miss
		_, _ = c.Get(ctx, "non-existing-stats-key")

		// Set a value
		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Cause a hit
		_, err = c.Get(ctx, testKey)
		require.NoError(t, err)

		// Check stats
		finalStats := cacheWithStats.Stats()

		assert.GreaterOrEqual(t, finalStats.Hits, initialStats.Hits+1, "Hits should increase")
		assert.GreaterOrEqual(t, finalStats.Misses, initialStats.Misses+1, "Misses should increase")
	})
}

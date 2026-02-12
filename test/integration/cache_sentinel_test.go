//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_Cache_Sentinel_BasicOperations tests basic Redis Sentinel cache operations (Get, Set, Delete, Exists).
func TestIntegration_Cache_Sentinel_BasicOperations(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_basic_ops")

	cfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg.Redis.KeyPrefix = keyPrefix

	c, err := helpers.NewSentinelCache(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	t.Run("Set and Get", func(t *testing.T) {
		testKey := "test-key-1"
		testValue := []byte("test-value-1")

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

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

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		exists, err := c.Exists(ctx, testKey)
		require.NoError(t, err)
		assert.True(t, exists)

		err = c.Delete(ctx, testKey)
		require.NoError(t, err)

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

// TestIntegration_Cache_Sentinel_WithAuthentication tests sentinel cache with master password authentication.
func TestIntegration_Cache_Sentinel_WithAuthentication(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_auth")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			KeyPrefix: keyPrefix,
			PoolSize:  5,
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    helpers.GetRedisSentinelMasterName(),
				SentinelAddrs: helpers.GetRedisSentinelAddrs(),
				Password:      helpers.GetRedisMasterPassword(),
			},
		},
	}

	c, err := helpers.NewSentinelCache(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	t.Run("authenticated operations work", func(t *testing.T) {
		testKey := "auth-test-key"
		testValue := []byte("auth-test-value")

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		value, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, value)
	})

	t.Run("wrong password fails", func(t *testing.T) {
		wrongCfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				KeyPrefix: keyPrefix + "wrong:",
				Sentinel: &config.RedisSentinelConfig{
					MasterName:    helpers.GetRedisSentinelMasterName(),
					SentinelAddrs: helpers.GetRedisSentinelAddrs(),
					Password:      "wrong-password-12345",
				},
			},
		}

		_, err := helpers.NewSentinelCache(wrongCfg, logger)
		assert.Error(t, err, "should fail with wrong password")
	})
}

// TestIntegration_Cache_Sentinel_TTL tests TTL expiration with sentinel cache.
func TestIntegration_Cache_Sentinel_TTL(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_ttl")

	cfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg.TTL = config.Duration(1 * time.Second)
	cfg.Redis.KeyPrefix = keyPrefix

	c, err := helpers.NewSentinelCache(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	t.Run("Key expires after TTL", func(t *testing.T) {
		testKey := "ttl-test-key"
		testValue := []byte("ttl-test-value")
		shortTTL := 1 * time.Second

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

		err := c.Set(ctx, testKey, testValue, 0)
		require.NoError(t, err)

		// Verify it exists
		value, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, value)
	})
}

// TestIntegration_Cache_Sentinel_KeyPrefix tests key prefix isolation with sentinel cache.
func TestIntegration_Cache_Sentinel_KeyPrefix(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()

	prefix1 := helpers.GenerateTestKeyPrefix("sentinel_prefix1")
	prefix2 := helpers.GenerateTestKeyPrefix("sentinel_prefix2")

	cfg1 := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg1.Redis.KeyPrefix = prefix1

	cfg2 := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg2.Redis.KeyPrefix = prefix2

	c1, err := helpers.NewSentinelCache(cfg1, logger)
	require.NoError(t, err)
	defer c1.Close()

	c2, err := helpers.NewSentinelCache(cfg2, logger)
	require.NoError(t, err)
	defer c2.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, prefix1)
		_ = helpers.CleanupRedis(sentinelClient, prefix2)
	}()

	t.Run("Keys are isolated by prefix", func(t *testing.T) {
		testKey := "shared-key"
		value1 := []byte("value-from-cache-1")
		value2 := []byte("value-from-cache-2")

		err := c1.Set(ctx, testKey, value1, 5*time.Minute)
		require.NoError(t, err)

		err = c2.Set(ctx, testKey, value2, 5*time.Minute)
		require.NoError(t, err)

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

		err := c1.Set(ctx, testKey, value1, 5*time.Minute)
		require.NoError(t, err)

		err = c2.Set(ctx, testKey, value2, 5*time.Minute)
		require.NoError(t, err)

		err = c1.Delete(ctx, testKey)
		require.NoError(t, err)

		_, err = c1.Get(ctx, testKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		retrieved2, err := c2.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, value2, retrieved2)
	})
}

// TestIntegration_Cache_Sentinel_Statistics tests cache hit/miss statistics with sentinel.
func TestIntegration_Cache_Sentinel_Statistics(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_stats")

	cfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg.Redis.KeyPrefix = keyPrefix

	c, err := helpers.NewSentinelCache(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	cacheWithStats, ok := c.(cache.CacheWithStats)
	if !ok {
		t.Skip("Cache does not support statistics")
	}

	t.Run("Statistics track hits and misses", func(t *testing.T) {
		initialStats := cacheWithStats.Stats()

		// Cause a miss
		_, _ = c.Get(ctx, "non-existing-stats-key")

		// Set a value
		testKey := "stats-test-key"
		testValue := []byte("stats-test-value")
		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Cause a hit
		_, err = c.Get(ctx, testKey)
		require.NoError(t, err)

		finalStats := cacheWithStats.Stats()

		assert.GreaterOrEqual(t, finalStats.Hits, initialStats.Hits+1, "Hits should increase")
		assert.GreaterOrEqual(t, finalStats.Misses, initialStats.Misses+1, "Misses should increase")
	})
}

// TestIntegration_Cache_Sentinel_GetWithTTL tests GetWithTTL pipeline operation with sentinel.
func TestIntegration_Cache_Sentinel_GetWithTTL(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_getttl")

	cfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg.Redis.KeyPrefix = keyPrefix

	c, err := helpers.NewSentinelCache(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	// Cast to redisCache to access GetWithTTL
	type cacheWithTTL interface {
		GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error)
	}

	cwt, ok := c.(cacheWithTTL)
	if !ok {
		t.Skip("Cache does not support GetWithTTL")
	}

	t.Run("GetWithTTL returns value and remaining TTL", func(t *testing.T) {
		testKey := "getttl-test-key"
		testValue := []byte("getttl-test-value")
		ttl := 5 * time.Minute

		err := c.Set(ctx, testKey, testValue, ttl)
		require.NoError(t, err)

		value, remainingTTL, err := cwt.GetWithTTL(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, value)
		assert.Greater(t, remainingTTL, time.Duration(0), "remaining TTL should be positive")
		assert.LessOrEqual(t, remainingTTL, ttl, "remaining TTL should not exceed original TTL")
	})

	t.Run("GetWithTTL returns cache miss for non-existing key", func(t *testing.T) {
		_, _, err := cwt.GetWithTTL(ctx, "non-existing-getttl-key")
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})
}

// TestIntegration_Cache_Sentinel_SetNX tests SetNX operation with sentinel.
func TestIntegration_Cache_Sentinel_SetNX(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_setnx")

	cfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg.Redis.KeyPrefix = keyPrefix

	c, err := helpers.NewSentinelCache(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	type cacheWithSetNX interface {
		SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	}

	csn, ok := c.(cacheWithSetNX)
	if !ok {
		t.Skip("Cache does not support SetNX")
	}

	t.Run("SetNX succeeds for new key", func(t *testing.T) {
		testKey := "setnx-new-key"
		testValue := []byte("setnx-new-value")

		ok, err := csn.SetNX(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)
		assert.True(t, ok, "SetNX should succeed for new key")

		value, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, value)
	})

	t.Run("SetNX fails for existing key", func(t *testing.T) {
		testKey := "setnx-existing-key"
		originalValue := []byte("original-value")
		newValue := []byte("new-value")

		// Set the key first
		err := c.Set(ctx, testKey, originalValue, 5*time.Minute)
		require.NoError(t, err)

		// SetNX should fail
		ok, err := csn.SetNX(ctx, testKey, newValue, 5*time.Minute)
		require.NoError(t, err)
		assert.False(t, ok, "SetNX should fail for existing key")

		// Original value should be preserved
		value, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, originalValue, value)
	})
}

// TestIntegration_Cache_Sentinel_Expire tests Expire operation with sentinel.
func TestIntegration_Cache_Sentinel_Expire(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_expire")

	cfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg.Redis.KeyPrefix = keyPrefix

	c, err := helpers.NewSentinelCache(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	type cacheWithExpire interface {
		Expire(ctx context.Context, key string, ttl time.Duration) error
	}

	ce, ok := c.(cacheWithExpire)
	if !ok {
		t.Skip("Cache does not support Expire")
	}

	t.Run("Expire updates TTL and key expires", func(t *testing.T) {
		testKey := "expire-test-key"
		testValue := []byte("expire-test-value")

		// Set with long TTL
		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Update TTL to short duration
		shortTTL := 1 * time.Second
		err = ce.Expire(ctx, testKey, shortTTL)
		require.NoError(t, err)

		// Verify key still exists immediately
		value, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, value)

		// Wait for new TTL to expire
		time.Sleep(shortTTL + 500*time.Millisecond)

		// Verify key has expired
		_, err = c.Get(ctx, testKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})
}

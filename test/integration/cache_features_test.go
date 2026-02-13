//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// ---------------------------------------------------------------------------
// TTL Jitter Integration Tests
// ---------------------------------------------------------------------------

// TestIntegration_Cache_Features_TTLJitter_WithRedis tests that TTL jitter
// produces varied TTLs when storing values in Redis.
func TestIntegration_Cache_Features_TTLJitter_WithRedis(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("ttl_jitter")

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("TTLJitter=0.1 produces varied TTLs", func(t *testing.T) {
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(10 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       helpers.GetRedisURL(),
				KeyPrefix: keyPrefix + "jitter01:",
				TTLJitter: 0.1,
			},
		}

		c, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c.Close()

		// Cast to get GetWithTTL
		type cacheWithTTL interface {
			GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error)
		}
		cwt, ok := c.(cacheWithTTL)
		require.True(t, ok, "cache should support GetWithTTL")

		// Store multiple values and collect their TTLs
		const numKeys = 20
		ttls := make([]time.Duration, 0, numKeys)
		baseTTL := 10 * time.Minute

		for i := 0; i < numKeys; i++ {
			key := fmt.Sprintf("jitter-key-%d", i)
			value := []byte(fmt.Sprintf("jitter-value-%d", i))

			err := c.Set(ctx, key, value, baseTTL)
			require.NoError(t, err)

			_, remainingTTL, err := cwt.GetWithTTL(ctx, key)
			require.NoError(t, err)
			ttls = append(ttls, remainingTTL)
		}

		// With 10% jitter on 10 minutes, TTLs should be in [9m, 11m] range.
		// Verify that not all TTLs are identical (jitter is applied).
		allSame := true
		for i := 1; i < len(ttls); i++ {
			if ttls[i] != ttls[0] {
				allSame = false
				break
			}
		}
		assert.False(t, allSame, "with TTLJitter=0.1, TTLs should vary across keys")

		// Verify all TTLs are within the expected jitter range
		minExpected := time.Duration(float64(baseTTL) * 0.85) // some margin
		maxExpected := time.Duration(float64(baseTTL) * 1.15) // some margin
		for i, ttl := range ttls {
			assert.Greater(t, ttl, minExpected,
				"key %d TTL %v should be > %v", i, ttl, minExpected)
			assert.Less(t, ttl, maxExpected,
				"key %d TTL %v should be < %v", i, ttl, maxExpected)
		}
	})

	t.Run("TTLJitter=0 produces exact TTLs", func(t *testing.T) {
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(10 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       helpers.GetRedisURL(),
				KeyPrefix: keyPrefix + "nojitter:",
				TTLJitter: 0,
			},
		}

		c, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c.Close()

		type cacheWithTTL interface {
			GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error)
		}
		cwt, ok := c.(cacheWithTTL)
		require.True(t, ok, "cache should support GetWithTTL")

		const numKeys = 10
		baseTTL := 10 * time.Minute

		for i := 0; i < numKeys; i++ {
			key := fmt.Sprintf("exact-key-%d", i)
			value := []byte(fmt.Sprintf("exact-value-%d", i))

			err := c.Set(ctx, key, value, baseTTL)
			require.NoError(t, err)

			_, remainingTTL, err := cwt.GetWithTTL(ctx, key)
			require.NoError(t, err)

			// Without jitter, TTL should be very close to baseTTL
			// Allow 2 seconds tolerance for Redis round-trip
			diff := baseTTL - remainingTTL
			assert.Less(t, diff, 2*time.Second,
				"key %d TTL diff %v should be < 2s without jitter", i, diff)
		}
	})
}

// TestIntegration_Cache_Features_TTLJitter_WithSentinel tests TTL jitter with
// Redis Sentinel cache.
func TestIntegration_Cache_Features_TTLJitter_WithSentinel(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_ttl_jitter")

	cfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg.Redis.KeyPrefix = keyPrefix
	cfg.Redis.TTLJitter = 0.1
	cfg.TTL = config.Duration(10 * time.Minute)

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

	type cacheWithTTL interface {
		GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error)
	}
	cwt, ok := c.(cacheWithTTL)
	require.True(t, ok, "cache should support GetWithTTL")

	t.Run("sentinel cache with jitter produces varied TTLs", func(t *testing.T) {
		const numKeys = 15
		baseTTL := 10 * time.Minute
		ttls := make([]time.Duration, 0, numKeys)

		for i := 0; i < numKeys; i++ {
			key := fmt.Sprintf("sentinel-jitter-%d", i)
			value := []byte(fmt.Sprintf("sentinel-value-%d", i))

			err := c.Set(ctx, key, value, baseTTL)
			require.NoError(t, err)

			_, remainingTTL, err := cwt.GetWithTTL(ctx, key)
			require.NoError(t, err)
			ttls = append(ttls, remainingTTL)
		}

		// Verify not all TTLs are identical
		allSame := true
		for i := 1; i < len(ttls); i++ {
			if ttls[i] != ttls[0] {
				allSame = false
				break
			}
		}
		assert.False(t, allSame, "sentinel cache with TTLJitter=0.1 should produce varied TTLs")
	})
}

// ---------------------------------------------------------------------------
// Hash Keys Integration Tests
// ---------------------------------------------------------------------------

// TestIntegration_Cache_Features_HashKeys_WithRedis tests that hash keys
// feature works correctly with real Redis.
func TestIntegration_Cache_Features_HashKeys_WithRedis(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("hash_keys")

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("HashKeys=true stores and retrieves values correctly", func(t *testing.T) {
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       helpers.GetRedisURL(),
				KeyPrefix: keyPrefix + "hashed:",
				HashKeys:  true,
			},
		}

		c, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c.Close()

		testKey := "GET:/api/v1/users?page=1"
		testValue := []byte(`{"users":["alice","bob"]}`)

		// Set value
		err = c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Get value back
		retrieved, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)

		// Verify key exists
		exists, err := c.Exists(ctx, testKey)
		require.NoError(t, err)
		assert.True(t, exists)

		// Delete and verify
		err = c.Delete(ctx, testKey)
		require.NoError(t, err)

		_, err = c.Get(ctx, testKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("HashKeys=true uses hashed keys in Redis", func(t *testing.T) {
		prefix := keyPrefix + "verify_hash:"
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       helpers.GetRedisURL(),
				KeyPrefix: prefix,
				HashKeys:  true,
			},
		}

		c, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c.Close()

		testKey := "my-plain-key"
		testValue := []byte("my-value")

		err = c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// The raw key in Redis should be prefix + SHA256(testKey), not prefix + testKey
		expectedHashedKey := prefix + cache.HashKey(testKey)
		plainKey := prefix + testKey

		// Verify the hashed key exists in Redis
		val, err := redisClient.Get(ctx, expectedHashedKey).Bytes()
		require.NoError(t, err, "hashed key should exist in Redis")
		assert.Equal(t, testValue, val)

		// Verify the plain key does NOT exist in Redis
		_, err = redisClient.Get(ctx, plainKey).Result()
		assert.Error(t, err, "plain key should NOT exist in Redis when HashKeys=true")
	})

	t.Run("HashKeys=false uses plain keys in Redis", func(t *testing.T) {
		prefix := keyPrefix + "plain:"
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       helpers.GetRedisURL(),
				KeyPrefix: prefix,
				HashKeys:  false,
			},
		}

		c, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c.Close()

		testKey := "my-plain-key"
		testValue := []byte("my-value")

		err = c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// The raw key in Redis should be prefix + testKey
		plainKey := prefix + testKey
		val, err := redisClient.Get(ctx, plainKey).Bytes()
		require.NoError(t, err, "plain key should exist in Redis")
		assert.Equal(t, testValue, val)

		// Verify the hashed key does NOT exist
		hashedKey := prefix + cache.HashKey(testKey)
		_, err = redisClient.Get(ctx, hashedKey).Result()
		assert.Error(t, err, "hashed key should NOT exist when HashKeys=false")
	})

	t.Run("HashKeys=true handles multiple keys correctly", func(t *testing.T) {
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:       helpers.GetRedisURL(),
				KeyPrefix: keyPrefix + "multi_hash:",
				HashKeys:  true,
			},
		}

		c, err := cache.New(cfg, logger)
		require.NoError(t, err)
		defer c.Close()

		keys := []string{
			"GET:/api/v1/items",
			"GET:/api/v1/items?page=2",
			"POST:/api/v1/items",
			"GET:/api/v1/users/123",
		}

		// Set all keys
		for i, key := range keys {
			value := []byte(fmt.Sprintf("value-%d", i))
			err := c.Set(ctx, key, value, 5*time.Minute)
			require.NoError(t, err)
		}

		// Retrieve all keys
		for i, key := range keys {
			expected := []byte(fmt.Sprintf("value-%d", i))
			retrieved, err := c.Get(ctx, key)
			require.NoError(t, err, "should retrieve key %s", key)
			assert.Equal(t, expected, retrieved)
		}
	})
}

// TestIntegration_Cache_Features_HashKeys_WithSentinel tests hash keys with
// Redis Sentinel cache.
func TestIntegration_Cache_Features_HashKeys_WithSentinel(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("sentinel_hash_keys")

	cfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cfg.Redis.KeyPrefix = keyPrefix
	cfg.Redis.HashKeys = true

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

	t.Run("sentinel cache with hash keys stores and retrieves correctly", func(t *testing.T) {
		testKey := "sentinel-hash-test-key"
		testValue := []byte("sentinel-hash-test-value")

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		retrieved, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)
	})

	t.Run("sentinel cache with hash keys uses hashed keys in Redis", func(t *testing.T) {
		testKey := "sentinel-verify-hash"
		testValue := []byte("sentinel-verify-value")

		err := c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Verify the hashed key exists in Redis via raw client
		expectedHashedKey := keyPrefix + cache.HashKey(testKey)
		val, err := sentinelClient.Get(ctx, expectedHashedKey).Bytes()
		require.NoError(t, err, "hashed key should exist in Redis via sentinel")
		assert.Equal(t, testValue, val)
	})
}

// ---------------------------------------------------------------------------
// Vault Password Integration Tests
// ---------------------------------------------------------------------------

// TestIntegration_Cache_Features_VaultPassword tests that cache can connect
// to Redis using a password resolved from Vault.
func TestIntegration_Cache_Features_VaultPassword(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)
	helpers.SkipIfVaultUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("vault_password")

	// Setup Vault with a Redis password secret
	vaultSetup := helpers.SetupVaultForTesting(t)

	// Write the Redis password to Vault
	redisPassword := helpers.GetEnvOrDefault("TEST_REDIS_PASSWORD", "password")
	err := vaultSetup.WriteSecret("redis/standalone", map[string]interface{}{
		"password": redisPassword,
	})
	require.NoError(t, err, "should write redis password to vault")

	t.Cleanup(func() {
		_ = vaultSetup.DeleteSecret("redis/standalone")
	})

	// Cleanup Redis keys
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("cache connects using vault password", func(t *testing.T) {
		// Create a Redis URL without password (password will come from Vault)
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:               "redis://default@127.0.0.1:6379",
				KeyPrefix:         keyPrefix,
				PasswordVaultPath: helpers.GetVaultKVMount() + "/redis/standalone",
			},
		}

		// Create vault client using the vault package
		vaultCfg := &vault.Config{
			Enabled:    true,
			Address:    helpers.GetVaultAddr(),
			AuthMethod: vault.AuthMethodToken,
			Token:      helpers.GetVaultToken(),
		}

		vc, err := vault.New(vaultCfg, logger)
		require.NoError(t, err, "should create vault client")
		defer vc.Close()

		err = vc.Authenticate(ctx)
		require.NoError(t, err, "should authenticate with vault")

		c, err := cache.New(cfg, logger, cache.WithVaultClient(vc))
		require.NoError(t, err, "cache should connect using vault password")
		defer c.Close()

		// Verify cache operations work
		testKey := "vault-pw-test"
		testValue := []byte("vault-pw-value")

		err = c.Set(ctx, testKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		retrieved, err := c.Get(ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)
	})

	t.Run("invalid vault path returns error", func(t *testing.T) {
		cfg := &config.CacheConfig{
			Enabled: true,
			Type:    config.CacheTypeRedis,
			TTL:     config.Duration(5 * time.Minute),
			Redis: &config.RedisCacheConfig{
				URL:               "redis://default@127.0.0.1:6379",
				KeyPrefix:         keyPrefix + "invalid:",
				PasswordVaultPath: helpers.GetVaultKVMount() + "/nonexistent/path",
			},
		}

		vaultCfg := &vault.Config{
			Enabled:    true,
			Address:    helpers.GetVaultAddr(),
			AuthMethod: vault.AuthMethodToken,
			Token:      helpers.GetVaultToken(),
		}

		vc, err := vault.New(vaultCfg, logger)
		require.NoError(t, err, "should create vault client")
		defer vc.Close()

		err = vc.Authenticate(ctx)
		require.NoError(t, err, "should authenticate with vault")

		_, err = cache.New(cfg, logger, cache.WithVaultClient(vc))
		assert.Error(t, err, "should fail with invalid vault path")
	})
}

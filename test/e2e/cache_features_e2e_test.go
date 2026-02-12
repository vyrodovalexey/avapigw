//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// ---------------------------------------------------------------------------
// TTL Jitter E2E Tests
// ---------------------------------------------------------------------------

// TestE2E_Cache_Features_TTLJitter tests that a gateway with TTL jitter
// configured serves requests correctly and cached responses expire within
// the expected jitter range.
func TestE2E_Cache_Features_TTLJitter(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_ttl_jitter")

	// Create Redis cache with TTL jitter
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
			TTLJitter: 0.1,
		},
	}

	c, err := cache.New(cacheCfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	// Start gateway
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	cfg := createCacheFeaturesTestConfig(port, testCfg.Backend1URL, keyPrefix, 0.1, false)

	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("gateway with TTL jitter serves requests correctly", func(t *testing.T) {
		// Make request through gateway
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})

	t.Run("cached responses expire within expected jitter range", func(t *testing.T) {
		type cacheWithTTL interface {
			GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error)
		}
		cwt, ok := c.(cacheWithTTL)
		require.True(t, ok, "cache should support GetWithTTL")

		baseTTL := 3 * time.Second
		const numKeys = 10
		ttls := make([]time.Duration, 0, numKeys)

		for i := 0; i < numKeys; i++ {
			key := fmt.Sprintf("e2e:jitter:expire:%d", i)
			data := map[string]interface{}{
				"id":   fmt.Sprintf("item-%d", i),
				"name": fmt.Sprintf("Jitter Test Item %d", i),
			}
			dataBytes, err := json.Marshal(data)
			require.NoError(t, err)

			err = c.Set(ctx, key, dataBytes, baseTTL)
			require.NoError(t, err)

			_, remainingTTL, err := cwt.GetWithTTL(ctx, key)
			require.NoError(t, err)
			ttls = append(ttls, remainingTTL)
		}

		// Verify TTLs are within the jitter range (±10% of 3s = 2.7s to 3.3s)
		// Allow some margin for Redis round-trip
		minExpected := time.Duration(float64(baseTTL) * 0.80)
		maxExpected := time.Duration(float64(baseTTL) * 1.20)
		for i, ttl := range ttls {
			assert.Greater(t, ttl, minExpected,
				"key %d TTL %v should be > %v", i, ttl, minExpected)
			assert.Less(t, ttl, maxExpected,
				"key %d TTL %v should be < %v", i, ttl, maxExpected)
		}

		// Wait for all entries to expire (max possible TTL + margin)
		maxWait := time.Duration(float64(baseTTL)*1.15) + 500*time.Millisecond
		time.Sleep(maxWait)

		// Verify all entries have expired
		for i := 0; i < numKeys; i++ {
			key := fmt.Sprintf("e2e:jitter:expire:%d", i)
			_, err := c.Get(ctx, key)
			assert.ErrorIs(t, err, cache.ErrCacheMiss,
				"key %d should have expired after jitter TTL", i)
		}
	})
}

// ---------------------------------------------------------------------------
// Hash Keys E2E Tests
// ---------------------------------------------------------------------------

// TestE2E_Cache_Features_HashKeys tests that a gateway with hash keys enabled
// caches and serves correctly, and that keys in Redis are hashed.
func TestE2E_Cache_Features_HashKeys(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_hash_keys")

	// Create Redis cache with hash keys enabled
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
			HashKeys:  true,
		},
	}

	c, err := cache.New(cacheCfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	// Start gateway
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	cfg := createCacheFeaturesTestConfig(port, testCfg.Backend1URL, keyPrefix, 0, true)

	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("gateway with hash keys caches and serves correctly", func(t *testing.T) {
		// Cache some data with hash keys
		cacheKey := "e2e:hashkeys:items:list"
		cachedResponse := map[string]interface{}{
			"success": true,
			"data": []map[string]interface{}{
				{"id": "hk-1", "name": "Hash Key Item 1"},
				{"id": "hk-2", "name": "Hash Key Item 2"},
			},
		}

		cachedBytes, err := json.Marshal(cachedResponse)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, cachedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve from cache
		retrievedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var retrievedData map[string]interface{}
		err = json.Unmarshal(retrievedBytes, &retrievedData)
		require.NoError(t, err)

		assert.True(t, retrievedData["success"].(bool))
		data, ok := retrievedData["data"].([]interface{})
		require.True(t, ok)
		assert.Len(t, data, 2)
	})

	t.Run("keys in Redis are hashed", func(t *testing.T) {
		cacheKey := "e2e:hashkeys:verify"
		testValue := []byte(`{"verified":true}`)

		err := c.Set(ctx, cacheKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		// Verify the hashed key exists in Redis
		expectedHashedKey := keyPrefix + cache.HashKey(cacheKey)
		val, err := redisClient.Get(ctx, expectedHashedKey).Bytes()
		require.NoError(t, err, "hashed key should exist in Redis")
		assert.Equal(t, testValue, val)

		// Verify the plain key does NOT exist
		plainKey := keyPrefix + cacheKey
		_, err = redisClient.Get(ctx, plainKey).Result()
		assert.Error(t, err, "plain key should NOT exist when HashKeys=true")
	})

	t.Run("gateway serves requests with hash keys enabled", func(t *testing.T) {
		// Make request through gateway
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})

	t.Run("complete cache journey with hash keys", func(t *testing.T) {
		cacheKey := "e2e:hashkeys:journey"

		// 1. Cache miss
		_, err := c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// 2. Store data
		testData := []byte(`{"id":"journey-1","name":"Journey Item"}`)
		err = c.Set(ctx, cacheKey, testData, 5*time.Minute)
		require.NoError(t, err)

		// 3. Cache hit
		retrieved, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)
		assert.Equal(t, testData, retrieved)

		// 4. Verify hashed key in Redis
		hashedKey := keyPrefix + cache.HashKey(cacheKey)
		exists, err := redisClient.Exists(ctx, hashedKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists, "hashed key should exist in Redis")

		// 5. Invalidate
		err = c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		// 6. Verify deleted
		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// 7. Verify hashed key removed from Redis
		exists, err = redisClient.Exists(ctx, hashedKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(0), exists, "hashed key should be removed from Redis")
	})
}

// ---------------------------------------------------------------------------
// Combined Features E2E Test
// ---------------------------------------------------------------------------

// TestE2E_Cache_Features_Combined tests that TTL jitter and hash keys work
// together correctly in an end-to-end scenario.
func TestE2E_Cache_Features_Combined(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_combined_features")

	// Create Redis cache with both features enabled
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
			TTLJitter: 0.1,
			HashKeys:  true,
		},
	}

	c, err := cache.New(cacheCfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	t.Run("store and retrieve with both features", func(t *testing.T) {
		cacheKey := "combined:test:key"
		testValue := []byte(`{"combined":true,"features":["ttl_jitter","hash_keys"]}`)

		err := c.Set(ctx, cacheKey, testValue, 5*time.Minute)
		require.NoError(t, err)

		retrieved, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrieved)

		// Verify key is hashed in Redis
		hashedKey := keyPrefix + cache.HashKey(cacheKey)
		val, err := redisClient.Get(ctx, hashedKey).Bytes()
		require.NoError(t, err)
		assert.Equal(t, testValue, val)
	})

	t.Run("TTL jitter applied with hashed keys", func(t *testing.T) {
		type cacheWithTTL interface {
			GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error)
		}
		cwt, ok := c.(cacheWithTTL)
		require.True(t, ok)

		baseTTL := 10 * time.Minute
		const numKeys = 10
		ttls := make([]time.Duration, 0, numKeys)

		for i := 0; i < numKeys; i++ {
			key := fmt.Sprintf("combined:jitter:%d", i)
			value := []byte(fmt.Sprintf("combined-value-%d", i))

			err := c.Set(ctx, key, value, baseTTL)
			require.NoError(t, err)

			_, remainingTTL, err := cwt.GetWithTTL(ctx, key)
			require.NoError(t, err)
			ttls = append(ttls, remainingTTL)

			// Verify key is hashed
			hashedKey := keyPrefix + cache.HashKey(key)
			exists, err := redisClient.Exists(ctx, hashedKey).Result()
			require.NoError(t, err)
			assert.Equal(t, int64(1), exists, "hashed key %d should exist", i)
		}

		// Verify TTLs vary (jitter applied)
		allSame := true
		for i := 1; i < len(ttls); i++ {
			if ttls[i] != ttls[0] {
				allSame = false
				break
			}
		}
		assert.False(t, allSame, "TTLs should vary with jitter even when hash keys are enabled")
	})
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// createCacheFeaturesTestConfig creates a gateway config for cache features E2E tests.
func createCacheFeaturesTestConfig(
	port int, backendURL, keyPrefix string, ttlJitter float64, hashKeys bool,
) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "cache-features-e2e-test-gateway",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			Routes: []config.Route{
				{
					Name: "health-check",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Exact: "/health"},
							Methods: []string{"GET"},
						},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status:  200,
						Body:    `{"status":"healthy","gateway":"cache-features-e2e-test"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "cached-api",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Prefix: "/api/v1/"},
							Methods: []string{"GET", "POST", "PUT", "DELETE"},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8801,
							},
							Weight: 100,
						},
					},
					Timeout: config.Duration(30 * time.Second),
					Cache: &config.CacheConfig{
						Enabled: true,
						Type:    config.CacheTypeRedis,
						TTL:     config.Duration(5 * time.Minute),
						Redis: &config.RedisCacheConfig{
							URL:       helpers.GetRedisURL(),
							KeyPrefix: keyPrefix,
							TTLJitter: ttlJitter,
							HashKeys:  hashKeys,
						},
					},
				},
			},
		},
	}
}

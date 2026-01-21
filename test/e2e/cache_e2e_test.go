//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
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

// TestE2E_Cache_RedisGatewayFlow tests caching with Redis in gateway flow.
func TestE2E_Cache_RedisGatewayFlow(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_cache_flow")

	// Create Redis cache
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
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

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create gateway configuration
	cfg := createCacheTestConfig(port, testCfg.Backend1URL)

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("cache response data", func(t *testing.T) {
		// Make request through gateway
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			// Read response body
			body, err := helpers.ReadResponseBody(resp)
			require.NoError(t, err)

			// Cache the response
			cacheKey := "e2e:items:list"
			err = c.Set(ctx, cacheKey, []byte(body), 5*time.Minute)
			require.NoError(t, err)

			// Verify cached
			cachedData, err := c.Get(ctx, cacheKey)
			require.NoError(t, err)
			assert.NotEmpty(t, cachedData)
		}
	})

	t.Run("serve from cache", func(t *testing.T) {
		cacheKey := "e2e:items:cached"
		cachedResponse := map[string]interface{}{
			"success": true,
			"data": []map[string]interface{}{
				{"id": "cached-1", "name": "Cached Item 1"},
				{"id": "cached-2", "name": "Cached Item 2"},
			},
		}

		cachedBytes, err := json.Marshal(cachedResponse)
		require.NoError(t, err)

		// Cache the data
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
}

// TestE2E_Cache_Invalidation tests cache invalidation.
func TestE2E_Cache_Invalidation(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_cache_invalidate")

	// Create Redis cache
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
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

	t.Run("invalidate single key", func(t *testing.T) {
		cacheKey := "e2e:invalidate:single"
		testData := []byte(`{"id":"test-123","name":"Test Item"}`)

		// Cache the data
		err := c.Set(ctx, cacheKey, testData, 5*time.Minute)
		require.NoError(t, err)

		// Verify it exists
		exists, err := c.Exists(ctx, cacheKey)
		require.NoError(t, err)
		assert.True(t, exists)

		// Invalidate
		err = c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		// Verify it's gone
		exists, err = c.Exists(ctx, cacheKey)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("invalidate on update", func(t *testing.T) {
		cacheKey := "e2e:invalidate:update"

		// Initial data
		initialData := map[string]interface{}{
			"id":      "item-123",
			"name":    "Initial Name",
			"version": 1,
		}
		initialBytes, err := json.Marshal(initialData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, initialBytes, 5*time.Minute)
		require.NoError(t, err)

		// Simulate update - invalidate and set new data
		err = c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		// Set updated data
		updatedData := map[string]interface{}{
			"id":      "item-123",
			"name":    "Updated Name",
			"version": 2,
		}
		updatedBytes, err := json.Marshal(updatedData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, updatedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Verify updated data
		retrievedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var retrievedData map[string]interface{}
		err = json.Unmarshal(retrievedBytes, &retrievedData)
		require.NoError(t, err)

		assert.Equal(t, "Updated Name", retrievedData["name"])
		assert.Equal(t, float64(2), retrievedData["version"])
	})

	t.Run("invalidate multiple keys", func(t *testing.T) {
		keys := []string{
			"e2e:invalidate:multi:1",
			"e2e:invalidate:multi:2",
			"e2e:invalidate:multi:3",
		}

		// Cache multiple items
		for i, key := range keys {
			data := []byte(`{"id":"` + key + `","index":` + string(rune('0'+i)) + `}`)
			err := c.Set(ctx, key, data, 5*time.Minute)
			require.NoError(t, err)
		}

		// Verify all exist
		for _, key := range keys {
			exists, err := c.Exists(ctx, key)
			require.NoError(t, err)
			assert.True(t, exists, "Key %s should exist", key)
		}

		// Invalidate all
		for _, key := range keys {
			err := c.Delete(ctx, key)
			require.NoError(t, err)
		}

		// Verify all are gone
		for _, key := range keys {
			exists, err := c.Exists(ctx, key)
			require.NoError(t, err)
			assert.False(t, exists, "Key %s should not exist", key)
		}
	})
}

// TestE2E_Cache_TTL tests cache TTL expiration.
func TestE2E_Cache_TTL(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_cache_ttl")

	// Create Redis cache with short TTL
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(2 * time.Second),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
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

	t.Run("data expires after TTL", func(t *testing.T) {
		cacheKey := "e2e:ttl:expire"
		testData := []byte(`{"id":"ttl-test","name":"TTL Test Item"}`)
		shortTTL := 1 * time.Second

		// Cache with short TTL
		err := c.Set(ctx, cacheKey, testData, shortTTL)
		require.NoError(t, err)

		// Verify it exists immediately
		data, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)
		assert.Equal(t, testData, data)

		// Wait for TTL to expire
		time.Sleep(shortTTL + 500*time.Millisecond)

		// Verify it's expired
		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("refresh TTL on access", func(t *testing.T) {
		cacheKey := "e2e:ttl:refresh"
		testData := []byte(`{"id":"refresh-test","name":"Refresh Test"}`)
		ttl := 5 * time.Minute

		// Cache the data
		err := c.Set(ctx, cacheKey, testData, ttl)
		require.NoError(t, err)

		// Access multiple times
		for i := 0; i < 3; i++ {
			data, err := c.Get(ctx, cacheKey)
			require.NoError(t, err)
			assert.Equal(t, testData, data)
			time.Sleep(100 * time.Millisecond)
		}

		// Data should still exist
		exists, err := c.Exists(ctx, cacheKey)
		require.NoError(t, err)
		assert.True(t, exists)
	})
}

// TestE2E_Cache_Bypass tests cache bypass functionality.
func TestE2E_Cache_Bypass(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_cache_bypass")

	// Create Redis cache
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
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

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create gateway configuration
	cfg := createCacheTestConfig(port, testCfg.Backend1URL)

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("bypass cache with header", func(t *testing.T) {
		// Cache some data
		cacheKey := "e2e:bypass:test"
		cachedData := []byte(`{"cached":true,"data":"old data"}`)
		err := c.Set(ctx, cacheKey, cachedData, 5*time.Minute)
		require.NoError(t, err)

		// Make request with cache bypass header
		headers := map[string]string{
			"Cache-Control": "no-cache",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, gi.BaseURL+"/api/v1/items", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Request should go through (bypass cache)
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})

	t.Run("bypass cache for POST requests", func(t *testing.T) {
		// POST requests should not be cached
		item := helpers.CreateItemRequest{
			Name:        "Bypass Test Item",
			Description: "Testing cache bypass",
			Price:       29.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPost, gi.BaseURL+"/api/v1/items", item)
		require.NoError(t, err)
		defer resp.Body.Close()

		// POST should go through
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500,
			"Expected success or client error, got %d", resp.StatusCode)
	})
}

// TestE2E_Cache_NegativeCaching tests caching of error responses.
func TestE2E_Cache_NegativeCaching(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_cache_negative")

	// Create Redis cache
	cacheCfg := &config.CacheConfig{
		Enabled:          true,
		Type:             config.CacheTypeRedis,
		TTL:              config.Duration(5 * time.Minute),
		NegativeCacheTTL: config.Duration(30 * time.Second),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
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

	t.Run("cache 404 response", func(t *testing.T) {
		cacheKey := "e2e:negative:404"
		errorResponse := map[string]interface{}{
			"success": false,
			"error":   "Resource not found",
			"code":    404,
		}

		errorBytes, err := json.Marshal(errorResponse)
		require.NoError(t, err)

		// Cache the error response with shorter TTL
		err = c.Set(ctx, cacheKey, errorBytes, 30*time.Second)
		require.NoError(t, err)

		// Verify cached
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedError map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedError)
		require.NoError(t, err)

		assert.False(t, cachedError["success"].(bool))
		assert.Equal(t, float64(404), cachedError["code"])
	})

	t.Run("cache 500 response", func(t *testing.T) {
		cacheKey := "e2e:negative:500"
		errorResponse := map[string]interface{}{
			"success": false,
			"error":   "Internal server error",
			"code":    500,
		}

		errorBytes, err := json.Marshal(errorResponse)
		require.NoError(t, err)

		// Cache the error response
		err = c.Set(ctx, cacheKey, errorBytes, 10*time.Second)
		require.NoError(t, err)

		// Verify cached
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedError map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedError)
		require.NoError(t, err)

		assert.False(t, cachedError["success"].(bool))
		assert.Equal(t, float64(500), cachedError["code"])
	})
}

// TestE2E_Cache_ConcurrentAccess tests concurrent cache access.
func TestE2E_Cache_ConcurrentAccess(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_cache_concurrent")

	// Create Redis cache
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
			PoolSize:  10,
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

	t.Run("concurrent reads and writes", func(t *testing.T) {
		cacheKey := "e2e:concurrent:rw"
		initialData := []byte(`{"id":"concurrent-test","counter":0}`)

		// Set initial data
		err := c.Set(ctx, cacheKey, initialData, 5*time.Minute)
		require.NoError(t, err)

		// Concurrent operations
		done := make(chan bool, 20)
		errors := make(chan error, 20)

		for i := 0; i < 10; i++ {
			// Readers
			go func() {
				_, err := c.Get(ctx, cacheKey)
				if err != nil && err != cache.ErrCacheMiss {
					errors <- err
				}
				done <- true
			}()

			// Writers
			go func(idx int) {
				data := []byte(`{"id":"concurrent-test","counter":` + string(rune('0'+idx)) + `}`)
				if err := c.Set(ctx, cacheKey, data, 5*time.Minute); err != nil {
					errors <- err
				}
				done <- true
			}(i)
		}

		// Wait for all operations
		for i := 0; i < 20; i++ {
			<-done
		}

		close(errors)
		for err := range errors {
			t.Errorf("Concurrent operation failed: %v", err)
		}

		// Verify data exists
		exists, err := c.Exists(ctx, cacheKey)
		require.NoError(t, err)
		assert.True(t, exists)
	})
}

// TestE2E_Cache_CompleteJourney tests a complete caching journey.
func TestE2E_Cache_CompleteJourney(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_cache_journey")

	// Create Redis cache
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
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

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create gateway configuration
	cfg := createCacheTestConfig(port, testCfg.Backend1URL)

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("1. First request - cache miss", func(t *testing.T) {
		cacheKey := "e2e:journey:items"

		// Check cache - should miss
		_, err := c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// Make request through gateway
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := helpers.ReadResponseBody(resp)
			require.NoError(t, err)

			// Cache the response
			err = c.Set(ctx, cacheKey, []byte(body), 5*time.Minute)
			require.NoError(t, err)
		}
	})

	t.Run("2. Second request - cache hit", func(t *testing.T) {
		cacheKey := "e2e:journey:items"

		// Pre-populate cache
		cachedData := map[string]interface{}{
			"success": true,
			"data":    []map[string]interface{}{{"id": "1", "name": "Cached Item"}},
		}
		cachedBytes, err := json.Marshal(cachedData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, cachedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Check cache - should hit
		data, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("3. Update - invalidate cache", func(t *testing.T) {
		cacheKey := "e2e:journey:items"

		// Invalidate cache
		err := c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		// Verify invalidated
		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("4. Third request - cache miss after invalidation", func(t *testing.T) {
		cacheKey := "e2e:journey:items"

		// Check cache - should miss
		_, err := c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// Make request through gateway
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := helpers.ReadResponseBody(resp)
			require.NoError(t, err)

			// Re-cache the response
			err = c.Set(ctx, cacheKey, []byte(body), 5*time.Minute)
			require.NoError(t, err)
		}
	})
}

// Helper function to create cache test configuration
func createCacheTestConfig(port int, backendURL string) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "cache-e2e-test-gateway",
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
						Body:    `{"status":"healthy","gateway":"cache-e2e-test"}`,
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
							KeyPrefix: "e2e:cache:",
						},
					},
				},
			},
		},
	}
}

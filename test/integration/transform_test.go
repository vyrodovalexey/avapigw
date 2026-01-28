//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/transform"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_Transform_WithRedisCache tests transformation with Redis caching.
func TestIntegration_Transform_WithRedisCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("transform_cache")

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

	// Create transformer
	transformer := transform.NewResponseTransformer(logger)

	t.Run("Transform and cache result", func(t *testing.T) {
		// Test data
		testData := helpers.CreateTestData()

		// Transform configuration
		transformCfg := &config.ResponseTransformConfig{
			AllowFields: []string{"id", "name", "email"},
			DenyFields:  []string{"password"},
		}

		// Transform the data
		transformed, err := transformer.TransformResponse(ctx, testData, transformCfg)
		require.NoError(t, err)

		// Cache the transformed result
		cacheKey := "transform:test:1"
		transformedBytes, err := json.Marshal(transformed)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, transformedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve from cache
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedData map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedData)
		require.NoError(t, err)

		// Verify transformed data
		transformedMap, ok := transformed.(map[string]interface{})
		require.True(t, ok)

		assert.Equal(t, transformedMap["id"], cachedData["id"])
		assert.Equal(t, transformedMap["name"], cachedData["name"])
		assert.Equal(t, transformedMap["email"], cachedData["email"])
		assert.NotContains(t, cachedData, "password")
	})

	t.Run("Cache hit returns same transformed data", func(t *testing.T) {
		// Pre-cache some transformed data
		cacheKey := "transform:cached:1"
		cachedData := map[string]interface{}{
			"id":   "cached-123",
			"name": "Cached Item",
		}
		cachedBytes, err := json.Marshal(cachedData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, cachedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve from cache
		retrievedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var retrievedData map[string]interface{}
		err = json.Unmarshal(retrievedBytes, &retrievedData)
		require.NoError(t, err)

		assert.Equal(t, cachedData["id"], retrievedData["id"])
		assert.Equal(t, cachedData["name"], retrievedData["name"])
	})
}

// TestIntegration_Transform_CacheInvalidation tests transformation cache invalidation.
func TestIntegration_Transform_CacheInvalidation(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("transform_invalidate")

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

	t.Run("Invalidate cached transformation", func(t *testing.T) {
		cacheKey := "transform:invalidate:1"
		cachedData := map[string]interface{}{
			"id":   "to-invalidate",
			"name": "Will be invalidated",
		}
		cachedBytes, err := json.Marshal(cachedData)
		require.NoError(t, err)

		// Cache the data
		err = c.Set(ctx, cacheKey, cachedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Verify it exists
		exists, err := c.Exists(ctx, cacheKey)
		require.NoError(t, err)
		assert.True(t, exists)

		// Invalidate (delete) the cache
		err = c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		// Verify it's invalidated
		exists, err = c.Exists(ctx, cacheKey)
		require.NoError(t, err)
		assert.False(t, exists)

		// Get should return cache miss
		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})

	t.Run("Update cached transformation", func(t *testing.T) {
		cacheKey := "transform:update:1"

		// Initial data
		initialData := map[string]interface{}{
			"id":      "update-123",
			"name":    "Initial Name",
			"version": 1,
		}
		initialBytes, err := json.Marshal(initialData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, initialBytes, 5*time.Minute)
		require.NoError(t, err)

		// Updated data
		updatedData := map[string]interface{}{
			"id":      "update-123",
			"name":    "Updated Name",
			"version": 2,
		}
		updatedBytes, err := json.Marshal(updatedData)
		require.NoError(t, err)

		// Update the cache
		err = c.Set(ctx, cacheKey, updatedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		retrievedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var retrievedData map[string]interface{}
		err = json.Unmarshal(retrievedBytes, &retrievedData)
		require.NoError(t, err)

		assert.Equal(t, "Updated Name", retrievedData["name"])
		assert.Equal(t, float64(2), retrievedData["version"])
	})
}

// TestIntegration_Transform_CacheMiss tests transformation with cache miss.
func TestIntegration_Transform_CacheMiss(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("transform_miss")

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

	// Create transformer
	transformer := transform.NewResponseTransformer(logger)

	t.Run("Cache miss triggers transformation", func(t *testing.T) {
		cacheKey := "transform:miss:1"

		// Try to get from cache (should miss)
		_, err := c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// On cache miss, perform transformation
		testData := helpers.CreateTestData()
		transformCfg := &config.ResponseTransformConfig{
			AllowFields: []string{"id", "name"},
		}

		transformed, err := transformer.TransformResponse(ctx, testData, transformCfg)
		require.NoError(t, err)

		// Cache the result
		transformedBytes, err := json.Marshal(transformed)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, transformedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Subsequent get should hit cache
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedData map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedData)
		require.NoError(t, err)

		assert.Contains(t, cachedData, "id")
		assert.Contains(t, cachedData, "name")
	})

	t.Run("Simulate cache-aside pattern", func(t *testing.T) {
		cacheKey := "transform:aside:1"

		// Cache-aside pattern: try cache first, then compute and cache
		getData := func() (map[string]interface{}, error) {
			// Try cache first
			cachedBytes, err := c.Get(ctx, cacheKey)
			if err == nil {
				var data map[string]interface{}
				if err := json.Unmarshal(cachedBytes, &data); err == nil {
					return data, nil
				}
			}

			// Cache miss - compute the data
			testData := helpers.CreateNestedTestData()
			transformCfg := &config.ResponseTransformConfig{
				AllowFields: []string{"user"},
			}

			transformed, err := transformer.TransformResponse(ctx, testData, transformCfg)
			if err != nil {
				return nil, err
			}

			transformedMap, ok := transformed.(map[string]interface{})
			if !ok {
				return nil, assert.AnError
			}

			// Cache the result
			transformedBytes, err := json.Marshal(transformedMap)
			if err != nil {
				return nil, err
			}

			if err := c.Set(ctx, cacheKey, transformedBytes, 5*time.Minute); err != nil {
				return nil, err
			}

			return transformedMap, nil
		}

		// First call - should miss cache and compute
		data1, err := getData()
		require.NoError(t, err)
		assert.Contains(t, data1, "user")

		// Second call - should hit cache
		data2, err := getData()
		require.NoError(t, err)
		assert.Equal(t, data1["user"], data2["user"])
	})
}

// TestIntegration_Transform_StaleWhileRevalidate tests stale-while-revalidate pattern.
func TestIntegration_Transform_StaleWhileRevalidate(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("transform_swr")

	// Create Redis cache with short TTL
	cacheCfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(1 * time.Second), // Short TTL for testing
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

	t.Run("Stale data expires and requires revalidation", func(t *testing.T) {
		cacheKey := "transform:swr:1"
		staleData := map[string]interface{}{
			"id":        "swr-123",
			"name":      "Stale Data",
			"timestamp": time.Now().Unix(),
		}
		staleBytes, err := json.Marshal(staleData)
		require.NoError(t, err)

		// Cache with short TTL
		err = c.Set(ctx, cacheKey, staleBytes, 1*time.Second)
		require.NoError(t, err)

		// Verify data is available
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)
		assert.NotEmpty(t, cachedBytes)

		// Wait for TTL to expire
		time.Sleep(1500 * time.Millisecond)

		// Data should be expired (cache miss)
		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// Revalidate by setting fresh data
		freshData := map[string]interface{}{
			"id":        "swr-123",
			"name":      "Fresh Data",
			"timestamp": time.Now().Unix(),
		}
		freshBytes, err := json.Marshal(freshData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, freshBytes, 5*time.Minute)
		require.NoError(t, err)

		// Verify fresh data is available
		retrievedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var retrievedData map[string]interface{}
		err = json.Unmarshal(retrievedBytes, &retrievedData)
		require.NoError(t, err)

		assert.Equal(t, "Fresh Data", retrievedData["name"])
	})
}

// TestIntegration_Transform_FieldMappingWithCache tests field mapping with caching.
func TestIntegration_Transform_FieldMappingWithCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("transform_mapping")

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

	// Create transformer
	transformer := transform.NewResponseTransformer(logger)

	t.Run("Field mapping transformation is cached correctly", func(t *testing.T) {
		testData := map[string]interface{}{
			"user_id":    "123",
			"user_name":  "John Doe",
			"user_email": "john@example.com",
		}

		transformCfg := &config.ResponseTransformConfig{
			FieldMappings: []config.FieldMapping{
				{Source: "user_id", Target: "id"},
				{Source: "user_name", Target: "name"},
				{Source: "user_email", Target: "email"},
			},
		}

		// Transform
		transformed, err := transformer.TransformResponse(ctx, testData, transformCfg)
		require.NoError(t, err)

		// Cache
		cacheKey := "transform:mapping:1"
		transformedBytes, err := json.Marshal(transformed)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, transformedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedData map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedData)
		require.NoError(t, err)

		assert.Equal(t, "123", cachedData["id"])
		assert.Equal(t, "John Doe", cachedData["name"])
		assert.Equal(t, "john@example.com", cachedData["email"])
	})
}

// TestIntegration_Transform_ArrayOperationsWithCache tests array operations with caching.
func TestIntegration_Transform_ArrayOperationsWithCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("transform_array")

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

	// Create transformer
	transformer := transform.NewResponseTransformer(logger)

	t.Run("Array transformation is cached correctly", func(t *testing.T) {
		testData := map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"id": 1, "name": "Item 1", "price": 10.0},
				map[string]interface{}{"id": 2, "name": "Item 2", "price": 20.0},
				map[string]interface{}{"id": 3, "name": "Item 3", "price": 30.0},
			},
		}

		transformCfg := &config.ResponseTransformConfig{
			ArrayOperations: []config.ArrayOperation{
				{Field: "items", Operation: config.ArrayOperationLimit, Value: 2},
			},
		}

		// Transform
		transformed, err := transformer.TransformResponse(ctx, testData, transformCfg)
		require.NoError(t, err)

		// Cache
		cacheKey := "transform:array:1"
		transformedBytes, err := json.Marshal(transformed)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, transformedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedData map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedData)
		require.NoError(t, err)

		items, ok := cachedData["items"].([]interface{})
		require.True(t, ok)
		assert.Len(t, items, 2)
	})
}

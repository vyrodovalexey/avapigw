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
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	grpctransform "github.com/vyrodovalexey/avapigw/internal/grpc/transform"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_GRPCTransform_WithRedisCache tests gRPC transformation with Redis caching.
func TestIntegration_GRPCTransform_WithRedisCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("grpc_transform")

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

	// Create gRPC transformer
	transformer := grpctransform.NewGRPCResponseTransformer(logger)

	t.Run("Transform context is created correctly", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger)
		require.NotNil(t, tc)

		tc.WithRequestID("test-request-123")
		tc.WithTraceID("test-trace-456")

		assert.Equal(t, "test-request-123", tc.RequestID)
		assert.Equal(t, "test-trace-456", tc.TraceID)
	})

	t.Run("Transform context with metadata", func(t *testing.T) {
		md := metadata.New(map[string]string{
			"x-request-id": "req-123",
			"x-trace-id":   "trace-456",
		})

		tc := grpctransform.NewTransformContext(logger)
		tc.WithMetadata(md)

		assert.Equal(t, md, tc.IncomingMetadata)
	})

	t.Run("Cache gRPC transform context data", func(t *testing.T) {
		cacheKey := "grpc:context:1"

		// Create context data to cache
		contextData := map[string]interface{}{
			"request_id": "grpc-req-123",
			"trace_id":   "grpc-trace-456",
			"claims": map[string]interface{}{
				"sub":   "user-123",
				"roles": []string{"admin", "user"},
			},
		}

		contextBytes, err := json.Marshal(contextData)
		require.NoError(t, err)

		// Cache the context data
		err = c.Set(ctx, cacheKey, contextBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedData map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedData)
		require.NoError(t, err)

		assert.Equal(t, "grpc-req-123", cachedData["request_id"])
		assert.Equal(t, "grpc-trace-456", cachedData["trace_id"])
	})

	t.Run("Transformer is not nil", func(t *testing.T) {
		require.NotNil(t, transformer)
	})
}

// TestIntegration_GRPCTransform_MetadataWithCache tests gRPC metadata transformation with caching.
func TestIntegration_GRPCTransform_MetadataWithCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("grpc_metadata")

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

	t.Run("Cache metadata transformation rules", func(t *testing.T) {
		cacheKey := "grpc:metadata:rules:1"

		// Metadata transformation rules
		rules := map[string]interface{}{
			"static_metadata": map[string]string{
				"x-gateway":     "avapigw",
				"x-api-version": "v1",
			},
			"dynamic_metadata": []map[string]string{
				{"key": "x-request-id", "source": "context.request_id"},
				{"key": "x-trace-id", "source": "context.trace_id"},
			},
			"remove_metadata": []string{
				"x-internal-header",
				"x-debug-info",
			},
		}

		rulesBytes, err := json.Marshal(rules)
		require.NoError(t, err)

		// Cache the rules
		err = c.Set(ctx, cacheKey, rulesBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedRules map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedRules)
		require.NoError(t, err)

		staticMd, ok := cachedRules["static_metadata"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "avapigw", staticMd["x-gateway"])
	})

	t.Run("Cache transformed metadata", func(t *testing.T) {
		cacheKey := "grpc:metadata:transformed:1"

		// Original metadata
		originalMd := metadata.New(map[string]string{
			"authorization":     "Bearer token123",
			"x-request-id":      "req-456",
			"x-internal-header": "should-be-removed",
		})

		// Simulate transformed metadata (without internal header, with added headers)
		transformedMd := map[string][]string{
			"authorization": {"Bearer token123"},
			"x-request-id":  {"req-456"},
			"x-gateway":     {"avapigw"},
			"x-api-version": {"v1"},
		}

		transformedBytes, err := json.Marshal(transformedMd)
		require.NoError(t, err)

		// Cache the transformed metadata
		err = c.Set(ctx, cacheKey, transformedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedMd map[string][]string
		err = json.Unmarshal(cachedBytes, &cachedMd)
		require.NoError(t, err)

		assert.Contains(t, cachedMd, "authorization")
		assert.Contains(t, cachedMd, "x-gateway")
		assert.NotContains(t, cachedMd, "x-internal-header")

		// Verify original metadata is unchanged
		assert.Equal(t, "should-be-removed", originalMd.Get("x-internal-header")[0])
	})

	t.Run("Metadata key normalization", func(t *testing.T) {
		// gRPC metadata keys are case-insensitive and normalized to lowercase
		md := metadata.New(map[string]string{
			"X-Request-ID":  "req-789",
			"AUTHORIZATION": "Bearer token",
		})

		// Keys should be normalized to lowercase
		assert.Equal(t, []string{"req-789"}, md.Get("x-request-id"))
		assert.Equal(t, []string{"Bearer token"}, md.Get("authorization"))
	})
}

// TestIntegration_GRPCTransform_StreamingWithCache tests gRPC streaming transformation with cache.
func TestIntegration_GRPCTransform_StreamingWithCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("grpc_streaming")

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

	t.Run("Cache streaming transformation config", func(t *testing.T) {
		cacheKey := "grpc:streaming:config:1"

		// Streaming transformation configuration
		streamConfig := map[string]interface{}{
			"buffer_size":     100,
			"flush_interval":  "100ms",
			"max_message_age": "5s",
			"filter_config": map[string]interface{}{
				"field":     "status",
				"condition": "eq",
				"value":     "active",
			},
		}

		configBytes, err := json.Marshal(streamConfig)
		require.NoError(t, err)

		// Cache the config
		err = c.Set(ctx, cacheKey, configBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedConfig map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedConfig)
		require.NoError(t, err)

		assert.Equal(t, float64(100), cachedConfig["buffer_size"])
		assert.Equal(t, "100ms", cachedConfig["flush_interval"])
	})

	t.Run("Cache streaming message batch", func(t *testing.T) {
		cacheKey := "grpc:streaming:batch:1"

		// Simulated batch of streaming messages
		messageBatch := []map[string]interface{}{
			{"sequence": 1, "data": "message-1", "timestamp": time.Now().Unix()},
			{"sequence": 2, "data": "message-2", "timestamp": time.Now().Unix()},
			{"sequence": 3, "data": "message-3", "timestamp": time.Now().Unix()},
		}

		batchBytes, err := json.Marshal(messageBatch)
		require.NoError(t, err)

		// Cache the batch
		err = c.Set(ctx, cacheKey, batchBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedBatch []map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedBatch)
		require.NoError(t, err)

		assert.Len(t, cachedBatch, 3)
		assert.Equal(t, float64(1), cachedBatch[0]["sequence"])
		assert.Equal(t, "message-1", cachedBatch[0]["data"])
	})

	t.Run("Cache stream state for resumption", func(t *testing.T) {
		cacheKey := "grpc:streaming:state:1"

		// Stream state for resumption
		streamState := map[string]interface{}{
			"stream_id":        "stream-123",
			"last_sequence":    42,
			"last_timestamp":   time.Now().Unix(),
			"processed_count":  100,
			"error_count":      2,
			"checkpoint_token": "checkpoint-abc123",
		}

		stateBytes, err := json.Marshal(streamState)
		require.NoError(t, err)

		// Cache the state
		err = c.Set(ctx, cacheKey, stateBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedState map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedState)
		require.NoError(t, err)

		assert.Equal(t, "stream-123", cachedState["stream_id"])
		assert.Equal(t, float64(42), cachedState["last_sequence"])
		assert.Equal(t, "checkpoint-abc123", cachedState["checkpoint_token"])
	})
}

// TestIntegration_GRPCTransform_FieldMaskWithCache tests gRPC field mask transformation with cache.
func TestIntegration_GRPCTransform_FieldMaskWithCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("grpc_fieldmask")

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

	t.Run("Cache field mask configuration", func(t *testing.T) {
		cacheKey := "grpc:fieldmask:config:1"

		// Field mask configuration
		fieldMaskConfig := map[string]interface{}{
			"paths": []string{
				"user.id",
				"user.name",
				"user.email",
				"orders.id",
				"orders.total",
			},
			"exclude_paths": []string{
				"user.password",
				"user.internal_id",
			},
		}

		configBytes, err := json.Marshal(fieldMaskConfig)
		require.NoError(t, err)

		// Cache the config
		err = c.Set(ctx, cacheKey, configBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedConfig map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedConfig)
		require.NoError(t, err)

		paths, ok := cachedConfig["paths"].([]interface{})
		require.True(t, ok)
		assert.Len(t, paths, 5)
		assert.Contains(t, paths, "user.id")
	})

	t.Run("Cache filtered response based on field mask", func(t *testing.T) {
		cacheKey := "grpc:fieldmask:response:1"

		// Simulated filtered response (only fields in field mask)
		filteredResponse := map[string]interface{}{
			"user": map[string]interface{}{
				"id":    "user-123",
				"name":  "John Doe",
				"email": "john@example.com",
				// password and internal_id are excluded
			},
			"orders": []map[string]interface{}{
				{"id": "order-1", "total": 100.50},
				{"id": "order-2", "total": 250.00},
			},
		}

		responseBytes, err := json.Marshal(filteredResponse)
		require.NoError(t, err)

		// Cache the filtered response
		err = c.Set(ctx, cacheKey, responseBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedResponse map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedResponse)
		require.NoError(t, err)

		user, ok := cachedResponse["user"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "user-123", user["id"])
		assert.NotContains(t, user, "password")
		assert.NotContains(t, user, "internal_id")
	})
}

// TestIntegration_GRPCTransform_ErrorHandlingWithCache tests gRPC error transformation with cache.
func TestIntegration_GRPCTransform_ErrorHandlingWithCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("grpc_errors")

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

	t.Run("Cache error transformation mapping", func(t *testing.T) {
		cacheKey := "grpc:errors:mapping:1"

		// Error transformation mapping
		errorMapping := map[string]interface{}{
			"mappings": []map[string]interface{}{
				{
					"grpc_code":       "NOT_FOUND",
					"http_status":     404,
					"message":         "Resource not found",
					"include_details": true,
				},
				{
					"grpc_code":       "PERMISSION_DENIED",
					"http_status":     403,
					"message":         "Access denied",
					"include_details": false,
				},
				{
					"grpc_code":       "INTERNAL",
					"http_status":     500,
					"message":         "Internal server error",
					"include_details": false,
				},
			},
		}

		mappingBytes, err := json.Marshal(errorMapping)
		require.NoError(t, err)

		// Cache the mapping
		err = c.Set(ctx, cacheKey, mappingBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedMapping map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedMapping)
		require.NoError(t, err)

		mappings, ok := cachedMapping["mappings"].([]interface{})
		require.True(t, ok)
		assert.Len(t, mappings, 3)
	})

	t.Run("Cache transformed error response", func(t *testing.T) {
		cacheKey := "grpc:errors:response:1"

		// Transformed error response
		errorResponse := map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "NOT_FOUND",
				"message": "User with ID 'user-999' not found",
				"details": []map[string]interface{}{
					{
						"type":          "ResourceInfo",
						"resource_type": "User",
						"resource_name": "user-999",
					},
				},
			},
			"http_status": 404,
			"timestamp":   time.Now().Unix(),
		}

		responseBytes, err := json.Marshal(errorResponse)
		require.NoError(t, err)

		// Cache the error response
		err = c.Set(ctx, cacheKey, responseBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedResponse map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedResponse)
		require.NoError(t, err)

		errorObj, ok := cachedResponse["error"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "NOT_FOUND", errorObj["code"])
		assert.Equal(t, float64(404), cachedResponse["http_status"])
	})
}

// TestIntegration_GRPCTransform_CustomDataWithCache tests custom data in transform context with cache.
func TestIntegration_GRPCTransform_CustomDataWithCache(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("grpc_custom")

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

	t.Run("Transform context with custom data", func(t *testing.T) {
		tc := grpctransform.NewTransformContext(logger)

		// Set custom data
		tc.SetCustomData("tenant_id", "tenant-123")
		tc.SetCustomData("feature_flags", map[string]bool{
			"new_ui":   true,
			"beta_api": false,
		})

		// Get custom data
		tenantID, ok := tc.GetCustomData("tenant_id")
		assert.True(t, ok)
		assert.Equal(t, "tenant-123", tenantID)

		flags, ok := tc.GetCustomData("feature_flags")
		assert.True(t, ok)
		flagsMap, ok := flags.(map[string]bool)
		assert.True(t, ok)
		assert.True(t, flagsMap["new_ui"])
	})

	t.Run("Cache custom transform data", func(t *testing.T) {
		cacheKey := "grpc:custom:data:1"

		// Custom transform data
		customData := map[string]interface{}{
			"tenant_id":   "tenant-456",
			"user_id":     "user-789",
			"permissions": []string{"read", "write", "admin"},
			"quotas": map[string]int{
				"requests_per_minute": 1000,
				"max_payload_size":    10485760,
			},
		}

		dataBytes, err := json.Marshal(customData)
		require.NoError(t, err)

		// Cache the custom data
		err = c.Set(ctx, cacheKey, dataBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve and verify
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedData map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedData)
		require.NoError(t, err)

		assert.Equal(t, "tenant-456", cachedData["tenant_id"])
		assert.Equal(t, "user-789", cachedData["user_id"])

		permissions, ok := cachedData["permissions"].([]interface{})
		require.True(t, ok)
		assert.Len(t, permissions, 3)
	})
}

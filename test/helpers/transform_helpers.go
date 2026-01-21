// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// Redis test helpers

// GetRedisURL returns the Redis URL from environment or default.
func GetRedisURL() string {
	return getEnvOrDefault("TEST_REDIS_URL", "redis://default:password@127.0.0.1:6379")
}

// IsRedisAvailable checks if Redis is available.
func IsRedisAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	opts, err := redis.ParseURL(GetRedisURL())
	if err != nil {
		return false
	}

	client := redis.NewClient(opts)
	defer client.Close()

	return client.Ping(ctx).Err() == nil
}

// SkipIfRedisUnavailable skips the test if Redis is not available.
func SkipIfRedisUnavailable(t *testing.T) {
	if !IsRedisAvailable() {
		t.Skip("Redis not available at", GetRedisURL(), "- skipping test")
	}
}

// CreateRedisClient creates a Redis client for testing.
func CreateRedisClient() (*redis.Client, error) {
	opts, err := redis.ParseURL(GetRedisURL())
	if err != nil {
		return nil, err
	}
	return redis.NewClient(opts), nil
}

// CleanupRedis removes all keys with the given prefix.
func CleanupRedis(client *redis.Client, prefix string) error {
	ctx := context.Background()
	iter := client.Scan(ctx, 0, prefix+"*", 0).Iterator()
	for iter.Next(ctx) {
		if err := client.Del(ctx, iter.Val()).Err(); err != nil {
			return err
		}
	}
	return iter.Err()
}

// Transform test helpers

// CreateTestTransformConfig creates a test transformation configuration.
func CreateTestTransformConfig() *config.TransformConfig {
	return &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			StaticHeaders: map[string]string{
				"X-Test-Header": "test-value",
			},
			DefaultValues: map[string]interface{}{
				"version": "1.0",
			},
		},
		Response: &config.ResponseTransformConfig{
			AllowFields: []string{"id", "name", "data"},
			FieldMappings: []config.FieldMapping{
				{Source: "old_field", Target: "new_field"},
			},
		},
	}
}

// CreateTestResponseTransformConfig creates a test response transformation configuration.
func CreateTestResponseTransformConfig() *config.ResponseTransformConfig {
	return &config.ResponseTransformConfig{
		AllowFields: []string{"id", "name", "email"},
		DenyFields:  []string{"password", "secret"},
		FieldMappings: []config.FieldMapping{
			{Source: "user_name", Target: "username"},
		},
		GroupFields: []config.FieldGroup{
			{Name: "contact", Fields: []string{"email", "phone"}},
		},
		FlattenFields: []string{"metadata"},
	}
}

// CreateTestRequestTransformConfig creates a test request transformation configuration.
func CreateTestRequestTransformConfig() *config.RequestTransformConfig {
	return &config.RequestTransformConfig{
		StaticHeaders: map[string]string{
			"X-Gateway-Version": "1.0",
		},
		DynamicHeaders: []config.DynamicHeader{
			{Name: "X-Request-ID", Source: "context.request_id"},
		},
		InjectFields: []config.FieldInjection{
			{Field: "gateway_timestamp", Value: "injected"},
		},
		RemoveFields:  []string{"internal_field"},
		DefaultValues: map[string]interface{}{"api_version": "v1"},
	}
}

// CreateTestGRPCTransformConfig creates a test gRPC transformation configuration.
func CreateTestGRPCTransformConfig() *config.GRPCTransformConfig {
	return &config.GRPCTransformConfig{
		Request: &config.GRPCRequestTransformConfig{
			StaticMetadata: map[string]string{
				"x-gateway": "avapigw",
			},
			DynamicMetadata: []config.DynamicMetadata{
				{Key: "x-request-id", Source: "context.request_id"},
			},
		},
		Response: &config.GRPCResponseTransformConfig{
			FieldMask: []string{"id", "name", "data"},
			FieldMappings: []config.FieldMapping{
				{Source: "old_field", Target: "new_field"},
			},
		},
	}
}

// CreateTestCacheConfig creates a test cache configuration.
func CreateTestCacheConfig(cacheType string) *config.CacheConfig {
	cfg := &config.CacheConfig{
		Enabled:    true,
		Type:       cacheType,
		TTL:        config.Duration(5 * time.Minute),
		MaxEntries: 1000,
		KeyConfig: &config.CacheKeyConfig{
			IncludeMethod: true,
			IncludePath:   true,
		},
	}

	if cacheType == config.CacheTypeRedis {
		cfg.Redis = &config.RedisCacheConfig{
			URL:       GetRedisURL(),
			PoolSize:  5,
			KeyPrefix: "test:",
		}
	}

	return cfg
}

// CreateTestEncodingConfig creates a test encoding configuration.
func CreateTestEncodingConfig() *config.EncodingConfig {
	return &config.EncodingConfig{
		RequestEncoding:          config.EncodingJSON,
		ResponseEncoding:         config.EncodingJSON,
		EnableContentNegotiation: true,
		SupportedContentTypes: []string{
			config.ContentTypeJSON,
			config.ContentTypeXML,
			config.ContentTypeYAML,
		},
		JSON: &config.JSONEncodingConfig{
			PrettyPrint: false,
		},
	}
}

// Test data helpers

// CreateTestData creates sample test data for transformation tests.
func CreateTestData() map[string]interface{} {
	return map[string]interface{}{
		"id":       "123",
		"name":     "Test Item",
		"email":    "test@example.com",
		"password": "secret123",
		"phone":    "555-1234",
		"metadata": map[string]interface{}{
			"created_at": "2024-01-01",
			"updated_at": "2024-01-02",
		},
		"items": []interface{}{
			map[string]interface{}{"id": 1, "name": "Item 1"},
			map[string]interface{}{"id": 2, "name": "Item 2"},
		},
	}
}

// CreateNestedTestData creates nested test data for transformation tests.
func CreateNestedTestData() map[string]interface{} {
	return map[string]interface{}{
		"user": map[string]interface{}{
			"id":       "user-123",
			"name":     "John Doe",
			"email":    "john@example.com",
			"password": "secret",
			"address": map[string]interface{}{
				"street": "123 Main St",
				"city":   "New York",
				"zip":    "10001",
			},
		},
		"orders": []interface{}{
			map[string]interface{}{
				"id":     "order-1",
				"total":  100.50,
				"status": "completed",
			},
			map[string]interface{}{
				"id":     "order-2",
				"total":  250.00,
				"status": "pending",
			},
		},
	}
}

// Environment helpers

// GetTestBackend1URL returns the HTTP backend 1 URL.
func GetTestBackend1URL() string {
	return getEnvOrDefault("TEST_BACKEND1_URL", "http://127.0.0.1:8801")
}

// GetTestBackend2URL returns the HTTP backend 2 URL.
func GetTestBackend2URL() string {
	return getEnvOrDefault("TEST_BACKEND2_URL", "http://127.0.0.1:8802")
}

// GetTestGRPCBackend1URL returns the gRPC backend 1 URL.
func GetTestGRPCBackend1URL() string {
	return getEnvOrDefault("TEST_GRPC_BACKEND1_URL", "127.0.0.1:8803")
}

// GetTestGRPCBackend2URL returns the gRPC backend 2 URL.
func GetTestGRPCBackend2URL() string {
	return getEnvOrDefault("TEST_GRPC_BACKEND2_URL", "127.0.0.1:8804")
}

// GetEnvOrDefault returns the environment variable value or a default.
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GenerateTestKeyPrefix generates a unique key prefix for test isolation.
func GenerateTestKeyPrefix(testName string) string {
	return fmt.Sprintf("test:%s:%d:", testName, time.Now().UnixNano())
}

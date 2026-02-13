// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
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
// Supported cacheTypes: "memory", "redis", "redis-sentinel"
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

	if cacheType == "redis-sentinel" {
		cfg.Type = config.CacheTypeRedis
		cfg.Redis = &config.RedisCacheConfig{
			PoolSize:  5,
			KeyPrefix: "test:",
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    GetRedisSentinelMasterName(),
				SentinelAddrs: GetRedisSentinelAddrs(),
				Password:      GetRedisMasterPassword(),
			},
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

// Redis Sentinel test helpers

// GetRedisSentinelAddrs returns the Redis Sentinel addresses from environment or default.
func GetRedisSentinelAddrs() []string {
	addrs := getEnvOrDefault("TEST_REDIS_SENTINEL_ADDRS", "127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381")
	return strings.Split(addrs, ",")
}

// GetRedisSentinelMasterName returns the Redis Sentinel master name from environment or default.
func GetRedisSentinelMasterName() string {
	return getEnvOrDefault("TEST_REDIS_SENTINEL_MASTER_NAME", "mymaster")
}

// GetRedisMasterPassword returns the Redis master password from environment or default.
func GetRedisMasterPassword() string {
	return getEnvOrDefault("TEST_REDIS_MASTER_PASSWORD", "password")
}

// GetRedisSentinelMasterPort returns the host-mapped port for the Redis Sentinel master.
// When running tests on the host, sentinel discovers the master at a Docker-internal IP
// which is unreachable. This port is the host-mapped port for the master container.
func GetRedisSentinelMasterPort() string {
	return getEnvOrDefault("TEST_REDIS_SENTINEL_MASTER_PORT", "6380")
}

// sentinelDialer returns a custom net.Dialer function that intercepts connections to
// Docker-internal IPs (172.x.x.x) and redirects them to 127.0.0.1 on the host-mapped
// master port. This is necessary because Redis Sentinel discovers the master at its
// Docker-internal IP, which is unreachable from the host.
func sentinelDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	masterPort := GetRedisSentinelMasterPort()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return net.DialTimeout(network, addr, 2*time.Second)
		}
		// If the address is a Docker-internal IP (172.x.x.x or 10.x.x.x),
		// redirect to localhost on the host-mapped master port.
		if strings.HasPrefix(host, "172.") || strings.HasPrefix(host, "10.") {
			addr = "127.0.0.1:" + masterPort
		}
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, network, addr)
	}
}

// IsRedisSentinelAvailable checks if Redis Sentinel is available.
// It uses a custom dialer to handle Docker networking where sentinel discovers
// the master at a Docker-internal IP unreachable from the host.
func IsRedisSentinelAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    GetRedisSentinelMasterName(),
		SentinelAddrs: GetRedisSentinelAddrs(),
		Password:      GetRedisMasterPassword(),
		Dialer:        sentinelDialer(),
	})
	defer client.Close()

	return client.Ping(ctx).Err() == nil
}

// SkipIfRedisSentinelUnavailable skips the test if Redis Sentinel is not available.
func SkipIfRedisSentinelUnavailable(t *testing.T) {
	if !IsRedisSentinelAvailable() {
		t.Skip("Redis Sentinel not available - skipping test")
	}
}

// CreateRedisSentinelClient creates a Redis Sentinel client for testing.
// It uses a custom dialer to handle Docker networking where sentinel discovers
// the master at a Docker-internal IP unreachable from the host.
func CreateRedisSentinelClient() (*redis.Client, error) {
	client := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    GetRedisSentinelMasterName(),
		SentinelAddrs: GetRedisSentinelAddrs(),
		Password:      GetRedisMasterPassword(),
		Dialer:        sentinelDialer(),
	})
	return client, nil
}

// SentinelDialer returns the custom dialer for sentinel connections.
// This is exported so integration tests can pass it to cache.New via cache.WithRedisDialer.
func SentinelDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return sentinelDialer()
}

// NewSentinelCache creates a new sentinel cache for testing with the custom Docker dialer.
// This wraps cache.New with the WithRedisDialer option to handle Docker networking.
func NewSentinelCache(cfg *config.CacheConfig, logger observability.Logger) (cache.Cache, error) {
	return cache.New(cfg, logger, cache.WithRedisDialer(sentinelDialer()))
}

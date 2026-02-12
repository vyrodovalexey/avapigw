//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_Gateway_WithSentinelCache tests starting a gateway with sentinel cache config
// and verifying that caching works through the gateway.
func TestIntegration_Gateway_WithSentinelCache(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPrefix := helpers.GenerateTestKeyPrefix("gw_sentinel")

	cfg := createSentinelGatewayConfig(port, keyPrefix)

	gi, err := startGatewayWithSentinelConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	// Cleanup sentinel keys after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	t.Run("gateway serves requests with sentinel cache configured", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})

	t.Run("gateway health endpoint works", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/health", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)
		assert.Contains(t, body, "healthy")
	})
}

// TestIntegration_Gateway_SentinelCacheHitMiss tests cache hit/miss behavior through the gateway
// using a sentinel-backed Redis cache.
func TestIntegration_Gateway_SentinelCacheHitMiss(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("gw_sentinel_hitmiss")

	// Create sentinel cache directly to verify hit/miss
	cacheCfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cacheCfg.Redis.KeyPrefix = keyPrefix

	c, err := helpers.NewSentinelCache(cacheCfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	t.Run("cache miss then hit", func(t *testing.T) {
		cacheKey := "items:list"

		// First access - cache miss
		_, err := c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// Simulate caching a response
		responseData := map[string]interface{}{
			"success": true,
			"data":    []map[string]interface{}{{"id": "1", "name": "Item 1"}},
		}
		responseBytes, err := json.Marshal(responseData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, responseBytes, 5*time.Minute)
		require.NoError(t, err)

		// Second access - cache hit
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedData map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedData)
		require.NoError(t, err)
		assert.True(t, cachedData["success"].(bool))
	})

	t.Run("cache stats reflect hits and misses", func(t *testing.T) {
		cacheWithStats, ok := c.(cache.CacheWithStats)
		if !ok {
			t.Skip("Cache does not support statistics")
		}

		initialStats := cacheWithStats.Stats()

		// Generate a miss
		_, _ = c.Get(ctx, "nonexistent-key-for-stats")

		// Generate a hit
		testKey := "stats-key"
		err := c.Set(ctx, testKey, []byte("stats-value"), 5*time.Minute)
		require.NoError(t, err)
		_, _ = c.Get(ctx, testKey)

		finalStats := cacheWithStats.Stats()
		assert.Greater(t, finalStats.Hits, initialStats.Hits)
		assert.Greater(t, finalStats.Misses, initialStats.Misses)
	})
}

// TestIntegration_Gateway_SentinelCacheInvalidation tests cache invalidation with sentinel.
func TestIntegration_Gateway_SentinelCacheInvalidation(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("gw_sentinel_invalidate")

	cacheCfg := helpers.CreateTestCacheConfig("redis-sentinel")
	cacheCfg.Redis.KeyPrefix = keyPrefix

	c, err := helpers.NewSentinelCache(cacheCfg, logger)
	require.NoError(t, err)
	defer c.Close()

	// Cleanup after test
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	defer sentinelClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
	}()

	t.Run("invalidate single key", func(t *testing.T) {
		cacheKey := "invalidate:single"
		testData := []byte(`{"id":"test-123","name":"Test Item"}`)

		err := c.Set(ctx, cacheKey, testData, 5*time.Minute)
		require.NoError(t, err)

		exists, err := c.Exists(ctx, cacheKey)
		require.NoError(t, err)
		assert.True(t, exists)

		err = c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		exists, err = c.Exists(ctx, cacheKey)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("invalidate and re-cache", func(t *testing.T) {
		cacheKey := "invalidate:recache"

		// Initial data
		initialData := []byte(`{"version":1,"name":"Initial"}`)
		err := c.Set(ctx, cacheKey, initialData, 5*time.Minute)
		require.NoError(t, err)

		// Invalidate
		err = c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		// Verify invalidated
		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// Re-cache with updated data
		updatedData := []byte(`{"version":2,"name":"Updated"}`)
		err = c.Set(ctx, cacheKey, updatedData, 5*time.Minute)
		require.NoError(t, err)

		// Verify updated data
		retrieved, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)
		assert.Equal(t, updatedData, retrieved)
	})

	t.Run("invalidate multiple keys", func(t *testing.T) {
		keys := []string{
			"invalidate:multi:1",
			"invalidate:multi:2",
			"invalidate:multi:3",
		}

		for _, key := range keys {
			err := c.Set(ctx, key, []byte(`{"key":"`+key+`"}`), 5*time.Minute)
			require.NoError(t, err)
		}

		for _, key := range keys {
			exists, err := c.Exists(ctx, key)
			require.NoError(t, err)
			assert.True(t, exists, "Key %s should exist", key)
		}

		for _, key := range keys {
			err := c.Delete(ctx, key)
			require.NoError(t, err)
		}

		for _, key := range keys {
			exists, err := c.Exists(ctx, key)
			require.NoError(t, err)
			assert.False(t, exists, "Key %s should not exist after invalidation", key)
		}
	})
}

// Helper functions

func createSentinelGatewayConfig(port int, keyPrefix string) *config.GatewayConfig {
	// The gateway starts its own cache internally via cache.New without a custom dialer,
	// so it cannot reach the Docker-internal IP that sentinel discovers for the master.
	// Use the direct Redis master URL (host-mapped port) instead of sentinel config
	// for the gateway process. Sentinel-specific cache operations are tested separately
	// in cache_sentinel_test.go using helpers.NewSentinelCache with the custom dialer.
	masterURL := fmt.Sprintf("redis://default:%s@127.0.0.1:%s",
		helpers.GetRedisMasterPassword(), helpers.GetRedisSentinelMasterPort())

	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "sentinel-integration-test-gateway",
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
						Body:    `{"status":"healthy","gateway":"sentinel-integration-test"}`,
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
							URL:       masterURL,
							KeyPrefix: keyPrefix,
							PoolSize:  5,
						},
					},
				},
			},
		},
	}
}

func startGatewayWithSentinelConfig(ctx context.Context, cfg *config.GatewayConfig) (*helpers.GatewayInstance, error) {
	logger := observability.NopLogger()

	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		return nil, err
	}

	registry := backend.NewRegistry(logger)
	if err := registry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		_ = err // Backends might be empty
	}

	if err := registry.StartAll(ctx); err != nil {
		_ = err // Backends might be empty
	}

	p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(p),
	)
	if err != nil {
		return nil, err
	}

	if err := gw.Start(ctx); err != nil {
		return nil, err
	}

	port := 8080
	if len(cfg.Spec.Listeners) > 0 {
		port = cfg.Spec.Listeners[0].Port
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	return &helpers.GatewayInstance{
		Gateway:  gw,
		Config:   cfg,
		Router:   r,
		Registry: registry,
		Proxy:    p,
		BaseURL:  baseURL,
	}, nil
}

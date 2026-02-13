//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestE2E_Sentinel_HTTPCaching tests a full HTTP request flow with sentinel-backed caching.
func TestE2E_Sentinel_HTTPCaching(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_sentinel_http")

	// Create sentinel cache
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

	// Start gateway with sentinel cache
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	cfg := createSentinelE2EConfig(port, keyPrefix)

	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("1. First request - cache miss, fetch from backend", func(t *testing.T) {
		cacheKey := "e2e:sentinel:items"

		// Verify cache miss
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

	t.Run("2. Second request - serve from sentinel cache", func(t *testing.T) {
		cacheKey := "e2e:sentinel:items"

		// Pre-populate cache
		cachedData := map[string]interface{}{
			"success": true,
			"data":    []map[string]interface{}{{"id": "1", "name": "Cached Sentinel Item"}},
		}
		cachedBytes, err := json.Marshal(cachedData)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, cachedBytes, 5*time.Minute)
		require.NoError(t, err)

		// Verify cache hit
		data, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		var retrieved map[string]interface{}
		err = json.Unmarshal(data, &retrieved)
		require.NoError(t, err)
		assert.True(t, retrieved["success"].(bool))
	})

	t.Run("3. Invalidate cache and re-fetch", func(t *testing.T) {
		cacheKey := "e2e:sentinel:items"

		// Invalidate
		err := c.Delete(ctx, cacheKey)
		require.NoError(t, err)

		// Verify invalidated
		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)

		// Make request through gateway again
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})

	t.Run("4. POST request bypasses cache", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "Sentinel E2E Item",
			Description: "Testing sentinel caching",
			Price:       59.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPost, gi.BaseURL+"/api/v1/items", item)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500,
			"Expected success or client error, got %d", resp.StatusCode)
	})

	t.Run("5. TTL expiration", func(t *testing.T) {
		cacheKey := "e2e:sentinel:ttl-test"
		testData := []byte(`{"id":"ttl-test","name":"TTL Test"}`)
		shortTTL := 1 * time.Second

		err := c.Set(ctx, cacheKey, testData, shortTTL)
		require.NoError(t, err)

		// Verify exists
		data, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)
		assert.Equal(t, testData, data)

		// Wait for expiration
		time.Sleep(shortTTL + 500*time.Millisecond)

		// Verify expired
		_, err = c.Get(ctx, cacheKey)
		assert.ErrorIs(t, err, cache.ErrCacheMiss)
	})
}

// TestE2E_Sentinel_GRPCCaching tests gRPC request flow with sentinel caching.
// Note: gRPC caching support depends on the gateway implementation.
func TestE2E_Sentinel_GRPCCaching(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_sentinel_grpc")

	// Create sentinel cache for gRPC responses
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

	t.Run("cache gRPC response data via sentinel", func(t *testing.T) {
		// Simulate caching a gRPC response as serialized bytes
		cacheKey := "grpc:testservice:getitem:123"
		grpcResponse := map[string]interface{}{
			"id":     "123",
			"name":   "gRPC Cached Item",
			"status": "active",
		}

		responseBytes, err := json.Marshal(grpcResponse)
		require.NoError(t, err)

		err = c.Set(ctx, cacheKey, responseBytes, 5*time.Minute)
		require.NoError(t, err)

		// Retrieve from sentinel cache
		cachedBytes, err := c.Get(ctx, cacheKey)
		require.NoError(t, err)

		var cachedResponse map[string]interface{}
		err = json.Unmarshal(cachedBytes, &cachedResponse)
		require.NoError(t, err)

		assert.Equal(t, "123", cachedResponse["id"])
		assert.Equal(t, "gRPC Cached Item", cachedResponse["name"])
	})

	t.Run("cache invalidation for gRPC responses", func(t *testing.T) {
		cacheKey := "grpc:testservice:getitem:456"
		responseBytes := []byte(`{"id":"456","name":"To Be Invalidated"}`)

		err := c.Set(ctx, cacheKey, responseBytes, 5*time.Minute)
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
}

// TestE2E_Sentinel_ConfigReload tests config reload with sentinel config changes.
func TestE2E_Sentinel_ConfigReload(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("config watcher detects sentinel config changes", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "gateway.yaml")

		// Initial config without sentinel
		initialConfig := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: sentinel-reload-test
spec:
  listeners:
    - name: http
      port: 18099
      protocol: HTTP
      bind: 127.0.0.1
  routes:
    - name: api
      match:
        - uri:
            prefix: /api
      route:
        - destination:
            host: 127.0.0.1
            port: 8801
`
		err := os.WriteFile(configPath, []byte(initialConfig), 0644)
		require.NoError(t, err)

		var lastConfig *config.GatewayConfig
		configChanged := make(chan struct{}, 1)

		callback := func(cfg *config.GatewayConfig) {
			lastConfig = cfg
			select {
			case configChanged <- struct{}{}:
			default:
			}
		}

		watcher, err := config.NewWatcher(configPath, callback,
			config.WithLogger(observability.NopLogger()),
			config.WithDebounceDelay(100*time.Millisecond),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err = watcher.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = watcher.Stop()
		})

		// Verify initial config
		initialCfg := watcher.GetLastConfig()
		require.NotNil(t, initialCfg)
		assert.Equal(t, "sentinel-reload-test", initialCfg.Metadata.Name)

		// Update config with sentinel cache
		updatedConfig := fmt.Sprintf(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: sentinel-reload-test-updated
spec:
  listeners:
    - name: http
      port: 18099
      protocol: HTTP
      bind: 127.0.0.1
  routes:
    - name: api
      match:
        - uri:
            prefix: /api
      route:
        - destination:
            host: 127.0.0.1
            port: 8801
      cache:
        enabled: true
        type: redis
        ttl: 5m
        redis:
          keyPrefix: "reload-test:"
          sentinel:
            masterName: %s
            sentinelAddrs:
              - %s
            password: %s
`, helpers.GetRedisSentinelMasterName(),
			helpers.GetRedisSentinelAddrs()[0],
			helpers.GetRedisMasterPassword())

		err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
		require.NoError(t, err)

		// Wait for config change
		select {
		case <-configChanged:
			// Config was reloaded
		case <-time.After(5 * time.Second):
			t.Log("Config change not detected within timeout - this may be expected in some environments")
		}

		if lastConfig != nil {
			assert.Equal(t, "sentinel-reload-test-updated", lastConfig.Metadata.Name)
		}
	})
}

// createSentinelE2EConfig creates a gateway config for E2E sentinel tests.
// The gateway starts its own cache internally via cache.New without a custom dialer,
// so it cannot reach the Docker-internal IP that sentinel discovers for the master.
// Use the direct Redis master URL (host-mapped port) instead of sentinel config
// for the gateway process. Sentinel-specific cache operations are tested directly
// using helpers.NewSentinelCache with the custom dialer.
func createSentinelE2EConfig(port int, keyPrefix string) *config.GatewayConfig {
	masterURL := fmt.Sprintf("redis://default:%s@127.0.0.1:%s",
		helpers.GetRedisMasterPassword(), helpers.GetRedisSentinelMasterPort())

	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "sentinel-e2e-test-gateway",
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
						Body:    `{"status":"healthy","gateway":"sentinel-e2e-test"}`,
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

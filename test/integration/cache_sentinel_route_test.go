//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
// This file verifies route-level response caching through the gateway data
// path against the REAL Redis Sentinel deployment of the docker-compose
// test environment: miss -> hit behavior (X-Cache), cache entries with the
// configured key prefix on the sentinel-managed master, TTL jitter bounds,
// and key hashing.
package integration

import (
	"context"
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
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// sentinelRouteCacheConfig builds a route cache config carrying the
// sentinel connection settings of the docker-compose environment.
func sentinelRouteCacheConfig(keyPrefix string, ttl time.Duration, jitter float64) *config.CacheConfig {
	return &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(ttl),
		Redis: &config.RedisCacheConfig{
			KeyPrefix: keyPrefix,
			PoolSize:  5,
			TTLJitter: jitter,
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    helpers.GetRedisSentinelMasterName(),
				SentinelAddrs: helpers.GetRedisSentinelAddrs(),
				Password:      helpers.GetRedisMasterPassword(),
			},
		},
	}
}

// startSentinelCachedGateway starts a gateway whose route handler is
// wrapped with the route cache middleware backed by a sentinel-mode cache
// (using the shared test dialer for Docker networking), proxying to the
// REST test backend. This mirrors exactly how the RouteMiddlewareManager
// wires route caches (cache.New + middleware.CacheFromConfig).
func startSentinelCachedGateway(
	t *testing.T, ctx context.Context, port int, cacheCfg *config.CacheConfig,
) (*helpers.GatewayInstance, cache.Cache) {
	t.Helper()

	logger := observability.NopLogger()

	c, err := helpers.NewSentinelCache(cacheCfg, logger)
	require.NoError(t, err, "sentinel cache must connect through sentinel discovery")
	t.Cleanup(func() { _ = c.Close() })

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: fmt.Sprintf("sentinel-cache-gw-%d", port)},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: port, Protocol: config.ProtocolHTTP, Bind: "127.0.0.1"},
			},
			Routes: []config.Route{
				{
					Name: "health-check",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}, Methods: []string{"GET"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status: 200, Body: `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "cached-api",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET", "POST"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}, Weight: 100},
					},
					Timeout: config.Duration(15 * time.Second),
					Cache:   cacheCfg,
				},
			},
		},
	}

	r := router.New()
	require.NoError(t, r.LoadRoutes(cfg.Spec.Routes))

	registry := backend.NewRegistry(logger)
	p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

	// Wrap the proxy with the same cache middleware the route middleware
	// manager builds for routes with cache configs.
	handler := middleware.CacheFromConfig(c, cacheCfg, logger)(p)

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(handler),
	)
	require.NoError(t, err)
	require.NoError(t, gw.Start(ctx))
	t.Cleanup(func() { _ = gw.Stop(context.Background()) })

	gi := &helpers.GatewayInstance{
		Gateway: gw,
		Config:  cfg,
		Router:  r,
		Proxy:   p,
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
	}
	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second))
	return gi, c
}

// TestIntegration_Cache_Sentinel_RouteChain verifies the route cache data
// path against the real sentinel deployment: first GET misses and fills the
// cache, subsequent GETs are served with X-Cache: HIT, the entry is visible
// on the master under the configured key prefix, and its TTL stays within
// the configured jitter bounds.
func TestIntegration_Cache_Sentinel_RouteChain(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keyPrefix := helpers.GenerateTestKeyPrefix("it_cache_sentinel")
	const (
		cacheTTL  = 2 * time.Minute
		ttlJitter = 0.2
	)

	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
		_ = sentinelClient.Close()
	})

	cacheCfg := sentinelRouteCacheConfig(keyPrefix, cacheTTL, ttlJitter)
	gi, _ := startSentinelCachedGateway(t, ctx, 18440, cacheCfg)

	client := &http.Client{Timeout: 10 * time.Second}
	const path = "/api/v1/items"
	cacheKey := keyPrefix + "GET:" + path

	t.Run("first GET is a cache miss served by the backend", func(t *testing.T) {
		resp, err := client.Get(gi.BaseURL + path)
		require.NoError(t, err)
		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("X-Cache"), "first response must not be a cache hit")
		assert.Contains(t, body, "success")

		// The cache fill completes on the server after the client has the
		// response; wait for the entry before asserting hit behavior.
		require.Eventually(t, func() bool {
			n, err := sentinelClient.Exists(ctx, cacheKey).Result()
			return err == nil && n == 1
		}, 5*time.Second, 50*time.Millisecond, "cache entry must appear on the master")
	})

	t.Run("second GET is served from the sentinel-backed cache", func(t *testing.T) {
		resp, err := client.Get(gi.BaseURL + path)
		require.NoError(t, err)
		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "HIT", resp.Header.Get("X-Cache"), "second response must be a cache hit")
		assert.Contains(t, body, "success")
	})

	t.Run("cache entry is visible on the master with the key prefix", func(t *testing.T) {
		exists, err := sentinelClient.Exists(ctx, cacheKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists, "cache entry %s must exist on the master", cacheKey)
	})

	t.Run("entry TTL stays within the configured jitter bounds", func(t *testing.T) {
		ttl, err := sentinelClient.PTTL(ctx, cacheKey).Result()
		require.NoError(t, err)

		lower := time.Duration(float64(cacheTTL) * (1 - ttlJitter))
		upper := time.Duration(float64(cacheTTL) * (1 + ttlJitter))

		// The lower bound is relaxed slightly for elapsed wall time
		// between Set and PTTL.
		assert.GreaterOrEqual(t, ttl, lower-10*time.Second,
			"TTL %v must not undershoot ttl*(1-jitter)=%v", ttl, lower)
		assert.LessOrEqual(t, ttl, upper,
			"TTL %v must not overshoot ttl*(1+jitter)=%v", ttl, upper)
	})

	t.Run("POST requests bypass the cache", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "Sentinel Route Cache Item",
			Description: "created through the cached route",
			Price:       10.5,
		}
		resp, err := helpers.MakeRequest(http.MethodPost, gi.BaseURL+path, item)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.NotEqual(t, "HIT", resp.Header.Get("X-Cache"), "POST must never be served from cache")
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500,
			"POST should reach the backend, got %d", resp.StatusCode)
	})

	t.Run("invalidating the entry restores miss behavior", func(t *testing.T) {
		require.NoError(t, sentinelClient.Del(ctx, cacheKey).Err())

		resp, err := client.Get(gi.BaseURL + path)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("X-Cache"), "after invalidation the next GET must miss")
	})
}

// TestIntegration_Cache_RouteChain_MasterURL_FullChain verifies the FULL
// production route chain (RouteMiddlewareManager + CacheFactory built from
// CRD-shaped route config) with a redis cache pointing at the
// sentinel-managed master via its host-mapped URL, including hashKeys
// behavior (keys are SHA256-hashed before storage).
func TestIntegration_Cache_RouteChain_MasterURL_FullChain(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keyPrefix := helpers.GenerateTestKeyPrefix("it_cache_chain")
	masterURL := fmt.Sprintf("redis://default:%s@127.0.0.1:%s",
		helpers.GetRedisMasterPassword(), helpers.GetRedisSentinelMasterPort())

	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
		_ = sentinelClient.Close()
	})

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "cache-chain-master-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 18441, Protocol: config.ProtocolHTTP, Bind: "127.0.0.1"},
			},
			Routes: []config.Route{
				{
					Name: "health-check",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}, Methods: []string{"GET"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status: 200, Body: `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "cached-hashed",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}, Weight: 100},
					},
					Timeout: config.Duration(15 * time.Second),
					Cache: &config.CacheConfig{
						Enabled: true,
						Type:    config.CacheTypeRedis,
						TTL:     config.Duration(90 * time.Second),
						Redis: &config.RedisCacheConfig{
							URL:       masterURL,
							KeyPrefix: keyPrefix,
							PoolSize:  5,
							HashKeys:  true,
						},
					},
				},
			},
		},
	}

	gi, err := helpers.StartGatewayWithRouteMiddleware(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })
	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second))

	client := &http.Client{Timeout: 10 * time.Second}
	const path = "/api/v1/items"
	hashedKey := keyPrefix + cache.HashKey("GET:"+path)

	t.Run("miss then hit through the full route chain", func(t *testing.T) {
		// Bodies must be drained before Close: closing an unread body
		// tears down the connection, which cancels the server-side
		// request context and aborts the still-running cache fill.
		resp1, err := client.Get(gi.BaseURL + path)
		require.NoError(t, err)
		_, err = helpers.ReadResponseBody(resp1)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp1.StatusCode)
		assert.Empty(t, resp1.Header.Get("X-Cache"))

		// The cache fill completes on the server after the client has the
		// response; wait for the entry before asserting hit behavior.
		require.Eventually(t, func() bool {
			n, err := sentinelClient.Exists(ctx, hashedKey).Result()
			return err == nil && n == 1
		}, 5*time.Second, 50*time.Millisecond, "cache entry must appear on the master")

		resp2, err := client.Get(gi.BaseURL + path)
		require.NoError(t, err)
		_, err = helpers.ReadResponseBody(resp2)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp2.StatusCode)
		assert.Equal(t, "HIT", resp2.Header.Get("X-Cache"))
	})

	t.Run("hashKeys stores the SHA256-hashed key, not the raw key", func(t *testing.T) {
		rawKey := keyPrefix + "GET:" + path

		rawExists, err := sentinelClient.Exists(ctx, rawKey).Result()
		require.NoError(t, err)
		hashedExists, err := sentinelClient.Exists(ctx, hashedKey).Result()
		require.NoError(t, err)

		assert.Zero(t, rawExists, "raw cache key must not be stored when hashKeys is on")
		assert.Equal(t, int64(1), hashedExists, "hashed cache key %s must exist", hashedKey)

		ttl, err := sentinelClient.TTL(ctx, hashedKey).Result()
		require.NoError(t, err)
		assert.Positive(t, ttl, "cache entry must carry the configured TTL")
		assert.LessOrEqual(t, ttl, 90*time.Second, "TTL must not exceed the configured value (no jitter)")
	})
}

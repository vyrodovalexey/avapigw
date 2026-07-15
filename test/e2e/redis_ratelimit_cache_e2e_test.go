//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestE2E_FullConfig_AuthRateLimitCacheTransformCORS runs the full user
// journey on ONE route combining authentication (JWT), distributed rate
// limiting (redis store backed by the sentinel-managed master), response
// caching (redis, TTL jitter), response transformation (field deny) and
// CORS — all built through the production per-route middleware chain
// (RouteMiddlewareManager), exactly as a CRD-expressed APIRoute would be.
func TestE2E_FullConfig_AuthRateLimitCacheTransformCORS(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const (
		routeName = "full-config-route"
		gwPort    = 18520
		cacheTTL  = 2 * time.Minute
		ttlJitter = 0.2
		burst     = 5
	)

	rlPrefix := helpers.GenerateTestKeyPrefix("e2e_full_rl")
	cachePrefix := helpers.GenerateTestKeyPrefix("e2e_full_cache")
	masterURL := fmt.Sprintf("redis://default:%s@127.0.0.1:%s",
		helpers.GetRedisMasterPassword(), helpers.GetRedisSentinelMasterPort())

	// State inspection and cleanup through the sentinel-discovered master.
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, rlPrefix)
		_ = helpers.CleanupRedis(sentinelClient, cachePrefix)
		_ = sentinelClient.Close()
	})

	// Route-level JWT auth uses an RS256 static public key (PEM), the
	// supported static-key format for route Authentication configs.
	rsaPriv, _, err := helpers.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	pubPEM, err := helpers.EncodeRSAPublicKeyPEM(&rsaPriv.PublicKey)
	require.NoError(t, err)

	cfg := fullConfigGateway(gwPort, routeName, masterURL, rlPrefix, cachePrefix, pubPEM, cacheTTL, ttlJitter, burst)

	gi, err := helpers.StartGatewayWithRouteMiddleware(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })
	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second))

	// Mint a valid RS256 token matching the route's static public key
	// (the converter registers the PublicKey under kid "default-public").
	claims := helpers.CreateJWTClaims("e2e-user", "avapigw-e2e", []string{"gateway"}, []string{"user"}, time.Hour)
	token, err := helpers.CreateTestJWT(claims, rsaPriv, "RS256", "default-public")
	require.NoError(t, err)

	const path = "/api/v1/items"
	authGet := func(origin string) (*http.Response, string) {
		req, err := http.NewRequest(http.MethodGet, gi.BaseURL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		require.NoError(t, err)
		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)
		return resp, body
	}

	t.Run("1. request without token is rejected with 401", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+path, nil)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("2. request with an invalid token is rejected with 401", func(t *testing.T) {
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, gi.BaseURL+path, nil,
			map[string]string{"Authorization": "Bearer invalid.token.value"})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// NOTE: the cache is deliberately filled by a request WITHOUT an
	// Origin header, for two reasons: (a) the REST test backend reflects
	// any Origin with permissive CORS headers of its own, so miss-path
	// CORS assertions would test the backend rather than the gateway;
	// (b) the route cache snapshots the response header map at fill time,
	// so filling from an allowed origin would bake its
	// Access-Control-Allow-Origin into the cached entry and replay it to
	// other origins (reported as a cache/CORS interaction finding).
	// Hit-path responses never consult the backend, which makes the
	// gateway's own CORS decisions cleanly assertable there.
	t.Run("3. authenticated request without origin: cache miss, transformed body", func(t *testing.T) {
		resp, body := authGet("")

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("X-Cache"), "first response must be a cache miss")
		assert.Contains(t, body, "success")
		assert.NotContains(t, body, `"data"`, "transform must deny the data field")

		// Wait for the server-side cache fill to complete.
		cacheKey := cachePrefix + "GET:" + path
		require.Eventually(t, func() bool {
			n, err := sentinelClient.Exists(ctx, cacheKey).Result()
			return err == nil && n == 1
		}, 5*time.Second, 50*time.Millisecond, "cache entry must appear on the master")
	})

	t.Run("4. allowed origin is served from cache with gateway CORS headers, still transformed", func(t *testing.T) {
		resp, body := authGet("https://app.example.com")

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "HIT", resp.Header.Get("X-Cache"), "second response must be a cache hit")
		assert.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"),
			"CORS headers must be added per-request on cache hits (CORS runs outside the cache)")
		assert.Contains(t, body, "success")
		assert.NotContains(t, body, `"data"`, "cached response must be the transformed one")
	})

	t.Run("5. cache hits do not grant CORS headers to non-allowlisted origins", func(t *testing.T) {
		resp, _ := authGet("https://evil.example.com")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "HIT", resp.Header.Get("X-Cache"))
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"),
			"the gateway must not grant Access-Control-Allow-Origin to disallowed origins on hits")
	})

	t.Run("6. burst exhaustion returns 429 with Retry-After before the cache", func(t *testing.T) {
		var throttled *http.Response
		allowed := 0
		for i := 0; i < burst+3; i++ {
			resp, _ := authGet("")
			if resp.StatusCode == http.StatusTooManyRequests {
				throttled = resp
				break
			}
			require.Equal(t, http.StatusOK, resp.StatusCode)
			allowed++
		}

		require.NotNil(t, throttled, "burst must eventually be exhausted (got %d 200s)", allowed)
		assert.Equal(t, "1", throttled.Header.Get("Retry-After"))
		assert.Empty(t, throttled.Header.Get("X-Cache"),
			"throttled requests must be rejected before reaching the cache")
	})

	t.Run("7. sentinel-backed state is visible on the master", func(t *testing.T) {
		bucketKey := rlPrefix + "ratelimit:" + routeName
		exists, err := sentinelClient.Exists(ctx, bucketKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists, "rate limit bucket %s must exist", bucketKey)

		cacheKey := cachePrefix + "GET:" + path
		ttl, err := sentinelClient.PTTL(ctx, cacheKey).Result()
		require.NoError(t, err)

		lower := time.Duration(float64(cacheTTL) * (1 - ttlJitter))
		upper := time.Duration(float64(cacheTTL) * (1 + ttlJitter))
		assert.GreaterOrEqual(t, ttl, lower-10*time.Second,
			"cache TTL %v must respect the jitter lower bound %v", ttl, lower)
		assert.LessOrEqual(t, ttl, upper,
			"cache TTL %v must respect the jitter upper bound %v", ttl, upper)
	})

	t.Run("8. metrics endpoint exposes the redis rate limit counters", func(t *testing.T) {
		// Mirror the production wiring (registerSubsystemMetrics): the
		// middleware metrics singleton is registered on the gateway's
		// registry and pre-initialized so all families are exposed.
		reg := prometheus.NewRegistry()
		middleware.GetMiddlewareMetrics().MustRegister(reg)
		middleware.GetMiddlewareMetrics().Init()
		metricsSrv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		defer metricsSrv.Close()

		resp, err := http.Get(metricsSrv.URL)
		require.NoError(t, err)
		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		routeLabel := `route="` + routeName + `"`
		assert.Contains(t, body, "gateway_middleware_redis_rate_limit_allowed_total{"+routeLabel,
			"allowed counter must be exposed with the route label")
		assert.Contains(t, body, "gateway_middleware_redis_rate_limit_denied_total{"+routeLabel,
			"denied counter must be exposed with the route label")
		assert.Contains(t, body, "gateway_middleware_redis_rate_limit_duration_seconds_bucket",
			"decision duration histogram must be exposed")
	})
}

// fullConfigGateway builds the combined-feature gateway configuration.
func fullConfigGateway(
	port int, routeName, masterURL, rlPrefix, cachePrefix, jwtPublicKeyPEM string,
	cacheTTL time.Duration, ttlJitter float64, burst int,
) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "e2e-full-config-gw"},
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
					Name: routeName,
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET", "POST", "OPTIONS"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}, Weight: 100},
					},
					Timeout: config.Duration(15 * time.Second),
					Authentication: &config.AuthenticationConfig{
						Enabled: true,
						JWT: &config.JWTAuthConfig{
							Enabled:   true,
							PublicKey: jwtPublicKeyPEM,
							Algorithm: "RS256",
						},
					},
					RateLimit: &config.RateLimitConfig{
						Enabled:           true,
						RequestsPerSecond: 1,
						Burst:             burst,
						Store:             config.RateLimitStoreRedis,
						Redis: &config.RateLimitRedisConfig{
							URL:         masterURL,
							KeyPrefix:   rlPrefix,
							ReadTimeout: config.Duration(250 * time.Millisecond),
							Retry: &config.RedisRetryConfig{
								MaxRetries:     2,
								InitialBackoff: config.Duration(50 * time.Millisecond),
								MaxBackoff:     config.Duration(200 * time.Millisecond),
							},
						},
					},
					Cache: &config.CacheConfig{
						Enabled: true,
						Type:    config.CacheTypeRedis,
						TTL:     config.Duration(cacheTTL),
						Redis: &config.RedisCacheConfig{
							URL:       masterURL,
							KeyPrefix: cachePrefix,
							PoolSize:  5,
							TTLJitter: ttlJitter,
						},
					},
					Transform: &config.TransformConfig{
						Response: &config.ResponseTransformConfig{
							DenyFields: []string{"data"},
						},
					},
					CORS: &config.CORSConfig{
						AllowOrigins:  []string{"https://app.example.com"},
						AllowMethods:  []string{"GET", "POST", "OPTIONS"},
						AllowHeaders:  []string{"Authorization", "Content-Type"},
						ExposeHeaders: []string{"X-Cache"},
						MaxAge:        600,
					},
				},
			},
		},
	}
}

// TestE2E_Sentinel_DistributedRateLimit verifies the distributed rate
// limiting journey through REAL Redis Sentinel discovery: two gateway
// instances share one token bucket on the sentinel-managed master, the
// combined rate is enforced, and the new redis rate limit metrics are
// exposed after traffic.
func TestE2E_Sentinel_DistributedRateLimit(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const (
		scope = "e2e-sentinel-rl"
		burst = 6
	)
	keyPrefix := helpers.GenerateTestKeyPrefix("e2e_sentinel_rl")

	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
		_ = sentinelClient.Close()
	})

	rlCfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             burst,
		Store:             config.RateLimitStoreRedis,
		Redis: &config.RateLimitRedisConfig{
			KeyPrefix:   keyPrefix,
			ReadTimeout: config.Duration(250 * time.Millisecond),
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    helpers.GetRedisSentinelMasterName(),
				SentinelAddrs: helpers.GetRedisSentinelAddrs(),
				Password:      helpers.GetRedisMasterPassword(),
			},
		},
	}

	// Two limiter instances (one per gateway replica) bound to the same
	// sentinel deployment through the shared Docker-aware dialer.
	newLimiter := func() *middleware.RedisRateLimiter {
		client := redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    rlCfg.Redis.Sentinel.MasterName,
			SentinelAddrs: rlCfg.Redis.Sentinel.SentinelAddrs,
			Password:      rlCfg.Redis.Sentinel.Password,
			Dialer:        helpers.SentinelDialer(),
		})
		require.NoError(t, client.Ping(ctx).Err(), "sentinel-discovered master must be reachable")

		rrl, err := middleware.NewRedisRateLimiter(ctx, rlCfg, scope, observability.NopLogger(),
			middleware.WithRedisRateLimiterClient(client))
		require.NoError(t, err)
		t.Cleanup(rrl.Stop)
		return rrl
	}

	gw1 := startSentinelLimitedGatewayE2E(t, ctx, 18521, newLimiter())
	gw2 := startSentinelLimitedGatewayE2E(t, ctx, 18522, newLimiter())

	t.Run("1. combined burst is enforced across both instances", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		allowed, denied := 0, 0
		for i := 0; i < 14; i++ {
			base := gw1.BaseURL
			if i%2 == 1 {
				base = gw2.BaseURL
			}
			resp, err := client.Get(base + "/api/v1/items")
			require.NoError(t, err)
			_, _ = helpers.ReadResponseBody(resp)
			switch resp.StatusCode {
			case http.StatusOK:
				allowed++
			case http.StatusTooManyRequests:
				denied++
			}
		}

		t.Logf("distributed split: allowed=%d denied=%d (burst=%d)", allowed, denied, burst)
		assert.GreaterOrEqual(t, allowed, burst, "shared burst must be admitted")
		assert.LessOrEqual(t, allowed, burst+1,
			"combined admitted count must honor one shared bucket across instances")
		assert.GreaterOrEqual(t, denied, 7, "past-burst requests must be throttled on both instances")
	})

	t.Run("2. single shared bucket exists on the sentinel-managed master", func(t *testing.T) {
		bucketKey := keyPrefix + "ratelimit:" + scope
		exists, err := sentinelClient.Exists(ctx, bucketKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists, "bucket key %s must exist", bucketKey)

		keys, err := sentinelClient.Keys(ctx, keyPrefix+"*").Result()
		require.NoError(t, err)
		assert.Len(t, keys, 1, "exactly one shared bucket key must exist for the scope")
	})

	t.Run("3. bucket refills and traffic recovers", func(t *testing.T) {
		time.Sleep(1500 * time.Millisecond) // rps=1 refills at least one token

		resp, err := http.Get(gw1.BaseURL + "/api/v1/items")
		require.NoError(t, err)
		_, _ = helpers.ReadResponseBody(resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "traffic must recover after refill")
	})

	t.Run("4. metrics expose allowed, denied, errors and duration series", func(t *testing.T) {
		// Mirror the production wiring (registerSubsystemMetrics): the
		// middleware metrics singleton is registered on the gateway's
		// registry and pre-initialized so all families are exposed.
		reg := prometheus.NewRegistry()
		middleware.GetMiddlewareMetrics().MustRegister(reg)
		middleware.GetMiddlewareMetrics().Init()
		metricsSrv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		defer metricsSrv.Close()

		resp, err := http.Get(metricsSrv.URL)
		require.NoError(t, err)
		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)

		assert.Contains(t, body, "gateway_middleware_redis_rate_limit_allowed_total")
		assert.Contains(t, body, "gateway_middleware_redis_rate_limit_denied_total")
		assert.Contains(t, body, "gateway_middleware_redis_rate_limit_errors_total")
		assert.Contains(t, body, "gateway_middleware_redis_rate_limit_duration_seconds_bucket")
	})
}

// startSentinelLimitedGatewayE2E starts a gateway whose route handler is
// wrapped with the given sentinel-backed rate limit middleware.
func startSentinelLimitedGatewayE2E(
	t *testing.T, ctx context.Context, port int, rrl *middleware.RedisRateLimiter,
) *helpers.GatewayInstance {
	t.Helper()

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: fmt.Sprintf("e2e-sentinel-rl-gw-%d", port)},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: port, Protocol: config.ProtocolHTTP, Bind: "127.0.0.1"},
			},
			Routes: []config.Route{
				{
					Name: "api",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}, Weight: 100},
					},
					Timeout: config.Duration(15 * time.Second),
				},
			},
		},
	}

	logger := observability.NopLogger()
	r := router.New()
	require.NoError(t, r.LoadRoutes(cfg.Spec.Routes))

	registry := backend.NewRegistry(logger)
	p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))
	handler := middleware.RedisRateLimit(rrl)(p)

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

	// TCP readiness: an HTTP probe would consume rate limiter tokens.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp",
			fmt.Sprintf("127.0.0.1:%d", port))
		if dialErr == nil {
			_ = conn.Close()
			return gi
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("gateway listener on port %d did not become ready", port)
	return nil
}

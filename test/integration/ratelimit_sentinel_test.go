//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
// This file verifies distributed (redis-backed) route rate limiting against
// the REAL Redis Sentinel deployment from the docker-compose test
// environment: token buckets shared across gateway instances, bucket keys
// observable on the sentinel-managed master, and failure policies.
package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

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

// sentinelRateLimitConfig builds a rate limit config carrying the sentinel
// connection settings of the docker-compose environment (from ENV).
func sentinelRateLimitConfig(rps, burst int, perClient bool, keyPrefix string) *config.RateLimitConfig {
	return &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: rps,
		Burst:             burst,
		PerClient:         perClient,
		Store:             config.RateLimitStoreRedis,
		Redis: &config.RateLimitRedisConfig{
			KeyPrefix:      keyPrefix,
			ReadTimeout:    config.Duration(250 * time.Millisecond),
			ConnectTimeout: config.Duration(2 * time.Second),
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    helpers.GetRedisSentinelMasterName(),
				SentinelAddrs: helpers.GetRedisSentinelAddrs(),
				Password:      helpers.GetRedisMasterPassword(),
			},
			Retry: &config.RedisRetryConfig{
				MaxRetries:     1,
				InitialBackoff: config.Duration(50 * time.Millisecond),
				MaxBackoff:     config.Duration(200 * time.Millisecond),
			},
		},
	}
}

// newSentinelRateLimiter builds a RedisRateLimiter bound to the real
// sentinel deployment. The failover client uses the shared test dialer so
// the master announced at a Docker-internal IP is reachable from the host.
func newSentinelRateLimiter(
	t *testing.T, ctx context.Context, cfg *config.RateLimitConfig, scope string,
) *middleware.RedisRateLimiter {
	t.Helper()

	client := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    cfg.Redis.Sentinel.MasterName,
		SentinelAddrs: cfg.Redis.Sentinel.SentinelAddrs,
		Password:      cfg.Redis.Sentinel.Password,
		Dialer:        helpers.SentinelDialer(),
	})

	require.NoError(t, client.Ping(ctx).Err(), "sentinel-discovered master must be reachable")

	rrl, err := middleware.NewRedisRateLimiter(ctx, cfg, scope, observability.NopLogger(),
		middleware.WithRedisRateLimiterClient(client))
	require.NoError(t, err)
	t.Cleanup(rrl.Stop)

	return rrl
}

// startSentinelRateLimitedGateway starts a gateway whose route handler is
// wrapped with the given redis rate limit middleware, proxying to the REST
// test backend.
func startSentinelRateLimitedGateway(
	t *testing.T, ctx context.Context, port int, rrl *middleware.RedisRateLimiter,
) *helpers.GatewayInstance {
	t.Helper()

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: fmt.Sprintf("sentinel-rl-gw-%d", port)},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: port, Protocol: config.ProtocolHTTP, Bind: "127.0.0.1"},
			},
			Routes: []config.Route{
				{
					Name: "api",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET", "POST"}},
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

	// Wait for the listener via TCP dial: an HTTP readiness probe would
	// consume rate limiter tokens and skew the burst arithmetic.
	waitForTCPListener(t, fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
	return gi
}

// waitForTCPListener waits until the given address accepts TCP connections.
func waitForTCPListener(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("listener %s did not become ready within %s", addr, timeout)
}

// sentinelFireRequests performs n sequential GET requests against url and
// returns (allowed, denied) counts. Requests are logged on unexpected codes.
func sentinelFireRequests(t *testing.T, url string, n int) (allowed, denied int) {
	t.Helper()

	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < n; i++ {
		resp, err := client.Get(url)
		require.NoError(t, err)
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			denied++
		default:
			t.Logf("request %d: unexpected status %d", i, resp.StatusCode)
		}
	}
	return allowed, denied
}

// TestIntegration_RateLimit_Sentinel_BurstSplit verifies the distributed
// token bucket against the real sentinel deployment: a burst of requests is
// split into ~burst 200s and the rest 429s, and the bucket key is created
// on the sentinel-managed master.
func TestIntegration_RateLimit_Sentinel_BurstSplit(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keyPrefix := helpers.GenerateTestKeyPrefix("it_rl_sentinel")
	scope := "sentinel-burst"

	// Cleanup bucket keys on the master after the test.
	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
		_ = sentinelClient.Close()
	})

	cfg := sentinelRateLimitConfig(1, 5, false, keyPrefix)
	rrl := newSentinelRateLimiter(t, ctx, cfg, scope)
	gi := startSentinelRateLimitedGateway(t, ctx, 18430, rrl)

	allowed, denied := sentinelFireRequests(t, gi.BaseURL+"/api/v1/items", 12)

	t.Logf("sentinel burst split: allowed=%d denied=%d (burst=5)", allowed, denied)

	assert.GreaterOrEqual(t, allowed, 5, "burst must be admitted")
	assert.LessOrEqual(t, allowed, 6, "admitted requests must stay within burst plus refill slack")
	assert.GreaterOrEqual(t, denied, 6, "past-burst requests must be denied with 429")

	t.Run("bucket key exists on the sentinel-managed master", func(t *testing.T) {
		bucketKey := keyPrefix + "ratelimit:" + scope
		exists, err := sentinelClient.Exists(ctx, bucketKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists, "bucket key %s must exist on the master", bucketKey)

		// The bucket hash carries the token count and refill timestamp.
		fields, err := sentinelClient.HGetAll(ctx, bucketKey).Result()
		require.NoError(t, err)
		assert.Contains(t, fields, "t", "bucket must store the token count")
		assert.Contains(t, fields, "ts", "bucket must store the refill timestamp")

		// Idle-bucket TTL bounds redis memory.
		ttl, err := sentinelClient.TTL(ctx, bucketKey).Result()
		require.NoError(t, err)
		assert.Positive(t, ttl, "bucket must carry an idle-expiry TTL")
	})
}

// TestIntegration_RateLimit_Sentinel_SharedBucket verifies that two gateway
// instances sharing the same sentinel deployment, key prefix, and scope
// enforce one combined token bucket (distributed rate limiting).
func TestIntegration_RateLimit_Sentinel_SharedBucket(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keyPrefix := helpers.GenerateTestKeyPrefix("it_rl_shared")
	scope := "sentinel-shared"

	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
		_ = sentinelClient.Close()
	})

	cfg := sentinelRateLimitConfig(1, 6, false, keyPrefix)

	// Two independent limiter instances (as two gateway replicas would
	// have) sharing scope + prefix and therefore one redis bucket.
	rrl1 := newSentinelRateLimiter(t, ctx, cfg, scope)
	rrl2 := newSentinelRateLimiter(t, ctx, cfg, scope)

	gw1 := startSentinelRateLimitedGateway(t, ctx, 18431, rrl1)
	gw2 := startSentinelRateLimitedGateway(t, ctx, 18432, rrl2)

	client := &http.Client{Timeout: 10 * time.Second}
	allowed, denied := 0, 0
	for i := 0; i < 12; i++ {
		base := gw1.BaseURL
		if i%2 == 1 {
			base = gw2.BaseURL
		}
		resp, err := client.Get(base + "/api/v1/items")
		require.NoError(t, err)
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			denied++
		}
	}

	t.Logf("shared bucket across two gateways: allowed=%d denied=%d (burst=6)", allowed, denied)

	assert.GreaterOrEqual(t, allowed, 6, "shared burst must be admitted")
	assert.LessOrEqual(t, allowed, 7,
		"the combined admitted count must honor ONE shared bucket (12 would mean per-instance buckets)")
	assert.GreaterOrEqual(t, denied, 5, "past-burst requests must be denied on both instances")

	bucketKey := keyPrefix + "ratelimit:" + scope
	exists, err := sentinelClient.Exists(ctx, bucketKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists, "exactly one shared bucket key must exist")
}

// TestIntegration_RateLimit_RouteChain_SentinelMasterURL verifies the FULL
// production route chain (RouteMiddlewareManager built from CRD-shaped
// route config) with store=redis pointing at the sentinel-managed master
// via its host-mapped standalone URL: burst split, per-client isolation,
// and bucket keys with the configured prefix.
func TestIntegration_RateLimit_RouteChain_SentinelMasterURL(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keyPrefix := helpers.GenerateTestKeyPrefix("it_rl_chain")
	masterURL := fmt.Sprintf("redis://default:%s@127.0.0.1:%s",
		helpers.GetRedisMasterPassword(), helpers.GetRedisSentinelMasterPort())

	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
		_ = sentinelClient.Close()
	})

	const routeName = "chain-rl-master"
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "rl-chain-master-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 18433, Protocol: config.ProtocolHTTP, Bind: "127.0.0.1"},
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
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}, Weight: 100},
					},
					Timeout: config.Duration(15 * time.Second),
					RateLimit: &config.RateLimitConfig{
						Enabled:           true,
						RequestsPerSecond: 1,
						Burst:             4,
						Store:             config.RateLimitStoreRedis,
						Redis: &config.RateLimitRedisConfig{
							URL:         masterURL,
							KeyPrefix:   keyPrefix,
							ReadTimeout: config.Duration(250 * time.Millisecond),
							Retry: &config.RedisRetryConfig{
								MaxRetries:     2,
								InitialBackoff: config.Duration(50 * time.Millisecond),
								MaxBackoff:     config.Duration(200 * time.Millisecond),
							},
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

	allowed, denied := sentinelFireRequests(t, gi.BaseURL+"/api/v1/items", 10)
	t.Logf("full-chain master URL split: allowed=%d denied=%d (burst=4)", allowed, denied)

	assert.GreaterOrEqual(t, allowed, 4, "burst must be admitted through the full route chain")
	assert.LessOrEqual(t, allowed, 5, "admitted requests must stay within burst plus refill slack")
	assert.GreaterOrEqual(t, denied, 5, "past-burst requests must be denied")

	t.Run("bucket key with configured prefix exists on the master", func(t *testing.T) {
		bucketKey := keyPrefix + "ratelimit:" + routeName
		exists, err := sentinelClient.Exists(ctx, bucketKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists, "bucket key %s must exist", bucketKey)
	})
}

// TestIntegration_RateLimit_RouteChain_Sentinel_FailOpen verifies the FULL
// production route chain with a sentinel-mode redis store built internally
// by the gateway (no injected client). Fail-open semantics guarantee route
// availability regardless of whether the sentinel-announced master address
// is reachable from the test host: either the limiter reaches redis (bucket
// key appears on the master) or every decision fails open (availability is
// preserved). Both outcomes keep traffic flowing.
func TestIntegration_RateLimit_RouteChain_Sentinel_FailOpen(t *testing.T) {
	helpers.SkipIfRedisSentinelUnavailable(t)
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keyPrefix := helpers.GenerateTestKeyPrefix("it_rl_failopen")

	sentinelClient, err := helpers.CreateRedisSentinelClient()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = helpers.CleanupRedis(sentinelClient, keyPrefix)
		_ = sentinelClient.Close()
	})

	const routeName = "chain-rl-sentinel-failopen"
	rl := sentinelRateLimitConfig(50, 100, false, keyPrefix)
	// Keep the construction-time connectivity check short: when the
	// announced master is unreachable from the host every dial costs the
	// full connect timeout.
	rl.Redis.ConnectTimeout = config.Duration(300 * time.Millisecond)

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "rl-chain-sentinel-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 18434, Protocol: config.ProtocolHTTP, Bind: "127.0.0.1"},
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
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET"}},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}, Weight: 100},
					},
					Timeout:   config.Duration(15 * time.Second),
					RateLimit: rl,
				},
			},
		},
	}

	gi, err := helpers.StartGatewayWithRouteMiddleware(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })
	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second))

	// The first request triggers the lazy chain build, which includes the
	// limiter's best-effort connectivity check (up to the full per-route
	// init budget when the announced master is unreachable from the host).
	// Use a generous timeout for it; fail-open must still answer 200.
	warmupClient := &http.Client{Timeout: 30 * time.Second}
	warmupResp, err := warmupClient.Get(gi.BaseURL + "/api/v1/items")
	require.NoError(t, err, "fail-open limiter construction must not block the route")
	_ = warmupResp.Body.Close()
	require.Equal(t, http.StatusOK, warmupResp.StatusCode)

	// With burst=100 and fail-open, every request must be admitted whether
	// or not the master is reachable from the host. Decisions are bounded
	// by the configured readTimeout once the chain is built.
	allowed, denied := sentinelFireRequests(t, gi.BaseURL+"/api/v1/items", 5)
	assert.Equal(t, 5, allowed, "fail-open sentinel limiter must never block within burst")
	assert.Zero(t, denied)

	// Invariant: the limiter either reached redis (bucket key exists on
	// the master) or applied the fail-open policy on every decision.
	bucketKey := keyPrefix + "ratelimit:" + routeName
	exists, err := sentinelClient.Exists(ctx, bucketKey).Result()
	require.NoError(t, err)
	t.Logf("sentinel-built limiter reached master: %v (bucket key %s)", exists == 1, bucketKey)
}

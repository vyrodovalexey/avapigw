//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify redis-backed distributed route-level rate limiting
// through the full gateway route chain (listener -> router -> per-route
// middleware -> proxy) using miniredis, so no external services are needed.
package functional

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// ---------------------------------------------------------------------------
// Test scaffolding
// ---------------------------------------------------------------------------

// startCountingBackend starts an in-process HTTP backend that counts hits
// and returns a JSON body. It returns the backend, its port, and the hit
// counter.
func startCountingBackend(t *testing.T) (*httptest.Server, int, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{"hit":` +
			strconv.FormatInt(hits.Load(), 10) + `}}`))
	}))
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)

	return ts, port, &hits
}

// rateLimitedGatewayConfig builds a gateway config with a health route and
// a single rate-limited API route proxying to the given backend port.
func rateLimitedGatewayConfig(
	gatewayPort, backendPort int, routeName string, rl *config.RateLimitConfig,
) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "fn-ratelimit-redis-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: gatewayPort, Protocol: config.ProtocolHTTP, Bind: "127.0.0.1"},
			},
			Routes: []config.Route{
				{
					Name: "health-check",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}, Methods: []string{"GET"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status:  200,
						Body:    `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: routeName,
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/"}, Methods: []string{"GET", "POST"}},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{Host: "127.0.0.1", Port: backendPort},
							Weight:      100,
						},
					},
					Timeout:   config.Duration(10 * time.Second),
					RateLimit: rl,
				},
			},
		},
	}
}

// startRateLimitedGateway starts a gateway with the full per-route
// middleware chain and waits until it is ready.
func startRateLimitedGateway(
	t *testing.T, ctx context.Context, cfg *config.GatewayConfig,
) *helpers.GatewayInstance {
	t.Helper()

	gi, err := helpers.StartGatewayWithRouteMiddleware(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = gi.Stop(context.Background()) })

	require.NoError(t, helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second))
	return gi
}

// fireRequests performs n sequential GET requests and returns the observed
// status codes.
func fireRequests(t *testing.T, url string, n int, headers map[string]string) []int {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	codes := make([]int, 0, n)
	for i := 0; i < n; i++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	return codes
}

// countCodes returns how many entries in codes equal want.
func countCodes(codes []int, want int) int {
	n := 0
	for _, c := range codes {
		if c == want {
			n++
		}
	}
	return n
}

// gatherCounter reads a counter value with the given label pairs from the
// shared middleware metrics singleton through a fresh Prometheus registry.
// Returns 0 when the series does not exist yet.
func gatherCounter(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()

	reg := prometheus.NewRegistry()
	middleware.GetMiddlewareMetrics().MustRegister(reg)

	families, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if metricMatchesLabels(m, labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// metricMatchesLabels reports whether the metric carries all given labels.
func metricMatchesLabels(m *dto.Metric, labels map[string]string) bool {
	got := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range labels {
		if got[k] != v {
			return false
		}
	}
	return true
}

// redisRateLimitConfig builds an enabled redis-store rate limit config
// pointing at the given miniredis address.
func redisRouteRateLimit(rps, burst int, perClient bool, addr, keyPrefix string) *config.RateLimitConfig {
	return &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: rps,
		Burst:             burst,
		PerClient:         perClient,
		Store:             config.RateLimitStoreRedis,
		Redis: &config.RateLimitRedisConfig{
			URL:       "redis://" + addr,
			KeyPrefix: keyPrefix,
			Retry: &config.RedisRetryConfig{
				MaxRetries:     1,
				InitialBackoff: config.Duration(10 * time.Millisecond),
				MaxBackoff:     config.Duration(50 * time.Millisecond),
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Route chain enforcement
// ---------------------------------------------------------------------------

// TestFunctional_RateLimit_RouteChain_MemoryStore verifies that route-level
// rate limiting with the default in-memory store is enforced through the
// full gateway route chain (this enforcement is new: route-level rateLimit
// used to be silently ignored by the data path).
func TestFunctional_RateLimit_RouteChain_MemoryStore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, backendPort, hits := startCountingBackend(t)

	cfg := rateLimitedGatewayConfig(19110, backendPort, "fn-rl-memory", &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             3,
	})
	gi := startRateLimitedGateway(t, ctx, cfg)

	codes := fireRequests(t, gi.BaseURL+"/api/items", 8, nil)

	// The burst admits the first requests; the tail is throttled. One
	// refill token of slack is allowed in case the loop crosses a second.
	allowed := countCodes(codes, http.StatusOK)
	denied := countCodes(codes, http.StatusTooManyRequests)

	assert.Equal(t, []int{200, 200, 200}, codes[:3], "burst must admit the first three requests")
	assert.GreaterOrEqual(t, allowed, 3, "burst should be admitted")
	assert.LessOrEqual(t, allowed, 4, "at most one refill token of slack")
	assert.GreaterOrEqual(t, denied, 4, "past-burst requests must get 429")
	assert.Equal(t, http.StatusTooManyRequests, codes[len(codes)-1], "last request must be throttled")
	assert.Equal(t, int64(allowed), hits.Load(), "backend must see only admitted requests")
}

// TestFunctional_RateLimit_RouteChain_RedisStore verifies the redis-store
// distributed limiter through the full gateway route chain: allowed until
// burst, denied after, bucket key created in redis, 429 semantics.
func TestFunctional_RateLimit_RouteChain_RedisStore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mr := miniredis.RunT(t)
	_, backendPort, hits := startCountingBackend(t)

	const routeName = "fn-rl-redis"
	cfg := rateLimitedGatewayConfig(19111, backendPort, routeName,
		redisRouteRateLimit(1, 3, false, mr.Addr(), "fnrl:"))
	gi := startRateLimitedGateway(t, ctx, cfg)

	allowedBefore := gatherCounter(t, "gateway_middleware_redis_rate_limit_allowed_total",
		map[string]string{"route": routeName})
	deniedBefore := gatherCounter(t, "gateway_middleware_redis_rate_limit_denied_total",
		map[string]string{"route": routeName})

	codes := fireRequests(t, gi.BaseURL+"/api/items", 8, nil)

	allowed := countCodes(codes, http.StatusOK)
	denied := countCodes(codes, http.StatusTooManyRequests)

	t.Run("burst admitted then throttled", func(t *testing.T) {
		assert.Equal(t, []int{200, 200, 200}, codes[:3], "burst must admit the first three requests")
		assert.GreaterOrEqual(t, allowed, 3)
		assert.LessOrEqual(t, allowed, 4, "at most one refill token of slack")
		assert.GreaterOrEqual(t, denied, 4)
		assert.Equal(t, int64(allowed), hits.Load(), "throttled requests must not reach the backend")
	})

	t.Run("429 response carries Retry-After and JSON error", func(t *testing.T) {
		resp, err := http.Get(gi.BaseURL + "/api/items")
		require.NoError(t, err)
		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)

		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))
		assert.Contains(t, body, "rate limit exceeded")
	})

	t.Run("token bucket state lives in redis under the route scope", func(t *testing.T) {
		assert.True(t, mr.Exists("fnrl:ratelimit:"+routeName),
			"bucket key fnrl:ratelimit:%s must exist in redis", routeName)
	})

	t.Run("redis rate limit metrics are recorded per route", func(t *testing.T) {
		allowedAfter := gatherCounter(t, "gateway_middleware_redis_rate_limit_allowed_total",
			map[string]string{"route": routeName})
		deniedAfter := gatherCounter(t, "gateway_middleware_redis_rate_limit_denied_total",
			map[string]string{"route": routeName})

		assert.GreaterOrEqual(t, allowedAfter-allowedBefore, float64(3),
			"allowed counter must grow with admitted requests")
		assert.GreaterOrEqual(t, deniedAfter-deniedBefore, float64(4),
			"denied counter must grow with throttled requests")
	})
}

// TestFunctional_RateLimit_RouteChain_RedisStore_PerClient verifies that
// PerClient=true isolates token buckets per client IP: the client IP is
// derived from X-Forwarded-For when the direct peer is a trusted proxy,
// mirroring the production trustedProxies wiring.
func TestFunctional_RateLimit_RouteChain_RedisStore_PerClient(t *testing.T) {
	// Not parallel: this test swaps the process-global client IP extractor
	// (as cmd/gateway does at startup) and restores it on exit.
	middleware.SetGlobalIPExtractor(middleware.NewClientIPExtractor([]string{"127.0.0.1"}))
	defer middleware.SetGlobalIPExtractor(middleware.NewClientIPExtractor(nil))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mr := miniredis.RunT(t)
	_, backendPort, _ := startCountingBackend(t)

	const routeName = "fn-rl-perclient"
	cfg := rateLimitedGatewayConfig(19112, backendPort, routeName,
		redisRouteRateLimit(1, 2, true, mr.Addr(), "fnpc:"))
	gi := startRateLimitedGateway(t, ctx, cfg)

	clientA := map[string]string{"X-Forwarded-For": "10.1.1.1"}
	clientB := map[string]string{"X-Forwarded-For": "10.2.2.2"}

	t.Run("client A exhausts its own bucket", func(t *testing.T) {
		codes := fireRequests(t, gi.BaseURL+"/api/items", 3, clientA)
		assert.Equal(t, []int{200, 200, 429}, codes)
	})

	t.Run("client B still has a full bucket", func(t *testing.T) {
		codes := fireRequests(t, gi.BaseURL+"/api/items", 2, clientB)
		assert.Equal(t, []int{200, 200}, codes)
	})

	t.Run("per-client buckets exist in redis", func(t *testing.T) {
		assert.True(t, mr.Exists("fnpc:ratelimit:"+routeName+":client:10.1.1.1"),
			"client A bucket must exist")
		assert.True(t, mr.Exists("fnpc:ratelimit:"+routeName+":client:10.2.2.2"),
			"client B bucket must exist")
	})
}

// TestFunctional_RateLimit_RouteChain_RedisStore_SharedBucket verifies the
// distributed semantics: two gateway instances sharing the same redis and
// key prefix enforce one combined token bucket.
func TestFunctional_RateLimit_RouteChain_RedisStore_SharedBucket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mr := miniredis.RunT(t)
	_, backendPort, _ := startCountingBackend(t)

	// Same route name (limiter scope) and key prefix on both instances.
	const routeName = "fn-rl-shared"
	rl := redisRouteRateLimit(1, 4, false, mr.Addr(), "fnshared:")

	gw1 := startRateLimitedGateway(t, ctx, rateLimitedGatewayConfig(19113, backendPort, routeName, rl))
	gw2 := startRateLimitedGateway(t, ctx, rateLimitedGatewayConfig(19114, backendPort, routeName, rl))

	// Alternate requests across the two gateways: the combined admitted
	// count must honor the single shared bucket, not one bucket each.
	client := &http.Client{Timeout: 5 * time.Second}
	allowed, denied := 0, 0
	for i := 0; i < 10; i++ {
		base := gw1.BaseURL
		if i%2 == 1 {
			base = gw2.BaseURL
		}
		resp, err := client.Get(base + "/api/items")
		require.NoError(t, err)
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			denied++
		}
	}

	assert.GreaterOrEqual(t, allowed, 4, "shared burst must be admitted")
	assert.LessOrEqual(t, allowed, 5,
		"two instances must share one bucket (10 would mean per-instance buckets)")
	assert.GreaterOrEqual(t, denied, 5)
	assert.True(t, mr.Exists("fnshared:ratelimit:"+routeName), "single shared bucket key must exist")
}

// ---------------------------------------------------------------------------
// Failure policies on redis outage
// ---------------------------------------------------------------------------

// TestFunctional_RateLimit_RouteChain_RedisStore_FailOpenOutage verifies
// that with failOpen (default) a redis outage lets traffic through and
// records failure metrics.
func TestFunctional_RateLimit_RouteChain_RedisStore_FailOpenOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	_, backendPort, _ := startCountingBackend(t)

	const routeName = "fn-rl-failopen"
	rl := redisRouteRateLimit(1, 2, false, mr.Addr(), "fnfo:")
	rl.Redis.ReadTimeout = config.Duration(100 * time.Millisecond)

	cfg := rateLimitedGatewayConfig(19115, backendPort, routeName, rl)
	gi := startRateLimitedGateway(t, ctx, cfg)

	// Limiter works while redis is up.
	codes := fireRequests(t, gi.BaseURL+"/api/items", 1, nil)
	require.Equal(t, []int{200}, codes, "request with redis up must pass")

	errorsBefore := gatherCounter(t, "gateway_middleware_redis_rate_limit_errors_total",
		map[string]string{"route": routeName, "policy": "fail_open"})

	// Kill redis: fail-open must keep the route available.
	mr.Close()

	codes = fireRequests(t, gi.BaseURL+"/api/items", 4, nil)
	assert.Equal(t, []int{200, 200, 200, 200}, codes,
		"fail-open must allow traffic during a redis outage")

	errorsAfter := gatherCounter(t, "gateway_middleware_redis_rate_limit_errors_total",
		map[string]string{"route": routeName, "policy": "fail_open"})
	assert.GreaterOrEqual(t, errorsAfter-errorsBefore, float64(4),
		"every outage decision must increment the errors counter with policy=fail_open")
}

// TestFunctional_RateLimit_RouteChain_RedisStore_FailClosedOutage verifies
// that with failOpen=false a redis outage rejects requests with 429.
func TestFunctional_RateLimit_RouteChain_RedisStore_FailClosedOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	_, backendPort, hits := startCountingBackend(t)

	const routeName = "fn-rl-failclosed"
	failOpen := false
	rl := redisRouteRateLimit(1, 5, false, mr.Addr(), "fnfc:")
	rl.Redis.FailOpen = &failOpen
	rl.Redis.ReadTimeout = config.Duration(100 * time.Millisecond)

	cfg := rateLimitedGatewayConfig(19116, backendPort, routeName, rl)
	gi := startRateLimitedGateway(t, ctx, cfg)

	// Limiter works while redis is up (constructs with PingRequired).
	codes := fireRequests(t, gi.BaseURL+"/api/items", 1, nil)
	require.Equal(t, []int{200}, codes, "request with redis up must pass")
	backendHitsUp := hits.Load()

	errorsBefore := gatherCounter(t, "gateway_middleware_redis_rate_limit_errors_total",
		map[string]string{"route": routeName, "policy": "fail_closed"})

	// Kill redis: fail-closed must reject rather than run unlimited.
	mr.Close()

	codes = fireRequests(t, gi.BaseURL+"/api/items", 3, nil)
	assert.Equal(t, []int{429, 429, 429}, codes,
		"fail-closed must reject traffic during a redis outage")
	assert.Equal(t, backendHitsUp, hits.Load(), "rejected requests must not reach the backend")

	errorsAfter := gatherCounter(t, "gateway_middleware_redis_rate_limit_errors_total",
		map[string]string{"route": routeName, "policy": "fail_closed"})
	assert.GreaterOrEqual(t, errorsAfter-errorsBefore, float64(3),
		"every outage decision must increment the errors counter with policy=fail_closed")
}

// ---------------------------------------------------------------------------
// Configuration validation surface (YAML -> loader -> validator)
// ---------------------------------------------------------------------------

// TestFunctional_RateLimitAndCache_Redis_ConfigValidationSurface verifies
// the YAML configuration surface of the redis rate limiter store and the
// route-level redis cache: enum values, redis-required-when-store-redis,
// url/sentinel mutual exclusion, and ttlJitter bounds. It goes through the
// real loader (LoadConfigFromReader) and validator (ValidateConfig), i.e.
// the exact path a config file takes at gateway startup.
func TestFunctional_RateLimitAndCache_Redis_ConfigValidationSurface(t *testing.T) {
	t.Parallel()

	const header = `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: validation-surface
spec:
  listeners:
    - name: http
      port: 18080
      protocol: HTTP
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

	tests := []struct {
		name          string
		routeFragment string
		wantErr       string
	}{
		{
			name: "valid redis store with url",
			routeFragment: `      rateLimit:
        enabled: true
        requestsPerSecond: 10
        burst: 5
        store: redis
        redis:
          url: redis://127.0.0.1:6379
          keyPrefix: "rl:"
          failOpen: false
`,
		},
		{
			name: "valid redis store with sentinel",
			routeFragment: `      rateLimit:
        enabled: true
        requestsPerSecond: 10
        burst: 5
        store: redis
        redis:
          sentinel:
            masterName: mymaster
            sentinelAddrs:
              - 127.0.0.1:26379
              - 127.0.0.1:26380
            password: password
`,
		},
		{
			name: "invalid store enum",
			routeFragment: `      rateLimit:
        enabled: true
        requestsPerSecond: 10
        burst: 5
        store: etcd
`,
			wantErr: "invalid store",
		},
		{
			name: "store redis requires redis block",
			routeFragment: `      rateLimit:
        enabled: true
        requestsPerSecond: 10
        burst: 5
        store: redis
`,
			wantErr: "redis configuration with url or sentinel is required",
		},
		{
			name: "rate limit url and sentinel are mutually exclusive",
			routeFragment: `      rateLimit:
        enabled: true
        requestsPerSecond: 10
        burst: 5
        store: redis
        redis:
          url: redis://127.0.0.1:6379
          sentinel:
            masterName: mymaster
            sentinelAddrs:
              - 127.0.0.1:26379
`,
			wantErr: "url and sentinel are mutually exclusive",
		},
		{
			name: "memory store rejects redis block",
			routeFragment: `      rateLimit:
        enabled: true
        requestsPerSecond: 10
        burst: 5
        store: memory
        redis:
          url: redis://127.0.0.1:6379
`,
			wantErr: "redis configuration is only valid when store is 'redis'",
		},
		{
			name: "valid redis cache with sentinel and jitter",
			routeFragment: `      cache:
        enabled: true
        type: redis
        ttl: 5m
        redis:
          keyPrefix: "c:"
          ttlJitter: 0.3
          sentinel:
            masterName: mymaster
            sentinelAddrs:
              - 127.0.0.1:26379
            password: password
`,
		},
		{
			name: "invalid cache type enum",
			routeFragment: `      cache:
        enabled: true
        type: memcached
        ttl: 5m
`,
			wantErr: "invalid type",
		},
		{
			name: "cache type redis requires redis block",
			routeFragment: `      cache:
        enabled: true
        type: redis
        ttl: 5m
`,
			wantErr: "redis configuration with url or sentinel is required",
		},
		{
			name: "cache url and sentinel are mutually exclusive",
			routeFragment: `      cache:
        enabled: true
        type: redis
        ttl: 5m
        redis:
          url: redis://127.0.0.1:6379
          sentinel:
            masterName: mymaster
            sentinelAddrs:
              - 127.0.0.1:26379
`,
			wantErr: "url and sentinel are mutually exclusive",
		},
		{
			name: "cache ttlJitter above bounds",
			routeFragment: `      cache:
        enabled: true
        type: redis
        ttl: 5m
        redis:
          url: redis://127.0.0.1:6379
          ttlJitter: 1.5
`,
			wantErr: "ttlJitter must be between 0.0 and 1.0",
		},
		{
			name: "cache ttlJitter below bounds",
			routeFragment: `      cache:
        enabled: true
        type: redis
        ttl: 5m
        redis:
          url: redis://127.0.0.1:6379
          ttlJitter: -0.1
`,
			wantErr: "ttlJitter must be between 0.0 and 1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			yaml := header + tt.routeFragment
			cfg, err := config.LoadConfigFromReader(strings.NewReader(yaml))
			require.NoError(t, err, "YAML must parse")

			err = config.ValidateConfig(cfg)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

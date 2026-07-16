package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// rateLimitedRoute builds a route with the given rate limit configuration.
func rateLimitedRoute(name string, rl *config.RateLimitConfig) *config.Route {
	return &config.Route{Name: name, RateLimit: rl}
}

// serveThroughRoute applies the route middleware chain and performs one request.
func serveThroughRoute(m *RouteMiddlewareManager, route *config.Route) *httptest.ResponseRecorder {
	handler := m.ApplyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), route)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	return rec
}

func TestRouteMiddleware_RateLimit_MemoryStore(t *testing.T) {
	m := NewRouteMiddlewareManager(nil, observability.NopLogger())
	defer m.Stop()

	// RequestsPerSecond=1 keeps the refill window (1s) well above any realistic
	// gap between the three sequential in-process requests, so the third is
	// deterministically throttled even under heavy concurrent test load.
	route := rateLimitedRoute("rl-mem", &config.RateLimitConfig{
		Enabled: true, RequestsPerSecond: 1, Burst: 2,
	})

	// Burst admits two requests, the third is throttled.
	for i := 0; i < 2; i++ {
		if rec := serveThroughRoute(m, route); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, rec.Code)
		}
	}
	if rec := serveThroughRoute(m, route); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request = %d, want 429", rec.Code)
	}

	// Lifecycle handle is tracked for cleanup.
	m.mu.RLock()
	_, tracked := m.routeRateLimiters["rl-mem"]
	m.mu.RUnlock()
	if !tracked {
		t.Error("route rate limiter must be tracked for lifecycle management")
	}
}

func TestRouteMiddleware_RateLimit_RedisStore(t *testing.T) {
	mr := miniredis.RunT(t)

	m := NewRouteMiddlewareManager(nil, observability.NopLogger())
	defer m.Stop()

	// RequestsPerSecond=1 makes the refill window (1s) far larger than any
	// plausible scheduling gap between the three in-process requests below.
	// The manager path cannot inject a fake clock, so a higher RPS (e.g. 100 =>
	// 10ms refill) can non-deterministically refill a token under heavy load
	// and let the third request through. Deterministic refill semantics are
	// covered separately by TestRedisRateLimiter_RefillOverTime (fake clock).
	route := rateLimitedRoute("rl-redis", &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             2,
		Store:             config.RateLimitStoreRedis,
		Redis: &config.RateLimitRedisConfig{
			URL: "redis://" + mr.Addr(),
			Retry: &config.RedisRetryConfig{
				MaxRetries:     1,
				InitialBackoff: config.Duration(time.Millisecond),
			},
		},
	})

	for i := 0; i < 2; i++ {
		if rec := serveThroughRoute(m, route); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, rec.Code)
		}
	}
	if rec := serveThroughRoute(m, route); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request = %d, want 429", rec.Code)
	}

	// Bucket state lives in redis under the route scope.
	if !mr.Exists("avapigw:ratelimit:rl-redis") {
		t.Error("redis bucket key for the route scope must exist")
	}
}

func TestRouteMiddleware_RateLimit_Disabled(t *testing.T) {
	m := NewRouteMiddlewareManager(nil, observability.NopLogger())
	defer m.Stop()

	route := rateLimitedRoute("rl-off", &config.RateLimitConfig{Enabled: false})

	for i := 0; i < 5; i++ {
		if rec := serveThroughRoute(m, route); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 (disabled limiter)", i+1, rec.Code)
		}
	}

	m.mu.RLock()
	count := len(m.routeRateLimiters)
	m.mu.RUnlock()
	if count != 0 {
		t.Errorf("disabled rate limit must not track limiters, got %d", count)
	}
}

func TestRouteMiddleware_RateLimit_FailOpenConstructionError(t *testing.T) {
	m := NewRouteMiddlewareManager(nil, observability.NopLogger())
	defer m.Stop()

	// Invalid URL is a hard construction error; failOpen (default true)
	// degrades to no limiting so the route stays available.
	route := rateLimitedRoute("rl-failopen", &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		Store:             config.RateLimitStoreRedis,
		Redis:             &config.RateLimitRedisConfig{URL: "://invalid-url"},
	})

	for i := 0; i < 3; i++ {
		if rec := serveThroughRoute(m, route); rec.Code != http.StatusOK {
			t.Fatalf("fail-open construction error must not block traffic, got %d", rec.Code)
		}
	}
}

func TestRouteMiddleware_RateLimit_FailClosedConstructionError(t *testing.T) {
	m := NewRouteMiddlewareManager(nil, observability.NopLogger())
	defer m.Stop()

	failOpen := false
	route := rateLimitedRoute("rl-failclosed", &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		Store:             config.RateLimitStoreRedis,
		Redis: &config.RateLimitRedisConfig{
			URL:      "://invalid-url",
			FailOpen: &failOpen,
		},
	})

	// A strict limiter that cannot be built must never run unenforced.
	if rec := serveThroughRoute(m, route); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("fail-closed construction error must reject traffic, got %d", rec.Code)
	}
}

func TestRouteMiddleware_RateLimit_LifecycleOnClearCache(t *testing.T) {
	m := NewRouteMiddlewareManager(nil, observability.NopLogger())

	route := rateLimitedRoute("rl-lifecycle", &config.RateLimitConfig{
		Enabled: true, RequestsPerSecond: 10, Burst: 5,
	})

	if rec := serveThroughRoute(m, route); rec.Code != http.StatusOK {
		t.Fatalf("request = %d, want 200", rec.Code)
	}

	m.mu.RLock()
	before := len(m.routeRateLimiters)
	m.mu.RUnlock()
	if before != 1 {
		t.Fatalf("tracked limiters = %d, want 1", before)
	}

	m.ClearCache()

	m.mu.RLock()
	after := len(m.routeRateLimiters)
	m.mu.RUnlock()
	if after != 0 {
		t.Errorf("tracked limiters after ClearCache = %d, want 0", after)
	}

	// Chains rebuild transparently after the reset.
	if rec := serveThroughRoute(m, route); rec.Code != http.StatusOK {
		t.Fatalf("request after ClearCache = %d, want 200", rec.Code)
	}

	m.Stop()
}

func TestRouteMiddleware_RateLimit_LifecycleOnUpdateGlobalConfig(t *testing.T) {
	m := NewRouteMiddlewareManager(nil, observability.NopLogger())
	defer m.Stop()

	route := rateLimitedRoute("rl-update", &config.RateLimitConfig{
		Enabled: true, RequestsPerSecond: 10, Burst: 5,
	})
	if rec := serveThroughRoute(m, route); rec.Code != http.StatusOK {
		t.Fatalf("request = %d, want 200", rec.Code)
	}

	m.UpdateGlobalConfig(&config.GatewaySpec{})

	m.mu.RLock()
	after := len(m.routeRateLimiters)
	m.mu.RUnlock()
	if after != 0 {
		t.Errorf("tracked limiters after UpdateGlobalConfig = %d, want 0", after)
	}
}

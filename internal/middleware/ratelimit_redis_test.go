package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// fakeClock is an injectable time source for deterministic refill tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// redisRateLimitConfig builds an enabled redis-store rate limit config.
func redisRateLimitConfig(rps, burst int, perClient bool, url string) *config.RateLimitConfig {
	return &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: rps,
		Burst:             burst,
		PerClient:         perClient,
		Store:             config.RateLimitStoreRedis,
		Redis: &config.RateLimitRedisConfig{
			URL: url,
			Retry: &config.RedisRetryConfig{
				MaxRetries:     1,
				InitialBackoff: config.Duration(time.Millisecond),
				MaxBackoff:     config.Duration(2 * time.Millisecond),
			},
		},
	}
}

// newTestRedisLimiter builds a limiter bound to a miniredis instance with a
// fake clock. The injected client bypasses connection construction.
func newTestRedisLimiter(
	t *testing.T, mr *miniredis.Miniredis, cfg *config.RateLimitConfig, scope string,
	opts ...RedisRateLimiterOption,
) (*RedisRateLimiter, *fakeClock) {
	t.Helper()

	clock := newFakeClock()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	allOpts := append([]RedisRateLimiterOption{
		WithRedisRateLimiterClient(client),
		WithRedisRateLimiterNowFunc(clock.Now),
	}, opts...)

	rl, err := NewRedisRateLimiter(context.Background(), cfg, scope,
		observability.NopLogger(), allOpts...)
	if err != nil {
		t.Fatalf("NewRedisRateLimiter: %v", err)
	}
	return rl, clock
}

// --- Constructor validation ---

func TestNewRedisRateLimiter_MissingRedisConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.RateLimitConfig
	}{
		{name: "nil config", cfg: nil},
		{name: "nil redis block", cfg: &config.RateLimitConfig{Enabled: true, Store: "redis"}},
		{name: "empty redis block", cfg: &config.RateLimitConfig{
			Enabled: true, Store: "redis", Redis: &config.RateLimitRedisConfig{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRedisRateLimiter(context.Background(), tt.cfg, "s", nil)
			if err == nil || !strings.Contains(err.Error(), "requires redis configuration") {
				t.Fatalf("expected configuration error, got %v", err)
			}
		})
	}
}

func TestNewRedisRateLimiter_FailClosed_Unreachable(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	failOpen := false
	cfg := redisRateLimitConfig(10, 5, false, "redis://"+addr)
	cfg.Redis.FailOpen = &failOpen

	_, err := NewRedisRateLimiter(context.Background(), cfg, "s", observability.NopLogger())
	if err == nil || !strings.Contains(err.Error(), "failed to build redis rate limiter client") {
		t.Fatalf("fail-closed limiter must fail construction on unreachable redis, got %v", err)
	}
}

func TestNewRedisRateLimiter_FailOpen_Unreachable(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	cfg := redisRateLimitConfig(10, 5, false, "redis://"+addr)

	rl, err := NewRedisRateLimiter(context.Background(), cfg, "s", observability.NopLogger())
	if err != nil {
		t.Fatalf("fail-open limiter must start degraded, got %v", err)
	}
	defer rl.Stop()

	// Degraded limiter fails open.
	if !rl.Allow(context.Background(), "1.2.3.4") {
		t.Error("fail-open limiter must allow when redis is unreachable")
	}
}

// --- Token bucket semantics ---

func TestRedisRateLimiter_BurstThenDeny(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, _ := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "burst")
	defer rl.Stop()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if !rl.Allow(ctx, "1.2.3.4") {
			t.Fatalf("request %d within burst must be allowed", i+1)
		}
	}
	if rl.Allow(ctx, "1.2.3.4") {
		t.Error("request beyond burst must be denied")
	}
}

func TestRedisRateLimiter_RefillOverTime(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, clock := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "refill")
	defer rl.Stop()

	ctx := context.Background()

	// Drain the bucket.
	for i := 0; i < 5; i++ {
		if !rl.Allow(ctx, "c") {
			t.Fatalf("drain request %d must be allowed", i+1)
		}
	}
	if rl.Allow(ctx, "c") {
		t.Fatal("bucket must be empty after drain")
	}

	// 100ms at 10 rps refills exactly one token.
	clock.Advance(100 * time.Millisecond)
	if !rl.Allow(ctx, "c") {
		t.Error("one token must be available after 100ms refill")
	}
	if rl.Allow(ctx, "c") {
		t.Error("only one token must refill in 100ms")
	}

	// A full second refills to burst capacity (capped at 5).
	clock.Advance(10 * time.Second)
	for i := 0; i < 5; i++ {
		if !rl.Allow(ctx, "c") {
			t.Errorf("request %d after full refill must be allowed", i+1)
		}
	}
	if rl.Allow(ctx, "c") {
		t.Error("refill must be capped at burst capacity")
	}
}

func TestRedisRateLimiter_PerClientIsolation(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, _ := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 2, true, "redis://"+mr.Addr()), "perclient")
	defer rl.Stop()

	ctx := context.Background()

	// Client A drains its bucket.
	for i := 0; i < 2; i++ {
		if !rl.Allow(ctx, "10.0.0.1") {
			t.Fatalf("client A request %d must be allowed", i+1)
		}
	}
	if rl.Allow(ctx, "10.0.0.1") {
		t.Error("client A must be limited after burst")
	}

	// Client B has an independent bucket.
	if !rl.Allow(ctx, "10.0.0.2") {
		t.Error("client B must not be affected by client A's bucket")
	}
}

func TestRedisRateLimiter_SharedBucketAcrossInstances(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := redisRateLimitConfig(10, 3, false, "redis://"+mr.Addr())

	// Two limiter instances (two gateway replicas) share the same scope.
	rl1, clock1 := newTestRedisLimiter(t, mr, cfg, "shared")
	defer rl1.Stop()
	rl2, _ := newTestRedisLimiter(t, mr, cfg, "shared")
	defer rl2.Stop()
	rl2.nowFunc = clock1.Now // same time source for determinism

	ctx := context.Background()
	allowed := 0
	for i := 0; i < 3; i++ {
		if rl1.Allow(ctx, "c") {
			allowed++
		}
		if rl2.Allow(ctx, "c") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("distributed bucket must admit exactly burst=3 across instances, got %d", allowed)
	}
}

func TestRedisRateLimiter_IdleBucketTTLExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, clock := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "ttl")
	defer rl.Stop()

	ctx := context.Background()
	if !rl.Allow(ctx, "c") {
		t.Fatal("first request must be allowed")
	}

	key := "avapigw:ratelimit:ttl"
	if !mr.Exists(key) {
		t.Fatalf("bucket key %q must exist after first request", key)
	}

	// idle TTL = burst/rps + 60s margin = 60.5s; fast-forward past it.
	mr.FastForward(61 * time.Second)
	if mr.Exists(key) {
		t.Error("idle bucket must expire via PEXPIRE")
	}

	// A fresh bucket starts full again.
	clock.Advance(61 * time.Second)
	for i := 0; i < 5; i++ {
		if !rl.Allow(ctx, "c") {
			t.Errorf("request %d on fresh bucket must be allowed", i+1)
		}
	}
}

func TestRedisRateLimiter_ClockSkewNeverRefillsBackwards(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, clock := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 2, false, "redis://"+mr.Addr()), "skew")
	defer rl.Stop()

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if !rl.Allow(ctx, "c") {
			t.Fatalf("drain request %d must be allowed", i+1)
		}
	}

	// A replica with a lagging clock must not gain tokens.
	clock.Advance(-10 * time.Second)
	if rl.Allow(ctx, "c") {
		t.Error("negative elapsed time must not refill the bucket")
	}
}

// --- Failure policies at runtime ---

func TestRedisRateLimiter_FailOpenOnOutage(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, _ := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "outage")
	defer rl.Stop()

	ctx := context.Background()
	errBefore := testutil.ToFloat64(
		GetMiddlewareMetrics().redisRateLimitErrors.WithLabelValues(unknownRoute, failPolicyOpen))

	mr.Close()

	if !rl.Allow(ctx, "c") {
		t.Error("failOpen=true must allow on redis outage")
	}

	errAfter := testutil.ToFloat64(
		GetMiddlewareMetrics().redisRateLimitErrors.WithLabelValues(unknownRoute, failPolicyOpen))
	if errAfter != errBefore+1 {
		t.Errorf("fail_open error counter = %v, want %v", errAfter, errBefore+1)
	}
}

func TestRedisRateLimiter_FailClosedOnOutage(t *testing.T) {
	mr := miniredis.RunT(t)
	failOpen := false
	cfg := redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr())
	cfg.Redis.FailOpen = &failOpen

	rl, _ := newTestRedisLimiter(t, mr, cfg, "outage-closed")
	defer rl.Stop()

	ctx := context.Background()
	errBefore := testutil.ToFloat64(
		GetMiddlewareMetrics().redisRateLimitErrors.WithLabelValues(unknownRoute, failPolicyClosed))

	mr.Close()

	if rl.Allow(ctx, "c") {
		t.Error("failOpen=false must deny on redis outage")
	}

	errAfter := testutil.ToFloat64(
		GetMiddlewareMetrics().redisRateLimitErrors.WithLabelValues(unknownRoute, failPolicyClosed))
	if errAfter != errBefore+1 {
		t.Errorf("fail_closed error counter = %v, want %v", errAfter, errBefore+1)
	}
}

func TestRedisRateLimiter_OutageWarnRateLimited(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, clock := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "warn")
	defer rl.Stop()

	mr.Close()

	// First failure elects the warner; immediate subsequent failures do not.
	if !rl.shouldWarnOutage() {
		t.Error("first outage must warn")
	}
	if rl.shouldWarnOutage() {
		t.Error("second outage within the window must not warn")
	}

	clock.Advance(redisOutageWarnInterval + time.Second)
	if !rl.shouldWarnOutage() {
		t.Error("outage after the warn interval must warn again")
	}
}

// --- Lifecycle ---

func TestRedisRateLimiter_StopIdempotent(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, _ := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "stop")

	rl.Stop()
	rl.Stop() // must not panic or double-close
}

func TestRedisRateLimiter_UpdateConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, _ := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 2, false, "redis://"+mr.Addr()), "update")
	defer rl.Stop()

	rl.UpdateConfig(nil) // no-op

	rl.UpdateConfig(&config.RateLimitConfig{RequestsPerSecond: 100, Burst: 50, PerClient: true})

	rl.mu.RLock()
	rps, burst, perClient := rl.rps, rl.burst, rl.perClient
	rl.mu.RUnlock()

	if rps != 100 || burst != 50 || !perClient {
		t.Errorf("config not updated: rps=%d burst=%d perClient=%v", rps, burst, perClient)
	}
}

// --- HTTP middleware integration ---

func TestRedisRateLimit_Middleware(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, _ := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 2, false, "redis://"+mr.Addr()), "mw")
	defer rl.Stop()

	handler := RedisRateLimit(rl)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request = %d, want 429", rec.Code)
	}
	if rec.Header().Get(HeaderRetryAfter) != "1" {
		t.Error("Retry-After header missing")
	}
	if !strings.Contains(rec.Body.String(), "rate limit exceeded") {
		t.Errorf("unexpected body: %s", rec.Body.String())
	}
}

func TestRedisRateLimit_Middleware_HitCallbackAndRouteLabel(t *testing.T) {
	mr := miniredis.RunT(t)

	var hitRoute string
	rl, _ := newTestRedisLimiter(t, mr,
		redisRateLimitConfig(10, 1, false, "redis://"+mr.Addr()), "mw-hits",
		WithRedisRateLimiterHitCallback(func(route string) { hitRoute = route }),
	)
	defer rl.Stop()

	handler := RedisRateLimit(rl)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req = req.WithContext(util.ContextWithRoute(req.Context(), "orders-route"))

	deniedBefore := testutil.ToFloat64(
		GetMiddlewareMetrics().redisRateLimitDenied.WithLabelValues("orders-route"))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request = %d, want 429", rec.Code)
	}
	if hitRoute != "orders-route" {
		t.Errorf("hit callback route = %q, want orders-route", hitRoute)
	}

	deniedAfter := testutil.ToFloat64(
		GetMiddlewareMetrics().redisRateLimitDenied.WithLabelValues("orders-route"))
	if deniedAfter != deniedBefore+1 {
		t.Errorf("redis denied counter = %v, want %v", deniedAfter, deniedBefore+1)
	}
}

// --- Store-aware construction ---

func TestNewRateLimitMiddleware_Disabled(t *testing.T) {
	mw, handle, err := NewRateLimitMiddleware(
		context.Background(), nil, "s", observability.NopLogger(), RateLimitDeps{})
	if err != nil {
		t.Fatalf("disabled config must not error: %v", err)
	}
	if handle != nil {
		t.Error("disabled config must return nil handle")
	}

	// Middleware must be a passthrough.
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("passthrough failed: %d", rec.Code)
	}
}

func TestNewRateLimitMiddleware_MemoryStore(t *testing.T) {
	cfg := &config.RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5}

	var hits int
	mw, handle, err := NewRateLimitMiddleware(
		context.Background(), cfg, "s", observability.NopLogger(),
		RateLimitDeps{HitCallback: func(string) { hits++ }})
	if err != nil {
		t.Fatalf("memory store: %v", err)
	}
	if handle == nil {
		t.Fatal("memory store must return a lifecycle handle")
	}
	defer handle.Stop()

	if _, ok := handle.(*RateLimiter); !ok {
		t.Errorf("handle = %T, want *RateLimiter", handle)
	}
	if mw == nil {
		t.Fatal("middleware must not be nil")
	}
}

func TestNewRateLimitMiddleware_RedisStore(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr())

	mw, handle, err := NewRateLimitMiddleware(
		context.Background(), cfg, "global", observability.NopLogger(), RateLimitDeps{})
	if err != nil {
		t.Fatalf("redis store: %v", err)
	}
	defer handle.Stop()

	if _, ok := handle.(*RedisRateLimiter); !ok {
		t.Fatalf("handle = %T, want *RedisRateLimiter", handle)
	}

	// Requests flow through the distributed limiter.
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("first request = %d, want 200", rec.Code)
	}
}

func TestNewRateLimitMiddleware_RedisStore_ConstructionError(t *testing.T) {
	failOpen := false
	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             5,
		Store:             config.RateLimitStoreRedis,
		Redis: &config.RateLimitRedisConfig{
			URL:      "redis://127.0.0.1:1",
			FailOpen: &failOpen,
			Retry: &config.RedisRetryConfig{
				MaxRetries:     1,
				InitialBackoff: config.Duration(time.Millisecond),
				MaxBackoff:     config.Duration(2 * time.Millisecond),
			},
		},
	}

	_, _, err := NewRateLimitMiddleware(
		context.Background(), cfg, "s", observability.NopLogger(), RateLimitDeps{})
	if err == nil {
		t.Fatal("fail-closed redis store with unreachable server must error")
	}
}

func TestIdleBucketTTL(t *testing.T) {
	tests := []struct {
		name  string
		rps   int
		burst int
		want  time.Duration
	}{
		{name: "normal", rps: 10, burst: 5, want: 500*time.Millisecond + time.Minute},
		{name: "zero rps guarded", rps: 0, burst: 5, want: time.Minute},
		{name: "large burst", rps: 1, burst: 120, want: 2*time.Minute + time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := idleBucketTTL(tt.rps, tt.burst); got != tt.want {
				t.Errorf("idleBucketTTL(%d,%d) = %v, want %v", tt.rps, tt.burst, got, tt.want)
			}
		})
	}
}

// --- Test doubles for logging, vault, and client lifecycle ---

// observedZapLogger adapts a zap observer core to observability.Logger so
// tests can assert log volume by level and message.
type observedZapLogger struct{ z *zap.Logger }

func newObservedLogger(level zapcore.Level) (observability.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(level)
	return &observedZapLogger{z: zap.New(core)}, logs
}

func (l *observedZapLogger) Debug(msg string, fields ...observability.Field) {
	l.z.Debug(msg, fields...)
}
func (l *observedZapLogger) Info(msg string, fields ...observability.Field) {
	l.z.Info(msg, fields...)
}
func (l *observedZapLogger) Warn(msg string, fields ...observability.Field) {
	l.z.Warn(msg, fields...)
}
func (l *observedZapLogger) Error(msg string, fields ...observability.Field) {
	l.z.Error(msg, fields...)
}
func (l *observedZapLogger) Fatal(msg string, fields ...observability.Field) {
	l.z.Fatal(msg, fields...)
}
func (l *observedZapLogger) With(fields ...observability.Field) observability.Logger {
	return &observedZapLogger{z: l.z.With(fields...)}
}
func (l *observedZapLogger) WithContext(_ context.Context) observability.Logger { return l }
func (l *observedZapLogger) Sync() error                                        { return l.z.Sync() }

// rlMockKVClient implements vault.KVClient for rate limiter vault tests.
type rlMockKVClient struct {
	secrets map[string]map[string]interface{}
}

func (m *rlMockKVClient) Read(_ context.Context, mount, path string) (map[string]interface{}, error) {
	if secret, ok := m.secrets[mount+"/"+path]; ok {
		return secret, nil
	}
	return nil, errors.New("secret not found")
}

func (m *rlMockKVClient) Write(_ context.Context, _, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *rlMockKVClient) Delete(_ context.Context, _, _ string) error           { return nil }
func (m *rlMockKVClient) List(_ context.Context, _, _ string) ([]string, error) { return nil, nil }

// rlMockVaultClient implements vault.Client for rate limiter vault tests.
type rlMockVaultClient struct {
	kv vault.KVClient
}

func (m *rlMockVaultClient) IsEnabled() bool                      { return true }
func (m *rlMockVaultClient) Authenticate(_ context.Context) error { return nil }
func (m *rlMockVaultClient) RenewToken(_ context.Context) error   { return nil }
func (m *rlMockVaultClient) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *rlMockVaultClient) PKI() vault.PKIClient         { return nil }
func (m *rlMockVaultClient) KV() vault.KVClient           { return m.kv }
func (m *rlMockVaultClient) Transit() vault.TransitClient { return nil }
func (m *rlMockVaultClient) Close() error                 { return nil }

// failingCloseClient wraps a real redis client and fails Close, counting
// invocations to prove Stop idempotency.
type failingCloseClient struct {
	redis.UniversalClient
	closeCalls atomic.Int32
}

func (f *failingCloseClient) Close() error {
	f.closeCalls.Add(1)
	return errors.New("close failed")
}

// --- Constructor micro branches ---

func TestNewRedisRateLimiter_NilLoggerNormalized(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	rl, err := NewRedisRateLimiter(context.Background(),
		redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "nil-logger", nil,
		WithRedisRateLimiterClient(client))
	if err != nil {
		t.Fatalf("valid config with nil logger must construct: %v", err)
	}
	defer rl.Stop()

	if rl.logger == nil {
		t.Fatal("nil logger must be normalized to a nop logger")
	}
	if !rl.Allow(context.Background(), "c") {
		t.Error("limiter with normalized logger must serve decisions")
	}
}

func TestNewRedisRateLimiter_ConfiguredReadTimeout(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr())
	cfg.Redis.ReadTimeout = config.Duration(42 * time.Millisecond)

	rl, _ := newTestRedisLimiter(t, mr, cfg, "op-timeout")
	defer rl.Stop()

	if rl.opTimeout != 42*time.Millisecond {
		t.Errorf("opTimeout = %v, want configured readTimeout 42ms", rl.opTimeout)
	}
}

func TestResolveRateLimitKeyPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   string
	}{
		{name: "empty defaults", prefix: "", want: defaultRedisRateLimitKeyPrefix},
		{name: "custom preserved", prefix: "gw:", want: "gw:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveRateLimitKeyPrefix(tt.prefix); got != tt.want {
				t.Errorf("resolveRateLimitKeyPrefix(%q) = %q, want %q", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestResolveRateLimitOpTimeout(t *testing.T) {
	tests := []struct {
		name        string
		readTimeout time.Duration
		want        time.Duration
	}{
		{name: "zero defaults", readTimeout: 0, want: defaultRedisRateLimitOpTimeout},
		{name: "negative defaults", readTimeout: -time.Second, want: defaultRedisRateLimitOpTimeout},
		{name: "configured honored", readTimeout: 42 * time.Millisecond, want: 42 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveRateLimitOpTimeout(tt.readTimeout); got != tt.want {
				t.Errorf("resolveRateLimitOpTimeout(%v) = %v, want %v", tt.readTimeout, got, tt.want)
			}
		})
	}
}

func TestRedisRateLimiter_CustomKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr())
	cfg.Redis.KeyPrefix = "gw:"

	rl, _ := newTestRedisLimiter(t, mr, cfg, "prefix")
	defer rl.Stop()

	if !rl.Allow(context.Background(), "c") {
		t.Fatal("first request must be allowed")
	}
	if !mr.Exists("gw:ratelimit:prefix") {
		t.Error("bucket key must use the configured custom prefix")
	}
	if mr.Exists("avapigw:ratelimit:prefix") {
		t.Error("default prefix must not be used when a custom prefix is configured")
	}
}

// --- UpdateConfig behavioral proof (new limits govern scripted decisions) ---

func TestRedisRateLimiter_UpdateConfig_NewBurstHonored(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, _ := newTestRedisLimiter(t, mr,
		redisRateLimitConfig(10, 2, true, "redis://"+mr.Addr()), "update-burst")
	defer rl.Stop()

	ctx := context.Background()

	// The old burst=2 governs a fresh bucket before the update.
	for i := 0; i < 2; i++ {
		if !rl.Allow(ctx, "10.0.0.1") {
			t.Fatalf("request %d within old burst must be allowed", i+1)
		}
	}
	if rl.Allow(ctx, "10.0.0.1") {
		t.Fatal("old burst=2 must deny the 3rd request")
	}

	rl.UpdateConfig(&config.RateLimitConfig{RequestsPerSecond: 10, Burst: 5, PerClient: true})

	// A fresh bucket (new client) initializes at the NEW burst: exactly
	// 5 immediate admissions prove burst=5 reached the Lua script.
	allowed := 0
	for i := 0; i < 6; i++ {
		if rl.Allow(ctx, "10.0.0.2") {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("fresh bucket after UpdateConfig admitted %d, want new burst 5", allowed)
	}
}

func TestRedisRateLimiter_UpdateConfig_NewRateHonored(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, clock := newTestRedisLimiter(t, mr,
		redisRateLimitConfig(10, 2, false, "redis://"+mr.Addr()), "update-rate")
	defer rl.Stop()

	ctx := context.Background()

	// Drain the stored bucket under the old config (rps=10, burst=2).
	for i := 0; i < 2; i++ {
		if !rl.Allow(ctx, "c") {
			t.Fatalf("drain request %d must be allowed", i+1)
		}
	}
	if rl.Allow(ctx, "c") {
		t.Fatal("bucket must be empty after drain")
	}

	rl.UpdateConfig(&config.RateLimitConfig{RequestsPerSecond: 100, Burst: 5})

	// At the NEW rate of 100 rps, 10ms refills exactly one token; the old
	// 10 rps rate would have refilled only 0.1 tokens.
	clock.Advance(10 * time.Millisecond)
	if !rl.Allow(ctx, "c") {
		t.Error("10ms at new rate 100rps must refill exactly one token")
	}
	if rl.Allow(ctx, "c") {
		t.Error("only one token must refill in 10ms at 100rps")
	}

	// A long idle period caps the stored bucket refill at the NEW burst.
	clock.Advance(10 * time.Second)
	allowed := 0
	for i := 0; i < 6; i++ {
		if rl.Allow(ctx, "c") {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("stored bucket refill admitted %d, want cap at new burst 5", allowed)
	}
}

// --- Concurrency regressions ---

func TestRedisRateLimiter_ConcurrentSharedBucket(t *testing.T) {
	mr := miniredis.RunT(t)
	const burst = 10

	// Generous read timeout keeps decisions bounded well above CI latency
	// so no request resolves through the failure policy.
	cfg := redisRateLimitConfig(10, burst, false, "redis://"+mr.Addr())
	cfg.Redis.ReadTimeout = config.Duration(5 * time.Second)

	rl, _ := newTestRedisLimiter(t, mr, cfg, "conc-shared")
	defer rl.Stop()

	const goroutines = 50
	var (
		allowed atomic.Int64
		wg      sync.WaitGroup
	)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if rl.Allow(context.Background(), "shared-client") {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// The whole read-modify-write is one atomic Lua script and the clock
	// is fixed (no refill): exactly burst admissions, zero tolerance.
	if got := allowed.Load(); got != burst {
		t.Errorf("concurrent shared bucket admitted %d, want exactly burst=%d", got, burst)
	}
}

func TestRedisRateLimiter_ConcurrentOutageWarnElection(t *testing.T) {
	mr := miniredis.RunT(t)
	logger, logs := newObservedLogger(zapcore.DebugLevel)

	clock := newFakeClock()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	rl, err := NewRedisRateLimiter(context.Background(),
		redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "conc-warn", logger,
		WithRedisRateLimiterClient(client),
		WithRedisRateLimiterNowFunc(clock.Now))
	if err != nil {
		t.Fatalf("NewRedisRateLimiter: %v", err)
	}
	defer rl.Stop()

	mr.Close() // force a real outage: every decision fails

	const goroutines = 100
	var (
		allowed atomic.Int64
		wg      sync.WaitGroup
	)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if rl.Allow(context.Background(), "c") {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := allowed.Load(); got != goroutines {
		t.Errorf("fail-open outage must allow all %d requests, got %d", goroutines, got)
	}

	// The clock is fixed, so the warn window never advances: the CAS elects
	// exactly one warner; every other failure logs at DEBUG.
	const outageMsg = "redis rate limiter unavailable, applying failure policy"
	warns := logs.FilterMessage(outageMsg).FilterLevelExact(zapcore.WarnLevel).Len()
	debugs := logs.FilterMessage(outageMsg).FilterLevelExact(zapcore.DebugLevel).Len()
	if warns != 1 {
		t.Errorf("outage WARN count = %d, want exactly 1 (CAS election)", warns)
	}
	if debugs != goroutines-1 {
		t.Errorf("outage DEBUG count = %d, want %d (rate-limited logging)", debugs, goroutines-1)
	}
}

// --- Failover regression: EVALSHA -> EVAL fallback after SCRIPT FLUSH ---

func TestRedisRateLimiter_ScriptFlushFailover(t *testing.T) {
	mr := miniredis.RunT(t)
	rl, _ := newTestRedisLimiter(t, mr, redisRateLimitConfig(10, 3, false, "redis://"+mr.Addr()), "flush")
	defer rl.Stop()

	ctx := context.Background()

	// Warm the server-side script cache and consume 2 of 3 tokens.
	for i := 0; i < 2; i++ {
		if !rl.Allow(ctx, "c") {
			t.Fatalf("request %d must be allowed", i+1)
		}
	}

	// Simulate a failover that wipes the script cache mid-run.
	flushClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = flushClient.Close() })
	if err := flushClient.ScriptFlush(ctx).Err(); err != nil {
		t.Fatalf("SCRIPT FLUSH: %v", err)
	}
	exists, err := flushClient.ScriptExists(ctx, rl.script.Hash()).Result()
	if err != nil {
		t.Fatalf("SCRIPT EXISTS: %v", err)
	}
	if len(exists) != 1 || exists[0] {
		t.Fatal("script must be evicted from the server cache after SCRIPT FLUSH")
	}

	// The next decision transparently falls back EVALSHA -> EVAL and keeps
	// the stored bucket state: third token consumed, fourth denied.
	if !rl.Allow(ctx, "c") {
		t.Error("Allow after SCRIPT FLUSH must succeed via the EVAL fallback")
	}
	if rl.Allow(ctx, "c") {
		t.Error("bucket state must survive SCRIPT FLUSH (burst=3 exhausted)")
	}
}

// --- Stop close-error path ---

func TestRedisRateLimiter_StopCloseError(t *testing.T) {
	mr := miniredis.RunT(t)
	logger, logs := newObservedLogger(zapcore.DebugLevel)

	inner := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = inner.Close() })
	failing := &failingCloseClient{UniversalClient: inner}

	rl, err := NewRedisRateLimiter(context.Background(),
		redisRateLimitConfig(10, 5, false, "redis://"+mr.Addr()), "stop-err", logger,
		WithRedisRateLimiterClient(failing))
	if err != nil {
		t.Fatalf("NewRedisRateLimiter: %v", err)
	}

	rl.Stop()
	rl.Stop() // second call must be a no-op, not a second close

	if got := failing.closeCalls.Load(); got != 1 {
		t.Errorf("close calls = %d, want exactly 1 (idempotent stop)", got)
	}
	warns := logs.FilterMessage("failed to close redis rate limiter client").Len()
	if warns != 1 {
		t.Errorf("close-error WARN count = %d, want 1", warns)
	}
}

// --- Vault wiring through the middleware construction path ---

func TestNewRateLimitMiddleware_RedisStore_VaultPassword(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("s3cret")

	// Fail-closed makes construction require an authenticated ping, so the
	// test can only pass when the Vault password reaches the redis client.
	failOpen := false
	cfg := redisRateLimitConfig(10, 2, false, "redis://"+mr.Addr())
	cfg.Redis.FailOpen = &failOpen
	cfg.Redis.PasswordVaultPath = "secret/redis-rl"

	t.Run("without vault client construction fails", func(t *testing.T) {
		_, _, err := NewRateLimitMiddleware(context.Background(), cfg, "vault-rl",
			observability.NopLogger(), RateLimitDeps{})
		if err == nil {
			t.Fatal("fail-closed limiter against AUTH-required redis must fail without a vault client")
		}
	})

	t.Run("vault client resolves password", func(t *testing.T) {
		vc := &rlMockVaultClient{kv: &rlMockKVClient{
			secrets: map[string]map[string]interface{}{
				"secret/redis-rl": {"password": "s3cret"},
			},
		}}

		mw, handle, err := NewRateLimitMiddleware(context.Background(), cfg, "vault-rl",
			observability.NopLogger(), RateLimitDeps{VaultClient: vc})
		if err != nil {
			t.Fatalf("vault-wired construction: %v", err)
		}
		defer handle.Stop()

		if _, ok := handle.(*RedisRateLimiter); !ok {
			t.Fatalf("handle = %T, want *RedisRateLimiter", handle)
		}

		// Authenticated Lua decisions run: burst=2 admitted, third denied.
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		for i := 0; i < 2; i++ {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("request %d = %d, want 200", i+1, rec.Code)
			}
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("throttled request = %d, want 429", rec.Code)
		}
	})
}

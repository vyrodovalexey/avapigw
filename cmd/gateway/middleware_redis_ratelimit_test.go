package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// redisRateLimitGatewayConfig builds a gateway config with a redis-backed
// global rate limiter.
func redisRateLimitGatewayConfig(url string, failOpen bool) *config.GatewayConfig {
	fo := failOpen
	return &config.GatewayConfig{
		Spec: config.GatewaySpec{
			RateLimit: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             2,
				Store:             config.RateLimitStoreRedis,
				Redis: &config.RateLimitRedisConfig{
					URL:      url,
					FailOpen: &fo,
					Retry: &config.RedisRetryConfig{
						MaxRetries:     1,
						InitialBackoff: config.Duration(time.Millisecond),
						MaxBackoff:     config.Duration(2 * time.Millisecond),
					},
				},
			},
		},
	}
}

func TestBuildMiddlewareChain_RedisRateLimit(t *testing.T) {
	mr := miniredis.RunT(t)

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test-redis-rl")
	cfg := redisRateLimitGatewayConfig("redis://"+mr.Addr(), true)
	tracer := initTracer(cfg, logger)
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	result, err := buildMiddlewareChain(
		baseHandler, cfg,
		logger, metrics, tracer, audit.NewNoopLogger(), nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("buildMiddlewareChain: %v", err)
	}
	if result.rateLimiter == nil {
		t.Fatal("rate limiter handle must be set")
	}
	defer result.rateLimiter.Stop()

	if _, ok := result.rateLimiter.(*middleware.RedisRateLimiter); !ok {
		t.Fatalf("rateLimiter = %T, want *middleware.RedisRateLimiter", result.rateLimiter)
	}

	// Burst=2 through the full chain, third request throttled via redis.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		result.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	result.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request = %d, want 429", rec.Code)
	}

	// UpdateConfig works through the lifecycle handle (hot reload path).
	result.rateLimiter.UpdateConfig(&config.RateLimitConfig{
		RequestsPerSecond: 200, Burst: 400,
	})
}

func TestBuildMiddlewareChain_RedisRateLimit_FailClosedConstructionError(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test-redis-rl-err")
	cfg := redisRateLimitGatewayConfig("redis://"+addr, false)
	tracer := initTracer(cfg, logger)
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	_, err := buildMiddlewareChain(
		baseHandler, cfg,
		logger, metrics, tracer, audit.NewNoopLogger(), nil, nil, nil,
	)
	if err == nil {
		t.Fatal("fail-closed redis limiter with unreachable redis must fail chain construction")
	}
}

func TestBuildMiddlewareChain_RedisRateLimit_FailOpenDegraded(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test-redis-rl-degraded")
	cfg := redisRateLimitGatewayConfig("redis://"+addr, true)
	tracer := initTracer(cfg, logger)
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	result, err := buildMiddlewareChain(
		baseHandler, cfg,
		logger, metrics, tracer, audit.NewNoopLogger(), nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("fail-open limiter must start degraded, got %v", err)
	}
	defer result.rateLimiter.Stop()

	// Redis is down; fail-open policy admits traffic.
	rec := httptest.NewRecorder()
	result.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("degraded fail-open request = %d, want 200", rec.Code)
	}
}

// ============================================================
// Vault wiring for the redis rate limiter (deps.VaultClient)
// ============================================================

// mockKVClientForRateLimit implements vault.KVClient with static secrets.
type mockKVClientForRateLimit struct {
	secrets map[string]map[string]interface{}
}

func (m *mockKVClientForRateLimit) Read(
	_ context.Context, mount, path string,
) (map[string]interface{}, error) {
	if secret, ok := m.secrets[mount+"/"+path]; ok {
		return secret, nil
	}
	return nil, errors.New("secret not found")
}

func (m *mockKVClientForRateLimit) Write(
	_ context.Context, _, _ string, _ map[string]interface{},
) error {
	return nil
}

func (m *mockKVClientForRateLimit) Delete(_ context.Context, _, _ string) error { return nil }

func (m *mockKVClientForRateLimit) List(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}

// mockVaultClientForRateLimit implements vault.Client with a working KV
// engine for redis password resolution.
type mockVaultClientForRateLimit struct {
	kv vault.KVClient
}

func (m *mockVaultClientForRateLimit) IsEnabled() bool                      { return true }
func (m *mockVaultClientForRateLimit) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClientForRateLimit) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClientForRateLimit) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClientForRateLimit) PKI() vault.PKIClient         { return nil }
func (m *mockVaultClientForRateLimit) KV() vault.KVClient           { return m.kv }
func (m *mockVaultClientForRateLimit) Transit() vault.TransitClient { return nil }
func (m *mockVaultClientForRateLimit) Close() error                 { return nil }

// TestBuildMiddlewareChain_RedisRateLimit_VaultPassword proves the
// middleware assembly hands deps.VaultClient through to the redis client:
// against an AUTH-required redis, a fail-closed chain can only start when
// the Vault-referenced password is resolved and applied.
func TestBuildMiddlewareChain_RedisRateLimit_VaultPassword(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("s3cret")

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test-redis-rl-vault")
	cfg := redisRateLimitGatewayConfig("redis://"+mr.Addr(), false) // fail-closed
	cfg.Spec.RateLimit.Redis.PasswordVaultPath = "secret/redis-rl"
	tracer := initTracer(cfg, logger)
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	vaultClient := &mockVaultClientForRateLimit{kv: &mockKVClientForRateLimit{
		secrets: map[string]map[string]interface{}{
			"secret/redis-rl": {"password": "s3cret"},
		},
	}}

	result, err := buildMiddlewareChain(
		baseHandler, cfg,
		logger, metrics, tracer, audit.NewNoopLogger(), nil, nil, vaultClient,
	)
	if err != nil {
		t.Fatalf("vault-wired chain must build against AUTH-required redis: %v", err)
	}
	defer result.rateLimiter.Stop()

	if _, ok := result.rateLimiter.(*middleware.RedisRateLimiter); !ok {
		t.Fatalf("rateLimiter = %T, want *middleware.RedisRateLimiter", result.rateLimiter)
	}

	// Authenticated distributed decisions run: burst=2 admitted, third 429.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		result.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	result.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request = %d, want 429", rec.Code)
	}
}

// TestBuildMiddlewareChain_RedisRateLimit_VaultPasswordMissing is the
// negative control for the vault wiring test: the same fail-closed config
// without a vault client cannot authenticate, so chain construction fails.
// This proves the positive test genuinely depends on the vault hand-off.
func TestBuildMiddlewareChain_RedisRateLimit_VaultPasswordMissing(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("s3cret")

	logger := observability.NopLogger()
	metrics := observability.NewMetrics("test-redis-rl-vault-missing")
	cfg := redisRateLimitGatewayConfig("redis://"+mr.Addr(), false) // fail-closed
	cfg.Spec.RateLimit.Redis.PasswordVaultPath = "secret/redis-rl"
	tracer := initTracer(cfg, logger)
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	_, err := buildMiddlewareChain(
		baseHandler, cfg,
		logger, metrics, tracer, audit.NewNoopLogger(), nil, nil, nil,
	)
	if err == nil {
		t.Fatal("fail-closed chain without a vault client must fail against AUTH-required redis")
	}
}

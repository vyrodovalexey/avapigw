// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// validSentinelSpec returns a minimal valid sentinel spec.
func validSentinelSpec() *avapigwv1alpha1.RedisSentinelSpec {
	return &avapigwv1alpha1.RedisSentinelSpec{
		MasterName:    "mymaster",
		SentinelAddrs: []string{"sentinel-0:26379"},
	}
}

// --- validateRateLimit store rules ---

func TestValidateRateLimit_StoreRules(t *testing.T) {
	tests := []struct {
		name    string
		rl      *avapigwv1alpha1.RateLimitConfig
		wantErr string
	}{
		{
			name: "memory store valid",
			rl:   &avapigwv1alpha1.RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5},
		},
		{
			name: "invalid store",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "etcd"},
			wantErr: "rateLimit.store must be 'memory' or 'redis'",
		},
		{
			name:    "store validated even when disabled",
			rl:      &avapigwv1alpha1.RateLimitConfig{Enabled: false, Store: "etcd"},
			wantErr: "rateLimit.store must be 'memory' or 'redis'",
		},
		{
			name: "redis block with memory store",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5,
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{URL: "redis://x"}},
			wantErr: "rateLimit.redis is only valid when rateLimit.store is 'redis'",
		},
		{
			name: "redis store without redis block",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis"},
			wantErr: "rateLimit.redis is required when rateLimit.store is 'redis'",
		},
		{
			name: "redis store with url valid",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{URL: "redis://localhost:6379"}},
		},
		{
			name: "redis store with sentinel valid",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{Sentinel: validSentinelSpec()}},
		},
		{
			name: "url and sentinel mutually exclusive",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL: "redis://x", Sentinel: validSentinelSpec()}},
			wantErr: "mutually exclusive",
		},
		{
			name: "neither url nor sentinel",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{}},
			wantErr: "requires either url or sentinel",
		},
		{
			name: "sentinel missing master name",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
						SentinelAddrs: []string{"s:26379"}}}},
			wantErr: "masterName is required",
		},
		{
			name: "sentinel missing addrs",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					Sentinel: &avapigwv1alpha1.RedisSentinelSpec{MasterName: "m"}}},
			wantErr: "sentinelAddrs must have at least one address",
		},
		{
			name: "invalid read timeout",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL: "redis://x", ReadTimeout: "not-a-duration"}},
			wantErr: "rateLimit.redis.readTimeout is invalid",
		},
		{
			name: "negative retry maxRetries",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL:   "redis://x",
					Retry: &avapigwv1alpha1.RedisRetrySpec{MaxRetries: -1}}},
			wantErr: "rateLimit.redis.retry.maxRetries must be non-negative",
		},
		{
			name: "invalid retry backoff",
			rl: &avapigwv1alpha1.RateLimitConfig{
				Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL:   "redis://x",
					Retry: &avapigwv1alpha1.RedisRetrySpec{InitialBackoff: "bogus"}}},
			wantErr: "rateLimit.redis.retry.initialBackoff is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimit(tt.rl)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// --- validateRouteCacheConfig ---

func TestValidateRouteCacheConfig(t *testing.T) {
	jitterHigh := 1.5
	jitterOK := 0.2

	tests := []struct {
		name    string
		cache   *avapigwv1alpha1.CacheConfig
		wantErr string
	}{
		{
			name:  "memory cache valid",
			cache: &avapigwv1alpha1.CacheConfig{Enabled: true, TTL: "5m"},
		},
		{
			name:    "invalid ttl",
			cache:   &avapigwv1alpha1.CacheConfig{Enabled: true, TTL: "bogus"},
			wantErr: "cache.ttl is invalid",
		},
		{
			name:    "invalid staleWhileRevalidate",
			cache:   &avapigwv1alpha1.CacheConfig{Enabled: true, StaleWhileRevalidate: "bogus"},
			wantErr: "cache.staleWhileRevalidate is invalid",
		},
		{
			name:    "invalid type",
			cache:   &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "memcached"},
			wantErr: "cache.type must be 'memory' or 'redis'",
		},
		{
			name: "redis block with memory type",
			cache: &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "memory",
				Redis: &avapigwv1alpha1.RedisCacheSpec{URL: "redis://x"}},
			wantErr: "cache.redis is only valid when cache.type is 'redis'",
		},
		{
			name:    "redis type without redis block",
			cache:   &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "redis"},
			wantErr: "cache.redis is required when cache.type is 'redis'",
		},
		{
			name: "redis with url valid",
			cache: &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://localhost:6379", TTLJitter: &jitterOK}},
		},
		{
			name: "redis with sentinel valid",
			cache: &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					Sentinel: validSentinelSpec(),
					Retry:    &avapigwv1alpha1.RedisRetrySpec{MaxRetries: 3, InitialBackoff: "100ms"},
				}},
		},
		{
			name: "url and sentinel mutually exclusive",
			cache: &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://x", Sentinel: validSentinelSpec()}},
			wantErr: "mutually exclusive",
		},
		{
			name: "sentinel invalid db",
			cache: &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
						MasterName: "m", SentinelAddrs: []string{"s:26379"}, DB: 16}}},
			wantErr: "db must be between 0 and 15",
		},
		{
			name: "ttl jitter out of range",
			cache: &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://x", TTLJitter: &jitterHigh}},
			wantErr: "cache.redis.ttlJitter must be between 0.0 and 1.0",
		},
		{
			name: "invalid connect timeout",
			cache: &avapigwv1alpha1.CacheConfig{Enabled: true, Type: "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://x", ConnectTimeout: "bogus"}},
			wantErr: "cache.redis.connectTimeout is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteCacheConfig(tt.cache)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// --- Warning helpers ---

func TestWarnBackendCacheReserved(t *testing.T) {
	if w := warnBackendCacheReserved(nil); len(w) != 0 {
		t.Errorf("nil cache: warnings = %v", w)
	}
	if w := warnBackendCacheReserved(&avapigwv1alpha1.BackendCacheConfig{Enabled: false}); len(w) != 0 {
		t.Errorf("disabled cache: warnings = %v", w)
	}

	w := warnBackendCacheReserved(&avapigwv1alpha1.BackendCacheConfig{Enabled: true})
	if len(w) != 1 || !strings.Contains(w[0], "RESERVED") {
		t.Errorf("enabled backend cache must warn about reserved config, got %v", w)
	}
}

func TestWarnRateLimitRedisStoreUnapplied(t *testing.T) {
	if w := warnRateLimitRedisStoreUnapplied(nil, "GRPCRoute"); len(w) != 0 {
		t.Errorf("nil ratelimit: warnings = %v", w)
	}
	if w := warnRateLimitRedisStoreUnapplied(
		&avapigwv1alpha1.RateLimitConfig{Store: "memory"}, "GRPCRoute"); len(w) != 0 {
		t.Errorf("memory store: warnings = %v", w)
	}

	w := warnRateLimitRedisStoreUnapplied(
		&avapigwv1alpha1.RateLimitConfig{Store: "redis"}, "GRPCRoute")
	if len(w) != 1 || !strings.Contains(w[0], "GRPCRoute") {
		t.Errorf("redis store must warn with kind, got %v", w)
	}
}

func TestWarnRouteCacheRedisTypeUnapplied(t *testing.T) {
	if w := warnRouteCacheRedisTypeUnapplied(nil, "GRPCRoute"); len(w) != 0 {
		t.Errorf("nil cache: warnings = %v", w)
	}
	if w := warnRouteCacheRedisTypeUnapplied(
		&avapigwv1alpha1.CacheConfig{Type: "memory"}, "GRPCRoute"); len(w) != 0 {
		t.Errorf("memory type: warnings = %v", w)
	}

	w := warnRouteCacheRedisTypeUnapplied(
		&avapigwv1alpha1.CacheConfig{Type: "redis"}, "GRPCRoute")
	if len(w) != 1 || !strings.Contains(w[0], "GRPCRoute") {
		t.Errorf("redis type must warn with kind, got %v", w)
	}
}

func TestWarnGraphQLRouteCacheIneffective(t *testing.T) {
	if w := warnGraphQLRouteCacheIneffective(nil); len(w) != 0 {
		t.Errorf("nil cache: warnings = %v", w)
	}
	if w := warnGraphQLRouteCacheIneffective(
		&avapigwv1alpha1.CacheConfig{Type: "memory"}); len(w) != 0 {
		t.Errorf("memory type: warnings = %v", w)
	}

	w := warnGraphQLRouteCacheIneffective(&avapigwv1alpha1.CacheConfig{Type: "redis"})
	if len(w) != 1 || !strings.Contains(w[0], "GET requests only") {
		t.Errorf("redis type must warn about GET-only caching semantics, got %v", w)
	}
	if !strings.Contains(w[0], "GraphQLRoute") {
		t.Errorf("warning must name GraphQLRoute, got %v", w)
	}
}

func TestWarnRouteCacheAndRateLimitSentinelSecrets(t *testing.T) {
	plaintext := &avapigwv1alpha1.RedisSentinelSpec{
		MasterName:       "m",
		SentinelAddrs:    []string{"s:26379"},
		Password:         "plain",
		SentinelPassword: "plain2",
	}

	if w := warnRouteCacheSentinelSecrets(nil); len(w) != 0 {
		t.Errorf("nil cache: warnings = %v", w)
	}
	if w := warnRateLimitSentinelSecrets(nil); len(w) != 0 {
		t.Errorf("nil ratelimit: warnings = %v", w)
	}

	cacheWarnings := warnRouteCacheSentinelSecrets(&avapigwv1alpha1.CacheConfig{
		Type:  "redis",
		Redis: &avapigwv1alpha1.RedisCacheSpec{Sentinel: plaintext},
	})
	if len(cacheWarnings) != 2 {
		t.Errorf("cache sentinel plaintext warnings = %d, want 2: %v", len(cacheWarnings), cacheWarnings)
	}

	rlWarnings := warnRateLimitSentinelSecrets(&avapigwv1alpha1.RateLimitConfig{
		Store: "redis",
		Redis: &avapigwv1alpha1.RateLimitRedisSpec{Sentinel: plaintext},
	})
	if len(rlWarnings) != 2 {
		t.Errorf("ratelimit sentinel plaintext warnings = %d, want 2: %v", len(rlWarnings), rlWarnings)
	}
}

// --- End-to-end webhook behavior ---

// baseAPIRoute returns a valid APIRoute for mutation in tests.
func baseAPIRoute() *avapigwv1alpha1.APIRoute {
	return &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-route", Namespace: "default"},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{Destination: avapigwv1alpha1.Destination{Host: "svc", Port: 8080}, Weight: 100},
			},
		},
	}
}

func TestAPIRouteValidator_RedisCacheAndRateLimit_Valid(t *testing.T) {
	validator := &APIRouteValidator{}
	route := baseAPIRoute()
	route.Spec.Cache = &avapigwv1alpha1.CacheConfig{
		Enabled: true,
		TTL:     "1m",
		Type:    "redis",
		Redis: &avapigwv1alpha1.RedisCacheSpec{
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:                "mymaster",
				SentinelAddrs:             []string{"sentinel-0:26379", "sentinel-1:26379"},
				PasswordVaultPath:         "secret/redis-master",
				SentinelPasswordVaultPath: "secret/redis-sentinel",
			},
		},
	}
	route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
		Store:             "redis",
		Redis: &avapigwv1alpha1.RateLimitRedisSpec{
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:        "mymaster",
				SentinelAddrs:     []string{"sentinel-0:26379"},
				PasswordVaultPath: "secret/redis-master",
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil", err)
	}
	// Vault paths are used, so no plaintext warnings are expected.
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
}

func TestAPIRouteValidator_RedisCache_Invalid(t *testing.T) {
	validator := &APIRouteValidator{}
	route := baseAPIRoute()
	route.Spec.Cache = &avapigwv1alpha1.CacheConfig{
		Enabled: true,
		Type:    "redis",
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil || !strings.Contains(err.Error(), "cache.redis is required") {
		t.Fatalf("expected cache.redis required error, got %v", err)
	}
}

func TestAPIRouteValidator_RedisRateLimit_PlaintextWarnings(t *testing.T) {
	validator := &APIRouteValidator{}
	route := baseAPIRoute()
	route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             20,
		Store:             "redis",
		Redis: &avapigwv1alpha1.RateLimitRedisSpec{
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "m",
				SentinelAddrs: []string{"s:26379"},
				Password:      "plaintext-password",
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "SECURITY WARNING") {
		t.Errorf("expected one plaintext security warning, got %v", warnings)
	}
}

func TestGRPCRouteValidator_RedisStoreWarnings(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "grpc-route", Namespace: "default"},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{Destination: avapigwv1alpha1.Destination{Host: "svc", Port: 9090}},
			},
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				Burst:             20,
				Store:             "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL: "redis://localhost:6379",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "rateLimit.store=redis is not applied for GRPCRoute") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected redis-store-unapplied warning, got %v", warnings)
	}
}

func TestGraphQLRouteValidator_RedisStoreAndCacheWarnings(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "gql-route", Namespace: "default"},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{Destination: avapigwv1alpha1.Destination{Host: "svc", Port: 8080}, Weight: 100},
			},
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				Burst:             20,
				Store:             "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL: "redis://localhost:6379",
				},
			},
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				TTL:     "1m",
				Type:    "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://localhost:6379",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil", err)
	}

	// The GraphQL data path enforces the redis-backed distributed rate
	// limiter through the shared route middleware chain, so no
	// "unapplied" warning may be emitted for rateLimit.store=redis.
	for _, w := range warnings {
		if strings.Contains(w, "rateLimit.store=redis is not applied") {
			t.Errorf("GraphQLRoute must not warn about unapplied redis rate limiting, got %q", w)
		}
	}

	// The redis cache is built by the chain but never takes effect for
	// POST GraphQL operations (GET-only caching), so a precise warning
	// is required.
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "GET requests only") && strings.Contains(w, "GraphQLRoute") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GET-only cache ineffectiveness warning, got %v", warnings)
	}
}

func TestGraphQLRouteValidator_RedisRateLimit_NoWarnings(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "gql-rl-route", Namespace: "default"},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{Destination: avapigwv1alpha1.Destination{Host: "svc", Port: 8080}, Weight: 100},
			},
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
				Store:             "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
						MasterName:        "mymaster",
						SentinelAddrs:     []string{"sentinel-0:26379"},
						PasswordVaultPath: "secret/redis-master",
					},
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil", err)
	}
	// Vault paths are used and the distributed limiter is enforced on the
	// GraphQL data path: a redis-store rate limit alone must be warn-free.
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
}

func TestBackendValidator_ReservedCacheWarning(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{{Address: "svc", Port: 8080}},
			Cache: &avapigwv1alpha1.BackendCacheConfig{Enabled: true, TTL: "1m"},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "RESERVED") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected reserved backend cache warning, got %v", warnings)
	}
}

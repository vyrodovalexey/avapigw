package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// --- RateLimitConfig store helpers ---

func TestRateLimitConfig_GetEffectiveStore(t *testing.T) {
	tests := []struct {
		name string
		cfg  *RateLimitConfig
		want string
	}{
		{name: "nil config", cfg: nil, want: RateLimitStoreMemory},
		{name: "empty store", cfg: &RateLimitConfig{}, want: RateLimitStoreMemory},
		{name: "memory store", cfg: &RateLimitConfig{Store: "memory"}, want: RateLimitStoreMemory},
		{name: "redis store", cfg: &RateLimitConfig{Store: "redis"}, want: RateLimitStoreRedis},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetEffectiveStore(); got != tt.want {
				t.Errorf("GetEffectiveStore() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitRedisConfig_GetEffectiveFailOpen(t *testing.T) {
	failOpen := true
	failClosed := false

	tests := []struct {
		name string
		cfg  *RateLimitRedisConfig
		want bool
	}{
		{name: "nil config defaults true", cfg: nil, want: true},
		{name: "unset defaults true", cfg: &RateLimitRedisConfig{}, want: true},
		{name: "explicit true", cfg: &RateLimitRedisConfig{FailOpen: &failOpen}, want: true},
		{name: "explicit false", cfg: &RateLimitRedisConfig{FailOpen: &failClosed}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetEffectiveFailOpen(); got != tt.want {
				t.Errorf("GetEffectiveFailOpen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRateLimitRedisConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name string
		cfg  *RateLimitRedisConfig
		want bool
	}{
		{name: "nil", cfg: nil, want: true},
		{name: "empty", cfg: &RateLimitRedisConfig{}, want: true},
		{name: "url set", cfg: &RateLimitRedisConfig{URL: "redis://x"}, want: false},
		{name: "sentinel without master", cfg: &RateLimitRedisConfig{
			Sentinel: &RedisSentinelConfig{}}, want: true},
		{name: "sentinel with master", cfg: &RateLimitRedisConfig{
			Sentinel: &RedisSentinelConfig{MasterName: "m"}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- JSON round-trip (CRD spec JSON must map onto these types) ---

func TestRateLimitConfig_JSONRoundTrip(t *testing.T) {
	failOpen := false
	src := &RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
		PerClient:         true,
		Store:             RateLimitStoreRedis,
		Redis: &RateLimitRedisConfig{
			Sentinel: &RedisSentinelConfig{
				MasterName:                "mymaster",
				SentinelAddrs:             []string{"s1:26379", "s2:26379"},
				DB:                        1,
				PasswordVaultPath:         "secret/redis-master",
				SentinelPasswordVaultPath: "secret/redis-sentinel",
			},
			PoolSize:     15,
			ReadTimeout:  Duration(50 * time.Millisecond),
			KeyPrefix:    "gw:",
			Retry:        &RedisRetryConfig{MaxRetries: 5, InitialBackoff: Duration(time.Second)},
			FailOpen:     &failOpen,
			WriteTimeout: Duration(75 * time.Millisecond),
		},
	}

	data, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got RateLimitConfig
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Store != RateLimitStoreRedis || got.Redis == nil {
		t.Fatalf("store/redis lost in round-trip: %+v", got)
	}
	if got.Redis.Sentinel.MasterName != "mymaster" || len(got.Redis.Sentinel.SentinelAddrs) != 2 {
		t.Errorf("sentinel lost: %+v", got.Redis.Sentinel)
	}
	if got.Redis.Sentinel.PasswordVaultPath != "secret/redis-master" ||
		got.Redis.Sentinel.SentinelPasswordVaultPath != "secret/redis-sentinel" {
		t.Errorf("vault paths lost: %+v", got.Redis.Sentinel)
	}
	if got.Redis.ReadTimeout.Duration() != 50*time.Millisecond {
		t.Errorf("readTimeout = %v", got.Redis.ReadTimeout.Duration())
	}
	if got.Redis.GetEffectiveFailOpen() {
		t.Error("failOpen=false lost in round-trip")
	}
	if got.Redis.Retry.MaxRetries != 5 {
		t.Errorf("retry lost: %+v", got.Redis.Retry)
	}
}

// --- Validator: rate limit store rules ---

func validationErrors(t *testing.T, spec GatewaySpec) []string {
	t.Helper()
	v := NewValidator()
	cfg := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1alpha1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "test"},
		Spec:       spec,
	}
	err := v.Validate(cfg)
	if err == nil {
		return nil
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T: %v", err, err)
	}
	msgs := make([]string, 0, len(verrs))
	for _, e := range verrs {
		msgs = append(msgs, e.Path+": "+e.Message)
	}
	return msgs
}

func containsError(msgs []string, substr string) bool {
	for _, m := range msgs {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

func TestValidator_RateLimitStore(t *testing.T) {
	baseRoute := func(rl *RateLimitConfig) GatewaySpec {
		return GatewaySpec{
			Listeners: []Listener{{Name: "l", Port: 8080, Protocol: "HTTP"}},
			Routes: []Route{{
				Name:      "r1",
				Match:     []RouteMatch{{URI: &URIMatch{Prefix: "/"}}},
				Route:     []RouteDestination{{Destination: Destination{Host: "b", Port: 80}}},
				RateLimit: rl,
			}},
		}
	}

	tests := []struct {
		name    string
		rl      *RateLimitConfig
		wantErr string
	}{
		{
			name: "memory store valid",
			rl:   &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5},
		},
		{
			name: "explicit memory store valid",
			rl:   &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "memory"},
		},
		{
			name:    "invalid store",
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "etcd"},
			wantErr: "invalid store: etcd",
		},
		{
			name: "redis block with memory store",
			rl: &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5,
				Redis: &RateLimitRedisConfig{URL: "redis://x"}},
			wantErr: "redis configuration is only valid when store is 'redis'",
		},
		{
			name:    "redis store without redis block",
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis"},
			wantErr: "redis configuration with url or sentinel is required",
		},
		{
			name: "redis store with url valid",
			rl: &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &RateLimitRedisConfig{URL: "redis://localhost:6379"}},
		},
		{
			name: "redis store with sentinel valid",
			rl: &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &RateLimitRedisConfig{Sentinel: &RedisSentinelConfig{
					MasterName: "m", SentinelAddrs: []string{"s:26379"}}}},
		},
		{
			name: "url and sentinel mutually exclusive",
			rl: &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &RateLimitRedisConfig{
					URL:      "redis://localhost:6379",
					Sentinel: &RedisSentinelConfig{MasterName: "m", SentinelAddrs: []string{"s:26379"}},
				}},
			wantErr: "url and sentinel are mutually exclusive",
		},
		{
			name: "sentinel missing addrs",
			rl: &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &RateLimitRedisConfig{Sentinel: &RedisSentinelConfig{MasterName: "m"}}},
			wantErr: "at least one sentinel address is required",
		},
		{
			name: "sentinel empty addr",
			rl: &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &RateLimitRedisConfig{Sentinel: &RedisSentinelConfig{
					MasterName: "m", SentinelAddrs: []string{""}}}},
			wantErr: "sentinel address cannot be empty",
		},
		{
			name: "sentinel missing master with addrs",
			rl: &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &RateLimitRedisConfig{Sentinel: &RedisSentinelConfig{
					SentinelAddrs: []string{"s:26379"}}}},
			wantErr: "masterName is required for sentinel mode",
		},
		{
			name: "negative read timeout",
			rl: &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 5, Store: "redis",
				Redis: &RateLimitRedisConfig{
					URL:         "redis://localhost:6379",
					ReadTimeout: Duration(-time.Second),
				}},
			wantErr: "readTimeout cannot be negative",
		},
		{
			name:    "store validated even when disabled",
			rl:      &RateLimitConfig{Enabled: false, Store: "bogus"},
			wantErr: "invalid store: bogus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := validationErrors(t, baseRoute(tt.rl))
			if tt.wantErr == "" {
				if len(msgs) != 0 {
					t.Fatalf("expected valid config, got errors: %v", msgs)
				}
				return
			}
			if !containsError(msgs, tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, msgs)
			}
		})
	}
}

// --- Validator: route cache rules ---

func TestValidator_RouteCache(t *testing.T) {
	baseRoute := func(cache *CacheConfig) GatewaySpec {
		return GatewaySpec{
			Listeners: []Listener{{Name: "l", Port: 8080, Protocol: "HTTP"}},
			Routes: []Route{{
				Name:  "r1",
				Match: []RouteMatch{{URI: &URIMatch{Prefix: "/"}}},
				Route: []RouteDestination{{Destination: Destination{Host: "b", Port: 80}}},
				Cache: cache,
			}},
		}
	}

	tests := []struct {
		name    string
		cache   *CacheConfig
		wantErr string
	}{
		{
			name:  "memory cache valid",
			cache: &CacheConfig{Enabled: true, TTL: Duration(time.Minute)},
		},
		{
			name:    "invalid type",
			cache:   &CacheConfig{Enabled: true, Type: "memcached"},
			wantErr: "invalid type: memcached",
		},
		{
			name:    "negative ttl",
			cache:   &CacheConfig{Enabled: true, TTL: Duration(-time.Second)},
			wantErr: "ttl cannot be negative",
		},
		{
			name: "redis block with memory type",
			cache: &CacheConfig{Enabled: true, Type: "memory",
				Redis: &RedisCacheConfig{URL: "redis://x"}},
			wantErr: "redis configuration is only valid when type is 'redis'",
		},
		{
			name:    "redis type without redis block",
			cache:   &CacheConfig{Enabled: true, Type: "redis"},
			wantErr: "redis configuration with url or sentinel is required",
		},
		{
			name: "redis with url valid",
			cache: &CacheConfig{Enabled: true, Type: "redis",
				Redis: &RedisCacheConfig{URL: "redis://localhost:6379"}},
		},
		{
			name: "redis with sentinel valid",
			cache: &CacheConfig{Enabled: true, Type: "redis",
				Redis: &RedisCacheConfig{Sentinel: &RedisSentinelConfig{
					MasterName: "m", SentinelAddrs: []string{"s:26379"}}}},
		},
		{
			name: "url and sentinel mutually exclusive",
			cache: &CacheConfig{Enabled: true, Type: "redis",
				Redis: &RedisCacheConfig{
					URL:      "redis://localhost:6379",
					Sentinel: &RedisSentinelConfig{MasterName: "m", SentinelAddrs: []string{"s:26379"}},
				}},
			wantErr: "url and sentinel are mutually exclusive",
		},
		{
			name: "sentinel requires addrs",
			cache: &CacheConfig{Enabled: true, Type: "redis",
				Redis: &RedisCacheConfig{Sentinel: &RedisSentinelConfig{MasterName: "m"}}},
			wantErr: "at least one sentinel address is required",
		},
		{
			name: "ttl jitter out of range",
			cache: &CacheConfig{Enabled: true, Type: "redis",
				Redis: &RedisCacheConfig{URL: "redis://x:6379", TTLJitter: 1.5}},
			wantErr: "ttlJitter must be between 0.0 and 1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := validationErrors(t, baseRoute(tt.cache))
			if tt.wantErr == "" {
				if len(msgs) != 0 {
					t.Fatalf("expected valid config, got errors: %v", msgs)
				}
				return
			}
			if !containsError(msgs, tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, msgs)
			}
		})
	}
}

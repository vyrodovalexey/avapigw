package controller

import (
	"encoding/json"
	"testing"
	"time"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// TestAPIRouteSpec_CacheRedisMapping verifies the operator's CR→gateway
// translation for route-level Redis cache configuration: the APIRoute spec
// is marshaled to JSON (as the controller does) and must unmarshal onto the
// gateway's config.Route with every field intact, including sentinel and
// Vault paths.
func TestAPIRouteSpec_CacheRedisMapping(t *testing.T) {
	jitter := 0.15
	hashKeys := true
	spec := avapigwv1alpha1.APIRouteSpec{
		Cache: &avapigwv1alpha1.CacheConfig{
			Enabled:              true,
			TTL:                  "5m",
			StaleWhileRevalidate: "30s",
			Type:                 "redis",
			Redis: &avapigwv1alpha1.RedisCacheSpec{
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:                "mymaster",
					SentinelAddrs:             []string{"sentinel-0:26379", "sentinel-1:26379"},
					SentinelPassword:          "sentinel-pw",
					Password:                  "master-pw",
					DB:                        2,
					PasswordVaultPath:         "secret/redis-master",
					SentinelPasswordVaultPath: "secret/redis-sentinel",
				},
				PoolSize:       20,
				ConnectTimeout: "2s",
				ReadTimeout:    "150ms",
				WriteTimeout:   "250ms",
				KeyPrefix:      "route-cache:",
				TTLJitter:      &jitter,
				HashKeys:       &hashKeys,
				Retry: &avapigwv1alpha1.RedisRetrySpec{
					MaxRetries:     4,
					InitialBackoff: "200ms",
					MaxBackoff:     "10s",
				},
			},
		},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	data, err = injectName(data, "cached-route")
	if err != nil {
		t.Fatalf("injectName: %v", err)
	}

	var route config.Route
	if err := json.Unmarshal(data, &route); err != nil {
		t.Fatalf("unmarshal into config.Route: %v", err)
	}

	if route.Name != "cached-route" {
		t.Errorf("name = %q", route.Name)
	}

	cache := route.Cache
	if cache == nil || !cache.Enabled {
		t.Fatalf("cache not mapped: %+v", cache)
	}
	if cache.Type != config.CacheTypeRedis {
		t.Errorf("type = %q, want redis", cache.Type)
	}
	if cache.TTL.Duration() != 5*time.Minute {
		t.Errorf("ttl = %v, want 5m", cache.TTL.Duration())
	}
	if cache.StaleWhileRevalidate.Duration() != 30*time.Second {
		t.Errorf("staleWhileRevalidate = %v", cache.StaleWhileRevalidate.Duration())
	}

	redisCfg := cache.Redis
	if redisCfg == nil {
		t.Fatal("redis config not mapped")
	}
	if redisCfg.PoolSize != 20 || redisCfg.KeyPrefix != "route-cache:" {
		t.Errorf("pool/prefix not mapped: %+v", redisCfg)
	}
	if redisCfg.ConnectTimeout.Duration() != 2*time.Second ||
		redisCfg.ReadTimeout.Duration() != 150*time.Millisecond ||
		redisCfg.WriteTimeout.Duration() != 250*time.Millisecond {
		t.Errorf("timeouts not mapped: %+v", redisCfg)
	}
	if redisCfg.TTLJitter != 0.15 || !redisCfg.HashKeys {
		t.Errorf("jitter/hashKeys not mapped: %+v", redisCfg)
	}

	sentinel := redisCfg.Sentinel
	if sentinel == nil {
		t.Fatal("sentinel not mapped")
	}
	if sentinel.MasterName != "mymaster" || len(sentinel.SentinelAddrs) != 2 {
		t.Errorf("sentinel identity not mapped: %+v", sentinel)
	}
	if sentinel.SentinelPassword != "sentinel-pw" || sentinel.Password != "master-pw" || sentinel.DB != 2 {
		t.Errorf("sentinel credentials not mapped: %+v", sentinel)
	}
	if sentinel.PasswordVaultPath != "secret/redis-master" ||
		sentinel.SentinelPasswordVaultPath != "secret/redis-sentinel" {
		t.Errorf("sentinel vault paths not mapped: %+v", sentinel)
	}

	retryCfg := redisCfg.Retry
	if retryCfg == nil {
		t.Fatal("retry not mapped")
	}
	if retryCfg.MaxRetries != 4 ||
		retryCfg.InitialBackoff.Duration() != 200*time.Millisecond ||
		retryCfg.MaxBackoff.Duration() != 10*time.Second {
		t.Errorf("retry not mapped: %+v", retryCfg)
	}
}

// TestAPIRouteSpec_CacheRedisMapping_StandaloneURL verifies standalone URL
// mode mapping including the URL-level Vault password path.
func TestAPIRouteSpec_CacheRedisMapping_StandaloneURL(t *testing.T) {
	spec := avapigwv1alpha1.APIRouteSpec{
		Cache: &avapigwv1alpha1.CacheConfig{
			Enabled: true,
			Type:    "redis",
			Redis: &avapigwv1alpha1.RedisCacheSpec{
				URL:               "redis://redis.svc:6379/1",
				PasswordVaultPath: "secret/redis",
			},
		},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var route config.Route
	if err := json.Unmarshal(data, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if route.Cache.Redis.URL != "redis://redis.svc:6379/1" {
		t.Errorf("url = %q", route.Cache.Redis.URL)
	}
	if route.Cache.Redis.PasswordVaultPath != "secret/redis" {
		t.Errorf("passwordVaultPath = %q", route.Cache.Redis.PasswordVaultPath)
	}
}

// TestAPIRouteSpec_RateLimitRedisMapping verifies the operator's CR→gateway
// translation for distributed rate limiting, including store selection,
// sentinel, vault paths, retry and failOpen.
func TestAPIRouteSpec_RateLimitRedisMapping(t *testing.T) {
	failOpen := false
	spec := avapigwv1alpha1.APIRouteSpec{
		RateLimit: &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 500,
			Burst:             1000,
			PerClient:         true,
			Store:             "redis",
			Redis: &avapigwv1alpha1.RateLimitRedisSpec{
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:                "mymaster",
					SentinelAddrs:             []string{"sentinel-0:26379"},
					DB:                        3,
					PasswordVaultPath:         "secret/rl-master",
					SentinelPasswordVaultPath: "secret/rl-sentinel",
				},
				PoolSize:          25,
				ConnectTimeout:    "1s",
				ReadTimeout:       "50ms",
				WriteTimeout:      "60ms",
				KeyPrefix:         "rl:",
				PasswordVaultPath: "secret/rl",
				Retry: &avapigwv1alpha1.RedisRetrySpec{
					MaxRetries:     2,
					InitialBackoff: "50ms",
					MaxBackoff:     "5s",
				},
				FailOpen: &failOpen,
			},
		},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}

	var route config.Route
	if err := json.Unmarshal(data, &route); err != nil {
		t.Fatalf("unmarshal into config.Route: %v", err)
	}

	rl := route.RateLimit
	if rl == nil || !rl.Enabled {
		t.Fatalf("rate limit not mapped: %+v", rl)
	}
	if rl.RequestsPerSecond != 500 || rl.Burst != 1000 || !rl.PerClient {
		t.Errorf("limits not mapped: %+v", rl)
	}
	if rl.GetEffectiveStore() != config.RateLimitStoreRedis {
		t.Errorf("store = %q, want redis", rl.Store)
	}

	redisCfg := rl.Redis
	if redisCfg == nil {
		t.Fatal("redis config not mapped")
	}
	if redisCfg.PoolSize != 25 || redisCfg.KeyPrefix != "rl:" ||
		redisCfg.PasswordVaultPath != "secret/rl" {
		t.Errorf("connection fields not mapped: %+v", redisCfg)
	}
	if redisCfg.ConnectTimeout.Duration() != time.Second {
		t.Errorf("connectTimeout = %v, want 1s", redisCfg.ConnectTimeout.Duration())
	}
	if redisCfg.ReadTimeout.Duration() != 50*time.Millisecond {
		t.Errorf("readTimeout = %v", redisCfg.ReadTimeout.Duration())
	}
	if redisCfg.WriteTimeout.Duration() != 60*time.Millisecond {
		t.Errorf("writeTimeout = %v, want 60ms", redisCfg.WriteTimeout.Duration())
	}
	if redisCfg.GetEffectiveFailOpen() {
		t.Error("failOpen=false lost in translation")
	}

	sentinel := redisCfg.Sentinel
	if sentinel == nil || sentinel.MasterName != "mymaster" || sentinel.DB != 3 {
		t.Fatalf("sentinel not mapped: %+v", sentinel)
	}
	if len(sentinel.SentinelAddrs) != 1 || sentinel.SentinelAddrs[0] != "sentinel-0:26379" {
		t.Errorf("sentinel addrs not mapped: %+v", sentinel.SentinelAddrs)
	}
	if sentinel.PasswordVaultPath != "secret/rl-master" ||
		sentinel.SentinelPasswordVaultPath != "secret/rl-sentinel" {
		t.Errorf("sentinel vault paths not mapped: %+v", sentinel)
	}

	if redisCfg.Retry == nil || redisCfg.Retry.MaxRetries != 2 ||
		redisCfg.Retry.InitialBackoff.Duration() != 50*time.Millisecond {
		t.Errorf("retry not mapped: %+v", redisCfg.Retry)
	}
	if redisCfg.Retry.MaxBackoff.Duration() != 5*time.Second {
		t.Errorf("retry.maxBackoff = %v, want 5s", redisCfg.Retry.MaxBackoff.Duration())
	}
}

// TestGRPCRouteSpec_RedisMapping verifies that the shared CRD types map onto
// the gateway's gRPC route configuration as well.
func TestGRPCRouteSpec_RedisMapping(t *testing.T) {
	spec := avapigwv1alpha1.GRPCRouteSpec{
		RateLimit: &avapigwv1alpha1.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 50,
			Burst:             100,
			Store:             "redis",
			Redis: &avapigwv1alpha1.RateLimitRedisSpec{
				URL: "redis://redis.svc:6379",
			},
		},
		Cache: &avapigwv1alpha1.CacheConfig{
			Enabled: true,
			Type:    "redis",
			Redis:   &avapigwv1alpha1.RedisCacheSpec{URL: "redis://redis.svc:6379"},
		},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var route config.GRPCRoute
	if err := json.Unmarshal(data, &route); err != nil {
		t.Fatalf("unmarshal into config.GRPCRoute: %v", err)
	}

	if route.RateLimit == nil || route.RateLimit.GetEffectiveStore() != config.RateLimitStoreRedis {
		t.Errorf("grpc rate limit store not mapped: %+v", route.RateLimit)
	}
	if route.Cache == nil || route.Cache.Type != config.CacheTypeRedis ||
		route.Cache.Redis == nil || route.Cache.Redis.URL == "" {
		t.Errorf("grpc cache not mapped: %+v", route.Cache)
	}
}

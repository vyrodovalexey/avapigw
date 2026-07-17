package v1alpha1

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestRedisCacheSpec_DeepCopy verifies deep copy semantics for the
// route-level Redis cache specification, including nested sentinel,
// retry, and pointer fields.
func TestRedisCacheSpec_DeepCopy(t *testing.T) {
	jitter := 0.25
	hashKeys := true
	src := &RedisCacheSpec{
		URL: "redis://localhost:6379",
		Sentinel: &RedisSentinelSpec{
			MasterName:    "mymaster",
			SentinelAddrs: []string{"s1:26379", "s2:26379"},
		},
		PoolSize:          10,
		ConnectTimeout:    "1s",
		ReadTimeout:       "100ms",
		WriteTimeout:      "200ms",
		KeyPrefix:         "cache:",
		TTLJitter:         &jitter,
		HashKeys:          &hashKeys,
		PasswordVaultPath: "secret/redis",
		Retry: &RedisRetrySpec{
			MaxRetries:     3,
			InitialBackoff: "100ms",
			MaxBackoff:     "10s",
		},
	}

	got := src.DeepCopy()

	if got == src {
		t.Fatal("DeepCopy must return a new object")
	}
	if got.URL != src.URL || got.PoolSize != src.PoolSize || got.KeyPrefix != src.KeyPrefix {
		t.Errorf("scalar fields not copied: %+v", got)
	}
	if got.Sentinel == src.Sentinel || got.Sentinel.MasterName != "mymaster" {
		t.Error("sentinel must be deep-copied")
	}
	if got.Retry == src.Retry || got.Retry.MaxRetries != 3 {
		t.Error("retry must be deep-copied")
	}
	if got.TTLJitter == src.TTLJitter || *got.TTLJitter != 0.25 {
		t.Error("ttlJitter pointer must be deep-copied")
	}
	if got.HashKeys == src.HashKeys || !*got.HashKeys {
		t.Error("hashKeys pointer must be deep-copied")
	}

	// Mutating the copy must not affect the source.
	got.Sentinel.SentinelAddrs[0] = "changed"
	if src.Sentinel.SentinelAddrs[0] != "s1:26379" {
		t.Error("sentinel addrs slice must not be shared")
	}

	var nilSpec *RedisCacheSpec
	if nilSpec.DeepCopy() != nil {
		t.Error("nil DeepCopy must return nil")
	}
}

// TestRateLimitRedisSpec_DeepCopy verifies deep copy semantics for the
// distributed rate limiter Redis specification.
func TestRateLimitRedisSpec_DeepCopy(t *testing.T) {
	failOpen := false
	src := &RateLimitRedisSpec{
		URL: "redis://localhost:6379",
		Sentinel: &RedisSentinelSpec{
			MasterName:    "mymaster",
			SentinelAddrs: []string{"s1:26379"},
		},
		PoolSize:          5,
		ConnectTimeout:    "1s",
		ReadTimeout:       "50ms",
		WriteTimeout:      "60ms",
		KeyPrefix:         "rl:",
		PasswordVaultPath: "secret/rl",
		Retry:             &RedisRetrySpec{MaxRetries: 2},
		FailOpen:          &failOpen,
	}

	got := src.DeepCopy()

	if got == src {
		t.Fatal("DeepCopy must return a new object")
	}
	if got.URL != src.URL || got.KeyPrefix != src.KeyPrefix {
		t.Errorf("scalar fields not copied: %+v", got)
	}
	if got.Sentinel == src.Sentinel || got.Sentinel.MasterName != "mymaster" {
		t.Error("sentinel must be deep-copied")
	}
	if got.Retry == src.Retry || got.Retry.MaxRetries != 2 {
		t.Error("retry must be deep-copied")
	}
	if got.FailOpen == src.FailOpen || *got.FailOpen {
		t.Error("failOpen pointer must be deep-copied")
	}

	var nilSpec *RateLimitRedisSpec
	if nilSpec.DeepCopy() != nil {
		t.Error("nil DeepCopy must return nil")
	}
}

// TestRedisRetrySpec_DeepCopy verifies deep copy semantics for the Redis
// retry specification.
func TestRedisRetrySpec_DeepCopy(t *testing.T) {
	src := &RedisRetrySpec{MaxRetries: 7, InitialBackoff: "1s", MaxBackoff: "30s"}

	got := src.DeepCopy()
	if got == src {
		t.Fatal("DeepCopy must return a new object")
	}
	if *got != *src {
		t.Errorf("copy = %+v, want %+v", got, src)
	}

	var nilSpec *RedisRetrySpec
	if nilSpec.DeepCopy() != nil {
		t.Error("nil DeepCopy must return nil")
	}
}

// TestCacheConfig_DeepCopy_WithRedis verifies that the extended route cache
// configuration deep-copies its Redis block.
func TestCacheConfig_DeepCopy_WithRedis(t *testing.T) {
	src := &CacheConfig{
		Enabled: true,
		TTL:     "5m",
		Type:    "redis",
		Redis:   &RedisCacheSpec{URL: "redis://x:6379"},
	}

	got := src.DeepCopy()
	if got == src || got.Redis == src.Redis {
		t.Fatal("cache and redis block must be deep-copied")
	}
	if got.Type != "redis" || got.Redis.URL != "redis://x:6379" {
		t.Errorf("fields not copied: %+v", got)
	}
}

// TestRateLimitConfig_DeepCopy_WithRedis verifies that the extended rate
// limit configuration deep-copies its store and Redis block.
func TestRateLimitConfig_DeepCopy_WithRedis(t *testing.T) {
	src := &RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             20,
		Store:             "redis",
		Redis:             &RateLimitRedisSpec{URL: "redis://x:6379"},
	}

	got := src.DeepCopy()
	if got == src || got.Redis == src.Redis {
		t.Fatal("rate limit and redis block must be deep-copied")
	}
	if got.Store != "redis" || got.Redis.URL != "redis://x:6379" {
		t.Errorf("fields not copied: %+v", got)
	}
}

// TestRateLimitConfig_JSONRoundTrip_AllRedisFields proves the JSON tags of
// the rate limit Redis spec round-trip EVERY field losslessly, including
// the fields previously set-but-unasserted (PoolSize, KeyPrefix,
// WriteTimeout, Sentinel.DB).
func TestRateLimitConfig_JSONRoundTrip_AllRedisFields(t *testing.T) {
	failOpen := false
	src := &RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             20,
		PerClient:         true,
		Store:             "redis",
		Redis: &RateLimitRedisSpec{
			URL: "redis://redis.svc:6379",
			Sentinel: &RedisSentinelSpec{
				MasterName:                "mymaster",
				SentinelAddrs:             []string{"s1:26379", "s2:26379"},
				SentinelPassword:          "sentinel-pw",
				Password:                  "master-pw",
				DB:                        1,
				PasswordVaultPath:         "secret/master",
				SentinelPasswordVaultPath: "secret/sentinel",
			},
			PoolSize:          15,
			ConnectTimeout:    "1500ms",
			ReadTimeout:       "45ms",
			WriteTimeout:      "75ms",
			KeyPrefix:         "gw:",
			PasswordVaultPath: "secret/rl",
			Retry: &RedisRetrySpec{
				MaxRetries:     4,
				InitialBackoff: "150ms",
				MaxBackoff:     "7s",
			},
			FailOpen: &failOpen,
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

	// Every field must survive: a tag typo on any field fails here.
	if !reflect.DeepEqual(&got, src) {
		t.Errorf("JSON round-trip lost data:\n got: %+v\nwant: %+v", &got, src)
	}

	// Explicit assertions for the review-flagged fields.
	if got.Redis.PoolSize != 15 {
		t.Errorf("poolSize = %d, want 15", got.Redis.PoolSize)
	}
	if got.Redis.KeyPrefix != "gw:" {
		t.Errorf("keyPrefix = %q, want gw:", got.Redis.KeyPrefix)
	}
	if got.Redis.WriteTimeout != "75ms" {
		t.Errorf("writeTimeout = %q, want 75ms", got.Redis.WriteTimeout)
	}
	if got.Redis.Sentinel.DB != 1 {
		t.Errorf("sentinel.db = %d, want 1", got.Redis.Sentinel.DB)
	}
	if got.Redis.Retry.InitialBackoff != "150ms" {
		t.Errorf("retry.initialBackoff = %q, want 150ms", got.Redis.Retry.InitialBackoff)
	}
	if got.Redis.FailOpen == nil || *got.Redis.FailOpen {
		t.Errorf("failOpen = %v, want false", got.Redis.FailOpen)
	}
}

// TestCacheConfig_JSONRoundTrip_AllRedisFields proves the JSON tags of the
// route cache Redis spec round-trip EVERY field losslessly.
func TestCacheConfig_JSONRoundTrip_AllRedisFields(t *testing.T) {
	jitter := 0.25
	hashKeys := true
	src := &CacheConfig{
		Enabled:              true,
		TTL:                  "5m",
		KeyComponents:        []string{"method", "path"},
		StaleWhileRevalidate: "30s",
		Type:                 "redis",
		Redis: &RedisCacheSpec{
			URL: "redis://redis.svc:6379",
			Sentinel: &RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"s1:26379"},
				DB:            2,
			},
			PoolSize:          9,
			ConnectTimeout:    "2s",
			ReadTimeout:       "100ms",
			WriteTimeout:      "200ms",
			KeyPrefix:         "cache:",
			TTLJitter:         &jitter,
			HashKeys:          &hashKeys,
			PasswordVaultPath: "secret/cache",
			Retry: &RedisRetrySpec{
				MaxRetries:     2,
				InitialBackoff: "100ms",
				MaxBackoff:     "10s",
			},
		},
	}

	data, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got CacheConfig
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(&got, src) {
		t.Errorf("JSON round-trip lost data:\n got: %+v\nwant: %+v", &got, src)
	}

	// Explicit assertions for the review-flagged fields.
	if got.Redis.PoolSize != 9 {
		t.Errorf("poolSize = %d, want 9", got.Redis.PoolSize)
	}
	if got.Redis.KeyPrefix != "cache:" {
		t.Errorf("keyPrefix = %q, want cache:", got.Redis.KeyPrefix)
	}
	if got.Redis.WriteTimeout != "200ms" {
		t.Errorf("writeTimeout = %q, want 200ms", got.Redis.WriteTimeout)
	}
	if got.Redis.Sentinel.DB != 2 {
		t.Errorf("sentinel.db = %d, want 2", got.Redis.Sentinel.DB)
	}
	if got.Redis.TTLJitter == nil || *got.Redis.TTLJitter != 0.25 {
		t.Errorf("ttlJitter = %v, want 0.25", got.Redis.TTLJitter)
	}
	if got.Redis.HashKeys == nil || !*got.Redis.HashKeys {
		t.Errorf("hashKeys = %v, want true", got.Redis.HashKeys)
	}
}

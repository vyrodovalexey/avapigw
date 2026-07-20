package authz

// Tests for T3.H2 (review H2-operator, gateway side): the authorization
// decision cache supports redis+sentinel external caching, accepts both
// serialization shapes (`redis` and the CRD's `sentinel`), and falls back
// loudly to the in-memory cache when the redis configuration is missing or
// unusable.

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// newRedisCacheAuthzConfig builds a minimal enabled authz config carrying
// the given cache configuration.
func newRedisCacheAuthzConfig(cache *CacheConfig) *Config {
	return &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{{
				Name:      "allow-admin",
				Roles:     []string{"admin"},
				Resources: []string{"/*"},
				Actions:   []string{"*"},
				Effect:    rbac.EffectAllow,
			}},
		},
		Cache: cache,
	}
}

// newAuthorizerForCacheTest builds an authorizer and returns its concrete
// type for cache inspection.
func newAuthorizerForCacheTest(t *testing.T, cache *CacheConfig) *authorizer {
	t.Helper()

	a, err := New(newRedisCacheAuthzConfig(cache))
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })

	concrete, ok := a.(*authorizer)
	require.True(t, ok)
	return concrete
}

func TestConvertCacheConfig_RedisShapes(t *testing.T) {
	t.Parallel()

	t.Run("redis block carried", func(t *testing.T) {
		t.Parallel()
		src := &config.AuthzCacheConfig{
			Enabled: true,
			Type:    "redis",
			TTL:     config.Duration(time.Minute),
			Redis:   &config.RedisCacheConfig{URL: "redis://localhost:6379"},
		}
		out := convertCacheConfig(src)
		require.NotNil(t, out.Redis)
		assert.Equal(t, "redis://localhost:6379", out.Redis.URL)
		assert.NotSame(t, src.Redis, out.Redis, "redis config must be deep-copied")
	})

	t.Run("CRD sentinel shape folded into redis config", func(t *testing.T) {
		t.Parallel()
		src := &config.AuthzCacheConfig{
			Enabled: true,
			Type:    "redis",
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"s1:26379"},
			},
		}
		out := convertCacheConfig(src)
		require.NotNil(t, out.Redis)
		require.NotNil(t, out.Redis.Sentinel)
		assert.Equal(t, "mymaster", out.Redis.Sentinel.MasterName)
		assert.NotSame(t, src.Sentinel, out.Redis.Sentinel, "sentinel config must be deep-copied")
	})

	t.Run("redis block sentinel wins over top-level sentinel", func(t *testing.T) {
		t.Parallel()
		src := &config.AuthzCacheConfig{
			Enabled: true,
			Type:    "redis",
			Redis: &config.RedisCacheConfig{
				Sentinel: &config.RedisSentinelConfig{MasterName: "inner"},
			},
			Sentinel: &config.RedisSentinelConfig{MasterName: "outer"},
		}
		out := convertCacheConfig(src)
		require.NotNil(t, out.Redis)
		assert.Equal(t, "inner", out.Redis.Sentinel.MasterName)
	})

	t.Run("no redis config yields nil", func(t *testing.T) {
		t.Parallel()
		out := convertCacheConfig(&config.AuthzCacheConfig{Enabled: true, Type: "memory"})
		assert.Nil(t, out.Redis)
	})
}

// TestConvertFromGatewayConfig_SentinelReachesAuthorizer covers the full
// conversion path: a gateway config carrying the CRD sentinel shape yields
// an authz config whose cache carries the redis connection.
func TestConvertFromGatewayConfig_SentinelReachesAuthorizer(t *testing.T) {
	t.Parallel()

	src := &config.AuthorizationConfig{
		Enabled: true,
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{{
				Name: "p", Roles: []string{"admin"},
				Resources: []string{"/*"}, Actions: []string{"*"},
			}},
		},
		Cache: &config.AuthzCacheConfig{
			Enabled: true,
			Type:    "redis",
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"s1:26379"},
			},
		},
	}

	out, err := ConvertFromGatewayConfig(src)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Cache)
	require.NotNil(t, out.Cache.Redis)
	require.NotNil(t, out.Cache.Redis.Sentinel)
	assert.Equal(t, "mymaster", out.Cache.Redis.Sentinel.MasterName)
}

func TestAuthorizer_RedisDecisionCache_EndToEnd(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	a := newAuthorizerForCacheTest(t, &CacheConfig{
		Enabled: true,
		Type:    "redis",
		TTL:     time.Minute,
		Redis:   &config.RedisCacheConfig{URL: "redis://" + mr.Addr()},
	})

	_, isExternal := a.cache.(*externalDecisionCache)
	assert.True(t, isExternal, "redis type with usable config must build the external decision cache")

	// A cached decision round-trips through Redis.
	key := &CacheKey{Subject: "alice", Resource: "/api", Action: "GET"}
	a.cache.Set(context.Background(), key, &CachedDecision{Allowed: true, Policy: "allow-admin"})
	cached, ok := a.cache.Get(context.Background(), key)
	require.True(t, ok, "decision must be readable back from redis")
	assert.True(t, cached.Allowed)
}

func TestAuthorizer_RedisDecisionCache_FallsBackWithoutConfig(t *testing.T) {
	t.Parallel()

	a := newAuthorizerForCacheTest(t, &CacheConfig{
		Enabled: true,
		Type:    "redis",
		TTL:     time.Minute,
		// Redis connection missing: must fall back to memory with a warning.
	})

	_, isMemory := a.cache.(*memoryDecisionCache)
	assert.True(t, isMemory, "missing redis config must fall back to the in-memory decision cache")
}

func TestAuthorizer_RedisDecisionCache_FallsBackOnUnreachableRedis(t *testing.T) {
	t.Parallel()

	a := newAuthorizerForCacheTest(t, &CacheConfig{
		Enabled: true,
		Type:    "redis",
		TTL:     time.Minute,
		Redis: &config.RedisCacheConfig{
			URL: "redis://127.0.0.1:1", // unreachable
			Retry: &config.RedisRetryConfig{
				MaxRetries:     1,
				InitialBackoff: config.Duration(time.Millisecond),
				MaxBackoff:     config.Duration(2 * time.Millisecond),
			},
		},
	})

	_, isMemory := a.cache.(*memoryDecisionCache)
	assert.True(t, isMemory, "unreachable redis must fall back to the in-memory decision cache")
}

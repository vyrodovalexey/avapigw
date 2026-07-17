//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
package operator_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// redisSentinelSpecFromEnvShape returns a CRD sentinel spec shaped like the
// docker-compose test environment (mymaster, three sentinels, password).
func redisSentinelSpecFromEnvShape() *avapigwv1alpha1.RedisSentinelSpec {
	return &avapigwv1alpha1.RedisSentinelSpec{
		MasterName: "mymaster",
		SentinelAddrs: []string{
			"127.0.0.1:26379",
			"127.0.0.1:26380",
			"127.0.0.1:26381",
		},
		Password: "password",
	}
}

// TestFunctional_APIRoute_RedisCache_Admission black-boxes the APIRoute
// admission surface for route-level redis cache configuration through the
// public webhook validator API.
func TestFunctional_APIRoute_RedisCache_Admission(t *testing.T) {
	validator := &webhook.APIRouteValidator{}
	jitter := 0.2
	badJitterHigh := 1.5
	badJitterLow := -0.1

	tests := []struct {
		name     string
		cache    *avapigwv1alpha1.CacheConfig
		wantErr  string
		wantWarn string
	}{
		{
			name: "redis cache with sentinel is admitted with plaintext warning",
			cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				TTL:     "5m",
				Type:    "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					KeyPrefix: "route:",
					TTLJitter: &jitter,
					Sentinel:  redisSentinelSpecFromEnvShape(),
				},
			},
			wantWarn: "plaintext",
		},
		{
			name: "redis cache with standalone url is admitted",
			cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				TTL:     "5m",
				Type:    "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://redis.svc:6379",
				},
			},
		},
		{
			name: "url and sentinel are mutually exclusive",
			cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				Type:    "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL:      "redis://redis.svc:6379",
					Sentinel: redisSentinelSpecFromEnvShape(),
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "type redis requires a redis block",
			cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				Type:    "redis",
			},
			wantErr: "cache.redis is required",
		},
		{
			name: "redis block without url or sentinel is rejected",
			cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				Type:    "redis",
				Redis:   &avapigwv1alpha1.RedisCacheSpec{KeyPrefix: "x:"},
			},
			wantErr: "requires either url or sentinel",
		},
		{
			name: "memory type rejects a redis block",
			cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				Type:    "memory",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://redis.svc:6379",
				},
			},
			wantErr: "only valid when cache.type is 'redis'",
		},
		{
			name: "ttlJitter above 1.0 is rejected",
			cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				Type:    "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL:       "redis://redis.svc:6379",
					TTLJitter: &badJitterHigh,
				},
			},
			wantErr: "ttlJitter must be between 0.0 and 1.0",
		},
		{
			name: "negative ttlJitter is rejected",
			cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				Type:    "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL:       "redis://redis.svc:6379",
					TTLJitter: &badJitterLow,
				},
			},
			wantErr: "ttlJitter must be between 0.0 and 1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := createBasicAPIRoute()
			route.Spec.Cache = tt.cache

			warnings, err := validator.ValidateCreate(context.Background(), route)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantWarn != "" {
				require.NotEmpty(t, warnings, "expected an admission warning")
				assert.Contains(t, warnings[0], tt.wantWarn)
			}
		})
	}
}

// TestFunctional_APIRoute_RedisRateLimit_Admission black-boxes the APIRoute
// admission surface for the distributed (redis-store) rate limiter.
func TestFunctional_APIRoute_RedisRateLimit_Admission(t *testing.T) {
	validator := &webhook.APIRouteValidator{}
	failOpen := false

	tests := []struct {
		name      string
		rateLimit *avapigwv1alpha1.RateLimitConfig
		wantErr   string
		wantWarn  string
	}{
		{
			name: "redis store with sentinel is admitted with plaintext warning",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 50,
				Burst:             100,
				PerClient:         true,
				Store:             "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					KeyPrefix: "rl:",
					FailOpen:  &failOpen,
					Sentinel:  redisSentinelSpecFromEnvShape(),
				},
			},
			wantWarn: "plaintext",
		},
		{
			name: "redis store with standalone url is admitted",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 50,
				Burst:             100,
				Store:             "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL:         "redis://redis.svc:6379",
					ReadTimeout: "100ms",
				},
			},
		},
		{
			name: "redis store requires a redis block",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 50,
				Burst:             100,
				Store:             "redis",
			},
			wantErr: "rateLimit.redis is required",
		},
		{
			name: "url and sentinel are mutually exclusive",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 50,
				Burst:             100,
				Store:             "redis",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL:      "redis://redis.svc:6379",
					Sentinel: redisSentinelSpecFromEnvShape(),
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "memory store rejects a redis block",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 50,
				Burst:             100,
				Store:             "memory",
				Redis: &avapigwv1alpha1.RateLimitRedisSpec{
					URL: "redis://redis.svc:6379",
				},
			},
			wantErr: "only valid when rateLimit.store is 'redis'",
		},
		{
			name: "invalid store enum is rejected",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 50,
				Burst:             100,
				Store:             "etcd",
			},
			wantErr: "rateLimit.store must be 'memory' or 'redis'",
		},
		{
			name: "store validation applies even when rate limiting is disabled",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled: false,
				Store:   "redis",
			},
			wantErr: "rateLimit.redis is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := createBasicAPIRoute()
			route.Spec.RateLimit = tt.rateLimit

			warnings, err := validator.ValidateCreate(context.Background(), route)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantWarn != "" {
				require.NotEmpty(t, warnings, "expected an admission warning")
				assert.Contains(t, warnings[0], tt.wantWarn)
			}
		})
	}
}

// TestFunctional_Route_RedisStore_UnappliedWarnings verifies the truthful
// admission warnings for redis-backed stores per route kind: gRPC routes
// warn that the distributed limiter / redis cache is not applied on their
// data path yet (in-memory limiting; no response caching); GraphQL routes
// enforce redis rate limiting through the shared route middleware chain
// (no unapplied warning) but warn that the redis cache has no effect for
// POST GraphQL operations (GET-only caching semantics).
func TestFunctional_Route_RedisStore_UnappliedWarnings(t *testing.T) {
	redisRL := &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             20,
		Store:             "redis",
		Redis: &avapigwv1alpha1.RateLimitRedisSpec{
			URL: "redis://redis.svc:6379",
		},
	}
	redisCache := &avapigwv1alpha1.CacheConfig{
		Enabled: true,
		TTL:     "1m",
		Type:    "redis",
		Redis: &avapigwv1alpha1.RedisCacheSpec{
			URL: "redis://redis.svc:6379",
		},
	}

	t.Run("GRPCRoute warns for redis store and redis cache", func(t *testing.T) {
		validator := &webhook.GRPCRouteValidator{}
		route := createBasicGRPCRoute()
		route.Spec.RateLimit = redisRL
		route.Spec.Cache = redisCache

		warnings, err := validator.ValidateCreate(context.Background(), route)
		require.NoError(t, err, "config is accepted for forward compatibility")

		joined := ""
		for _, w := range warnings {
			joined += w + "\n"
		}
		assert.Contains(t, joined, "rateLimit.store=redis is not applied for GRPCRoute")
		assert.Contains(t, joined, "cache.type=redis is not applied for GRPCRoute")
	})

	t.Run("GraphQLRoute enforces redis store, warns GET-only cache", func(t *testing.T) {
		validator := &webhook.GraphQLRouteValidator{}
		route := createBasicGraphQLRoute()
		route.Spec.RateLimit = redisRL
		route.Spec.Cache = redisCache

		warnings, err := validator.ValidateCreate(context.Background(), route)
		require.NoError(t, err, "config is accepted")

		joined := ""
		for _, w := range warnings {
			joined += w + "\n"
		}
		// Redis-backed distributed rate limiting IS enforced on the GraphQL
		// data path via the shared route middleware chain — no unapplied
		// warning may be emitted.
		assert.NotContains(t, joined, "rateLimit.store=redis is not applied",
			"GraphQLRoute enforces the redis rate limit store via the shared middleware chain")
		// The redis cache is built by the chain but never takes effect for
		// POST GraphQL operations (response caching is GET-only).
		assert.Contains(t, joined, "cache.type=redis on GraphQLRoute currently has no effect")
		assert.Contains(t, joined, "GET requests only")
	})

	t.Run("APIRoute does not warn (redis store is enforced for HTTP routes)", func(t *testing.T) {
		validator := &webhook.APIRouteValidator{}
		route := createBasicAPIRoute()
		route.Spec.RateLimit = redisRL
		route.Spec.Cache = redisCache

		warnings, err := validator.ValidateCreate(context.Background(), route)
		require.NoError(t, err)
		for _, w := range warnings {
			assert.NotContains(t, w, "is not applied",
				"APIRoute redis store/cache must not carry unapplied warnings")
		}
	})
}

// TestFunctional_APIRoute_RedisConfig_GatewayContract verifies the full
// CRD -> gateway contract: an admitted APIRoute spec with redis sentinel
// cache and redis rate limiting, marshaled to JSON the way the operator
// pushes config, unmarshals onto config.Route and passes the gateway's own
// configuration validation with all effective values intact.
func TestFunctional_APIRoute_RedisConfig_GatewayContract(t *testing.T) {
	jitter := 0.25
	hashKeys := true
	failOpen := false

	route := createBasicAPIRoute()
	route.Spec.Cache = &avapigwv1alpha1.CacheConfig{
		Enabled: true,
		TTL:     "2m",
		Type:    "redis",
		Redis: &avapigwv1alpha1.RedisCacheSpec{
			KeyPrefix: "contract:",
			TTLJitter: &jitter,
			HashKeys:  &hashKeys,
			Sentinel:  redisSentinelSpecFromEnvShape(),
		},
	}
	route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 25,
		Burst:             50,
		PerClient:         true,
		Store:             "redis",
		Redis: &avapigwv1alpha1.RateLimitRedisSpec{
			KeyPrefix:   "contract-rl:",
			ReadTimeout: "100ms",
			FailOpen:    &failOpen,
			Sentinel:    redisSentinelSpecFromEnvShape(),
		},
	}

	// 1. The CR is admitted by the webhook.
	validator := &webhook.APIRouteValidator{}
	_, err := validator.ValidateCreate(context.Background(), route)
	require.NoError(t, err, "CR must be admitted")

	// 2. The operator marshals the spec to JSON and the gateway unmarshals
	//    it onto config.Route (same translation the controller performs).
	data, err := json.Marshal(route.Spec)
	require.NoError(t, err)

	var gwRoute config.Route
	require.NoError(t, json.Unmarshal(data, &gwRoute))
	gwRoute.Name = route.Name

	// 3. The translated route passes the gateway's own validation.
	gwCfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "contract-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
			Routes: []config.Route{gwRoute},
		},
	}
	require.NoError(t, config.ValidateConfig(gwCfg),
		"CRD-expressed redis cache + rate limit must pass gateway validation")

	// 4. Effective values survive the translation.
	require.NotNil(t, gwRoute.Cache)
	assert.Equal(t, config.CacheTypeRedis, gwRoute.Cache.Type)
	require.NotNil(t, gwRoute.Cache.Redis)
	assert.Equal(t, "contract:", gwRoute.Cache.Redis.KeyPrefix)
	assert.InDelta(t, 0.25, gwRoute.Cache.Redis.TTLJitter, 0.0001)
	assert.True(t, gwRoute.Cache.Redis.HashKeys)
	require.NotNil(t, gwRoute.Cache.Redis.Sentinel)
	assert.Equal(t, "mymaster", gwRoute.Cache.Redis.Sentinel.MasterName)
	assert.Len(t, gwRoute.Cache.Redis.Sentinel.SentinelAddrs, 3)

	require.NotNil(t, gwRoute.RateLimit)
	assert.Equal(t, config.RateLimitStoreRedis, gwRoute.RateLimit.GetEffectiveStore())
	assert.True(t, gwRoute.RateLimit.PerClient)
	require.NotNil(t, gwRoute.RateLimit.Redis)
	assert.False(t, gwRoute.RateLimit.Redis.GetEffectiveFailOpen(),
		"failOpen=false must survive CRD -> gateway translation")
	assert.Equal(t, "contract-rl:", gwRoute.RateLimit.Redis.KeyPrefix)
	require.NotNil(t, gwRoute.RateLimit.Redis.Sentinel)
	assert.Equal(t, "mymaster", gwRoute.RateLimit.Redis.Sentinel.MasterName)
}

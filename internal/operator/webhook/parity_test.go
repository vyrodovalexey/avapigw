// Package webhook provides admission webhooks for validating avapigw resources.
package webhook

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// validateRedisTLSSpec
// ============================================================================

func TestValidateRedisTLSSpec(t *testing.T) {
	assert.NoError(t, validateRedisTLSSpec(nil, "cache.redis.tls"))
	assert.NoError(t, validateRedisTLSSpec(&avapigwv1alpha1.RedisTLSSpec{Enabled: true}, "cache.redis.tls"))
	assert.NoError(t, validateRedisTLSSpec(&avapigwv1alpha1.RedisTLSSpec{
		Enabled: true, CertFile: "/tls/cert.pem", KeyFile: "/tls/key.pem", CAFile: "/tls/ca.pem",
	}, "cache.redis.tls"))

	err := validateRedisTLSSpec(&avapigwv1alpha1.RedisTLSSpec{Enabled: true, CertFile: "/tls/cert.pem"}, "x.tls")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x.tls.certFile and x.tls.keyFile must be specified together")

	err = validateRedisTLSSpec(&avapigwv1alpha1.RedisTLSSpec{Enabled: true, KeyFile: "/tls/key.pem"}, "y.tls")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "y.tls.certFile and y.tls.keyFile must be specified together")
}

func TestValidateRedisConnectionSpec_TLSWired(t *testing.T) {
	err := validateRedisConnectionSpec(redisConnectionSpec{
		fieldPath: "cache.redis",
		url:       "redis://cache:6379/0",
		tls:       &avapigwv1alpha1.RedisTLSSpec{Enabled: true, CertFile: "/only-cert.pem"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache.redis.tls.certFile")
}

// ============================================================================
// validateAuthzCacheRedis / validateAuthzCacheConfig
// ============================================================================

func TestValidateAuthzCacheRedis(t *testing.T) {
	sentinel := &avapigwv1alpha1.RedisSentinelSpec{
		MasterName:    "mymaster",
		SentinelAddrs: []string{"s1:26379"},
	}

	tests := []struct {
		name    string
		cache   *avapigwv1alpha1.AuthzCacheConfig
		wantErr string
	}{
		{
			name:  "nil redis is valid",
			cache: &avapigwv1alpha1.AuthzCacheConfig{Enabled: true, Type: CacheTypeRedis},
		},
		{
			name: "redis with url",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true, Type: CacheTypeRedis,
				Redis: &avapigwv1alpha1.RedisCacheSpec{URL: "redis://cache:6379/0"},
			},
		},
		{
			name: "redis with sentinel",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true, Type: CacheTypeRedis,
				Redis: &avapigwv1alpha1.RedisCacheSpec{Sentinel: sentinel},
			},
		},
		{
			name: "redis requires type redis",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true, Type: CacheTypeMemory,
				Redis: &avapigwv1alpha1.RedisCacheSpec{URL: "redis://cache:6379/0"},
			},
			wantErr: "authorization.cache.redis is only valid when type is 'redis'",
		},
		{
			name: "redis and legacy sentinel are mutually exclusive",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true, Type: CacheTypeRedis,
				Redis:    &avapigwv1alpha1.RedisCacheSpec{URL: "redis://cache:6379/0"},
				Sentinel: sentinel,
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "redis without url or sentinel is rejected",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true, Type: CacheTypeRedis,
				Redis: &avapigwv1alpha1.RedisCacheSpec{},
			},
			wantErr: "requires either url or sentinel",
		},
		{
			name: "redis url and sentinel together rejected",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true, Type: CacheTypeRedis,
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://cache:6379/0", Sentinel: sentinel,
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "invalid ttlJitter rejected",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true, Type: CacheTypeRedis,
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://cache:6379/0", TTLJitter: float64Ptr(1.5),
				},
			},
			wantErr: "ttlJitter must be between 0.0 and 1.0",
		},
		{
			name: "invalid tls pairing rejected",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true, Type: CacheTypeRedis,
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					URL: "redis://cache:6379/0",
					TLS: &avapigwv1alpha1.RedisTLSSpec{Enabled: true, CertFile: "/cert.pem"},
				},
			},
			wantErr: "authorization.cache.redis.tls.certFile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthzCacheRedis(tt.cache)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func float64Ptr(f float64) *float64 { return &f }

func TestValidateAuthzCacheConfig_RedisField(t *testing.T) {
	// The full config-level validator must route through the redis checks.
	err := validateAuthzCacheConfig(&avapigwv1alpha1.AuthzCacheConfig{
		Enabled: true, Type: CacheTypeRedis,
		Redis: &avapigwv1alpha1.RedisCacheSpec{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires either url or sentinel")

	assert.NoError(t, validateAuthzCacheConfig(&avapigwv1alpha1.AuthzCacheConfig{
		Enabled: true, Type: CacheTypeRedis,
		Redis: &avapigwv1alpha1.RedisCacheSpec{URL: "redis://cache:6379/0"},
	}))
}

// ============================================================================
// validateRouteTransform
// ============================================================================

func TestValidateRouteTransform(t *testing.T) {
	assert.NoError(t, validateRouteTransform(nil))
	assert.NoError(t, validateRouteTransform(&avapigwv1alpha1.TransformConfig{}))

	valid := &avapigwv1alpha1.TransformConfig{
		Request: &avapigwv1alpha1.RequestTransform{
			PassthroughBody: true,
			StaticHeaders:   map[string]string{"X-Static": "v"},
			DynamicHeaders: []avapigwv1alpha1.TransformDynamicHeader{
				{Name: "X-User", Source: "jwt.claim.sub"},
			},
			InjectFields: []avapigwv1alpha1.TransformFieldInjection{
				{Field: "meta.user", Source: "jwt.claim.sub"},
				{Field: "meta.static", Value: &apiextensionsv1.JSON{Raw: []byte(`"v"`)}},
			},
			RemoveFields: []string{"secret"},
		},
		Response: &avapigwv1alpha1.ResponseTransform{
			AllowFields:   []string{"id", "name"},
			GroupFields:   []avapigwv1alpha1.TransformFieldGroup{{Name: "meta", Fields: []string{"a"}}},
			FlattenFields: []string{"nested"},
			ArrayOperations: []avapigwv1alpha1.TransformArrayOperation{
				{Field: "items", Operation: "limit", Value: &apiextensionsv1.JSON{Raw: []byte(`10`)}},
				{Field: "items", Operation: "filter", Condition: "item.active == true"},
			},
			MergeStrategy: "ndjson",
		},
	}
	assert.NoError(t, validateRouteTransform(valid))

	err := validateRouteTransform(&avapigwv1alpha1.TransformConfig{
		Request: &avapigwv1alpha1.RequestTransform{
			InjectFields: []avapigwv1alpha1.TransformFieldInjection{{Field: "meta"}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "injectFields[0] requires either value or source")

	err = validateRouteTransform(&avapigwv1alpha1.TransformConfig{
		Response: &avapigwv1alpha1.ResponseTransform{
			AllowFields: []string{"a"},
			DenyFields:  []string{"b"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot have both allowFields and denyFields")

	err = validateRouteTransform(&avapigwv1alpha1.TransformConfig{
		Response: &avapigwv1alpha1.ResponseTransform{
			ArrayOperations: []avapigwv1alpha1.TransformArrayOperation{
				{Field: "items", Operation: "filter"},
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "condition is required for the filter operation")
}

// ============================================================================
// validateRouteCacheConfig — new fields
// ============================================================================

func TestValidateRouteCacheConfig_NegativeCacheTTL(t *testing.T) {
	assert.NoError(t, validateRouteCacheConfig(&avapigwv1alpha1.CacheConfig{
		Enabled: true, NegativeCacheTTL: "5s",
		KeyConfig: &avapigwv1alpha1.CacheKeyConfig{IncludeMethod: true, IncludePath: true},
	}))

	err := validateRouteCacheConfig(&avapigwv1alpha1.CacheConfig{
		Enabled: true, NegativeCacheTTL: "not-a-duration",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache.negativeCacheTTL is invalid")
}

// ============================================================================
// Warnings
// ============================================================================

func TestWarnFieldNotApplied(t *testing.T) {
	warnings := warnFieldNotApplied("spec.maxSessions", kindGRPCRoute)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "spec.maxSessions is accepted but not applied for GRPCRoute")
	assert.Contains(t, warnings[0], "forward compatibility")
}

func TestWarnCacheKeyComponentsUnapplied(t *testing.T) {
	assert.Empty(t, warnCacheKeyComponentsUnapplied(nil, kindAPIRoute))
	assert.Empty(t, warnCacheKeyComponentsUnapplied(&avapigwv1alpha1.CacheConfig{Enabled: true}, kindAPIRoute))

	warnings := warnCacheKeyComponentsUnapplied(&avapigwv1alpha1.CacheConfig{
		Enabled: true, KeyComponents: []string{"method", "path"},
	}, kindAPIRoute)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "cache.keyComponents on APIRoute is deprecated")
	assert.Contains(t, warnings[0], "cache.keyConfig")
}

func TestWarnAuthzCacheRedisWithoutConnection(t *testing.T) {
	assert.Empty(t, warnAuthzCacheRedisWithoutConnection(nil, kindAPIRoute))
	assert.Empty(t, warnAuthzCacheRedisWithoutConnection(&avapigwv1alpha1.AuthorizationConfig{}, kindAPIRoute))
	assert.Empty(t, warnAuthzCacheRedisWithoutConnection(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{Enabled: true, Type: CacheTypeMemory},
	}, kindAPIRoute))

	// Genuinely unusable: type=redis with no connection config at all.
	warnings := warnAuthzCacheRedisWithoutConnection(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{Enabled: true, Type: CacheTypeRedis},
	}, kindAPIRoute)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "authorization.cache.type=redis on APIRoute has no Redis connection")
	assert.Contains(t, warnings[0], "in-memory decision cache")

	// Usable configs (redis or legacy sentinel present) do not warn.
	assert.Empty(t, warnAuthzCacheRedisWithoutConnection(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true, Type: CacheTypeRedis,
			Redis: &avapigwv1alpha1.RedisCacheSpec{URL: "redis://cache:6379/0"},
		},
	}, kindAPIRoute))
	assert.Empty(t, warnAuthzCacheRedisWithoutConnection(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true, Type: CacheTypeRedis,
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName: "m", SentinelAddrs: []string{"s:26379"},
			},
		},
	}, kindAPIRoute))
}

func TestWarnAuthzCacheSentinelDeprecated(t *testing.T) {
	assert.Empty(t, warnAuthzCacheSentinelDeprecated(nil))
	assert.Empty(t, warnAuthzCacheSentinelDeprecated(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{Enabled: true, Type: CacheTypeRedis},
	}))

	warnings := warnAuthzCacheSentinelDeprecated(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true, Type: CacheTypeRedis,
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName: "m", SentinelAddrs: []string{"s:26379"},
			},
		},
	})
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "authorization.cache.sentinel is deprecated")
	assert.Contains(t, warnings[0], "authorization.cache.redis.sentinel")
}

func TestWarnAuthzCacheSecrets(t *testing.T) {
	assert.Empty(t, warnAuthzCacheSecrets(nil))
	assert.Empty(t, warnAuthzCacheSecrets(&avapigwv1alpha1.AuthorizationConfig{}))

	// Plaintext password under the preferred redis.sentinel block.
	warnings := warnAuthzCacheSecrets(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true, Type: CacheTypeRedis,
			Redis: &avapigwv1alpha1.RedisCacheSpec{
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName: "m", SentinelAddrs: []string{"s:26379"},
					Password: "plaintext",
				},
			},
		},
	})
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "SECURITY WARNING")

	// Plaintext password under the deprecated sentinel block.
	warnings = warnAuthzCacheSecrets(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true, Type: CacheTypeRedis,
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName: "m", SentinelAddrs: []string{"s:26379"},
				SentinelPassword: "plaintext",
			},
		},
	})
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "SECURITY WARNING")

	// Pin: credentials embedded in redis.url (redis://:pass@host) are
	// intentionally NOT scanned today — only the structured sentinel
	// password fields are checked. This assertion surfaces any future
	// (deliberate) extension of the secret scanning as a test change.
	assert.Empty(t, warnAuthzCacheSecrets(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true, Type: CacheTypeRedis,
			Redis: &avapigwv1alpha1.RedisCacheSpec{URL: "redis://:plaintext-pass@cache:6379/0"},
		},
	}), "URL-embedded credentials are not scanned by warnAuthzCacheSecrets (current intent)")

	// A sentinel block under redis with only Vault paths does not warn.
	assert.Empty(t, warnAuthzCacheSecrets(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true, Type: CacheTypeRedis,
			Redis: &avapigwv1alpha1.RedisCacheSpec{
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName: "m", SentinelAddrs: []string{"s:26379"},
					Password: "resolved", PasswordVaultPath: "secret/redis",
				},
			},
		},
	}), "password with a vault path configured must not warn")
}

func TestWarnBackendRateLimitUnapplied(t *testing.T) {
	assert.Empty(t, warnBackendRateLimitUnapplied(nil, kindGRPCBackend))
	assert.Empty(t, warnBackendRateLimitUnapplied(&avapigwv1alpha1.RateLimitConfig{Enabled: false}, kindGRPCBackend))

	warnings := warnBackendRateLimitUnapplied(&avapigwv1alpha1.RateLimitConfig{
		Enabled: true, RequestsPerSecond: 10, Burst: 10,
	}, kindGRPCBackend)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "spec.rateLimit is accepted but not applied for GRPCBackend")
}

// ============================================================================
// Validator integration — warnings surfaced through the webhooks
// ============================================================================

func TestAPIRouteValidator_NewParityWarnings(t *testing.T) {
	validator := &APIRouteValidator{}

	route := &avapigwv1alpha1.APIRoute{Spec: avapigwv1alpha1.APIRouteSpec{
		Cache: &avapigwv1alpha1.CacheConfig{
			Enabled:       true,
			KeyComponents: []string{"method"},
		},
		Authorization: &avapigwv1alpha1.AuthorizationConfig{
			Enabled: true,
			RBAC: &avapigwv1alpha1.RBACConfig{
				Enabled:  true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{{Name: "p", Roles: []string{"admin"}}},
			},
			Cache: &avapigwv1alpha1.AuthzCacheConfig{Enabled: true, Type: CacheTypeRedis},
		},
	}}

	warnings, err := validator.validate(route)
	require.NoError(t, err)

	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "cache.keyComponents on APIRoute is deprecated")
	assert.Contains(t, joined, "authorization.cache.type=redis on APIRoute has no Redis connection")
}

func TestAPIRouteValidator_TransformValidationWired(t *testing.T) {
	validator := &APIRouteValidator{}

	route := &avapigwv1alpha1.APIRoute{Spec: avapigwv1alpha1.APIRouteSpec{
		Transform: &avapigwv1alpha1.TransformConfig{
			Response: &avapigwv1alpha1.ResponseTransform{
				AllowFields: []string{"a"},
				DenyFields:  []string{"b"},
			},
		},
	}}

	_, err := validator.validate(route)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot have both allowFields and denyFields")
}

func TestBackendValidator_OverSpecWarnings(t *testing.T) {
	validator := &BackendValidator{}

	backend := &avapigwv1alpha1.Backend{Spec: avapigwv1alpha1.BackendSpec{
		Hosts:         []avapigwv1alpha1.BackendHost{{Address: "svc", Port: 8080}},
		RequestLimits: &avapigwv1alpha1.RequestLimitsConfig{MaxBodySize: 1024},
		Transform:     &avapigwv1alpha1.BackendTransformConfig{},
		Encoding:      &avapigwv1alpha1.BackendEncodingConfig{},
	}}

	warnings, err := validator.validate(backend)
	require.NoError(t, err)

	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "spec.requestLimits is accepted but not applied for Backend")
	assert.Contains(t, joined, "spec.transform is accepted but not applied for Backend")
	assert.Contains(t, joined, "spec.encoding is accepted but not applied for Backend")
}

func TestGRPCRouteValidator_OverSpecWarnings(t *testing.T) {
	validator := &GRPCRouteValidator{}

	route := &avapigwv1alpha1.GRPCRoute{Spec: avapigwv1alpha1.GRPCRouteSpec{
		MaxSessions:   &avapigwv1alpha1.MaxSessionsConfig{Enabled: true, MaxConcurrent: 5},
		RequestLimits: &avapigwv1alpha1.RequestLimitsConfig{MaxBodySize: 1024},
	}}

	warnings, err := validator.validate(route)
	require.NoError(t, err)

	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "spec.maxSessions is accepted but not applied for GRPCRoute")
	assert.Contains(t, joined, "spec.requestLimits is accepted but not applied for GRPCRoute")
}

func TestGRPCBackendValidator_OverSpecWarnings(t *testing.T) {
	validator := &GRPCBackendValidator{}

	backend := &avapigwv1alpha1.GRPCBackend{Spec: avapigwv1alpha1.GRPCBackendSpec{
		Hosts:       []avapigwv1alpha1.BackendHost{{Address: "svc", Port: 9090}},
		MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{Enabled: true, MaxConcurrent: 5},
		RateLimit:   &avapigwv1alpha1.RateLimitConfig{Enabled: true, RequestsPerSecond: 5, Burst: 5},
	}}

	warnings, err := validator.validate(backend)
	require.NoError(t, err)

	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "spec.maxSessions is accepted but not applied for GRPCBackend")
	assert.Contains(t, joined, "spec.rateLimit is accepted but not applied for GRPCBackend")
}

func TestGraphQLRouteValidator_OverSpecWarnings(t *testing.T) {
	validator := &GraphQLRouteValidator{}

	route := &avapigwv1alpha1.GraphQLRoute{Spec: avapigwv1alpha1.GraphQLRouteSpec{
		MaxSessions:   &avapigwv1alpha1.MaxSessionsConfig{Enabled: true, MaxConcurrent: 5},
		RequestLimits: &avapigwv1alpha1.RequestLimitsConfig{MaxBodySize: 2048},
	}}

	warnings, err := validator.validate(route)
	require.NoError(t, err)

	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "spec.maxSessions is accepted but not applied for GraphQLRoute")
	assert.Contains(t, joined, "spec.requestLimits is accepted but not applied for GraphQLRoute")
}

func TestGraphQLBackendValidator_OverSpecWarnings(t *testing.T) {
	validator := &GraphQLBackendValidator{}

	backend := &avapigwv1alpha1.GraphQLBackend{Spec: avapigwv1alpha1.GraphQLBackendSpec{
		Hosts:       []avapigwv1alpha1.BackendHost{{Address: "svc", Port: 8080}},
		MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{Enabled: true, MaxConcurrent: 5},
		Encoding:    &avapigwv1alpha1.BackendEncodingConfig{},
	}}

	warnings, err := validator.validate(backend)
	require.NoError(t, err)

	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "spec.maxSessions is accepted but not applied for GraphQLBackend")
	assert.Contains(t, joined, "spec.encoding is accepted but not applied for GraphQLBackend")
}

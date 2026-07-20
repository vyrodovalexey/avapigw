// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// normalizeAuthorizationConfig — legacy sentinel → redis.sentinel
// ============================================================================

func TestNormalizeAuthorizationConfig_NilSafe(t *testing.T) {
	assert.Zero(t, normalizeAuthorizationConfig(nil))
	assert.Zero(t, normalizeAuthorizationConfig(&avapigwv1alpha1.AuthorizationConfig{}))
	assert.Zero(t, normalizeAuthorizationConfig(&avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{Enabled: true, Type: "redis"},
	}))
}

func TestNormalizeAuthorizationConfig_SentinelConverted(t *testing.T) {
	sentinel := &avapigwv1alpha1.RedisSentinelSpec{
		MasterName:    "mymaster",
		SentinelAddrs: []string{"s1:26379", "s2:26379"},
	}
	authz := &avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled:  true,
			Type:     "redis",
			Sentinel: sentinel,
		},
	}

	converted := normalizeAuthorizationConfig(authz)

	assert.Equal(t, 1, converted)
	require.NotNil(t, authz.Cache.Redis, "redis block must be populated")
	assert.Equal(t, sentinel, authz.Cache.Redis.Sentinel, "sentinel must move under redis")
	assert.Nil(t, authz.Cache.Sentinel, "legacy sentinel must be cleared")
}

func TestNormalizeAuthorizationConfig_RedisTakesPrecedence(t *testing.T) {
	preferred := &avapigwv1alpha1.RedisCacheSpec{URL: "redis://cache:6379/0"}
	authz := &avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled:  true,
			Type:     "redis",
			Redis:    preferred,
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{MasterName: "legacy"},
		},
	}

	converted := normalizeAuthorizationConfig(authz)

	assert.Zero(t, converted, "no conversion when the preferred redis block is set")
	assert.Same(t, preferred, authz.Cache.Redis, "preferred redis block must be untouched")
	assert.Nil(t, authz.Cache.Sentinel, "legacy sentinel must still be cleared")
}

// ============================================================================
// normalizeSecurityConfig — legacy CSP/HSTS header strings → structured blocks
// ============================================================================

func TestNormalizeSecurityConfig_NilSafe(t *testing.T) {
	assert.Zero(t, normalizeSecurityConfig(nil))
	assert.Zero(t, normalizeSecurityConfig(&avapigwv1alpha1.SecurityConfig{}))
	assert.Zero(t, normalizeSecurityConfig(&avapigwv1alpha1.SecurityConfig{
		Headers: &avapigwv1alpha1.SecurityHeadersConfig{Enabled: true},
	}))
}

func TestNormalizeSecurityConfig_LegacyCSPConverted(t *testing.T) {
	sec := &avapigwv1alpha1.SecurityConfig{
		Enabled: true,
		Headers: &avapigwv1alpha1.SecurityHeadersConfig{
			Enabled:               true,
			ContentSecurityPolicy: "default-src 'self'",
		},
	}

	converted := normalizeSecurityConfig(sec)

	assert.Equal(t, 1, converted)
	require.NotNil(t, sec.CSP)
	assert.True(t, sec.CSP.Enabled)
	assert.Equal(t, "default-src 'self'", sec.CSP.Policy)
	assert.Empty(t, sec.Headers.ContentSecurityPolicy, "legacy field must be cleared")
}

func TestNormalizeSecurityConfig_LegacyHSTSConverted(t *testing.T) {
	sec := &avapigwv1alpha1.SecurityConfig{
		Enabled: true,
		Headers: &avapigwv1alpha1.SecurityHeadersConfig{
			Enabled:                 true,
			StrictTransportSecurity: "max-age=31536000; includeSubDomains; preload",
		},
	}

	converted := normalizeSecurityConfig(sec)

	assert.Equal(t, 1, converted)
	require.NotNil(t, sec.HSTS)
	assert.True(t, sec.HSTS.Enabled)
	assert.Equal(t, 31536000, sec.HSTS.MaxAge)
	assert.True(t, sec.HSTS.IncludeSubDomains)
	assert.True(t, sec.HSTS.Preload)
	assert.Empty(t, sec.Headers.StrictTransportSecurity, "legacy field must be cleared")
}

func TestNormalizeSecurityConfig_StructuredBlocksTakePrecedence(t *testing.T) {
	csp := &avapigwv1alpha1.SecurityCSPConfig{Enabled: true, Policy: "structured"}
	hsts := &avapigwv1alpha1.SecurityHSTSConfig{Enabled: true, MaxAge: 60}
	sec := &avapigwv1alpha1.SecurityConfig{
		Enabled: true,
		CSP:     csp,
		HSTS:    hsts,
		Headers: &avapigwv1alpha1.SecurityHeadersConfig{
			Enabled:                 true,
			ContentSecurityPolicy:   "legacy",
			StrictTransportSecurity: "max-age=1",
		},
	}

	converted := normalizeSecurityConfig(sec)

	assert.Zero(t, converted, "structured blocks win; nothing is converted")
	assert.Same(t, csp, sec.CSP)
	assert.Same(t, hsts, sec.HSTS)
	assert.Empty(t, sec.Headers.ContentSecurityPolicy)
	assert.Empty(t, sec.Headers.StrictTransportSecurity)
}

// ============================================================================
// parseHSTSHeaderValue
// ============================================================================

func TestParseHSTSHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  avapigwv1alpha1.SecurityHSTSConfig
	}{
		{
			name:  "full directive set",
			value: "max-age=63072000; includeSubDomains; preload",
			want: avapigwv1alpha1.SecurityHSTSConfig{
				Enabled: true, MaxAge: 63072000, IncludeSubDomains: true, Preload: true,
			},
		},
		{
			name:  "max-age only",
			value: "max-age=300",
			want:  avapigwv1alpha1.SecurityHSTSConfig{Enabled: true, MaxAge: 300},
		},
		{
			name:  "case insensitive directives",
			value: "MAX-AGE=600; IncludeSubdomains; PRELOAD",
			want: avapigwv1alpha1.SecurityHSTSConfig{
				Enabled: true, MaxAge: 600, IncludeSubDomains: true, Preload: true,
			},
		},
		{
			name:  "malformed max-age ignored",
			value: "max-age=oops; includeSubDomains",
			want:  avapigwv1alpha1.SecurityHSTSConfig{Enabled: true, IncludeSubDomains: true},
		},
		{
			name:  "negative max-age ignored",
			value: "max-age=-5",
			want:  avapigwv1alpha1.SecurityHSTSConfig{Enabled: true},
		},
		{
			name:  "unknown directives ignored",
			value: "max-age=10; something-else",
			want:  avapigwv1alpha1.SecurityHSTSConfig{Enabled: true, MaxAge: 10},
		},
		{
			name:  "empty value still enables",
			value: "",
			want:  avapigwv1alpha1.SecurityHSTSConfig{Enabled: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHSTSHeaderValue(tt.value)
			require.NotNil(t, got)
			assert.Equal(t, tt.want, *got)
		})
	}
}

// ============================================================================
// normalizeRouteSpecShared
// ============================================================================

func TestNormalizeRouteSpecShared_CountsAllConversions(t *testing.T) {
	authz := &avapigwv1alpha1.AuthorizationConfig{
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true, Type: "redis",
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{MasterName: "m", SentinelAddrs: []string{"s:26379"}},
		},
	}
	sec := &avapigwv1alpha1.SecurityConfig{
		Enabled: true,
		Headers: &avapigwv1alpha1.SecurityHeadersConfig{
			Enabled:                 true,
			ContentSecurityPolicy:   "default-src 'none'",
			StrictTransportSecurity: "max-age=100",
		},
	}

	assert.Equal(t, 3, normalizeRouteSpecShared(authz, sec))
	assert.Zero(t, normalizeRouteSpecShared(authz, sec), "second pass is a no-op")
	assert.Zero(t, normalizeRouteSpecShared(nil, nil))
}

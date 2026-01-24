package authz

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
)

func TestConfig_Validate_NilConfig(t *testing.T) {
	t.Parallel()

	var cfg *Config
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_Disabled(t *testing.T) {
	t.Parallel()

	cfg := &Config{Enabled: false}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_InvalidDefaultPolicy(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: "invalid",
		RBAC:          &rbac.Config{Enabled: true},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid default policy")
}

func TestConfig_Validate_ValidDefaultPolicies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		policy Policy
	}{
		{"allow policy", PolicyAllow},
		{"deny policy", PolicyDeny},
		{"empty policy", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Enabled:       true,
				DefaultPolicy: tt.policy,
				RBAC:          &rbac.Config{Enabled: true},
			}
			err := cfg.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestConfig_Validate_NoAuthzMethod(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one authorization method must be configured")
}

func TestConfig_Validate_WithRBAC(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		RBAC: &rbac.Config{
			Enabled: true,
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_WithABAC(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		ABAC: &abac.Config{
			Enabled: true,
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_WithExternal(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		External: &external.Config{
			Enabled: true,
			Type:    "opa",
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_InvalidRBAC(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		RBAC: &rbac.Config{
			Enabled: true,
			RoleHierarchy: map[string][]string{
				"admin": {"admin"}, // Circular reference
			},
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rbac config")
}

func TestConfig_Validate_InvalidABAC(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		ABAC: &abac.Config{
			Enabled: true,
			Engine:  "invalid",
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "abac config")
}

func TestConfig_Validate_InvalidExternal(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		External: &external.Config{
			Enabled: true,
			Type:    "invalid",
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "external config")
}

func TestConfig_Validate_CacheNegativeTTL(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		RBAC:          &rbac.Config{Enabled: true},
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     -1 * time.Second,
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ttl must be non-negative")
}

func TestConfig_Validate_CacheNegativeMaxSize(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		RBAC:          &rbac.Config{Enabled: true},
		Cache: &CacheConfig{
			Enabled: true,
			MaxSize: -1,
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maxSize must be non-negative")
}

func TestConfig_Validate_CacheInvalidType(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		RBAC:          &rbac.Config{Enabled: true},
		Cache: &CacheConfig{
			Enabled: true,
			Type:    "invalid",
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cache type")
}

func TestConfig_Validate_CacheValidTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cacheType string
	}{
		{"empty type", ""},
		{"memory type", "memory"},
		{"redis type", "redis"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Enabled:       true,
				DefaultPolicy: PolicyDeny,
				RBAC:          &rbac.Config{Enabled: true},
				Cache: &CacheConfig{
					Enabled: true,
					Type:    tt.cacheType,
					TTL:     time.Minute,
					MaxSize: 100,
				},
			}
			err := cfg.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	require.NotNil(t, cfg)
	assert.False(t, cfg.Enabled)
	assert.Equal(t, PolicyDeny, cfg.DefaultPolicy)
	require.NotNil(t, cfg.Cache)
	assert.True(t, cfg.Cache.Enabled)
	assert.Equal(t, 5*time.Minute, cfg.Cache.TTL)
	assert.Equal(t, 10000, cfg.Cache.MaxSize)
	assert.Equal(t, "memory", cfg.Cache.Type)
}

func TestConfig_IsRBACEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Config
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "nil RBAC",
			cfg:      &Config{},
			expected: false,
		},
		{
			name:     "RBAC disabled",
			cfg:      &Config{RBAC: &rbac.Config{Enabled: false}},
			expected: false,
		},
		{
			name:     "RBAC enabled",
			cfg:      &Config{RBAC: &rbac.Config{Enabled: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.IsRBACEnabled())
		})
	}
}

func TestConfig_IsABACEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Config
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "nil ABAC",
			cfg:      &Config{},
			expected: false,
		},
		{
			name:     "ABAC disabled",
			cfg:      &Config{ABAC: &abac.Config{Enabled: false}},
			expected: false,
		},
		{
			name:     "ABAC enabled",
			cfg:      &Config{ABAC: &abac.Config{Enabled: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.IsABACEnabled())
		})
	}
}

func TestConfig_IsExternalEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Config
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "nil External",
			cfg:      &Config{},
			expected: false,
		},
		{
			name:     "External disabled",
			cfg:      &Config{External: &external.Config{Enabled: false}},
			expected: false,
		},
		{
			name:     "External enabled",
			cfg:      &Config{External: &external.Config{Enabled: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.IsExternalEnabled())
		})
	}
}

func TestConfig_GetEffectiveDefaultPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   Policy
		expected Policy
	}{
		{
			name:     "empty policy defaults to deny",
			policy:   "",
			expected: PolicyDeny,
		},
		{
			name:     "allow policy",
			policy:   PolicyAllow,
			expected: PolicyAllow,
		},
		{
			name:     "deny policy",
			policy:   PolicyDeny,
			expected: PolicyDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{DefaultPolicy: tt.policy}
			assert.Equal(t, tt.expected, cfg.GetEffectiveDefaultPolicy())
		})
	}
}

func TestConfig_ShouldSkipPath(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		SkipPaths: []string{
			"/health",
			"/metrics",
			"/api/v1/public/*",
		},
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "exact match",
			path:     "/health",
			expected: true,
		},
		{
			name:     "exact match metrics",
			path:     "/metrics",
			expected: true,
		},
		{
			name:     "wildcard match",
			path:     "/api/v1/public/users",
			expected: true,
		},
		{
			name:     "wildcard match nested",
			path:     "/api/v1/public/users/123",
			expected: true,
		},
		{
			name:     "no match",
			path:     "/api/v1/private/users",
			expected: false,
		},
		{
			name:     "partial match not skipped",
			path:     "/healthcheck",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, cfg.ShouldSkipPath(tt.path))
		})
	}
}

func TestConfig_ShouldSkipPath_EmptySkipPaths(t *testing.T) {
	t.Parallel()

	cfg := &Config{SkipPaths: []string{}}
	assert.False(t, cfg.ShouldSkipPath("/any/path"))
}

func TestMatchPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "/health",
			path:     "/health",
			expected: true,
		},
		{
			name:     "no match",
			pattern:  "/health",
			path:     "/metrics",
			expected: false,
		},
		{
			name:     "wildcard match",
			pattern:  "/api/*",
			path:     "/api/users",
			expected: true,
		},
		{
			name:     "wildcard match nested",
			pattern:  "/api/*",
			path:     "/api/users/123",
			expected: true,
		},
		{
			name:     "wildcard no match",
			pattern:  "/api/*",
			path:     "/other/path",
			expected: false,
		},
		{
			name:     "empty pattern",
			pattern:  "",
			path:     "/any",
			expected: false,
		},
		{
			name:     "empty path",
			pattern:  "/api/*",
			path:     "",
			expected: false,
		},
		{
			name:     "wildcard only",
			pattern:  "*",
			path:     "/any/path",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, matchPath(tt.pattern, tt.path))
		})
	}
}

func TestConfig_hasAnyAuthzMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Config
		expected bool
	}{
		{
			name:     "no methods",
			cfg:      &Config{},
			expected: false,
		},
		{
			name:     "RBAC nil",
			cfg:      &Config{RBAC: nil},
			expected: false,
		},
		{
			name:     "RBAC disabled",
			cfg:      &Config{RBAC: &rbac.Config{Enabled: false}},
			expected: false,
		},
		{
			name:     "RBAC enabled",
			cfg:      &Config{RBAC: &rbac.Config{Enabled: true}},
			expected: true,
		},
		{
			name:     "ABAC enabled",
			cfg:      &Config{ABAC: &abac.Config{Enabled: true}},
			expected: true,
		},
		{
			name:     "External enabled",
			cfg:      &Config{External: &external.Config{Enabled: true}},
			expected: true,
		},
		{
			name:     "multiple enabled",
			cfg:      &Config{RBAC: &rbac.Config{Enabled: true}, ABAC: &abac.Config{Enabled: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.hasAnyAuthzMethod())
		})
	}
}

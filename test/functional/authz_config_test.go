//go:build functional
// +build functional

package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/authz"
	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
)

func TestFunctional_AuthzConfig_Validation(t *testing.T) {
	t.Parallel()

	t.Run("valid config with RBAC enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled:       true,
			DefaultPolicy: authz.PolicyDeny,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "admin-all",
						Roles:     []string{"admin"},
						Resources: []string{"*"},
						Actions:   []string{"*"},
					},
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid config with ABAC enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled:       true,
			DefaultPolicy: authz.PolicyDeny,
			ABAC: &abac.Config{
				Enabled: true,
				Engine:  "cel",
				Policies: []abac.Policy{
					{
						Name:       "admin-access",
						Expression: `"admin" in subject.roles`,
					},
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid config with external authorization", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled:       true,
			DefaultPolicy: authz.PolicyDeny,
			External: &external.Config{
				Enabled: true,
				Type:    "opa",
				Timeout: 10 * time.Second,
				OPA: &external.OPAConfig{
					URL:    "http://localhost:8181",
					Policy: "authz/allow",
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid config - enabled but no authz method", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled:       true,
			DefaultPolicy: authz.PolicyDeny,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one authorization method")
	})

	t.Run("invalid config - invalid default policy", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled:       true,
			DefaultPolicy: "invalid",
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "test",
						Roles:     []string{"user"},
						Resources: []string{"*"},
						Actions:   []string{"*"},
					},
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid default policy")
	})

	t.Run("disabled config is always valid", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled: false,
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("nil config is valid", func(t *testing.T) {
		t.Parallel()

		var cfg *authz.Config
		err := cfg.Validate()
		require.NoError(t, err)
	})
}

func TestFunctional_AuthzConfig_RBACValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid RBAC config", func(t *testing.T) {
		t.Parallel()

		cfg := &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "admin-all",
					Roles:     []string{"admin"},
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Effect:    rbac.EffectAllow,
				},
				{
					Name:      "user-read",
					Roles:     []string{"user"},
					Resources: []string{"/api/*"},
					Actions:   []string{"GET"},
					Effect:    rbac.EffectAllow,
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid RBAC config with role hierarchy", func(t *testing.T) {
		t.Parallel()

		cfg := &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "user-read",
					Roles:     []string{"user"},
					Resources: []string{"/api/*"},
					Actions:   []string{"GET"},
				},
			},
			RoleHierarchy: map[string][]string{
				"admin": {"user"},
				"user":  {"reader"},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid RBAC config - policy missing name", func(t *testing.T) {
		t.Parallel()

		cfg := &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Roles:     []string{"admin"},
					Resources: []string{"*"},
					Actions:   []string{"*"},
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("invalid RBAC config - policy missing roles/permissions/groups", func(t *testing.T) {
		t.Parallel()

		cfg := &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test",
					Resources: []string{"*"},
					Actions:   []string{"*"},
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "roles")
	})

	t.Run("invalid RBAC config - policy missing resources", func(t *testing.T) {
		t.Parallel()

		cfg := &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:    "test",
					Roles:   []string{"admin"},
					Actions: []string{"*"},
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resources")
	})

	t.Run("invalid RBAC config - policy missing actions", func(t *testing.T) {
		t.Parallel()

		cfg := &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test",
					Roles:     []string{"admin"},
					Resources: []string{"*"},
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "actions")
	})

	t.Run("invalid RBAC config - invalid effect", func(t *testing.T) {
		t.Parallel()

		cfg := &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test",
					Roles:     []string{"admin"},
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Effect:    "invalid",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "effect")
	})

	t.Run("invalid RBAC config - role hierarchy cycle", func(t *testing.T) {
		t.Parallel()

		cfg := &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test",
					Roles:     []string{"user"},
					Resources: []string{"*"},
					Actions:   []string{"*"},
				},
			},
			RoleHierarchy: map[string][]string{
				"admin": {"user"},
				"user":  {"admin"}, // Cycle!
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cycle")
	})
}

func TestFunctional_AuthzConfig_ABACValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid ABAC config", func(t *testing.T) {
		t.Parallel()

		cfg := &abac.Config{
			Enabled: true,
			Engine:  "cel",
			Policies: []abac.Policy{
				{
					Name:       "admin-access",
					Expression: `"admin" in subject.roles`,
					Effect:     abac.EffectAllow,
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid ABAC config with resource/action scope", func(t *testing.T) {
		t.Parallel()

		cfg := &abac.Config{
			Enabled: true,
			Engine:  "cel",
			Policies: []abac.Policy{
				{
					Name:       "user-read",
					Expression: `"user" in subject.roles`,
					Effect:     abac.EffectAllow,
					Resources:  []string{"/api/*"},
					Actions:    []string{"GET"},
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid ABAC config - invalid engine", func(t *testing.T) {
		t.Parallel()

		cfg := &abac.Config{
			Enabled: true,
			Engine:  "invalid",
			Policies: []abac.Policy{
				{
					Name:       "test",
					Expression: `true`,
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "engine")
	})

	t.Run("invalid ABAC config - policy missing name", func(t *testing.T) {
		t.Parallel()

		cfg := &abac.Config{
			Enabled: true,
			Policies: []abac.Policy{
				{
					Expression: `"admin" in subject.roles`,
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("invalid ABAC config - policy missing expression", func(t *testing.T) {
		t.Parallel()

		cfg := &abac.Config{
			Enabled: true,
			Policies: []abac.Policy{
				{
					Name: "test",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expression")
	})

	t.Run("invalid ABAC config - invalid effect", func(t *testing.T) {
		t.Parallel()

		cfg := &abac.Config{
			Enabled: true,
			Policies: []abac.Policy{
				{
					Name:       "test",
					Expression: `true`,
					Effect:     "invalid",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "effect")
	})
}

func TestFunctional_AuthzConfig_CacheValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid cache config", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "test",
						Roles:     []string{"user"},
						Resources: []string{"*"},
						Actions:   []string{"*"},
					},
				},
			},
			Cache: &authz.CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: 10000,
				Type:    "memory",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid cache config - negative TTL", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "test",
						Roles:     []string{"user"},
						Resources: []string{"*"},
						Actions:   []string{"*"},
					},
				},
			},
			Cache: &authz.CacheConfig{
				Enabled: true,
				TTL:     -1 * time.Minute,
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ttl")
	})

	t.Run("invalid cache config - negative max size", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "test",
						Roles:     []string{"user"},
						Resources: []string{"*"},
						Actions:   []string{"*"},
					},
				},
			},
			Cache: &authz.CacheConfig{
				Enabled: true,
				MaxSize: -1,
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maxSize")
	})

	t.Run("invalid cache config - invalid type", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "test",
						Roles:     []string{"user"},
						Resources: []string{"*"},
						Actions:   []string{"*"},
					},
				},
			},
			Cache: &authz.CacheConfig{
				Enabled: true,
				Type:    "invalid",
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cache type")
	})
}

func TestFunctional_AuthzConfig_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := authz.DefaultConfig()
	require.NotNil(t, cfg)

	assert.False(t, cfg.Enabled)
	assert.Equal(t, authz.PolicyDeny, cfg.DefaultPolicy)
	assert.NotNil(t, cfg.Cache)
	assert.True(t, cfg.Cache.Enabled)
	assert.Equal(t, "memory", cfg.Cache.Type)
}

func TestFunctional_AuthzConfig_HelperMethods(t *testing.T) {
	t.Parallel()

	t.Run("IsRBACEnabled", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			RBAC: &rbac.Config{Enabled: true},
		}
		assert.True(t, cfg.IsRBACEnabled())

		cfg.RBAC.Enabled = false
		assert.False(t, cfg.IsRBACEnabled())

		cfg.RBAC = nil
		assert.False(t, cfg.IsRBACEnabled())
	})

	t.Run("IsABACEnabled", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			ABAC: &abac.Config{Enabled: true},
		}
		assert.True(t, cfg.IsABACEnabled())

		cfg.ABAC.Enabled = false
		assert.False(t, cfg.IsABACEnabled())

		cfg.ABAC = nil
		assert.False(t, cfg.IsABACEnabled())
	})

	t.Run("IsExternalEnabled", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			External: &external.Config{Enabled: true},
		}
		assert.True(t, cfg.IsExternalEnabled())

		cfg.External.Enabled = false
		assert.False(t, cfg.IsExternalEnabled())

		cfg.External = nil
		assert.False(t, cfg.IsExternalEnabled())
	})

	t.Run("GetEffectiveDefaultPolicy", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			DefaultPolicy: authz.PolicyAllow,
		}
		assert.Equal(t, authz.PolicyAllow, cfg.GetEffectiveDefaultPolicy())

		cfg.DefaultPolicy = ""
		assert.Equal(t, authz.PolicyDeny, cfg.GetEffectiveDefaultPolicy())
	})

	t.Run("ShouldSkipPath", func(t *testing.T) {
		t.Parallel()

		cfg := &authz.Config{
			SkipPaths: []string{
				"/health",
				"/metrics",
				"/api/public/*",
			},
		}

		assert.True(t, cfg.ShouldSkipPath("/health"))
		assert.True(t, cfg.ShouldSkipPath("/metrics"))
		assert.True(t, cfg.ShouldSkipPath("/api/public/test"))
		assert.True(t, cfg.ShouldSkipPath("/api/public/nested/path"))
		assert.False(t, cfg.ShouldSkipPath("/api/private"))
		assert.False(t, cfg.ShouldSkipPath("/healthcheck"))
	})
}

func TestFunctional_RBACConfig_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := rbac.DefaultConfig()
	require.NotNil(t, cfg)

	assert.False(t, cfg.Enabled)
	assert.NotNil(t, cfg.ClaimMapping)
	assert.Equal(t, "roles", cfg.ClaimMapping.Roles)
	assert.Equal(t, "permissions", cfg.ClaimMapping.Permissions)
	assert.Equal(t, "groups", cfg.ClaimMapping.Groups)
}

func TestFunctional_ABACConfig_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := abac.DefaultConfig()
	require.NotNil(t, cfg)

	assert.False(t, cfg.Enabled)
	assert.Equal(t, "cel", cfg.Engine)
}

func TestFunctional_RBACPolicy_GetEffectiveEffect(t *testing.T) {
	t.Parallel()

	t.Run("explicit allow", func(t *testing.T) {
		t.Parallel()

		policy := rbac.Policy{Effect: rbac.EffectAllow}
		assert.Equal(t, rbac.EffectAllow, policy.GetEffectiveEffect())
	})

	t.Run("explicit deny", func(t *testing.T) {
		t.Parallel()

		policy := rbac.Policy{Effect: rbac.EffectDeny}
		assert.Equal(t, rbac.EffectDeny, policy.GetEffectiveEffect())
	})

	t.Run("default to allow", func(t *testing.T) {
		t.Parallel()

		policy := rbac.Policy{}
		assert.Equal(t, rbac.EffectAllow, policy.GetEffectiveEffect())
	})
}

func TestFunctional_ABACPolicy_GetEffectiveEffect(t *testing.T) {
	t.Parallel()

	t.Run("explicit allow", func(t *testing.T) {
		t.Parallel()

		policy := abac.Policy{Effect: abac.EffectAllow}
		assert.Equal(t, abac.EffectAllow, policy.GetEffectiveEffect())
	})

	t.Run("explicit deny", func(t *testing.T) {
		t.Parallel()

		policy := abac.Policy{Effect: abac.EffectDeny}
		assert.Equal(t, abac.EffectDeny, policy.GetEffectiveEffect())
	})

	t.Run("default to allow", func(t *testing.T) {
		t.Parallel()

		policy := abac.Policy{}
		assert.Equal(t, abac.EffectAllow, policy.GetEffectiveEffect())
	})
}

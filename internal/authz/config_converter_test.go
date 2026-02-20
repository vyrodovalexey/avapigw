package authz

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestConvertFromGatewayConfig_NilInput(t *testing.T) {
	t.Parallel()

	result, err := ConvertFromGatewayConfig(nil)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestConvertFromGatewayConfig_Disabled(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled: false,
	}

	result, err := ConvertFromGatewayConfig(cfg)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestConvertFromGatewayConfig_RBACOnly(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled: true,
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "admin-policy",
					Roles:     []string{"admin"},
					Resources: []string{"/api/*"},
					Actions:   []string{"GET", "POST"},
					Effect:    "allow",
					Priority:  10,
				},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	require.NotNil(t, result.RBAC)
	assert.True(t, result.RBAC.Enabled)
	require.Len(t, result.RBAC.Policies, 1)
	assert.Equal(t, "admin-policy", result.RBAC.Policies[0].Name)
	assert.Equal(t, []string{"admin"}, result.RBAC.Policies[0].Roles)
	assert.Equal(t, []string{"/api/*"}, result.RBAC.Policies[0].Resources)
	assert.Equal(t, []string{"GET", "POST"}, result.RBAC.Policies[0].Actions)
	assert.Equal(t, rbac.PolicyEffect("allow"), result.RBAC.Policies[0].Effect)
	assert.Equal(t, 10, result.RBAC.Policies[0].Priority)
	assert.Nil(t, result.ABAC)
	assert.Nil(t, result.External)
	assert.Nil(t, result.Cache)
}

func TestConvertFromGatewayConfig_ABACOnly(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled: true,
		ABAC: &config.ABACConfig{
			Enabled: true,
			Policies: []config.ABACPolicyConfig{
				{
					Name:       "time-based-access",
					Expression: "request.time.getHours() >= 9 && request.time.getHours() <= 17",
					Resources:  []string{"/api/reports/*"},
					Actions:    []string{"GET"},
					Effect:     "allow",
					Priority:   5,
				},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	require.NotNil(t, result.ABAC)
	assert.True(t, result.ABAC.Enabled)
	assert.Equal(t, "cel", result.ABAC.Engine)
	require.Len(t, result.ABAC.Policies, 1)
	assert.Equal(t, "time-based-access", result.ABAC.Policies[0].Name)
	assert.Equal(t, "request.time.getHours() >= 9 && request.time.getHours() <= 17", result.ABAC.Policies[0].Expression)
	assert.Equal(t, []string{"/api/reports/*"}, result.ABAC.Policies[0].Resources)
	assert.Equal(t, []string{"GET"}, result.ABAC.Policies[0].Actions)
	assert.Equal(t, abac.PolicyEffect("allow"), result.ABAC.Policies[0].Effect)
	assert.Equal(t, 5, result.ABAC.Policies[0].Priority)
	assert.Nil(t, result.RBAC)
	assert.Nil(t, result.External)
	assert.Nil(t, result.Cache)
}

func TestConvertFromGatewayConfig_ExternalOnly(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled: true,
		External: &config.ExternalAuthzConfig{
			Enabled:  true,
			Timeout:  config.Duration(5 * time.Second),
			FailOpen: true,
			OPA: &config.OPAAuthzConfig{
				URL:    "http://opa:8181/v1/data/authz/allow",
				Policy: "authz/allow",
				Headers: map[string]string{
					"X-Custom-Header": "value",
				},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	require.NotNil(t, result.External)
	assert.True(t, result.External.Enabled)
	assert.Equal(t, "opa", result.External.Type)
	assert.Equal(t, 5*time.Second, result.External.Timeout)
	assert.True(t, result.External.FailOpen)
	require.NotNil(t, result.External.OPA)
	assert.Equal(t, "http://opa:8181/v1/data/authz/allow", result.External.OPA.URL)
	assert.Equal(t, "authz/allow", result.External.OPA.Policy)
	assert.Equal(t, map[string]string{"X-Custom-Header": "value"}, result.External.OPA.Headers)
	assert.Nil(t, result.RBAC)
	assert.Nil(t, result.ABAC)
	assert.Nil(t, result.Cache)
}

func TestConvertFromGatewayConfig_WithCache(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled: true,
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "basic",
					Roles:     []string{"user"},
					Resources: []string{"/*"},
					Actions:   []string{"GET"},
				},
			},
		},
		Cache: &config.AuthzCacheConfig{
			Enabled: true,
			TTL:     config.Duration(10 * time.Minute),
			MaxSize: 5000,
			Type:    "memory",
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Cache)
	assert.True(t, result.Cache.Enabled)
	assert.Equal(t, 10*time.Minute, result.Cache.TTL)
	assert.Equal(t, 5000, result.Cache.MaxSize)
	assert.Equal(t, "memory", result.Cache.Type)
}

func TestConvertFromGatewayConfig_FullConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled:       true,
		DefaultPolicy: "deny",
		SkipPaths:     []string{"/health", "/metrics"},
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "admin-all",
					Roles:     []string{"admin"},
					Resources: []string{"/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
					Priority:  100,
				},
			},
			RoleHierarchy: map[string][]string{
				"admin":  {"editor"},
				"editor": {"viewer"},
				"viewer": {},
			},
		},
		ABAC: &config.ABACConfig{
			Enabled: true,
			Policies: []config.ABACPolicyConfig{
				{
					Name:       "owner-access",
					Expression: "subject.id == resource.owner_id",
					Resources:  []string{"/api/documents/*"},
					Actions:    []string{"PUT", "DELETE"},
					Effect:     "allow",
					Priority:   50,
				},
			},
		},
		External: &config.ExternalAuthzConfig{
			Enabled:  true,
			Timeout:  config.Duration(3 * time.Second),
			FailOpen: false,
			OPA: &config.OPAAuthzConfig{
				URL:    "http://opa:8181/v1/data/authz",
				Policy: "authz",
			},
		},
		Cache: &config.AuthzCacheConfig{
			Enabled: true,
			TTL:     config.Duration(5 * time.Minute),
			MaxSize: 10000,
			Type:    "redis",
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Top-level fields
	assert.True(t, result.Enabled)
	assert.Equal(t, Policy("deny"), result.DefaultPolicy)
	assert.Equal(t, []string{"/health", "/metrics"}, result.SkipPaths)

	// RBAC
	require.NotNil(t, result.RBAC)
	assert.True(t, result.RBAC.Enabled)
	require.Len(t, result.RBAC.Policies, 1)
	assert.Equal(t, "admin-all", result.RBAC.Policies[0].Name)
	assert.NotNil(t, result.RBAC.RoleHierarchy)

	// ABAC
	require.NotNil(t, result.ABAC)
	assert.True(t, result.ABAC.Enabled)
	assert.Equal(t, "cel", result.ABAC.Engine)
	require.Len(t, result.ABAC.Policies, 1)
	assert.Equal(t, "owner-access", result.ABAC.Policies[0].Name)

	// External
	require.NotNil(t, result.External)
	assert.True(t, result.External.Enabled)
	assert.Equal(t, "opa", result.External.Type)
	assert.Equal(t, 3*time.Second, result.External.Timeout)
	assert.False(t, result.External.FailOpen)
	require.NotNil(t, result.External.OPA)

	// Cache
	require.NotNil(t, result.Cache)
	assert.True(t, result.Cache.Enabled)
	assert.Equal(t, 5*time.Minute, result.Cache.TTL)
	assert.Equal(t, 10000, result.Cache.MaxSize)
	assert.Equal(t, "redis", result.Cache.Type)
}

func TestConvertFromGatewayConfig_DefaultPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		defaultPolicy  string
		expectedPolicy Policy
	}{
		{
			name:           "allow policy",
			defaultPolicy:  "allow",
			expectedPolicy: PolicyAllow,
		},
		{
			name:           "deny policy",
			defaultPolicy:  "deny",
			expectedPolicy: PolicyDeny,
		},
		{
			name:           "empty policy",
			defaultPolicy:  "",
			expectedPolicy: Policy(""),
		},
		{
			name:           "custom policy string",
			defaultPolicy:  "custom",
			expectedPolicy: Policy("custom"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: tt.defaultPolicy,
				RBAC: &config.RBACConfig{
					Enabled: true,
					Policies: []config.RBACPolicyConfig{
						{
							Name:      "placeholder",
							Roles:     []string{"user"},
							Resources: []string{"/*"},
							Actions:   []string{"GET"},
						},
					},
				},
			}

			result, err := ConvertFromGatewayConfig(cfg)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedPolicy, result.DefaultPolicy)
		})
	}
}

func TestConvertFromGatewayConfig_SkipPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		skipPaths     []string
		expectedPaths []string
	}{
		{
			name:          "multiple paths",
			skipPaths:     []string{"/health", "/metrics", "/api/public/*"},
			expectedPaths: []string{"/health", "/metrics", "/api/public/*"},
		},
		{
			name:          "single path",
			skipPaths:     []string{"/health"},
			expectedPaths: []string{"/health"},
		},
		{
			name:          "empty paths",
			skipPaths:     []string{},
			expectedPaths: []string{},
		},
		{
			name:          "nil paths",
			skipPaths:     nil,
			expectedPaths: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.AuthorizationConfig{
				Enabled:   true,
				SkipPaths: tt.skipPaths,
			}

			result, err := ConvertFromGatewayConfig(cfg)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedPaths, result.SkipPaths)
		})
	}
}

func TestConvertFromGatewayConfig_RBACPolicies(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled: true,
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "admin-full-access",
					Roles:     []string{"admin", "super-admin"},
					Resources: []string{"/api/*", "/admin/*"},
					Actions:   []string{"GET", "POST", "PUT", "DELETE"},
					Effect:    "allow",
					Priority:  100,
				},
				{
					Name:      "viewer-read-only",
					Roles:     []string{"viewer"},
					Resources: []string{"/api/*"},
					Actions:   []string{"GET"},
					Effect:    "allow",
					Priority:  50,
				},
				{
					Name:      "deny-sensitive",
					Roles:     []string{"viewer", "editor"},
					Resources: []string{"/api/secrets/*"},
					Actions:   []string{"*"},
					Effect:    "deny",
					Priority:  200,
				},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.RBAC)
	require.Len(t, result.RBAC.Policies, 3)

	// Verify first policy
	p0 := result.RBAC.Policies[0]
	assert.Equal(t, "admin-full-access", p0.Name)
	assert.Equal(t, []string{"admin", "super-admin"}, p0.Roles)
	assert.Equal(t, []string{"/api/*", "/admin/*"}, p0.Resources)
	assert.Equal(t, []string{"GET", "POST", "PUT", "DELETE"}, p0.Actions)
	assert.Equal(t, rbac.EffectAllow, p0.Effect)
	assert.Equal(t, 100, p0.Priority)

	// Verify second policy
	p1 := result.RBAC.Policies[1]
	assert.Equal(t, "viewer-read-only", p1.Name)
	assert.Equal(t, []string{"viewer"}, p1.Roles)
	assert.Equal(t, []string{"/api/*"}, p1.Resources)
	assert.Equal(t, []string{"GET"}, p1.Actions)
	assert.Equal(t, rbac.EffectAllow, p1.Effect)
	assert.Equal(t, 50, p1.Priority)

	// Verify third policy
	p2 := result.RBAC.Policies[2]
	assert.Equal(t, "deny-sensitive", p2.Name)
	assert.Equal(t, []string{"viewer", "editor"}, p2.Roles)
	assert.Equal(t, []string{"/api/secrets/*"}, p2.Resources)
	assert.Equal(t, []string{"*"}, p2.Actions)
	assert.Equal(t, rbac.EffectDeny, p2.Effect)
	assert.Equal(t, 200, p2.Priority)
}

func TestConvertFromGatewayConfig_ABACPolicies(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled: true,
		ABAC: &config.ABACConfig{
			Enabled: true,
			Policies: []config.ABACPolicyConfig{
				{
					Name:       "owner-only",
					Expression: "subject.id == resource.owner_id",
					Resources:  []string{"/api/documents/*"},
					Actions:    []string{"PUT", "DELETE"},
					Effect:     "allow",
					Priority:   10,
				},
				{
					Name:       "department-access",
					Expression: "subject.department == resource.department",
					Resources:  []string{"/api/reports/*"},
					Actions:    []string{"GET"},
					Effect:     "allow",
					Priority:   5,
				},
				{
					Name:       "deny-after-hours",
					Expression: "request.time.getHours() < 8 || request.time.getHours() > 20",
					Resources:  []string{"/api/sensitive/*"},
					Actions:    []string{"*"},
					Effect:     "deny",
					Priority:   100,
				},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.ABAC)
	assert.True(t, result.ABAC.Enabled)
	assert.Equal(t, "cel", result.ABAC.Engine)
	require.Len(t, result.ABAC.Policies, 3)

	// Verify first policy
	p0 := result.ABAC.Policies[0]
	assert.Equal(t, "owner-only", p0.Name)
	assert.Equal(t, "subject.id == resource.owner_id", p0.Expression)
	assert.Equal(t, []string{"/api/documents/*"}, p0.Resources)
	assert.Equal(t, []string{"PUT", "DELETE"}, p0.Actions)
	assert.Equal(t, abac.EffectAllow, p0.Effect)
	assert.Equal(t, 10, p0.Priority)

	// Verify second policy
	p1 := result.ABAC.Policies[1]
	assert.Equal(t, "department-access", p1.Name)
	assert.Equal(t, "subject.department == resource.department", p1.Expression)
	assert.Equal(t, []string{"/api/reports/*"}, p1.Resources)
	assert.Equal(t, []string{"GET"}, p1.Actions)
	assert.Equal(t, abac.EffectAllow, p1.Effect)
	assert.Equal(t, 5, p1.Priority)

	// Verify third policy
	p2 := result.ABAC.Policies[2]
	assert.Equal(t, "deny-after-hours", p2.Name)
	assert.Equal(t, "request.time.getHours() < 8 || request.time.getHours() > 20", p2.Expression)
	assert.Equal(t, []string{"/api/sensitive/*"}, p2.Resources)
	assert.Equal(t, []string{"*"}, p2.Actions)
	assert.Equal(t, abac.EffectDeny, p2.Effect)
	assert.Equal(t, 100, p2.Priority)
}

func TestConvertFromGatewayConfig_RoleHierarchy(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled: true,
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "basic",
					Roles:     []string{"viewer"},
					Resources: []string{"/*"},
					Actions:   []string{"GET"},
				},
			},
			RoleHierarchy: map[string][]string{
				"admin":   {"editor", "viewer"},
				"editor":  {"viewer"},
				"viewer":  {},
				"manager": {"editor"},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.RBAC)
	require.NotNil(t, result.RBAC.RoleHierarchy)
	assert.Equal(t, []string{"editor", "viewer"}, result.RBAC.RoleHierarchy["admin"])
	assert.Equal(t, []string{"viewer"}, result.RBAC.RoleHierarchy["editor"])
	assert.Equal(t, []string{}, result.RBAC.RoleHierarchy["viewer"])
	assert.Equal(t, []string{"editor"}, result.RBAC.RoleHierarchy["manager"])
}

// TestConvertFromGatewayConfig_TableDriven covers various combinations in a table-driven style.
func TestConvertFromGatewayConfig_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cfg            *config.AuthorizationConfig
		expectNil      bool
		expectEnabled  bool
		expectRBAC     bool
		expectABAC     bool
		expectExternal bool
		expectCache    bool
		expectSkipLen  int
	}{
		{
			name:      "nil config",
			cfg:       nil,
			expectNil: true,
		},
		{
			name:      "disabled config",
			cfg:       &config.AuthorizationConfig{Enabled: false},
			expectNil: true,
		},
		{
			name: "enabled with RBAC",
			cfg: &config.AuthorizationConfig{
				Enabled: true,
				RBAC: &config.RBACConfig{
					Enabled: true,
					Policies: []config.RBACPolicyConfig{
						{Name: "p1", Roles: []string{"r"}, Resources: []string{"/*"}, Actions: []string{"GET"}},
					},
				},
			},
			expectEnabled: true,
			expectRBAC:    true,
		},
		{
			name: "enabled with ABAC",
			cfg: &config.AuthorizationConfig{
				Enabled: true,
				ABAC: &config.ABACConfig{
					Enabled: true,
					Policies: []config.ABACPolicyConfig{
						{Name: "p1", Expression: "true"},
					},
				},
			},
			expectEnabled: true,
			expectABAC:    true,
		},
		{
			name: "enabled with External",
			cfg: &config.AuthorizationConfig{
				Enabled: true,
				External: &config.ExternalAuthzConfig{
					Enabled: true,
					OPA: &config.OPAAuthzConfig{
						URL: "http://opa:8181",
					},
				},
			},
			expectEnabled:  true,
			expectExternal: true,
		},
		{
			name: "enabled with Cache",
			cfg: &config.AuthorizationConfig{
				Enabled: true,
				Cache: &config.AuthzCacheConfig{
					Enabled: true,
					TTL:     config.Duration(5 * time.Minute),
					MaxSize: 1000,
				},
			},
			expectEnabled: true,
			expectCache:   true,
		},
		{
			name: "enabled with skip paths",
			cfg: &config.AuthorizationConfig{
				Enabled:   true,
				SkipPaths: []string{"/health", "/ready", "/metrics"},
			},
			expectEnabled: true,
			expectSkipLen: 3,
		},
		{
			name: "disabled RBAC not converted",
			cfg: &config.AuthorizationConfig{
				Enabled: true,
				RBAC: &config.RBACConfig{
					Enabled: false,
					Policies: []config.RBACPolicyConfig{
						{Name: "p1", Roles: []string{"r"}, Resources: []string{"/*"}, Actions: []string{"GET"}},
					},
				},
			},
			expectEnabled: true,
			expectRBAC:    false,
		},
		{
			name: "disabled ABAC not converted",
			cfg: &config.AuthorizationConfig{
				Enabled: true,
				ABAC: &config.ABACConfig{
					Enabled: false,
					Policies: []config.ABACPolicyConfig{
						{Name: "p1", Expression: "true"},
					},
				},
			},
			expectEnabled: true,
			expectABAC:    false,
		},
		{
			name: "disabled External not converted",
			cfg: &config.AuthorizationConfig{
				Enabled: true,
				External: &config.ExternalAuthzConfig{
					Enabled: false,
				},
			},
			expectEnabled:  true,
			expectExternal: false,
		},
		{
			name: "disabled Cache not converted",
			cfg: &config.AuthorizationConfig{
				Enabled: true,
				Cache: &config.AuthzCacheConfig{
					Enabled: false,
				},
			},
			expectEnabled: true,
			expectCache:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ConvertFromGatewayConfig(tt.cfg)
			assert.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.expectEnabled, result.Enabled)
			assert.Equal(t, tt.expectRBAC, result.RBAC != nil)
			assert.Equal(t, tt.expectABAC, result.ABAC != nil)
			assert.Equal(t, tt.expectExternal, result.External != nil)
			assert.Equal(t, tt.expectCache, result.Cache != nil)
			assert.Len(t, result.SkipPaths, tt.expectSkipLen)
		})
	}
}

// TestConvertRBACConfig_ReturnsCorrectType verifies the return type.
func TestConvertRBACConfig_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	src := &config.RBACConfig{
		Enabled: true,
		Policies: []config.RBACPolicyConfig{
			{Name: "p1", Roles: []string{"r"}, Resources: []string{"/*"}, Actions: []string{"GET"}},
		},
	}

	result := convertRBACConfig(src)
	assert.IsType(t, &rbac.Config{}, result)
}

// TestConvertABACConfig_ReturnsCorrectType verifies the return type.
func TestConvertABACConfig_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	src := &config.ABACConfig{
		Enabled: true,
		Policies: []config.ABACPolicyConfig{
			{Name: "p1", Expression: "true"},
		},
	}

	result := convertABACConfig(src)
	assert.IsType(t, &abac.Config{}, result)
}

// TestConvertExternalConfig_ReturnsCorrectType verifies the return type.
func TestConvertExternalConfig_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	src := &config.ExternalAuthzConfig{
		Enabled: true,
		OPA: &config.OPAAuthzConfig{
			URL: "http://opa:8181",
		},
	}

	result := convertExternalConfig(src)
	assert.IsType(t, &external.Config{}, result)
}

// TestConvertCacheConfig_ReturnsCorrectType verifies the return type.
func TestConvertCacheConfig_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	src := &config.AuthzCacheConfig{
		Enabled: true,
		TTL:     config.Duration(5 * time.Minute),
		MaxSize: 1000,
	}

	result := convertCacheConfig(src)
	assert.IsType(t, &CacheConfig{}, result)
}

// TestConvertRBACConfig_NoPolicies verifies conversion with no policies.
func TestConvertRBACConfig_NoPolicies(t *testing.T) {
	t.Parallel()

	src := &config.RBACConfig{
		Enabled: true,
	}

	result := convertRBACConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Empty(t, result.Policies)
}

// TestConvertRBACConfig_NoRoleHierarchy verifies conversion with no role hierarchy.
func TestConvertRBACConfig_NoRoleHierarchy(t *testing.T) {
	t.Parallel()

	src := &config.RBACConfig{
		Enabled: true,
		Policies: []config.RBACPolicyConfig{
			{Name: "p1", Roles: []string{"r"}, Resources: []string{"/*"}, Actions: []string{"GET"}},
		},
	}

	result := convertRBACConfig(src)
	require.NotNil(t, result)
	assert.Nil(t, result.RoleHierarchy)
}

// TestConvertABACConfig_NoPolicies verifies conversion with no policies.
func TestConvertABACConfig_NoPolicies(t *testing.T) {
	t.Parallel()

	src := &config.ABACConfig{
		Enabled: true,
	}

	result := convertABACConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, "cel", result.Engine)
	assert.Empty(t, result.Policies)
}

// TestConvertExternalConfig_NoOPA verifies conversion without OPA config.
func TestConvertExternalConfig_NoOPA(t *testing.T) {
	t.Parallel()

	src := &config.ExternalAuthzConfig{
		Enabled:  true,
		Timeout:  config.Duration(2 * time.Second),
		FailOpen: false,
	}

	result := convertExternalConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, "opa", result.Type)
	assert.Equal(t, 2*time.Second, result.Timeout)
	assert.False(t, result.FailOpen)
	assert.Nil(t, result.OPA)
}

// TestConvertExternalConfig_ZeroTimeout verifies zero timeout conversion.
func TestConvertExternalConfig_ZeroTimeout(t *testing.T) {
	t.Parallel()

	src := &config.ExternalAuthzConfig{
		Enabled: true,
		Timeout: 0,
	}

	result := convertExternalConfig(src)
	require.NotNil(t, result)
	assert.Equal(t, time.Duration(0), result.Timeout)
}

// TestConvertCacheConfig_ZeroValues verifies zero value conversion.
func TestConvertCacheConfig_ZeroValues(t *testing.T) {
	t.Parallel()

	src := &config.AuthzCacheConfig{
		Enabled: true,
		TTL:     0,
		MaxSize: 0,
		Type:    "",
	}

	result := convertCacheConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, time.Duration(0), result.TTL)
	assert.Equal(t, 0, result.MaxSize)
	assert.Equal(t, "", result.Type)
}

// TestConvertFromGatewayConfig_DisabledWithContent verifies disabled config with content returns nil.
func TestConvertFromGatewayConfig_DisabledWithContent(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled:       false,
		DefaultPolicy: "deny",
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{Name: "p1", Roles: []string{"r"}, Resources: []string{"/*"}, Actions: []string{"GET"}},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

// TestConvertExternalConfig_OPAWithEmptyHeaders verifies OPA with empty headers.
func TestConvertExternalConfig_OPAWithEmptyHeaders(t *testing.T) {
	t.Parallel()

	src := &config.ExternalAuthzConfig{
		Enabled: true,
		OPA: &config.OPAAuthzConfig{
			URL:     "http://opa:8181",
			Policy:  "authz",
			Headers: map[string]string{},
		},
	}

	result := convertExternalConfig(src)
	require.NotNil(t, result)
	require.NotNil(t, result.OPA)
	assert.Equal(t, "http://opa:8181", result.OPA.URL)
	assert.Equal(t, "authz", result.OPA.Policy)
	assert.Empty(t, result.OPA.Headers)
}

// TestConvertRBACConfig_PolicyEffectMapping verifies effect string to PolicyEffect conversion.
func TestConvertRBACConfig_PolicyEffectMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		effect         string
		expectedEffect rbac.PolicyEffect
	}{
		{
			name:           "allow effect",
			effect:         "allow",
			expectedEffect: rbac.EffectAllow,
		},
		{
			name:           "deny effect",
			effect:         "deny",
			expectedEffect: rbac.EffectDeny,
		},
		{
			name:           "empty effect",
			effect:         "",
			expectedEffect: rbac.PolicyEffect(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src := &config.RBACConfig{
				Enabled: true,
				Policies: []config.RBACPolicyConfig{
					{
						Name:      "test",
						Roles:     []string{"role"},
						Resources: []string{"/*"},
						Actions:   []string{"GET"},
						Effect:    tt.effect,
					},
				},
			}

			result := convertRBACConfig(src)
			require.NotNil(t, result)
			require.Len(t, result.Policies, 1)
			assert.Equal(t, tt.expectedEffect, result.Policies[0].Effect)
		})
	}
}

// TestConvertABACConfig_PolicyEffectMapping verifies effect string to PolicyEffect conversion.
func TestConvertABACConfig_PolicyEffectMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		effect         string
		expectedEffect abac.PolicyEffect
	}{
		{
			name:           "allow effect",
			effect:         "allow",
			expectedEffect: abac.EffectAllow,
		},
		{
			name:           "deny effect",
			effect:         "deny",
			expectedEffect: abac.EffectDeny,
		},
		{
			name:           "empty effect",
			effect:         "",
			expectedEffect: abac.PolicyEffect(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src := &config.ABACConfig{
				Enabled: true,
				Policies: []config.ABACPolicyConfig{
					{
						Name:       "test",
						Expression: "true",
						Effect:     tt.effect,
					},
				},
			}

			result := convertABACConfig(src)
			require.NotNil(t, result)
			require.Len(t, result.Policies, 1)
			assert.Equal(t, tt.expectedEffect, result.Policies[0].Effect)
		})
	}
}

// TestConvertCacheConfig_RedisType verifies redis cache type conversion.
func TestConvertCacheConfig_RedisType(t *testing.T) {
	t.Parallel()

	src := &config.AuthzCacheConfig{
		Enabled: true,
		TTL:     config.Duration(10 * time.Minute),
		MaxSize: 50000,
		Type:    "redis",
	}

	result := convertCacheConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, 10*time.Minute, result.TTL)
	assert.Equal(t, 50000, result.MaxSize)
	assert.Equal(t, "redis", result.Type)
}

// TestConvertFromGatewayConfig_NilSubConfigs verifies nil sub-configs are handled.
func TestConvertFromGatewayConfig_NilSubConfigs(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthorizationConfig{
		Enabled:  true,
		RBAC:     nil,
		ABAC:     nil,
		External: nil,
		Cache:    nil,
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Nil(t, result.RBAC)
	assert.Nil(t, result.ABAC)
	assert.Nil(t, result.External)
	assert.Nil(t, result.Cache)
}

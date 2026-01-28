package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:      "test-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"*"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid policy - missing name",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"*"},
					},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "invalid policy - missing roles/permissions/groups",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:      "test-policy",
						Resources: []string{"/api/*"},
						Actions:   []string{"*"},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one of roles, permissions, or groups is required",
		},
		{
			name: "invalid policy - missing resources",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:    "test-policy",
						Roles:   []string{"admin"},
						Actions: []string{"*"},
					},
				},
			},
			wantErr: true,
			errMsg:  "resources is required",
		},
		{
			name: "invalid policy - missing actions",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:      "test-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
					},
				},
			},
			wantErr: true,
			errMsg:  "actions is required",
		},
		{
			name: "invalid policy - invalid effect",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:      "test-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"*"},
						Effect:    "invalid",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid effect",
		},
		{
			name: "valid role hierarchy",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:      "test-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"*"},
					},
				},
				RoleHierarchy: map[string][]string{
					"admin":      {"user"},
					"superadmin": {"admin"},
				},
			},
			wantErr: false,
		},
		{
			name: "cyclic role hierarchy",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:      "test-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"*"},
					},
				},
				RoleHierarchy: map[string][]string{
					"admin":      {"superadmin"},
					"superadmin": {"admin"}, // Cycle!
				},
			},
			wantErr: true,
			errMsg:  "cycle detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPolicy_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid policy with roles",
			policy: Policy{
				Name:      "test-policy",
				Roles:     []string{"admin"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
			},
			wantErr: false,
		},
		{
			name: "valid policy with permissions",
			policy: Policy{
				Name:        "test-policy",
				Permissions: []string{"users:read"},
				Resources:   []string{"/api/*"},
				Actions:     []string{"GET"},
			},
			wantErr: false,
		},
		{
			name: "valid policy with groups",
			policy: Policy{
				Name:      "test-policy",
				Groups:    []string{"engineering"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
			},
			wantErr: false,
		},
		{
			name: "valid policy with allow effect",
			policy: Policy{
				Name:      "test-policy",
				Roles:     []string{"admin"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
			},
			wantErr: false,
		},
		{
			name: "valid policy with deny effect",
			policy: Policy{
				Name:      "test-policy",
				Roles:     []string{"admin"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
				Effect:    EffectDeny,
			},
			wantErr: false,
		},
		{
			name: "missing name",
			policy: Policy{
				Roles:     []string{"admin"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "missing roles/permissions/groups",
			policy: Policy{
				Name:      "test-policy",
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
			},
			wantErr: true,
			errMsg:  "at least one of roles, permissions, or groups is required",
		},
		{
			name: "missing resources",
			policy: Policy{
				Name:    "test-policy",
				Roles:   []string{"admin"},
				Actions: []string{"*"},
			},
			wantErr: true,
			errMsg:  "resources is required",
		},
		{
			name: "missing actions",
			policy: Policy{
				Name:      "test-policy",
				Roles:     []string{"admin"},
				Resources: []string{"/api/*"},
			},
			wantErr: true,
			errMsg:  "actions is required",
		},
		{
			name: "invalid effect",
			policy: Policy{
				Name:      "test-policy",
				Roles:     []string{"admin"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
				Effect:    "invalid",
			},
			wantErr: true,
			errMsg:  "invalid effect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRoleHierarchy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		hierarchy map[string][]string
		wantErr   bool
	}{
		{
			name: "valid hierarchy",
			hierarchy: map[string][]string{
				"admin":      {"user"},
				"superadmin": {"admin"},
			},
			wantErr: false,
		},
		{
			name:      "empty hierarchy",
			hierarchy: map[string][]string{},
			wantErr:   false,
		},
		{
			name: "simple cycle",
			hierarchy: map[string][]string{
				"a": {"b"},
				"b": {"a"},
			},
			wantErr: true,
		},
		{
			name: "complex cycle",
			hierarchy: map[string][]string{
				"a": {"b"},
				"b": {"c"},
				"c": {"a"},
			},
			wantErr: true,
		},
		{
			name: "self-reference",
			hierarchy: map[string][]string{
				"a": {"a"},
			},
			wantErr: true,
		},
		{
			name: "diamond hierarchy (no cycle)",
			hierarchy: map[string][]string{
				"admin":      {"reader", "writer"},
				"superadmin": {"admin"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateRoleHierarchy(tt.hierarchy)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	assert.False(t, config.Enabled)
	assert.NotNil(t, config.ClaimMapping)
	assert.Equal(t, "roles", config.ClaimMapping.Roles)
	assert.Equal(t, "permissions", config.ClaimMapping.Permissions)
	assert.Equal(t, "groups", config.ClaimMapping.Groups)
}

func TestPolicy_GetEffectiveEffect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   Policy
		expected PolicyEffect
	}{
		{
			name: "explicit allow",
			policy: Policy{
				Effect: EffectAllow,
			},
			expected: EffectAllow,
		},
		{
			name: "explicit deny",
			policy: Policy{
				Effect: EffectDeny,
			},
			expected: EffectDeny,
		},
		{
			name:     "default (empty) is allow",
			policy:   Policy{},
			expected: EffectAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.policy.GetEffectiveEffect()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPolicyEffectConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, PolicyEffect("allow"), EffectAllow)
	assert.Equal(t, PolicyEffect("deny"), EffectDeny)
}

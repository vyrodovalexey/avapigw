package abac

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
				Engine:  "cel",
				Policies: []Policy{
					{
						Name:       "test-policy",
						Expression: "true",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with default engine",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:       "test-policy",
						Expression: "true",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid engine",
			config: &Config{
				Enabled: true,
				Engine:  "invalid",
			},
			wantErr: true,
			errMsg:  "invalid engine",
		},
		{
			name: "invalid policy - missing name",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Expression: "true",
					},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "invalid policy - missing expression",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name: "test-policy",
					},
				},
			},
			wantErr: true,
			errMsg:  "expression is required",
		},
		{
			name: "invalid policy - invalid effect",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:       "test-policy",
						Expression: "true",
						Effect:     "invalid",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid effect",
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
			name: "valid policy",
			policy: Policy{
				Name:       "test-policy",
				Expression: "true",
			},
			wantErr: false,
		},
		{
			name: "valid policy with allow effect",
			policy: Policy{
				Name:       "test-policy",
				Expression: "true",
				Effect:     EffectAllow,
			},
			wantErr: false,
		},
		{
			name: "valid policy with deny effect",
			policy: Policy{
				Name:       "test-policy",
				Expression: "true",
				Effect:     EffectDeny,
			},
			wantErr: false,
		},
		{
			name: "valid policy with resources and actions",
			policy: Policy{
				Name:       "test-policy",
				Expression: "true",
				Resources:  []string{"/api/*"},
				Actions:    []string{"GET", "POST"},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			policy: Policy{
				Expression: "true",
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "missing expression",
			policy: Policy{
				Name: "test-policy",
			},
			wantErr: true,
			errMsg:  "expression is required",
		},
		{
			name: "invalid effect",
			policy: Policy{
				Name:       "test-policy",
				Expression: "true",
				Effect:     "invalid",
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

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	assert.False(t, config.Enabled)
	assert.Equal(t, "cel", config.Engine)
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

func TestConfig_GetEffectiveEngine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name: "explicit engine",
			config: &Config{
				Engine: "cel",
			},
			expected: "cel",
		},
		{
			name:     "default engine",
			config:   &Config{},
			expected: "cel",
		},
		{
			name: "empty engine uses default",
			config: &Config{
				Engine: "",
			},
			expected: "cel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.GetEffectiveEngine()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPolicyEffectConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, PolicyEffect("allow"), EffectAllow)
	assert.Equal(t, PolicyEffect("deny"), EffectDeny)
}

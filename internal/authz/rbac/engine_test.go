package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewEngine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid config with policies",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:      "admin-policy",
						Roles:     []string{"admin"},
						Resources: []string{"*"},
						Actions:   []string{"*"},
						Effect:    EffectAllow,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid policy",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name: "", // Invalid - missing name
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			engine, err := NewEngine(tt.config,
				WithEngineLogger(observability.NopLogger()),
			)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, engine)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, engine)
			}
		})
	}
}

func TestEngine_Authorize_BasicRoles(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "admin-policy",
				Roles:     []string{"admin"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
			},
			{
				Name:      "user-read-policy",
				Roles:     []string{"user"},
				Resources: []string{"/api/users"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	tests := []struct {
		name     string
		request  *Request
		expected bool
	}{
		{
			name: "admin can access any resource",
			request: &Request{
				Subject:  "admin-user",
				Roles:    []string{"admin"},
				Resource: "/api/users",
				Action:   "DELETE",
			},
			expected: true,
		},
		{
			name: "user can read users",
			request: &Request{
				Subject:  "regular-user",
				Roles:    []string{"user"},
				Resource: "/api/users",
				Action:   "GET",
			},
			expected: true,
		},
		{
			name: "user cannot delete users",
			request: &Request{
				Subject:  "regular-user",
				Roles:    []string{"user"},
				Resource: "/api/users",
				Action:   "DELETE",
			},
			expected: false,
		},
		{
			name: "no matching role",
			request: &Request{
				Subject:  "guest",
				Roles:    []string{"guest"},
				Resource: "/api/users",
				Action:   "GET",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, err := engine.Authorize(context.Background(), tt.request)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
		})
	}
}

func TestEngine_Authorize_Permissions(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:        "read-users-policy",
				Permissions: []string{"users:read"},
				Resources:   []string{"/api/users"},
				Actions:     []string{"GET"},
				Effect:      EffectAllow,
			},
			{
				Name:        "write-users-policy",
				Permissions: []string{"users:write"},
				Resources:   []string{"/api/users"},
				Actions:     []string{"POST", "PUT", "DELETE"},
				Effect:      EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	tests := []struct {
		name     string
		request  *Request
		expected bool
	}{
		{
			name: "has read permission",
			request: &Request{
				Subject:     "user1",
				Permissions: []string{"users:read"},
				Resource:    "/api/users",
				Action:      "GET",
			},
			expected: true,
		},
		{
			name: "has write permission",
			request: &Request{
				Subject:     "user1",
				Permissions: []string{"users:write"},
				Resource:    "/api/users",
				Action:      "POST",
			},
			expected: true,
		},
		{
			name: "missing permission",
			request: &Request{
				Subject:     "user1",
				Permissions: []string{"users:read"},
				Resource:    "/api/users",
				Action:      "DELETE",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, err := engine.Authorize(context.Background(), tt.request)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
		})
	}
}

func TestEngine_Authorize_Groups(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "engineering-policy",
				Groups:    []string{"engineering"},
				Resources: []string{"/api/code/*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	tests := []struct {
		name     string
		request  *Request
		expected bool
	}{
		{
			name: "in engineering group",
			request: &Request{
				Subject:  "dev1",
				Groups:   []string{"engineering"},
				Resource: "/api/code/repo",
				Action:   "GET",
			},
			expected: true,
		},
		{
			name: "not in engineering group",
			request: &Request{
				Subject:  "sales1",
				Groups:   []string{"sales"},
				Resource: "/api/code/repo",
				Action:   "GET",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, err := engine.Authorize(context.Background(), tt.request)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
		})
	}
}

func TestEngine_Authorize_WildcardResource(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "all-resources",
				Roles:     []string{"superadmin"},
				Resources: []string{"*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  "superadmin",
		Roles:    []string{"superadmin"},
		Resource: "/any/resource/path",
		Action:   "ANY_ACTION",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngine_Authorize_PrefixResource(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "api-prefix",
				Roles:     []string{"api-user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	tests := []struct {
		name     string
		resource string
		expected bool
	}{
		{"matches prefix", "/api/users", true},
		{"matches prefix nested", "/api/users/123", true},
		{"does not match prefix", "/admin/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, err := engine.Authorize(context.Background(), &Request{
				Subject:  "user1",
				Roles:    []string{"api-user"},
				Resource: tt.resource,
				Action:   "GET",
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
		})
	}
}

func TestEngine_Authorize_RegexResource(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "user-resource",
				Roles:     []string{"user"},
				Resources: []string{"~/api/users/[0-9]+"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	tests := []struct {
		name     string
		resource string
		expected bool
	}{
		{"matches regex", "/api/users/123", true},
		{"matches regex long id", "/api/users/999999", true},
		{"does not match - non-numeric", "/api/users/abc", false},
		{"does not match - different path", "/api/posts/123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, err := engine.Authorize(context.Background(), &Request{
				Subject:  "user1",
				Roles:    []string{"user"},
				Resource: tt.resource,
				Action:   "GET",
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
		})
	}
}

func TestEngine_Authorize_DenyEffect(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "deny-delete",
				Roles:     []string{"user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"DELETE"},
				Effect:    EffectDeny,
				Priority:  100, // Higher priority
			},
			{
				Name:      "allow-all",
				Roles:     []string{"user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
				Priority:  50,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// DELETE should be denied (higher priority deny)
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  "user1",
		Roles:    []string{"user"},
		Resource: "/api/users",
		Action:   "DELETE",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// GET should be allowed
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  "user1",
		Roles:    []string{"user"},
		Resource: "/api/users",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngine_Authorize_Priority(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "low-priority-allow",
				Roles:     []string{"user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
				Priority:  10,
			},
			{
				Name:      "high-priority-deny",
				Roles:     []string{"user"},
				Resources: []string{"/api/admin/*"},
				Actions:   []string{"*"},
				Effect:    EffectDeny,
				Priority:  100,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Admin path should be denied (higher priority)
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  "user1",
		Roles:    []string{"user"},
		Resource: "/api/admin/settings",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Regular path should be allowed
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  "user1",
		Roles:    []string{"user"},
		Resource: "/api/users",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngine_Authorize_RoleHierarchy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "user-policy",
				Roles:     []string{"user"},
				Resources: []string{"/api/profile"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
			{
				Name:      "admin-policy",
				Roles:     []string{"admin"},
				Resources: []string{"/api/admin/*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
			},
		},
		RoleHierarchy: map[string][]string{
			"admin":      {"user"},  // admin inherits from user
			"superadmin": {"admin"}, // superadmin inherits from admin
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Admin should have user permissions
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  "admin1",
		Roles:    []string{"admin"},
		Resource: "/api/profile",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Superadmin should have admin and user permissions
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  "superadmin1",
		Roles:    []string{"superadmin"},
		Resource: "/api/admin/settings",
		Action:   "DELETE",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngine_Authorize_Conditions(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "tenant-policy",
				Roles:     []string{"user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
				Conditions: []Condition{
					{
						Key:      "tenant",
						Operator: "eq",
						Value:    "acme",
					},
				},
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Matching tenant
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  "user1",
		Roles:    []string{"user"},
		Resource: "/api/users",
		Action:   "GET",
		Context: map[string]interface{}{
			"tenant": "acme",
		},
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Non-matching tenant
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  "user1",
		Roles:    []string{"user"},
		Resource: "/api/users",
		Action:   "GET",
		Context: map[string]interface{}{
			"tenant": "other",
		},
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestEngine_Authorize_ConditionOperators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		condition Condition
		context   map[string]interface{}
		expected  bool
	}{
		{
			name:      "eq operator - match",
			condition: Condition{Key: "env", Operator: "eq", Value: "prod"},
			context:   map[string]interface{}{"env": "prod"},
			expected:  true,
		},
		{
			name:      "eq operator - no match",
			condition: Condition{Key: "env", Operator: "eq", Value: "prod"},
			context:   map[string]interface{}{"env": "dev"},
			expected:  false,
		},
		{
			name:      "ne operator - match",
			condition: Condition{Key: "env", Operator: "ne", Value: "prod"},
			context:   map[string]interface{}{"env": "dev"},
			expected:  true,
		},
		{
			name:      "ne operator - no match",
			condition: Condition{Key: "env", Operator: "ne", Value: "prod"},
			context:   map[string]interface{}{"env": "prod"},
			expected:  false,
		},
		{
			name:      "in operator - match",
			condition: Condition{Key: "env", Operator: "in", Value: []interface{}{"dev", "staging", "prod"}},
			context:   map[string]interface{}{"env": "staging"},
			expected:  true,
		},
		{
			name:      "in operator - no match",
			condition: Condition{Key: "env", Operator: "in", Value: []interface{}{"dev", "staging"}},
			context:   map[string]interface{}{"env": "prod"},
			expected:  false,
		},
		{
			name:      "contains operator - match",
			condition: Condition{Key: "path", Operator: "contains", Value: "admin"},
			context:   map[string]interface{}{"path": "/api/admin/users"},
			expected:  true,
		},
		{
			name:      "contains operator - no match",
			condition: Condition{Key: "path", Operator: "contains", Value: "admin"},
			context:   map[string]interface{}{"path": "/api/users"},
			expected:  false,
		},
		{
			name:      "missing key",
			condition: Condition{Key: "missing", Operator: "eq", Value: "value"},
			context:   map[string]interface{}{"other": "value"},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:       "test-policy",
						Roles:      []string{"user"},
						Resources:  []string{"*"},
						Actions:    []string{"*"},
						Effect:     EffectAllow,
						Conditions: []Condition{tt.condition},
					},
				},
			}

			engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
			require.NoError(t, err)

			decision, err := engine.Authorize(context.Background(), &Request{
				Subject:  "user1",
				Roles:    []string{"user"},
				Resource: "/test",
				Action:   "GET",
				Context:  tt.context,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
		})
	}
}

func TestEngine_AddPolicy(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(nil, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	policy := Policy{
		Name:      "new-policy",
		Roles:     []string{"user"},
		Resources: []string{"/api/*"},
		Actions:   []string{"GET"},
		Effect:    EffectAllow,
	}

	err = engine.AddPolicy(policy)
	require.NoError(t, err)

	policies := engine.GetPolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "new-policy", policies[0].Name)
}

func TestEngine_AddPolicy_Update(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "existing-policy",
				Roles:     []string{"user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Update existing policy
	updatedPolicy := Policy{
		Name:      "existing-policy",
		Roles:     []string{"admin"},
		Resources: []string{"/admin/*"},
		Actions:   []string{"*"},
		Effect:    EffectAllow,
	}

	err = engine.AddPolicy(updatedPolicy)
	require.NoError(t, err)

	policies := engine.GetPolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, []string{"admin"}, policies[0].Roles)
}

func TestEngine_AddPolicy_Invalid(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(nil, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	invalidPolicy := Policy{
		Name: "", // Invalid - missing name
	}

	err = engine.AddPolicy(invalidPolicy)
	assert.Error(t, err)
}

func TestEngine_RemovePolicy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "policy1",
				Roles:     []string{"user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
			{
				Name:      "policy2",
				Roles:     []string{"admin"},
				Resources: []string{"/admin/*"},
				Actions:   []string{"*"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = engine.RemovePolicy("policy1")
	require.NoError(t, err)

	policies := engine.GetPolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "policy2", policies[0].Name)
}

func TestEngine_RemovePolicy_NonExistent(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(nil, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Should not error when removing non-existent policy
	err = engine.RemovePolicy("nonexistent")
	assert.NoError(t, err)
}

func TestEngine_GetPolicies(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{Name: "policy1", Roles: []string{"user"}, Resources: []string{"*"}, Actions: []string{"*"}},
			{Name: "policy2", Roles: []string{"admin"}, Resources: []string{"*"}, Actions: []string{"*"}},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	policies := engine.GetPolicies()
	assert.Len(t, policies, 2)
}

func TestEngine_Authorize_DefaultRole(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:     true,
		DefaultRole: "guest",
		Policies: []Policy{
			{
				Name:      "guest-policy",
				Roles:     []string{"guest"},
				Resources: []string{"/public/*"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Request with no roles - the default role is checked when no policy matches
	// but the request itself doesn't have the guest role, so it won't match initially
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  "anonymous",
		Roles:    []string{},
		Resource: "/public/info",
		Action:   "GET",
	})
	require.NoError(t, err)
	// The default role is used as a fallback when no policies match
	// Since the request has no roles, it checks if the default role would match
	assert.True(t, decision.Allowed)
}

func TestEngine_Authorize_ActionCaseInsensitive(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "get-policy",
				Roles:     []string{"user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Lowercase action should match
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  "user1",
		Roles:    []string{"user"},
		Resource: "/api/users",
		Action:   "get",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngine_Authorize_WildcardRole(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:      "any-role-policy",
				Roles:     []string{"*"},
				Resources: []string{"/public/*"},
				Actions:   []string{"GET"},
				Effect:    EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  "anyone",
		Roles:    []string{"any-role"},
		Resource: "/public/info",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngineOptions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	metrics := NewMetrics("test")

	engine, err := NewEngine(nil,
		WithEngineLogger(logger),
		WithEngineMetrics(metrics),
	)
	require.NoError(t, err)
	assert.NotNil(t, engine)
}

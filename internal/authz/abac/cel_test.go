package abac

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
						Name:       "admin-policy",
						Expression: `subject.roles.exists(r, r == "admin")`,
						Effect:     EffectAllow,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid CEL expression",
			config: &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:       "invalid-policy",
						Expression: "invalid syntax {{{{",
					},
				},
			},
			wantErr: true,
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

func TestEngine_Authorize_SimpleExpressions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		expression string
		request    *Request
		expected   bool
	}{
		{
			name:       "always true",
			expression: "true",
			request: &Request{
				Subject:  map[string]interface{}{"id": "user1"},
				Resource: "/api/test",
				Action:   "GET",
			},
			expected: true,
		},
		{
			name:       "always false",
			expression: "false",
			request: &Request{
				Subject:  map[string]interface{}{"id": "user1"},
				Resource: "/api/test",
				Action:   "GET",
			},
			expected: false,
		},
		{
			name:       "check action",
			expression: `action == "GET"`,
			request: &Request{
				Subject:  map[string]interface{}{"id": "user1"},
				Resource: "/api/test",
				Action:   "GET",
			},
			expected: true,
		},
		{
			name:       "check resource",
			expression: `resource.startsWith("/api/")`,
			request: &Request{
				Subject:  map[string]interface{}{"id": "user1"},
				Resource: "/api/users",
				Action:   "GET",
			},
			expected: true,
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
						Expression: tt.expression,
						Effect:     EffectAllow,
					},
				},
			}

			engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
			require.NoError(t, err)

			decision, err := engine.Authorize(context.Background(), tt.request)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
		})
	}
}

func TestEngine_Authorize_SubjectAttributes(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "admin-policy",
				Expression: `subject.role == "admin"`,
				Effect:     EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Admin user
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject: map[string]interface{}{
			"id":   "user1",
			"role": "admin",
		},
		Resource: "/api/admin",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Non-admin user
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject: map[string]interface{}{
			"id":   "user2",
			"role": "user",
		},
		Resource: "/api/admin",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestEngine_Authorize_RequestAttributes(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "internal-only",
				Expression: `request.ip.startsWith("10.") || request.ip.startsWith("192.168.")`,
				Effect:     EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Internal IP
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/internal",
		Action:   "GET",
		RequestAttrs: map[string]interface{}{
			"ip": "10.0.0.1",
		},
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// External IP
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/internal",
		Action:   "GET",
		RequestAttrs: map[string]interface{}{
			"ip": "8.8.8.8",
		},
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestEngine_Authorize_EnvironmentAttributes(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "prod-only",
				Expression: `environment.env == "production"`,
				Effect:     EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Production environment
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/test",
		Action:   "GET",
		Environment: map[string]interface{}{
			"env": "production",
		},
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Development environment
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/test",
		Action:   "GET",
		Environment: map[string]interface{}{
			"env": "development",
		},
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestEngine_Authorize_ComplexExpressions(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name: "complex-policy",
				Expression: `
					(subject.role == "admin") ||
					(subject.role == "user" && action == "GET") ||
					(subject.department == "engineering" && resource.startsWith("/api/code/"))
				`,
				Effect: EffectAllow,
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
			name: "admin can do anything",
			request: &Request{
				Subject:  map[string]interface{}{"role": "admin"},
				Resource: "/api/admin/delete",
				Action:   "DELETE",
			},
			expected: true,
		},
		{
			name: "user can GET",
			request: &Request{
				Subject:  map[string]interface{}{"role": "user"},
				Resource: "/api/users",
				Action:   "GET",
			},
			expected: true,
		},
		{
			name: "user cannot DELETE",
			request: &Request{
				Subject:  map[string]interface{}{"role": "user"},
				Resource: "/api/users",
				Action:   "DELETE",
			},
			expected: false,
		},
		{
			name: "engineering can access code",
			request: &Request{
				Subject:  map[string]interface{}{"role": "user", "department": "engineering"},
				Resource: "/api/code/repo",
				Action:   "POST",
			},
			expected: true,
		},
		{
			name: "sales cannot access code",
			request: &Request{
				Subject:  map[string]interface{}{"role": "user", "department": "sales"},
				Resource: "/api/code/repo",
				Action:   "POST",
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

func TestEngine_Authorize_IPInRange(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "internal-network",
				Expression: `ip_in_range(request.client_ip, "10.0.0.0/8")`,
				Effect:     EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// IP in range
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/internal",
		Action:   "GET",
		RequestAttrs: map[string]interface{}{
			"client_ip": "10.1.2.3",
		},
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// IP not in range
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/internal",
		Action:   "GET",
		RequestAttrs: map[string]interface{}{
			"client_ip": "192.168.1.1",
		},
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestEngine_Authorize_DenyEffect(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "deny-delete",
				Expression: `action == "DELETE"`,
				Effect:     EffectDeny,
				Priority:   100,
			},
			{
				Name:       "allow-all",
				Expression: "true",
				Effect:     EffectAllow,
				Priority:   50,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// DELETE should be denied
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/users",
		Action:   "DELETE",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// GET should be allowed
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/users",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngine_Authorize_ResourceFilter(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "api-policy",
				Expression: "true",
				Effect:     EffectAllow,
				Resources:  []string{"/api/*"},
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Matching resource
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/users",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Non-matching resource
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/admin/users",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestEngine_Authorize_ActionFilter(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "read-only",
				Expression: "true",
				Effect:     EffectAllow,
				Actions:    []string{"GET", "HEAD"},
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Matching action
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/users",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Non-matching action
	decision, err = engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/users",
		Action:   "POST",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestEngine_AddPolicy(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(nil, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	policy := Policy{
		Name:       "new-policy",
		Expression: "true",
		Effect:     EffectAllow,
	}

	err = engine.AddPolicy(policy)
	require.NoError(t, err)

	policies := engine.GetPolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "new-policy", policies[0].Name)
}

func TestEngine_AddPolicy_InvalidExpression(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(nil, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	policy := Policy{
		Name:       "invalid-policy",
		Expression: "invalid syntax {{{{",
	}

	err = engine.AddPolicy(policy)
	assert.Error(t, err)
}

func TestEngine_AddPolicy_Update(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "existing-policy",
				Expression: "false",
				Effect:     EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Update existing policy
	updatedPolicy := Policy{
		Name:       "existing-policy",
		Expression: "true",
		Effect:     EffectAllow,
	}

	err = engine.AddPolicy(updatedPolicy)
	require.NoError(t, err)

	policies := engine.GetPolicies()
	assert.Len(t, policies, 1)

	// Verify the policy was updated
	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/test",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngine_RemovePolicy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{Name: "policy1", Expression: "true", Effect: EffectAllow},
			{Name: "policy2", Expression: "true", Effect: EffectAllow},
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

	err = engine.RemovePolicy("nonexistent")
	assert.NoError(t, err)
}

func TestEngine_GetPolicies(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{Name: "policy1", Expression: "true"},
			{Name: "policy2", Expression: "true"},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	policies := engine.GetPolicies()
	assert.Len(t, policies, 2)
}

func TestEngine_Authorize_NoMatchingPolicy(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "specific-policy",
				Expression: `subject.role == "admin"`,
				Effect:     EffectAllow,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"role": "user"},
		Resource: "/api/test",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, "no matching policy", decision.Reason)
}

func TestEngine_Authorize_Priority(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Policies: []Policy{
			{
				Name:       "low-priority",
				Expression: "true",
				Effect:     EffectAllow,
				Priority:   10,
			},
			{
				Name:       "high-priority",
				Expression: "true",
				Effect:     EffectDeny,
				Priority:   100,
			},
		},
	}

	engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
	require.NoError(t, err)

	decision, err := engine.Authorize(context.Background(), &Request{
		Subject:  map[string]interface{}{"id": "user1"},
		Resource: "/api/test",
		Action:   "GET",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, "high-priority", decision.Policy)
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

func TestIPInRangeBinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ip       string
		cidr     string
		expected bool
	}{
		{"in range", "10.0.0.1", "10.0.0.0/8", true},
		{"not in range", "192.168.1.1", "10.0.0.0/8", false},
		{"exact match", "10.0.0.1", "10.0.0.1/32", true},
		{"invalid IP", "invalid", "10.0.0.0/8", false},
		{"invalid CIDR", "10.0.0.1", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				Enabled: true,
				Policies: []Policy{
					{
						Name:       "ip-check",
						Expression: `ip_in_range(request.ip, "` + tt.cidr + `")`,
						Effect:     EffectAllow,
					},
				},
			}

			engine, err := NewEngine(config, WithEngineLogger(observability.NopLogger()))
			require.NoError(t, err)

			decision, err := engine.Authorize(context.Background(), &Request{
				Subject:  map[string]interface{}{"id": "user1"},
				Resource: "/test",
				Action:   "GET",
				RequestAttrs: map[string]interface{}{
					"ip": tt.ip,
				},
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
		})
	}
}

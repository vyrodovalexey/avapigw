package authz

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockRBACEngine is a mock RBAC engine for testing.
type mockRBACEngine struct {
	decision *rbac.Decision
	err      error
	policies []rbac.Policy
}

func (m *mockRBACEngine) Authorize(_ context.Context, _ *rbac.Request) (*rbac.Decision, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.decision, nil
}

func (m *mockRBACEngine) AddPolicy(policy rbac.Policy) error {
	m.policies = append(m.policies, policy)
	return nil
}

func (m *mockRBACEngine) RemovePolicy(name string) error {
	for i, p := range m.policies {
		if p.Name == name {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockRBACEngine) GetPolicies() []rbac.Policy {
	return m.policies
}

// mockABACEngine is a mock ABAC engine for testing.
type mockABACEngine struct {
	decision *abac.Decision
	err      error
	policies []abac.Policy
}

func (m *mockABACEngine) Authorize(_ context.Context, _ *abac.Request) (*abac.Decision, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.decision, nil
}

func (m *mockABACEngine) AddPolicy(policy abac.Policy) error {
	m.policies = append(m.policies, policy)
	return nil
}

func (m *mockABACEngine) RemovePolicy(name string) error {
	for i, p := range m.policies {
		if p.Name == name {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockABACEngine) GetPolicies() []abac.Policy {
	return m.policies
}

// newNoopMetrics creates a no-op metrics for testing.
func newNoopMetrics() *Metrics {
	return &Metrics{
		evaluationTotal:         nil,
		evaluationDuration:      nil,
		decisionTotal:           nil,
		cacheHits:               nil,
		cacheMisses:             nil,
		externalRequestTotal:    nil,
		externalRequestDuration: nil,
		policyCount:             nil,
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("nil config returns error", func(t *testing.T) {
		t.Parallel()

		authorizer, err := New(nil)
		assert.Error(t, err)
		assert.Nil(t, authorizer)
	})

	t.Run("disabled config", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
		require.NoError(t, err)
		assert.NotNil(t, authorizer)
		_ = authorizer.Close()
	})

	t.Run("with RBAC engine", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:        "test-policy",
						Roles:       []string{"admin"},
						Resources:   []string{"/api/*"},
						Actions:     []string{"*"},
						Effect:      "allow",
						Description: "Test policy",
					},
				},
			},
		}

		authorizer, err := New(config,
			WithAuthorizerLogger(observability.NopLogger()),
			WithAuthorizerMetrics(newNoopMetrics()),
		)
		require.NoError(t, err)
		assert.NotNil(t, authorizer)
		_ = authorizer.Close()
	})

	t.Run("with custom RBAC engine", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
			},
		}

		mockEngine := &mockRBACEngine{
			decision: &rbac.Decision{
				Allowed: true,
				Reason:  "mock allowed",
				Policy:  "mock-policy",
			},
		}

		authorizer, err := New(config,
			WithRBACEngine(mockEngine),
			WithAuthorizerMetrics(newNoopMetrics()),
		)
		require.NoError(t, err)
		assert.NotNil(t, authorizer)
		_ = authorizer.Close()
	})

	t.Run("with decision cache", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "test-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"*"},
						Effect:    "allow",
					},
				},
			},
			Cache: &CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: 1000,
			},
		}

		authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
		require.NoError(t, err)
		assert.NotNil(t, authorizer)
		_ = authorizer.Close()
	})
}

func TestAuthorizer_Authorize_Disabled(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: false,
	}

	authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "authorization disabled", decision.Reason)
}

func TestAuthorizer_Authorize_SkipPath(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:   true,
		SkipPaths: []string{"/health", "/metrics"},
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test-policy",
					Roles:     []string{"admin"},
					Resources: []string{"/api/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
				},
			},
		},
	}

	authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
		},
		Resource: "/health",
		Action:   "GET",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "path skipped", decision.Reason)
}

func TestAuthorizer_Authorize_NoIdentity(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test-policy",
					Roles:     []string{"admin"},
					Resources: []string{"/api/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
				},
			},
		},
	}

	authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: nil,
		Resource: "/api/users",
		Action:   "GET",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoIdentity)
	assert.Nil(t, decision)
}

func TestAuthorizer_Authorize_RBAC(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
		},
	}

	mockEngine := &mockRBACEngine{
		decision: &rbac.Decision{
			Allowed: true,
			Reason:  "role admin has permission",
			Policy:  "admin-policy",
		},
	}

	authorizer, err := New(config,
		WithRBACEngine(mockEngine),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
			Roles:   []string{"admin"},
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "role admin has permission", decision.Reason)
	assert.Equal(t, "admin-policy", decision.Policy)
	assert.Equal(t, "rbac", decision.Engine)
}

func TestAuthorizer_Authorize_RBAC_Denied(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
		},
	}

	mockEngine := &mockRBACEngine{
		decision: &rbac.Decision{
			Allowed: false,
			Reason:  "no matching policy",
			Policy:  "",
		},
	}

	authorizer, err := New(config,
		WithRBACEngine(mockEngine),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
			Roles:   []string{"guest"},
		},
		Resource: "/api/admin",
		Action:   "DELETE",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	// When RBAC returns no policy match, it falls through to default policy
	assert.False(t, decision.Allowed)
}

func TestAuthorizer_Authorize_ABAC(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		ABAC: &abac.Config{
			Enabled: true,
		},
	}

	mockEngine := &mockABACEngine{
		decision: &abac.Decision{
			Allowed: true,
			Reason:  "ABAC policy matched",
			Policy:  "abac-policy",
		},
	}

	authorizer, err := New(config,
		WithABACEngine(mockEngine),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
			Email:   "user@example.com",
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "ABAC policy matched", decision.Reason)
	assert.Equal(t, "abac-policy", decision.Policy)
	assert.Equal(t, "abac", decision.Engine)
}

func TestAuthorizer_Authorize_DefaultPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		defaultPolicy Policy
		expected      bool
	}{
		{
			name:          "default deny",
			defaultPolicy: PolicyDeny,
			expected:      false,
		},
		{
			name:          "default allow",
			defaultPolicy: PolicyAllow,
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				Enabled:       true,
				DefaultPolicy: tt.defaultPolicy,
				RBAC: &rbac.Config{
					Enabled: true,
				},
			}

			// Mock engine that returns no policy match
			mockEngine := &mockRBACEngine{
				decision: &rbac.Decision{
					Allowed: false,
					Reason:  "no matching policy",
					Policy:  "",
				},
			}

			authorizer, err := New(config,
				WithRBACEngine(mockEngine),
				WithDecisionCache(NewNoopDecisionCache()),
				WithAuthorizerMetrics(newNoopMetrics()),
			)
			require.NoError(t, err)
			defer authorizer.Close()

			req := &Request{
				Identity: &auth.Identity{
					Subject: "user123",
				},
				Resource: "/api/unknown",
				Action:   "GET",
			}

			decision, err := authorizer.Authorize(context.Background(), req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decision.Allowed)
			assert.Equal(t, "default policy", decision.Reason)
			assert.Equal(t, "default", decision.Engine)
		})
	}
}

func TestAuthorizer_Authorize_Cached(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
		},
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 1000,
		},
	}

	mockEngine := &mockRBACEngine{
		decision: &rbac.Decision{
			Allowed: true,
			Reason:  "cached decision",
			Policy:  "cached-policy",
		},
	}

	authorizer, err := New(config,
		WithRBACEngine(mockEngine),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
			Roles:   []string{"admin"},
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	// First call
	decision1, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision1.Allowed)
	assert.False(t, decision1.Cached)

	// Second call should be cached
	decision2, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision2.Allowed)
	assert.True(t, decision2.Cached)
}

func TestAuthorizer_Close(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test-policy",
					Roles:     []string{"admin"},
					Resources: []string{"/api/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
				},
			},
		},
	}

	authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
	require.NoError(t, err)

	err = authorizer.Close()
	assert.NoError(t, err)
}

func TestDecision_Fields(t *testing.T) {
	t.Parallel()

	decision := &Decision{
		Allowed: true,
		Reason:  "test reason",
		Policy:  "test-policy",
		Engine:  "rbac",
		Cached:  true,
	}

	assert.True(t, decision.Allowed)
	assert.Equal(t, "test reason", decision.Reason)
	assert.Equal(t, "test-policy", decision.Policy)
	assert.Equal(t, "rbac", decision.Engine)
	assert.True(t, decision.Cached)
}

func TestRequest_Fields(t *testing.T) {
	t.Parallel()

	identity := &auth.Identity{
		Subject: "user123",
		Roles:   []string{"admin"},
	}

	req := &Request{
		Identity: identity,
		Resource: "/api/users",
		Action:   "GET",
		Context: map[string]interface{}{
			"ip": "192.168.1.1",
		},
	}

	assert.Equal(t, identity, req.Identity)
	assert.Equal(t, "/api/users", req.Resource)
	assert.Equal(t, "GET", req.Action)
	assert.Equal(t, "192.168.1.1", req.Context["ip"])
}

func TestAuthorizer_WithAllOptions(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
		},
	}

	mockRBAC := &mockRBACEngine{
		decision: &rbac.Decision{Allowed: true, Policy: "test"},
	}
	mockABAC := &mockABACEngine{
		decision: &abac.Decision{Allowed: true, Policy: "test"},
	}

	authorizer, err := New(config,
		WithAuthorizerLogger(observability.NopLogger()),
		WithAuthorizerMetrics(newNoopMetrics()),
		WithRBACEngine(mockRBAC),
		WithABACEngine(mockABAC),
		WithDecisionCache(NewNoopDecisionCache()),
	)
	require.NoError(t, err)
	assert.NotNil(t, authorizer)
	_ = authorizer.Close()
}

func TestPolicyConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, Policy("allow"), PolicyAllow)
	assert.Equal(t, Policy("deny"), PolicyDeny)
}

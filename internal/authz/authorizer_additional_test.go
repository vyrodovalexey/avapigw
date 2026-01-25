package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockOPAClient implements external.OPAClient for testing.
type mockOPAClient struct {
	result   *external.OPAResult
	err      error
	closeErr error
}

func (m *mockOPAClient) Authorize(_ context.Context, _ *external.OPAInput) (*external.OPAResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func (m *mockOPAClient) Close() error {
	return m.closeErr
}

// TestAuthorizer_WithOPAClient tests authorizer with OPA client.
func TestAuthorizer_WithOPAClient(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	mockOPA := &mockOPAClient{
		result: &external.OPAResult{
			Allow:  true,
			Reason: "OPA allowed",
		},
	}

	authorizer, err := New(config,
		WithOPAClient(mockOPA),
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
	assert.Equal(t, "OPA allowed", decision.Reason)
	assert.Equal(t, "external", decision.Engine)
}

// TestAuthorizer_OPAError tests OPA error handling.
func TestAuthorizer_OPAError(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled:  true,
			FailOpen: false,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	mockOPA := &mockOPAClient{
		err: errors.New("OPA connection failed"),
	}

	authorizer, err := New(config,
		WithOPAClient(mockOPA),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
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
	assert.Error(t, err)
	assert.Nil(t, decision)
}

// TestAuthorizer_OPAErrorFailOpen tests OPA error with fail-open.
func TestAuthorizer_OPAErrorFailOpen(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled:  true,
			FailOpen: true,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	mockOPA := &mockOPAClient{
		err: errors.New("OPA connection failed"),
	}

	authorizer, err := New(config,
		WithOPAClient(mockOPA),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
		WithAuthorizerLogger(observability.NopLogger()),
	)
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
	assert.Contains(t, decision.Reason, "fail-open")
	assert.Equal(t, "external", decision.Engine)
}

// TestAuthorizer_RBACError tests RBAC error handling.
func TestAuthorizer_RBACError(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		RBAC: &rbac.Config{
			Enabled: true,
		},
	}

	mockEngine := &mockRBACEngine{
		err: errors.New("RBAC evaluation failed"),
	}

	authorizer, err := New(config,
		WithRBACEngine(mockEngine),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
		WithAuthorizerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Should fall through to default policy
	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, "default policy", decision.Reason)
}

// TestAuthorizer_ABACError tests ABAC error handling.
func TestAuthorizer_ABACError(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyAllow,
		ABAC: &abac.Config{
			Enabled: true,
		},
	}

	mockEngine := &mockABACEngine{
		err: errors.New("ABAC evaluation failed"),
	}

	authorizer, err := New(config,
		WithABACEngine(mockEngine),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
		WithAuthorizerLogger(observability.NopLogger()),
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

	// Should fall through to default policy
	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "default policy", decision.Reason)
}

// TestAuthorizer_ABACWithClaims tests ABAC with identity claims.
func TestAuthorizer_ABACWithClaims(t *testing.T) {
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
			Subject:     "user123",
			Email:       "user@example.com",
			TenantID:    "tenant1",
			Roles:       []string{"admin"},
			Permissions: []string{"read", "write"},
			Groups:      []string{"engineering"},
			Scopes:      []string{"api:read"},
			Claims: map[string]interface{}{
				"department": "engineering",
				"level":      5,
			},
		},
		Resource: "/api/users",
		Action:   "GET",
		Context: map[string]interface{}{
			"ip": "192.168.1.1",
		},
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "abac", decision.Engine)
}

// TestAuthorizer_CloseWithErrors tests close with errors.
func TestAuthorizer_CloseWithErrors(t *testing.T) {
	t.Parallel()

	t.Run("close with cache error", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "test",
						Roles:     []string{"admin"},
						Resources: []string{"/*"},
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
	})

	t.Run("close with OPA client error", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			External: &external.Config{
				Enabled: true,
				OPA: &external.OPAConfig{
					URL:    "http://localhost:8181",
					Policy: "authz/allow",
				},
			},
		}

		mockOPA := &mockOPAClient{
			closeErr: errors.New("close error"),
		}

		authorizer, err := New(config,
			WithOPAClient(mockOPA),
			WithDecisionCache(NewNoopDecisionCache()),
			WithAuthorizerMetrics(newNoopMetrics()),
		)
		require.NoError(t, err)

		err = authorizer.Close()
		assert.Error(t, err)
	})
}

// TestAuthorizer_InitializeABAC tests ABAC initialization.
func TestAuthorizer_InitializeABAC(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		ABAC: &abac.Config{
			Enabled: true,
			Policies: []abac.Policy{
				{
					Name:       "test-policy",
					Expression: `subject.id == "user123"`,
					Effect:     abac.EffectAllow,
					Priority:   1,
					Resources:  []string{"/api/*"},
					Actions:    []string{"GET"},
				},
			},
		},
	}

	authorizer, err := New(config,
		WithAuthorizerMetrics(newNoopMetrics()),
		WithAuthorizerLogger(observability.NopLogger()),
	)
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
}

// TestAuthorizer_CacheWithTTL tests cache with custom TTL.
func TestAuthorizer_CacheWithTTL(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
		},
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     10 * time.Minute,
			MaxSize: 500,
		},
	}

	mockEngine := &mockRBACEngine{
		decision: &rbac.Decision{
			Allowed: true,
			Reason:  "allowed",
			Policy:  "test-policy",
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

// TestAuthorizer_CacheDisabled tests with cache disabled.
func TestAuthorizer_CacheDisabled(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
		},
		Cache: &CacheConfig{
			Enabled: false,
		},
	}

	mockEngine := &mockRBACEngine{
		decision: &rbac.Decision{
			Allowed: true,
			Reason:  "allowed",
			Policy:  "test-policy",
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

	// Both calls should not be cached
	decision1, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, decision1.Cached)

	decision2, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, decision2.Cached)
}

// TestAuthorizer_RBACAndABAC tests with both RBAC and ABAC enabled.
func TestAuthorizer_RBACAndABAC(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
		},
		ABAC: &abac.Config{
			Enabled: true,
		},
	}

	// RBAC returns no policy match
	mockRBAC := &mockRBACEngine{
		decision: &rbac.Decision{
			Allowed: false,
			Reason:  "no matching policy",
			Policy:  "",
		},
	}

	// ABAC returns a match
	mockABAC := &mockABACEngine{
		decision: &abac.Decision{
			Allowed: true,
			Reason:  "ABAC matched",
			Policy:  "abac-policy",
		},
	}

	authorizer, err := New(config,
		WithRBACEngine(mockRBAC),
		WithABACEngine(mockABAC),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Should fall through to ABAC
	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "abac", decision.Engine)
}

// TestAuthorizer_ExternalTimeout tests external authorization with timeout.
func TestAuthorizer_ExternalTimeout(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			Timeout: 100 * time.Millisecond,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	mockOPA := &mockOPAClient{
		result: &external.OPAResult{
			Allow:  true,
			Reason: "allowed",
		},
	}

	authorizer, err := New(config,
		WithOPAClient(mockOPA),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
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
}

// TestAuthorizer_OPADenied tests OPA denied response.
func TestAuthorizer_OPADenied(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	mockOPA := &mockOPAClient{
		result: &external.OPAResult{
			Allow:  false,
			Reason: "OPA denied",
		},
	}

	authorizer, err := New(config,
		WithOPAClient(mockOPA),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
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
	assert.False(t, decision.Allowed)
	assert.Equal(t, "OPA denied", decision.Reason)
}

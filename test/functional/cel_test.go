//go:build functional
// +build functional

package functional

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
)

func TestFunctional_CEL_Engine_BasicExpressions(t *testing.T) {
	t.Parallel()

	policies := []abac.Policy{
		{
			Name:       "admin-access",
			Expression: `"admin" in subject.roles`,
			Effect:     abac.EffectAllow,
			Priority:   100,
		},
		{
			Name:       "user-read",
			Expression: `"user" in subject.roles && action == "GET"`,
			Effect:     abac.EffectAllow,
			Priority:   50,
		},
	}

	cfg := &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("admin role grants access", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "admin-user",
				"roles": []interface{}{"admin"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "admin-access", decision.Policy)
	})

	t.Run("user role with GET action", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "regular-user",
				"roles": []interface{}{"user"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "user-read", decision.Policy)
	})

	t.Run("user role with POST action denied", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "regular-user",
				"roles": []interface{}{"user"},
			},
			Resource: "/api/items",
			Action:   "POST",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("no matching role denied", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "guest",
				"roles": []interface{}{"guest"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})
}

func TestFunctional_CEL_Engine_ComplexExpressions(t *testing.T) {
	t.Parallel()

	policies := []abac.Policy{
		{
			Name:       "owner-access",
			Expression: `subject.id == request.owner_id`,
			Effect:     abac.EffectAllow,
			Priority:   100,
		},
		{
			Name:       "tenant-isolation",
			Expression: `subject.tenant_id == request.tenant_id`,
			Effect:     abac.EffectAllow,
			Priority:   90,
		},
		{
			Name:       "admin-or-owner",
			Expression: `"admin" in subject.roles || subject.id == request.owner_id`,
			Effect:     abac.EffectAllow,
			Priority:   80,
		},
	}

	cfg := &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("owner can access own resource", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"roles": []interface{}{"user"},
			},
			Resource: "/api/items/456",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"owner_id": "user-123",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "owner-access", decision.Policy)
	})

	t.Run("non-owner denied", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"roles": []interface{}{"user"},
			},
			Resource: "/api/items/456",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"owner_id": "user-456",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("same tenant can access", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":        "user-123",
				"tenant_id": "tenant-1",
				"roles":     []interface{}{"user"},
			},
			Resource: "/api/items/456",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"tenant_id": "tenant-1",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("different tenant denied", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":        "user-123",
				"tenant_id": "tenant-1",
				"roles":     []interface{}{"user"},
			},
			Resource: "/api/items/456",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"tenant_id": "tenant-2",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})
}

func TestFunctional_CEL_Engine_StringOperations(t *testing.T) {
	t.Parallel()

	policies := []abac.Policy{
		{
			Name:       "email-domain-check",
			Expression: `subject.email.endsWith("@company.com")`,
			Effect:     abac.EffectAllow,
			Priority:   100,
		},
		{
			Name:       "resource-prefix-check",
			Expression: `resource.startsWith("/api/v1/")`,
			Effect:     abac.EffectAllow,
			Priority:   50,
		},
		{
			Name:       "contains-check",
			Expression: `subject.name.contains("admin")`,
			Effect:     abac.EffectAllow,
			Priority:   40,
		},
	}

	cfg := &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("email domain matches", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"email": "john@company.com",
				"name":  "John Doe",
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "email-domain-check", decision.Policy)
	})

	t.Run("email domain does not match", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"email": "john@other.com",
				"name":  "John Doe",
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("resource prefix matches", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"email": "john@other.com",
				"name":  "John Doe",
			},
			Resource: "/api/v1/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "resource-prefix-check", decision.Policy)
	})

	t.Run("name contains admin", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"email": "john@other.com",
				"name":  "admin-user",
			},
			Resource: "/api/v2/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "contains-check", decision.Policy)
	})
}

func TestFunctional_CEL_Engine_ListOperations(t *testing.T) {
	t.Parallel()

	policies := []abac.Policy{
		{
			Name:       "has-required-scope",
			Expression: `"read" in subject.scopes`,
			Effect:     abac.EffectAllow,
			Priority:   100,
		},
		{
			Name:       "has-any-admin-role",
			Expression: `subject.roles.exists(r, r.startsWith("admin"))`,
			Effect:     abac.EffectAllow,
			Priority:   90,
		},
		{
			Name:       "all-scopes-valid",
			Expression: `subject.scopes.all(s, s in ["read", "write", "delete"])`,
			Effect:     abac.EffectAllow,
			Priority:   80,
		},
		{
			Name:       "multiple-roles",
			Expression: `size(subject.roles) >= 2`,
			Effect:     abac.EffectAllow,
			Priority:   70,
		},
	}

	cfg := &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("has required scope", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":     "user-123",
				"roles":  []interface{}{"user"},
				"scopes": []interface{}{"read", "write"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "has-required-scope", decision.Policy)
	})

	t.Run("missing required scope", func(t *testing.T) {
		t.Parallel()

		// Use a scope that's not in the "all-scopes-valid" list to ensure no policy matches
		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":     "user-123",
				"roles":  []interface{}{"user"},
				"scopes": []interface{}{"invalid-scope"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("has admin role prefix", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":     "user-123",
				"roles":  []interface{}{"admin-users", "viewer"},
				"scopes": []interface{}{"other"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "has-any-admin-role", decision.Policy)
	})

	t.Run("multiple roles check", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":     "user-123",
				"roles":  []interface{}{"user", "editor"},
				"scopes": []interface{}{"other"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "multiple-roles", decision.Policy)
	})
}

func TestFunctional_CEL_Engine_NumericOperations(t *testing.T) {
	t.Parallel()

	policies := []abac.Policy{
		{
			Name:       "high-priority-user",
			Expression: `subject.priority >= 10`,
			Effect:     abac.EffectAllow,
			Priority:   100,
		},
		{
			Name:       "rate-limit-check",
			Expression: `request.request_count < 100`,
			Effect:     abac.EffectAllow,
			Priority:   90,
		},
		{
			Name:       "amount-range",
			Expression: `request.amount >= 0 && request.amount <= 1000`,
			Effect:     abac.EffectAllow,
			Priority:   80,
		},
	}

	cfg := &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("high priority user", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":       "user-123",
				"priority": 15,
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "high-priority-user", decision.Policy)
	})

	t.Run("low priority user denied", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":       "user-123",
				"priority": 5,
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("within rate limit", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":       "user-123",
				"priority": 5,
			},
			Resource: "/api/items",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"request_count": 50,
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "rate-limit-check", decision.Policy)
	})

	t.Run("exceeds rate limit", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":       "user-123",
				"priority": 5,
			},
			Resource: "/api/items",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"request_count": 150,
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("amount in range", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":       "user-123",
				"priority": 5,
			},
			Resource: "/api/items",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"request_count": 150,
				"amount":        500,
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "amount-range", decision.Policy)
	})
}

func TestFunctional_CEL_Engine_IPRangeFunction(t *testing.T) {
	t.Parallel()

	policies := []abac.Policy{
		{
			Name:       "internal-network",
			Expression: `ip_in_range(request.client_ip, "10.0.0.0/8")`,
			Effect:     abac.EffectAllow,
			Priority:   100,
		},
		{
			Name:       "private-network",
			Expression: `ip_in_range(request.client_ip, "192.168.0.0/16")`,
			Effect:     abac.EffectAllow,
			Priority:   90,
		},
	}

	cfg := &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("IP in internal network", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id": "user-123",
			},
			Resource: "/api/internal",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"client_ip": "10.1.2.3",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "internal-network", decision.Policy)
	})

	t.Run("IP in private network", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id": "user-123",
			},
			Resource: "/api/internal",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"client_ip": "192.168.1.100",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "private-network", decision.Policy)
	})

	t.Run("IP not in allowed range", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id": "user-123",
			},
			Resource: "/api/internal",
			Action:   "GET",
			RequestAttrs: map[string]interface{}{
				"client_ip": "8.8.8.8",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})
}

func TestFunctional_CEL_Engine_ResourceActionScope(t *testing.T) {
	t.Parallel()

	policies := []abac.Policy{
		{
			Name:       "api-read",
			Expression: `"user" in subject.roles`,
			Effect:     abac.EffectAllow,
			Priority:   100,
			Resources:  []string{"/api/*"},
			Actions:    []string{"GET"},
		},
		{
			Name:       "api-write",
			Expression: `"admin" in subject.roles`,
			Effect:     abac.EffectAllow,
			Priority:   90,
			Resources:  []string{"/api/*"},
			Actions:    []string{"POST", "PUT", "DELETE"},
		},
	}

	cfg := &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("user can read API", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"roles": []interface{}{"user"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "api-read", decision.Policy)
	})

	t.Run("user cannot write API", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"roles": []interface{}{"user"},
			},
			Resource: "/api/items",
			Action:   "POST",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("admin can write API", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "admin-123",
				"roles": []interface{}{"admin"},
			},
			Resource: "/api/items",
			Action:   "POST",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "api-write", decision.Policy)
	})

	t.Run("policy not applied to non-matching resource", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"roles": []interface{}{"user"},
			},
			Resource: "/admin/settings",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})
}

func TestFunctional_CEL_Engine_PolicyManagement(t *testing.T) {
	t.Parallel()

	cfg := &abac.Config{
		Enabled: true,
		Engine:  "cel",
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("add policy", func(t *testing.T) {
		policy := abac.Policy{
			Name:       "new-policy",
			Expression: `"user" in subject.roles`,
			Effect:     abac.EffectAllow,
		}

		err := engine.AddPolicy(policy)
		require.NoError(t, err)

		policies := engine.GetPolicies()
		assert.Len(t, policies, 1)
		assert.Equal(t, "new-policy", policies[0].Name)

		// Verify policy works
		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":    "user-123",
				"roles": []interface{}{"user"},
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("add policy with invalid expression", func(t *testing.T) {
		policy := abac.Policy{
			Name:       "invalid-policy",
			Expression: `invalid syntax here!!!`,
			Effect:     abac.EffectAllow,
		}

		err := engine.AddPolicy(policy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "compile")
	})

	t.Run("update policy", func(t *testing.T) {
		policy := abac.Policy{
			Name:       "new-policy",
			Expression: `"admin" in subject.roles`,
			Effect:     abac.EffectAllow,
		}

		err := engine.AddPolicy(policy)
		require.NoError(t, err)

		policies := engine.GetPolicies()
		assert.Len(t, policies, 1)
		assert.Equal(t, `"admin" in subject.roles`, policies[0].Expression)
	})

	t.Run("remove policy", func(t *testing.T) {
		err := engine.RemovePolicy("new-policy")
		require.NoError(t, err)

		policies := engine.GetPolicies()
		assert.Len(t, policies, 0)
	})
}

func TestFunctional_CEL_Engine_DenyEffect(t *testing.T) {
	t.Parallel()

	policies := []abac.Policy{
		{
			Name:       "allow-users",
			Expression: `"user" in subject.roles`,
			Effect:     abac.EffectAllow,
			Priority:   50,
		},
		{
			Name:       "deny-blocked",
			Expression: `subject.blocked == true`,
			Effect:     abac.EffectDeny,
			Priority:   100, // Higher priority
		},
	}

	cfg := &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}

	engine, err := abac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("blocked user denied", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":      "user-123",
				"roles":   []interface{}{"user"},
				"blocked": true,
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Equal(t, "deny-blocked", decision.Policy)
	})

	t.Run("non-blocked user allowed", func(t *testing.T) {
		t.Parallel()

		req := &abac.Request{
			Subject: map[string]interface{}{
				"id":      "user-123",
				"roles":   []interface{}{"user"},
				"blocked": false,
			},
			Resource: "/api/items",
			Action:   "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "allow-users", decision.Policy)
	})
}

//go:build functional
// +build functional

package functional

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestFunctional_RBAC_Engine_BasicAuthorization(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:      "admin-all",
			Roles:     []string{"admin"},
			Resources: []string{"*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectAllow,
			Priority:  100,
		},
		{
			Name:      "user-read",
			Roles:     []string{"user"},
			Resources: []string{"/api/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
			Priority:  50,
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("admin can access everything", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("admin-user", []string{"admin"}, "/api/users", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "admin-all", decision.Policy)
	})

	t.Run("admin can write", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("admin-user", []string{"admin"}, "/api/users", "POST")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("user can read API", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("regular-user", []string{"user"}, "/api/items", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "user-read", decision.Policy)
	})

	t.Run("user cannot write", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("regular-user", []string{"user"}, "/api/items", "POST")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("user cannot access non-API paths", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("regular-user", []string{"user"}, "/admin/settings", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("no roles - denied", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("anonymous", []string{}, "/api/items", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})
}

func TestFunctional_RBAC_Engine_DenyPolicies(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:      "user-read",
			Roles:     []string{"user"},
			Resources: []string{"/api/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
			Priority:  50,
		},
		{
			Name:      "deny-admin-endpoints",
			Roles:     []string{"user"},
			Resources: []string{"/api/admin/*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectDeny,
			Priority:  100, // Higher priority
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("user can read regular API", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/items", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("user denied from admin endpoints", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/admin/settings", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Equal(t, "deny-admin-endpoints", decision.Policy)
	})
}

func TestFunctional_RBAC_Engine_RoleHierarchy(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:      "user-read",
			Roles:     []string{"user"},
			Resources: []string{"/api/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
		},
		{
			Name:      "reader-read",
			Roles:     []string{"reader"},
			Resources: []string{"/api/public/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
		RoleHierarchy: map[string][]string{
			"admin": {"user"},
			"user":  {"reader"},
		},
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("admin inherits user permissions", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("admin-user", []string{"admin"}, "/api/items", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("admin inherits reader permissions", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("admin-user", []string{"admin"}, "/api/public/docs", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("user inherits reader permissions", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("regular-user", []string{"user"}, "/api/public/docs", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("reader has only reader permissions", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("reader-user", []string{"reader"}, "/api/public/docs", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)

		// Reader cannot access non-public API
		req2 := helpers.CreateTestRBACRequest("reader-user", []string{"reader"}, "/api/items", "GET")
		decision2, err := engine.Authorize(ctx, req2)
		require.NoError(t, err)
		assert.False(t, decision2.Allowed)
	})
}

func TestFunctional_RBAC_Engine_MultipleRoles(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:      "reader-read",
			Roles:     []string{"reader"},
			Resources: []string{"/api/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
		},
		{
			Name:      "writer-write",
			Roles:     []string{"writer"},
			Resources: []string{"/api/*"},
			Actions:   []string{"POST", "PUT", "PATCH", "DELETE"},
			Effect:    rbac.EffectAllow,
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("user with both roles can read and write", func(t *testing.T) {
		t.Parallel()

		// Can read
		req := helpers.CreateTestRBACRequest("multi-user", []string{"reader", "writer"}, "/api/items", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)

		// Can write
		req2 := helpers.CreateTestRBACRequest("multi-user", []string{"reader", "writer"}, "/api/items", "POST")
		decision2, err := engine.Authorize(ctx, req2)
		require.NoError(t, err)
		assert.True(t, decision2.Allowed)
	})

	t.Run("reader only can read", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("reader-user", []string{"reader"}, "/api/items", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)

		req2 := helpers.CreateTestRBACRequest("reader-user", []string{"reader"}, "/api/items", "POST")
		decision2, err := engine.Authorize(ctx, req2)
		require.NoError(t, err)
		assert.False(t, decision2.Allowed)
	})

	t.Run("writer only can write", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("writer-user", []string{"writer"}, "/api/items", "POST")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)

		req2 := helpers.CreateTestRBACRequest("writer-user", []string{"writer"}, "/api/items", "GET")
		decision2, err := engine.Authorize(ctx, req2)
		require.NoError(t, err)
		assert.False(t, decision2.Allowed)
	})
}

func TestFunctional_RBAC_Engine_ResourcePatterns(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:      "exact-match",
			Roles:     []string{"user"},
			Resources: []string{"/api/v1/users"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
		},
		{
			Name:      "prefix-match",
			Roles:     []string{"user"},
			Resources: []string{"/api/v1/items/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
		},
		{
			Name:      "regex-match",
			Roles:     []string{"user"},
			Resources: []string{"~/api/v[0-9]+/orders/[0-9]+"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
		},
		{
			Name:      "wildcard-all",
			Roles:     []string{"admin"},
			Resources: []string{"*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectAllow,
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("exact match", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/v1/users", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "exact-match", decision.Policy)

		// Different path should not match
		req2 := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/v1/users/123", "GET")
		decision2, err := engine.Authorize(ctx, req2)
		require.NoError(t, err)
		assert.False(t, decision2.Allowed)
	})

	t.Run("prefix match", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/v1/items/123", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "prefix-match", decision.Policy)

		req2 := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/v1/items/nested/path", "GET")
		decision2, err := engine.Authorize(ctx, req2)
		require.NoError(t, err)
		assert.True(t, decision2.Allowed)
	})

	t.Run("regex match", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/v1/orders/12345", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "regex-match", decision.Policy)

		req2 := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/v2/orders/99999", "GET")
		decision2, err := engine.Authorize(ctx, req2)
		require.NoError(t, err)
		assert.True(t, decision2.Allowed)

		// Non-numeric order ID should not match
		req3 := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/v1/orders/abc", "GET")
		decision3, err := engine.Authorize(ctx, req3)
		require.NoError(t, err)
		assert.False(t, decision3.Allowed)
	})

	t.Run("wildcard matches everything", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("admin", []string{"admin"}, "/any/path/here", "DELETE")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "wildcard-all", decision.Policy)
	})
}

func TestFunctional_RBAC_Engine_ActionPatterns(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:      "read-only",
			Roles:     []string{"reader"},
			Resources: []string{"/api/*"},
			Actions:   []string{"GET", "HEAD", "OPTIONS"},
			Effect:    rbac.EffectAllow,
		},
		{
			Name:      "write-only",
			Roles:     []string{"writer"},
			Resources: []string{"/api/*"},
			Actions:   []string{"POST", "PUT", "PATCH", "DELETE"},
			Effect:    rbac.EffectAllow,
		},
		{
			Name:      "all-actions",
			Roles:     []string{"admin"},
			Resources: []string{"/api/*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectAllow,
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("reader can use read methods", func(t *testing.T) {
		t.Parallel()

		for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
			req := helpers.CreateTestRBACRequest("reader", []string{"reader"}, "/api/items", method)
			decision, err := engine.Authorize(ctx, req)
			require.NoError(t, err)
			assert.True(t, decision.Allowed, "reader should be allowed for %s", method)
		}
	})

	t.Run("reader cannot use write methods", func(t *testing.T) {
		t.Parallel()

		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			req := helpers.CreateTestRBACRequest("reader", []string{"reader"}, "/api/items", method)
			decision, err := engine.Authorize(ctx, req)
			require.NoError(t, err)
			assert.False(t, decision.Allowed, "reader should be denied for %s", method)
		}
	})

	t.Run("writer can use write methods", func(t *testing.T) {
		t.Parallel()

		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			req := helpers.CreateTestRBACRequest("writer", []string{"writer"}, "/api/items", method)
			decision, err := engine.Authorize(ctx, req)
			require.NoError(t, err)
			assert.True(t, decision.Allowed, "writer should be allowed for %s", method)
		}
	})

	t.Run("admin can use all methods", func(t *testing.T) {
		t.Parallel()

		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
			req := helpers.CreateTestRBACRequest("admin", []string{"admin"}, "/api/items", method)
			decision, err := engine.Authorize(ctx, req)
			require.NoError(t, err)
			assert.True(t, decision.Allowed, "admin should be allowed for %s", method)
		}
	})

	t.Run("action matching is case-insensitive", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("reader", []string{"reader"}, "/api/items", "get")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})
}

func TestFunctional_RBAC_Engine_Conditions(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:      "tenant-access",
			Roles:     []string{"user"},
			Resources: []string{"/api/*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectAllow,
			Conditions: []rbac.Condition{
				{
					Type:     "context",
					Key:      "tenant_id",
					Operator: "eq",
					Value:    "tenant-1",
				},
			},
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("condition matches", func(t *testing.T) {
		t.Parallel()

		req := &rbac.Request{
			Subject:  "user",
			Roles:    []string{"user"},
			Resource: "/api/items",
			Action:   "GET",
			Context: map[string]interface{}{
				"tenant_id": "tenant-1",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("condition does not match", func(t *testing.T) {
		t.Parallel()

		req := &rbac.Request{
			Subject:  "user",
			Roles:    []string{"user"},
			Resource: "/api/items",
			Action:   "GET",
			Context: map[string]interface{}{
				"tenant_id": "tenant-2",
			},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("condition key missing", func(t *testing.T) {
		t.Parallel()

		req := &rbac.Request{
			Subject:  "user",
			Roles:    []string{"user"},
			Resource: "/api/items",
			Action:   "GET",
			Context:  map[string]interface{}{},
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})
}

func TestFunctional_RBAC_Engine_PolicyManagement(t *testing.T) {
	t.Parallel()

	cfg := &rbac.Config{
		Enabled: true,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("add policy", func(t *testing.T) {
		policy := rbac.Policy{
			Name:      "new-policy",
			Roles:     []string{"user"},
			Resources: []string{"/api/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
		}

		err := engine.AddPolicy(policy)
		require.NoError(t, err)

		policies := engine.GetPolicies()
		assert.Len(t, policies, 1)
		assert.Equal(t, "new-policy", policies[0].Name)

		// Verify policy works
		req := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/items", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("update policy", func(t *testing.T) {
		// Add policy with same name should update
		policy := rbac.Policy{
			Name:      "new-policy",
			Roles:     []string{"admin"},
			Resources: []string{"/admin/*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectAllow,
		}

		err := engine.AddPolicy(policy)
		require.NoError(t, err)

		policies := engine.GetPolicies()
		assert.Len(t, policies, 1)
		assert.Equal(t, []string{"admin"}, policies[0].Roles)
	})

	t.Run("remove policy", func(t *testing.T) {
		err := engine.RemovePolicy("new-policy")
		require.NoError(t, err)

		policies := engine.GetPolicies()
		assert.Len(t, policies, 0)
	})

	t.Run("remove non-existent policy", func(t *testing.T) {
		err := engine.RemovePolicy("non-existent")
		require.NoError(t, err) // Should not error
	})
}

func TestFunctional_RBAC_Engine_PermissionsAndGroups(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:        "permission-based",
			Permissions: []string{"items:read"},
			Resources:   []string{"/api/items/*"},
			Actions:     []string{"GET"},
			Effect:      rbac.EffectAllow,
		},
		{
			Name:      "group-based",
			Groups:    []string{"developers"},
			Resources: []string{"/api/dev/*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectAllow,
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("permission-based access", func(t *testing.T) {
		t.Parallel()

		req := &rbac.Request{
			Subject:     "user",
			Permissions: []string{"items:read"},
			Resource:    "/api/items/123",
			Action:      "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("group-based access", func(t *testing.T) {
		t.Parallel()

		req := &rbac.Request{
			Subject:  "user",
			Groups:   []string{"developers"},
			Resource: "/api/dev/test",
			Action:   "POST",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("missing permission denied", func(t *testing.T) {
		t.Parallel()

		req := &rbac.Request{
			Subject:     "user",
			Permissions: []string{"items:write"},
			Resource:    "/api/items/123",
			Action:      "GET",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})

	t.Run("missing group denied", func(t *testing.T) {
		t.Parallel()

		req := &rbac.Request{
			Subject:  "user",
			Groups:   []string{"users"},
			Resource: "/api/dev/test",
			Action:   "POST",
		}
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
	})
}

func TestFunctional_RBAC_Engine_Priority(t *testing.T) {
	t.Parallel()

	policies := []rbac.Policy{
		{
			Name:      "allow-all",
			Roles:     []string{"user"},
			Resources: []string{"/api/*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectAllow,
			Priority:  10,
		},
		{
			Name:      "deny-sensitive",
			Roles:     []string{"user"},
			Resources: []string{"/api/sensitive/*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectDeny,
			Priority:  100, // Higher priority
		},
	}

	cfg := &rbac.Config{
		Enabled:  true,
		Policies: policies,
	}

	engine, err := rbac.NewEngine(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("higher priority deny takes precedence", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/sensitive/data", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Equal(t, "deny-sensitive", decision.Policy)
	})

	t.Run("lower priority allow works for other paths", func(t *testing.T) {
		t.Parallel()

		req := helpers.CreateTestRBACRequest("user", []string{"user"}, "/api/public/data", "GET")
		decision, err := engine.Authorize(ctx, req)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, "allow-all", decision.Policy)
	})
}

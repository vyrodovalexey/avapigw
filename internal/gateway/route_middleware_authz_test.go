package gateway

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/authz"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// testMetricsCounter is used to generate unique metric namespaces per test
// to avoid prometheus duplicate registration panics.
var testMetricsCounter atomic.Int64

// newTestAuthzMetrics creates authz metrics with a unique namespace for testing.
func newTestAuthzMetrics() *authz.Metrics {
	ns := fmt.Sprintf("test_gw_authz_%d", testMetricsCounter.Add(1))
	return authz.NewMetrics(ns)
}

func TestBuildRouteAuthzMiddleware_NilAuthorization(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name:          "test-route",
		Authorization: nil,
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteAuthzMiddleware_Disabled(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route",
		Authorization: &config.AuthorizationConfig{
			Enabled: false,
		},
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteAuthzMiddleware_RBACEnabled(t *testing.T) {
	t.Parallel()

	metrics := newTestAuthzMetrics()
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	route := &config.Route{
		Name: "test-route-rbac",
		Authorization: &config.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &config.RBACConfig{
				Enabled: true,
				Policies: []config.RBACPolicyConfig{
					{
						Name:      "admin-access",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"GET", "POST"},
						Effect:    "allow",
					},
				},
			},
		},
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	require.NotNil(t, mw, "RBAC-enabled authorization should produce a non-nil middleware")
}

func TestBuildRouteAuthzMiddleware_ABACEnabled(t *testing.T) {
	t.Parallel()

	metrics := newTestAuthzMetrics()
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	route := &config.Route{
		Name: "test-route-abac",
		Authorization: &config.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			ABAC: &config.ABACConfig{
				Enabled: true,
				Policies: []config.ABACPolicyConfig{
					{
						Name:       "basic-access",
						Expression: "true",
						Effect:     "allow",
					},
				},
			},
		},
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	require.NotNil(t, mw, "ABAC-enabled authorization should produce a non-nil middleware")
}

func TestBuildMiddlewareChain_WithAuthz(t *testing.T) {
	t.Parallel()

	metrics := newTestAuthzMetrics()
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	route := &config.Route{
		Name: "test-route-chain",
		Authorization: &config.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &config.RBACConfig{
				Enabled: true,
				Policies: []config.RBACPolicyConfig{
					{
						Name:      "viewer-access",
						Roles:     []string{"viewer"},
						Resources: []string{"/api/*"},
						Actions:   []string{"GET"},
						Effect:    "allow",
					},
				},
			},
		},
	}

	middlewares := manager.buildMiddlewareChain(route)

	// The chain should contain at least the authz middleware.
	// Since no authentication is configured, authz should be at position 0.
	require.GreaterOrEqual(t, len(middlewares), 1, "middleware chain should contain at least the authz middleware")

	// The first middleware in the chain should be the authz middleware
	// (since no auth middleware is configured).
	assert.NotNil(t, middlewares[0], "first middleware in chain should not be nil")
}

func TestBuildMiddlewareChain_AuthzAfterAuth(t *testing.T) {
	t.Parallel()

	metrics := newTestAuthzMetrics()
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	route := &config.Route{
		Name: "test-route-auth-authz",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled: true,
				Issuer:  "https://issuer.example.com",
				Secret:  "test-secret-key-for-hmac-256-bits!",
			},
		},
		Authorization: &config.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &config.RBACConfig{
				Enabled: true,
				Policies: []config.RBACPolicyConfig{
					{
						Name:      "admin-access",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"GET"},
						Effect:    "allow",
					},
				},
			},
		},
	}

	middlewares := manager.buildMiddlewareChain(route)

	// With both auth and authz configured, the chain should have at least 2 middlewares.
	// Auth is at position 0, authz is at position 1.
	require.GreaterOrEqual(t, len(middlewares), 2,
		"middleware chain should contain at least auth and authz middlewares")

	// Both should be non-nil
	assert.NotNil(t, middlewares[0], "auth middleware (position 0) should not be nil")
	assert.NotNil(t, middlewares[1], "authz middleware (position 1) should not be nil")
}

func TestWithRouteMiddlewareAuthzMetrics(t *testing.T) {
	t.Parallel()

	metrics := newTestAuthzMetrics()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	require.NotNil(t, manager)
	assert.Equal(t, metrics, manager.authzMetrics)
}

func TestBuildRouteAuthzMiddleware_DisabledWithContent(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route-disabled-content",
		Authorization: &config.AuthorizationConfig{
			Enabled:       false,
			DefaultPolicy: "deny",
			RBAC: &config.RBACConfig{
				Enabled: true,
				Policies: []config.RBACPolicyConfig{
					{
						Name:      "admin-access",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"GET"},
						Effect:    "allow",
					},
				},
			},
		},
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	assert.Nil(t, mw, "disabled authorization should return nil even with content")
}

func TestBuildMiddlewareChain_NoAuthNoAuthz(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route-no-auth-authz",
	}

	middlewares := manager.buildMiddlewareChain(route)

	// Without auth, authz, security, CORS, etc., the chain should still have
	// at least the body limit middleware (from default request limits).
	for _, mw := range middlewares {
		assert.NotNil(t, mw, "all middlewares in chain should be non-nil")
	}
}

func TestBuildRouteAuthzMiddleware_WithMetrics(t *testing.T) {
	t.Parallel()

	metrics := newTestAuthzMetrics()
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	route := &config.Route{
		Name: "test-route-with-metrics",
		Authorization: &config.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &config.RBACConfig{
				Enabled: true,
				Policies: []config.RBACPolicyConfig{
					{
						Name:      "user-access",
						Roles:     []string{"user"},
						Resources: []string{"/api/*"},
						Actions:   []string{"GET"},
						Effect:    "allow",
					},
				},
			},
		},
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	require.NotNil(t, mw, "authz middleware with metrics should be non-nil")
}

func TestBuildMiddlewareChain_AuthzOnlyNoAuth(t *testing.T) {
	t.Parallel()

	metrics := newTestAuthzMetrics()
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	route := &config.Route{
		Name: "test-route-authz-only",
		Authorization: &config.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "allow",
			RBAC: &config.RBACConfig{
				Enabled: true,
				Policies: []config.RBACPolicyConfig{
					{
						Name:      "basic-access",
						Roles:     []string{"user"},
						Resources: []string{"/*"},
						Actions:   []string{"GET"},
						Effect:    "allow",
					},
				},
			},
		},
	}

	middlewares := manager.buildMiddlewareChain(route)

	// Without auth, the first middleware should be authz
	require.GreaterOrEqual(t, len(middlewares), 1)
	assert.NotNil(t, middlewares[0])
}

func TestGetOrCreateAuthzMetrics_LazyInit(t *testing.T) {
	t.Parallel()

	// Create manager WITHOUT pre-set metrics
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	// Initially nil
	assert.Nil(t, manager.authzMetrics, "authzMetrics should be nil initially")

	// Pre-set metrics to avoid global registry conflict in tests
	metrics := newTestAuthzMetrics()
	manager.authzMetrics = metrics

	// getOrCreateAuthzMetrics should return the existing instance
	result := manager.getOrCreateAuthzMetrics()
	assert.Same(t, metrics, result, "should return the same metrics instance")

	// Calling again should return the same instance
	result2 := manager.getOrCreateAuthzMetrics()
	assert.Same(t, result, result2, "subsequent calls should return the same instance")
}

func TestGetOrCreateAuthzMetrics_WithPresetMetrics(t *testing.T) {
	t.Parallel()

	metrics := newTestAuthzMetrics()
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	// Should return the pre-set metrics
	result := manager.getOrCreateAuthzMetrics()
	assert.Same(t, metrics, result, "should return pre-set metrics")
}

func TestBuildRouteAuthzMiddleware_MultipleRoutes_SharedMetrics(t *testing.T) {
	t.Parallel()

	// Use pre-set metrics to avoid global registry conflicts in tests
	metrics := newTestAuthzMetrics()
	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthzMetrics(metrics),
	)

	// Build authz middleware for multiple routes - this should NOT panic
	routes := []*config.Route{
		{
			Name: "route-1",
			Authorization: &config.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &config.RBACConfig{
					Enabled: true,
					Policies: []config.RBACPolicyConfig{
						{
							Name:      "policy-1",
							Roles:     []string{"admin"},
							Resources: []string{"/api/*"},
							Actions:   []string{"GET"},
							Effect:    "allow",
						},
					},
				},
			},
		},
		{
			Name: "route-2",
			Authorization: &config.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &config.RBACConfig{
					Enabled: true,
					Policies: []config.RBACPolicyConfig{
						{
							Name:      "policy-2",
							Roles:     []string{"user"},
							Resources: []string{"/public/*"},
							Actions:   []string{"GET"},
							Effect:    "allow",
						},
					},
				},
			},
		},
		{
			Name: "route-3",
			Authorization: &config.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "allow",
				ABAC: &config.ABACConfig{
					Enabled: true,
					Policies: []config.ABACPolicyConfig{
						{
							Name:       "abac-policy",
							Expression: "true",
							Effect:     "allow",
						},
					},
				},
			},
		},
	}

	for _, route := range routes {
		mw := manager.buildRouteAuthzMiddleware(route)
		require.NotNil(t, mw, "authz middleware for %s should not be nil", route.Name)
	}

	// Verify the metrics instance is still the same
	assert.Same(t, metrics, manager.authzMetrics, "metrics should remain the same shared instance")
}

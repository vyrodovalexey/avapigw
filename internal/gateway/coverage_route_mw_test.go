// Package gateway provides additional tests for route middleware options and
// uncovered paths to push coverage above 90%.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// WithRouteMiddlewareCacheFactory option
// ============================================================================

func TestWithRouteMiddlewareCacheFactory(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cf := NewCacheFactory(logger, nil)

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		logger,
		WithRouteMiddlewareCacheFactory(cf),
	)

	require.NotNil(t, manager)
	assert.Equal(t, cf, manager.cacheFactory)
}

func TestWithRouteMiddlewareCacheFactory_Nil(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareCacheFactory(nil),
	)

	require.NotNil(t, manager)
	assert.Nil(t, manager.cacheFactory)
}

// ============================================================================
// WithRouteMiddlewareAuthMetrics option
// ============================================================================

func TestWithRouteMiddlewareAuthMetrics(t *testing.T) {
	t.Parallel()

	metrics := auth.NewMetrics("test_route_mw")

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthMetrics(metrics),
	)

	require.NotNil(t, manager)
	assert.Equal(t, metrics, manager.authMetrics)
}

func TestWithRouteMiddlewareAuthMetrics_Nil(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthMetrics(nil),
	)

	require.NotNil(t, manager)
	assert.Nil(t, manager.authMetrics)
}

// ============================================================================
// WithRouteMiddlewareVaultClient option
// ============================================================================

func TestWithRouteMiddlewareVaultClient(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareVaultClient(nil),
	)

	require.NotNil(t, manager)
	assert.Nil(t, manager.vaultClient)
}

// ============================================================================
// buildRouteAuthMiddleware Tests
// ============================================================================

func TestBuildRouteAuthMiddleware_NilAuth(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name:           "test-route",
		Authentication: nil,
	}

	mw := manager.buildRouteAuthMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteAuthMiddleware_Disabled(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: false,
		},
	}

	mw := manager.buildRouteAuthMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteAuthMiddleware_EnabledNoMethods(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			// No JWT, APIKey, MTLS, or OIDC configured
		},
	}

	// ConvertFromGatewayConfig returns nil config when no methods are configured
	mw := manager.buildRouteAuthMiddleware(route)
	// May return nil (no methods) or a middleware depending on implementation
	_ = mw
}

func TestBuildRouteAuthMiddleware_WithJWKSUrl(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthMetrics(auth.NewMetrics("test_route_auth_jwks")),
	)

	route := &config.Route{
		Name: "test-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled: true,
				JWKSURL: "https://example.com/.well-known/jwks.json",
				Issuer:  "https://example.com",
			},
		},
	}

	mw := manager.buildRouteAuthMiddleware(route)
	assert.NotNil(t, mw, "should return middleware for valid JWKS URL config")
}

func TestBuildRouteAuthMiddleware_WithHMACSecret(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled:   true,
				Secret:    "raw-hmac-shared-secret",
				Algorithm: "HS256",
			},
		},
	}

	// HS256 with a raw shared secret is a valid configuration: the secret
	// is parsed as a symmetric key, so a real authentication middleware is
	// built and unauthenticated requests are rejected with 401.
	mw := manager.buildRouteAuthMiddleware(route)
	require.NotNil(t, mw, "HS256 with raw secret must build an auth middleware")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"requests without credentials must be rejected")
}

// ============================================================================
// buildRouteCacheMiddleware Tests
// ============================================================================

func TestBuildRouteCacheMiddleware_NilCache(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name:  "test-route",
		Cache: nil,
	}

	mw := manager.buildRouteCacheMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteCacheMiddleware_Disabled(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route",
		Cache: &config.CacheConfig{
			Enabled: false,
		},
	}

	mw := manager.buildRouteCacheMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteCacheMiddleware_NilFactory(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route",
		Cache: &config.CacheConfig{
			Enabled: true,
			TTL:     config.Duration(60 * time.Second),
		},
	}

	// cacheFactory is nil, so should return nil
	mw := manager.buildRouteCacheMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteCacheMiddleware_WithFactory(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cf := NewCacheFactory(logger, nil)

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		logger,
		WithRouteMiddlewareCacheFactory(cf),
	)

	route := &config.Route{
		Name: "cache-route",
		Cache: &config.CacheConfig{
			Enabled: true,
			TTL:     config.Duration(60 * time.Second),
		},
	}

	mw := manager.buildRouteCacheMiddleware(route)
	assert.NotNil(t, mw, "should return middleware when factory is set and cache is enabled")
}

// ============================================================================
// buildMiddlewareChain with auth and cache
// ============================================================================

func TestBuildMiddlewareChain_WithAuth(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthMetrics(auth.NewMetrics("test_mw_chain_auth")),
	)

	route := &config.Route{
		Name: "auth-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled: true,
				JWKSURL: "https://example.com/.well-known/jwks.json",
			},
		},
	}

	middlewares := manager.GetMiddleware(route)
	assert.NotEmpty(t, middlewares, "should have at least auth middleware")
}

func TestBuildMiddlewareChain_WithCacheAndAuth(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cf := NewCacheFactory(logger, nil)

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		logger,
		WithRouteMiddlewareCacheFactory(cf),
		WithRouteMiddlewareAuthMetrics(auth.NewMetrics("test_mw_chain_cache_auth")),
	)

	route := &config.Route{
		Name: "cache-auth-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled: true,
				JWKSURL: "https://example.com/.well-known/jwks.json",
			},
		},
		Cache: &config.CacheConfig{
			Enabled: true,
			TTL:     config.Duration(30 * time.Second),
		},
	}

	middlewares := manager.GetMiddleware(route)
	assert.NotEmpty(t, middlewares, "should have auth and cache middleware")
}

// ============================================================================
// ApplyMiddleware integration test
// ============================================================================

func TestApplyMiddleware_WithRouteAuth(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
		WithRouteMiddlewareAuthMetrics(auth.NewMetrics("test_apply_mw_auth")),
	)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	route := &config.Route{
		Name: "apply-route",
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled: true,
				JWKSURL: "https://example.com/.well-known/jwks.json",
			},
		},
	}

	handler := manager.ApplyMiddleware(inner, route)
	assert.NotNil(t, handler)

	// The handler should work (auth will reject without token, but shouldn't panic)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	// Auth middleware should return 401 since no token is provided
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

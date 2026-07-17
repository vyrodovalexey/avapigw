// Package gateway tests for the fail-closed behavior of route security
// middleware construction: a route configured WITH authentication or
// authorization must never serve traffic without it, even when the
// middleware cannot be constructed from the configuration.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// brokenAuthRoute returns a route whose authenticator construction fails:
// RS256 requires a JWK or PEM public key, so a raw non-key string makes
// auth.NewAuthenticator return an error.
func brokenAuthRoute(name string) *config.Route {
	return &config.Route{
		Name: name,
		Authentication: &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled:   true,
				PublicKey: "definitely-not-a-pem-or-jwk-key",
				Algorithm: "RS256",
			},
		},
	}
}

// brokenAuthzRoute returns a route whose authorizer construction fails:
// the ABAC policy contains an invalid CEL expression.
func brokenAuthzRoute(name string) *config.Route {
	return &config.Route{
		Name: name,
		Authorization: &config.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			ABAC: &config.ABACConfig{
				Enabled: true,
				Policies: []config.ABACPolicyConfig{
					{
						Name:       "broken-policy",
						Expression: "((( this is not CEL",
						Effect:     "allow",
					},
				},
			},
		},
	}
}

// assertFailClosed serves a request through the middleware and asserts
// that the wrapped handler is never reached and the request is rejected
// with 503 Service Unavailable.
func assertFailClosed(t *testing.T, mw func(http.Handler) http.Handler) {
	t.Helper()

	nextCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/protected", nil))

	assert.False(t, nextCalled, "request must NOT pass through to the next handler")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.JSONEq(t, securityUnavailableBody, rec.Body.String())
}

func TestBuildRouteAuthMiddleware_ConstructionError_FailsClosed(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	mw := manager.buildRouteAuthMiddleware(brokenAuthRoute("broken-auth-route"))
	require.NotNil(t, mw,
		"authenticator construction error must yield a fail-closed middleware, not nil")

	assertFailClosed(t, mw)
}

func TestBuildRouteAuthzMiddleware_ConstructionError_FailsClosed(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	mw := manager.buildRouteAuthzMiddleware(brokenAuthzRoute("broken-authz-route"))
	require.NotNil(t, mw,
		"authorizer construction error must yield a fail-closed middleware, not nil")

	assertFailClosed(t, mw)
}

// TestApplyMiddleware_BrokenAuth_ChainRejects verifies the fail-closed
// fallback is actually wired into the assembled route chain: requests to a
// route with a broken authenticator are rejected end to end.
func TestApplyMiddleware_BrokenAuth_ChainRejects(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	backendCalled := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := manager.ApplyMiddleware(backend, brokenAuthRoute("broken-auth-chain"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/data", nil))

	assert.False(t, backendCalled, "backend must not be reached when auth failed to build")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestApplyMiddleware_BrokenAuthz_ChainRejects verifies the same end-to-end
// rejection for a broken authorizer.
func TestApplyMiddleware_BrokenAuthz_ChainRejects(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	backendCalled := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := manager.ApplyMiddleware(backend, brokenAuthzRoute("broken-authz-chain"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/data", nil))

	assert.False(t, backendCalled, "backend must not be reached when authz failed to build")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestSecurityFailClosedFallback_ResponseShape pins the response contract
// of the fallback middleware: 503, JSON content type, stable error body.
func TestSecurityFailClosedFallback_ResponseShape(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	for _, stage := range []string{stageAuthentication, stageAuthorization} {
		mw := manager.securityFailClosedFallback("shape-route", stage, assert.AnError)
		require.NotNil(t, mw)

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.JSONEq(t, securityUnavailableBody, rec.Body.String())
	}
}

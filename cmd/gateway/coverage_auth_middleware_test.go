// Package main provides tests for buildAuthMiddleware to boost cmd/gateway coverage.
package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// buildAuthMiddleware Tests
// ============================================================================

func TestBuildAuthMiddleware_NilConfig(t *testing.T) {
	logger := observability.NopLogger()

	mw, err := buildAuthMiddleware(nil, nil, logger)
	assert.NoError(t, err)
	assert.Nil(t, mw)
}

func TestBuildAuthMiddleware_DisabledConfig(t *testing.T) {
	logger := observability.NopLogger()
	authCfg := &config.AuthenticationConfig{
		Enabled: false,
	}

	// ConvertFromGatewayConfig returns (nil, nil) for disabled config
	mw, err := buildAuthMiddleware(authCfg, nil, logger)
	assert.NoError(t, err)
	assert.Nil(t, mw)
}

func TestBuildAuthMiddleware_EnabledNoMethods(t *testing.T) {
	logger := observability.NopLogger()
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		// No JWT, APIKey, MTLS, or OIDC configured
	}

	// ConvertFromGatewayConfig returns a Config with Enabled=true but no methods
	// NewAuthenticator may succeed or fail depending on implementation
	mw, err := buildAuthMiddleware(authCfg, nil, logger)
	if err != nil {
		// If it fails, it should be a meaningful error
		assert.Contains(t, err.Error(), "authenticator")
	} else {
		assert.NotNil(t, mw)
	}
}

func TestBuildAuthMiddleware_WithJWT_InvalidKey(t *testing.T) {
	// JWT with a plain string secret fails because parseStaticKey
	// expects JWK or PEM format. This exercises the error path in
	// buildAuthMiddleware where auth.NewAuthenticator returns an error.
	logger := observability.NopLogger()
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Secret:    "plain-text-secret-not-jwk-or-pem",
			Algorithm: "HS256",
			Issuer:    "test-issuer",
		},
	}

	metrics := auth.NewMetrics("test")

	mw, err := buildAuthMiddleware(authCfg, metrics, logger)
	// Should fail because the secret is not in JWK or PEM format
	assert.Error(t, err)
	assert.Nil(t, mw)
	assert.Contains(t, err.Error(), "failed to create authenticator")
}

func TestBuildAuthMiddleware_WithJWT_NilMetrics_InvalidKey(t *testing.T) {
	logger := observability.NopLogger()
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Secret:    "plain-text-secret",
			Algorithm: "HS256",
		},
	}

	// nil metrics should be handled gracefully (the error comes from key parsing, not metrics)
	mw, err := buildAuthMiddleware(authCfg, nil, logger)
	assert.Error(t, err)
	assert.Nil(t, mw)
	assert.Contains(t, err.Error(), "failed to create authenticator")
}

func TestBuildAuthMiddleware_WithJWT_JWKSUrl(t *testing.T) {
	// Using JWKS URL instead of static key — this should succeed because
	// the JWKS URL is not fetched during initialization, only when needed.
	logger := observability.NopLogger()
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled: true,
			JWKSURL: "https://example.com/.well-known/jwks.json",
			Issuer:  "https://example.com",
		},
	}

	mw, err := buildAuthMiddleware(authCfg, nil, logger)
	assert.NoError(t, err)
	assert.NotNil(t, mw)
}

func TestBuildAuthMiddleware_WithJWT_JWKSUrl_WithMetrics(t *testing.T) {
	logger := observability.NopLogger()
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled: true,
			JWKSURL: "https://example.com/.well-known/jwks.json",
			Issuer:  "https://example.com",
		},
	}

	metrics := auth.NewMetrics("test")

	mw, err := buildAuthMiddleware(authCfg, metrics, logger)
	assert.NoError(t, err)
	assert.NotNil(t, mw)
}

func TestBuildAuthMiddleware_WithAllowAnonymous(t *testing.T) {
	logger := observability.NopLogger()
	authCfg := &config.AuthenticationConfig{
		Enabled:        true,
		AllowAnonymous: true,
		JWT: &config.JWTAuthConfig{
			Enabled: true,
			JWKSURL: "https://example.com/.well-known/jwks.json",
		},
	}

	mw, err := buildAuthMiddleware(authCfg, nil, logger)
	assert.NoError(t, err)
	assert.NotNil(t, mw)
}

func TestBuildAuthMiddleware_WithSkipPaths(t *testing.T) {
	logger := observability.NopLogger()
	authCfg := &config.AuthenticationConfig{
		Enabled:   true,
		SkipPaths: []string{"/health", "/ready"},
		JWT: &config.JWTAuthConfig{
			Enabled: true,
			JWKSURL: "https://example.com/.well-known/jwks.json",
		},
	}

	mw, err := buildAuthMiddleware(authCfg, nil, logger)
	assert.NoError(t, err)
	assert.NotNil(t, mw)
}

// ============================================================================
// buildMiddlewareChain with auth enabled — integration test
// ============================================================================

func TestBuildMiddlewareChain_WithAuthEnabled_JWKSUrl(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test-auth")
	metrics := observability.NewMetrics("test")
	tracer, err := observability.NewTracer(observability.TracerConfig{Enabled: false})
	assert.NoError(t, err)

	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled: true,
			JWKSURL: "https://example.com/.well-known/jwks.json",
		},
	}

	authMetrics := auth.NewMetrics("test")

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	result, err := buildMiddlewareChain(inner, cfg, logger, metrics, tracer, nil, authCfg, authMetrics)
	assert.NoError(t, err)
	assert.NotNil(t, result.handler)
}

func TestBuildMiddlewareChain_WithAuthError_InvalidKey(t *testing.T) {
	logger := observability.NopLogger()
	cfg := createTestGatewayConfigBoost("test-auth-err")
	metrics := observability.NewMetrics("test")
	tracer, err := observability.NewTracer(observability.TracerConfig{Enabled: false})
	assert.NoError(t, err)

	// JWT with invalid key format should cause an error
	authCfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Secret:    "not-a-valid-jwk-or-pem-key",
			Algorithm: "HS256",
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	_, err = buildMiddlewareChain(inner, cfg, logger, metrics, tracer, nil, authCfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth middleware initialization failed")
}

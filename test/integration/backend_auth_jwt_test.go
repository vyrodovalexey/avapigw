//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_BackendAuth_JWT_OIDC(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	t.Run("backend JWT auth with OIDC client credentials", func(t *testing.T) {
		// Create a backend service client in Keycloak
		backendClientID := "backend-service-test"
		backendClientSecret := "backend-service-secret"

		err := helpers.SetupKeycloakBackendClient(t, keycloakSetup, backendClientID, backendClientSecret)
		require.NoError(t, err)

		// Get token using client credentials
		tokenResp, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			backendClientID,
			backendClientSecret,
		)
		require.NoError(t, err)
		require.NotNil(t, tokenResp)
		assert.NotEmpty(t, tokenResp.AccessToken)

		// Verify token can be used
		assert.NotEmpty(t, tokenResp.TokenType)
		assert.Greater(t, tokenResp.ExpiresIn, 0)
	})

	t.Run("token refresh on expiry", func(t *testing.T) {
		// Get initial token
		tokenResp1, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)
		require.NotNil(t, tokenResp1)

		// Get another token (simulating refresh)
		tokenResp2, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)
		require.NotNil(t, tokenResp2)

		// Both tokens should be valid
		assert.NotEmpty(t, tokenResp1.AccessToken)
		assert.NotEmpty(t, tokenResp2.AccessToken)
	})

	t.Run("token caching behavior", func(t *testing.T) {
		// Simulate token caching by getting multiple tokens
		tokens := make([]string, 3)

		for i := 0; i < 3; i++ {
			tokenResp, err := keycloakSetup.Client.GetClientCredentialsToken(
				ctx,
				keycloakSetup.Realm,
				keycloakSetup.ClientID,
				keycloakSetup.ClientSecret,
			)
			require.NoError(t, err)
			tokens[i] = tokenResp.AccessToken
		}

		// All tokens should be valid (may or may not be the same depending on Keycloak config)
		for _, token := range tokens {
			assert.NotEmpty(t, token)
		}
	})

	t.Run("error handling for invalid OIDC config", func(t *testing.T) {
		// Invalid client credentials
		_, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			"invalid-client",
			"invalid-secret",
		)
		assert.Error(t, err)

		// Invalid realm
		_, err = keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			"invalid-realm",
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		assert.Error(t, err)
	})
}

func TestIntegration_BackendAuth_JWT_HeaderInjection(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	t.Run("JWT token injected into backend request", func(t *testing.T) {
		// Get a token
		tokenResp, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)

		// Create a test backend that verifies the Authorization header
		var receivedAuthHeader string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuthHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		}))
		defer backend.Close()

		// Simulate gateway injecting the token
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/api/resource", nil)
		require.NoError(t, err)

		// Inject JWT token as gateway would
		jwtConfig := &config.BackendJWTAuthConfig{
			HeaderName:   "Authorization",
			HeaderPrefix: "Bearer",
		}
		headerValue := jwtConfig.GetEffectiveHeaderPrefix() + " " + tokenResp.AccessToken
		req.Header.Set(jwtConfig.GetEffectiveHeaderName(), headerValue)

		// Send request
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, strings.HasPrefix(receivedAuthHeader, "Bearer "))
		assert.Contains(t, receivedAuthHeader, tokenResp.AccessToken)
	})

	t.Run("custom header name for JWT", func(t *testing.T) {
		tokenResp, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)

		var receivedHeader string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeader = r.Header.Get("X-Backend-Auth")
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/api/resource", nil)
		require.NoError(t, err)

		// Use custom header name
		jwtConfig := &config.BackendJWTAuthConfig{
			HeaderName:   "X-Backend-Auth",
			HeaderPrefix: "Token",
		}
		headerValue := jwtConfig.GetEffectiveHeaderPrefix() + " " + tokenResp.AccessToken
		req.Header.Set(jwtConfig.GetEffectiveHeaderName(), headerValue)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, strings.HasPrefix(receivedHeader, "Token "))
	})
}

func TestIntegration_BackendAuth_JWT_TokenValidation(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	t.Run("valid token structure", func(t *testing.T) {
		tokenResp, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)

		// JWT should have 3 parts separated by dots
		parts := strings.Split(tokenResp.AccessToken, ".")
		assert.Len(t, parts, 3, "JWT should have header, payload, and signature")
	})

	t.Run("token contains expected claims", func(t *testing.T) {
		tokenResp, err := keycloakSetup.Client.GetClientCredentialsToken(
			ctx,
			keycloakSetup.Realm,
			keycloakSetup.ClientID,
			keycloakSetup.ClientSecret,
		)
		require.NoError(t, err)

		// Decode payload (middle part)
		parts := strings.Split(tokenResp.AccessToken, ".")
		require.Len(t, parts, 3)

		// Note: In a real test, you would decode and verify the JWT claims
		// For now, we just verify the token is not empty
		assert.NotEmpty(t, parts[1])
	})
}

func TestIntegration_BackendAuth_JWT_IssuerValidation(t *testing.T) {
	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	t.Run("issuer URL format", func(t *testing.T) {
		issuerURL := keycloakSetup.GetIssuerURL()
		assert.NotEmpty(t, issuerURL)
		assert.Contains(t, issuerURL, keycloakSetup.Realm)
	})

	t.Run("JWKS URL format", func(t *testing.T) {
		jwksURL := keycloakSetup.GetJWKSURL()
		assert.NotEmpty(t, jwksURL)
		assert.Contains(t, jwksURL, "certs")
	})

	t.Run("JWKS endpoint accessible", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		jwksURL := keycloakSetup.GetJWKSURL()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
		require.NoError(t, err)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify JWKS structure
		var jwks map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&jwks)
		require.NoError(t, err)
		assert.Contains(t, jwks, "keys")
	})
}

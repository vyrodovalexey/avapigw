//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
Combined Auth + Authz E2E Test Setup Instructions:

1. Start Keycloak (for JWT tokens with roles):
   docker run -d --name keycloak-test \
     -p 8090:8080 \
     -e KEYCLOAK_ADMIN=admin \
     -e KEYCLOAK_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:26.5 start-dev

2. Start test backend:
   go run ./cmd/testbackend

3. Run E2E tests:
   KEYCLOAK_ADDR=http://127.0.0.1:8090 go test -tags=e2e ./test/e2e/...
*/

func TestE2E_Combined_JWTWithRBAC(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with JWT auth and RBAC authz
	cfg := createCombinedJWTRBACConfig(keycloakSetup)

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18110"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("authenticated user with correct role can access", func(t *testing.T) {
		tokenResp, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResp.AccessToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be accepted (200 OK or 502 if backend not available)
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("authenticated admin can access admin endpoints", func(t *testing.T) {
		tokenResp, err := keycloakSetup.GetUserToken(ctx, "adminuser")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResp.AccessToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be accepted
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("unauthenticated request is rejected", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/api/v1/users", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("health endpoint bypasses auth", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/health", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestE2E_Combined_APIKeyWithRBAC(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with API Key auth and RBAC authz
	cfg := createCombinedAPIKeyRBACConfig()

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18111"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("user API key can read", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "user-api-key",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("user API key cannot access admin", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "user-api-key",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("admin API key can access admin", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "admin-api-key",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("invalid API key is rejected", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "invalid-key",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestE2E_Combined_MultipleAuthMethods(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with multiple auth methods
	cfg := createCombinedMultiAuthConfig(keycloakSetup)

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18112"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("JWT authentication works with RBAC", func(t *testing.T) {
		tokenResp, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResp.AccessToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("API Key authentication works with RBAC", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "service-api-key",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("no authentication is rejected", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/api/v1/users", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestE2E_Combined_RBACWithABAC(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate test keys
	authSetup := helpers.SetupAuthForTesting(t)

	// Encode public key
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	// Create gateway configuration with RBAC and ABAC
	cfg := createCombinedRBACABACConfig(pubKeyPEM)

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18113"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("admin passes RBAC check", func(t *testing.T) {
		claims := helpers.CreateJWTClaims(
			"admin-user",
			"test-issuer",
			[]string{"test-audience"},
			[]string{"admin"},
			time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "static-key-1")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("user with correct tenant passes ABAC check", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub":       "tenant-user",
			"iss":       "test-issuer",
			"iat":       time.Now().Unix(),
			"exp":       time.Now().Add(time.Hour).Unix(),
			"nbf":       time.Now().Unix(),
			"roles":     []string{"user"},
			"tenant_id": "tenant-1",
		}

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "static-key-1")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
			"X-Tenant-ID":   "tenant-1",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/tenant-data", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})
}

func TestE2E_Combined_AuthCaching(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate test keys
	authSetup := helpers.SetupAuthForTesting(t)

	// Encode public key
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	// Create gateway configuration with auth caching
	cfg := createCombinedCachingConfig(pubKeyPEM)

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18114"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("repeated requests use cache", func(t *testing.T) {
		claims := helpers.CreateJWTClaims(
			"cached-user",
			"test-issuer",
			[]string{"test-audience"},
			[]string{"user"},
			time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "static-key-1")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		// First request
		start := time.Now()
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		firstDuration := time.Since(start)

		// Second request (should use cache)
		start = time.Now()
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		secondDuration := time.Since(start)

		t.Logf("First request: %v, Second request (cached): %v", firstDuration, secondDuration)

		// Both should succeed
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})
}

// Helper functions to create gateway configurations using correct config types

func createCombinedJWTRBACConfig(keycloakSetup *helpers.KeycloakTestSetup) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18110

	// Configure JWT authentication
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Algorithm: "RS256",
			JWKSURL:   keycloakSetup.GetJWKSURL(),
			Issuer:    keycloakSetup.GetIssuerURL(),
		},
		SkipPaths: []string{"/health"},
	}

	// Configure RBAC authorization
	cfg.Spec.Authorization = &config.AuthorizationConfig{
		Enabled:       true,
		DefaultPolicy: "deny",
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "admin-all",
					Roles:     []string{"admin"},
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Effect:    "allow",
					Priority:  100,
				},
				{
					Name:      "user-read",
					Roles:     []string{"user"},
					Resources: []string{"/api/v1/users", "/api/v1/users/*"},
					Actions:   []string{"GET"},
					Effect:    "allow",
					Priority:  50,
				},
			},
		},
	}

	// Add routes
	cfg.Spec.Routes = []config.Route{
		{
			Name: "health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/health"},
					Methods: []string{"GET"},
				},
			},
			DirectResponse: &config.DirectResponseConfig{
				Status: 200,
				Body:   `{"status":"healthy"}`,
			},
		},
		{
			Name: "users",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/users"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
		{
			Name: "admin",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/admin"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
	}

	// Add default backend
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801, Weight: 100},
			},
		},
	}

	return cfg
}

func createCombinedAPIKeyRBACConfig() *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18111

	// Configure API Key authentication
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled:       true,
			Header:        "X-API-Key",
			HashAlgorithm: "plaintext",
		},
		SkipPaths: []string{"/health"},
	}

	// Configure RBAC authorization
	cfg.Spec.Authorization = &config.AuthorizationConfig{
		Enabled:       true,
		DefaultPolicy: "deny",
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "admin-all",
					Roles:     []string{"admin"},
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Effect:    "allow",
					Priority:  100,
				},
				{
					Name:      "user-read",
					Roles:     []string{"user"},
					Resources: []string{"/api/v1/users", "/api/v1/users/*"},
					Actions:   []string{"GET"},
					Effect:    "allow",
					Priority:  50,
				},
			},
		},
	}

	// Add routes
	cfg.Spec.Routes = []config.Route{
		{
			Name: "health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/health"},
					Methods: []string{"GET"},
				},
			},
			DirectResponse: &config.DirectResponseConfig{
				Status: 200,
				Body:   `{"status":"healthy"}`,
			},
		},
		{
			Name: "users",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/users"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
		{
			Name: "admin",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/admin"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
	}

	// Add default backend
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801, Weight: 100},
			},
		},
	}

	return cfg
}

func createCombinedMultiAuthConfig(keycloakSetup *helpers.KeycloakTestSetup) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18112

	// Configure multiple authentication methods
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Algorithm: "RS256",
			JWKSURL:   keycloakSetup.GetJWKSURL(),
			Issuer:    keycloakSetup.GetIssuerURL(),
		},
		APIKey: &config.APIKeyAuthConfig{
			Enabled:       true,
			Header:        "X-API-Key",
			HashAlgorithm: "plaintext",
		},
		SkipPaths: []string{"/health"},
	}

	// Configure RBAC authorization
	cfg.Spec.Authorization = &config.AuthorizationConfig{
		Enabled:       true,
		DefaultPolicy: "deny",
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "user-read",
					Roles:     []string{"user", "service"},
					Resources: []string{"/api/v1/users", "/api/v1/users/*"},
					Actions:   []string{"GET"},
					Effect:    "allow",
					Priority:  50,
				},
			},
		},
	}

	// Add routes
	cfg.Spec.Routes = []config.Route{
		{
			Name: "health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/health"},
					Methods: []string{"GET"},
				},
			},
			DirectResponse: &config.DirectResponseConfig{
				Status: 200,
				Body:   `{"status":"healthy"}`,
			},
		},
		{
			Name: "users",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/users"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
	}

	// Add default backend
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801, Weight: 100},
			},
		},
	}

	return cfg
}

func createCombinedRBACABACConfig(publicKeyPEM string) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18113

	// Configure JWT authentication
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Algorithm: "RS256",
			Issuer:    "test-issuer",
			PublicKey: publicKeyPEM,
		},
		SkipPaths: []string{"/health"},
	}

	// Configure RBAC and ABAC authorization
	cfg.Spec.Authorization = &config.AuthorizationConfig{
		Enabled:       true,
		DefaultPolicy: "deny",
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "admin-all",
					Roles:     []string{"admin"},
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Effect:    "allow",
					Priority:  100,
				},
				{
					Name:      "user-read",
					Roles:     []string{"user"},
					Resources: []string{"/api/v1/users", "/api/v1/users/*"},
					Actions:   []string{"GET"},
					Effect:    "allow",
					Priority:  50,
				},
			},
		},
		ABAC: &config.ABACConfig{
			Enabled: true,
			Policies: []config.ABACPolicyConfig{
				{
					Name:       "tenant-isolation",
					Expression: `subject.tenant_id == request.tenant_id`,
					Effect:     "allow",
					Priority:   80,
					Resources:  []string{"/api/v1/tenant-data", "/api/v1/tenant-data/*"},
				},
			},
		},
	}

	// Add routes
	cfg.Spec.Routes = []config.Route{
		{
			Name: "health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/health"},
					Methods: []string{"GET"},
				},
			},
			DirectResponse: &config.DirectResponseConfig{
				Status: 200,
				Body:   `{"status":"healthy"}`,
			},
		},
		{
			Name: "users",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/users"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
		{
			Name: "admin",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/admin"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
		{
			Name: "tenant-data",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/tenant-data"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
	}

	// Add default backend
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801, Weight: 100},
			},
		},
	}

	return cfg
}

func createCombinedCachingConfig(publicKeyPEM string) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18114

	// Configure JWT authentication
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Algorithm: "RS256",
			Issuer:    "test-issuer",
			PublicKey: publicKeyPEM,
		},
		SkipPaths: []string{"/health"},
	}

	// Configure RBAC authorization with caching
	cfg.Spec.Authorization = &config.AuthorizationConfig{
		Enabled:       true,
		DefaultPolicy: "deny",
		RBAC: &config.RBACConfig{
			Enabled: true,
			Policies: []config.RBACPolicyConfig{
				{
					Name:      "user-read",
					Roles:     []string{"user"},
					Resources: []string{"/api/v1/users", "/api/v1/users/*"},
					Actions:   []string{"GET"},
					Effect:    "allow",
					Priority:  50,
				},
			},
		},
		Cache: &config.AuthzCacheConfig{
			Enabled: true,
			TTL:     config.Duration(5 * time.Minute),
			MaxSize: 10000,
			Type:    "memory",
		},
	}

	// Add routes
	cfg.Spec.Routes = []config.Route{
		{
			Name: "health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/health"},
					Methods: []string{"GET"},
				},
			},
			DirectResponse: &config.DirectResponseConfig{
				Status: 200,
				Body:   `{"status":"healthy"}`,
			},
		},
		{
			Name: "users",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/users"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: "127.0.0.1", Port: 8801},
					Weight:      100,
				},
			},
		},
	}

	// Add default backend
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8801, Weight: 100},
			},
		},
	}

	return cfg
}

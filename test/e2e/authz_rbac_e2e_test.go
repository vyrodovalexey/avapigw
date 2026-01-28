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
RBAC E2E Test Setup Instructions:

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

func TestE2E_RBAC_Authorization(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate test keys
	authSetup := helpers.SetupAuthForTesting(t)

	// Encode public key
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	// Create gateway configuration with RBAC authorization
	cfg := createRBACAuthzGatewayConfig(pubKeyPEM)

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18100"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("admin can access all resources", func(t *testing.T) {
		// Create JWT with admin role
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

		// Admin can access /api/v1/users
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// Admin can access /api/v1/admin
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// Admin can POST to /api/v1/users
		resp, err = helpers.MakeRequestWithHeaders(http.MethodPost, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("user can read but not write", func(t *testing.T) {
		// Create JWT with user role
		claims := helpers.CreateJWTClaims(
			"regular-user",
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

		// User can GET /api/v1/users
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// User cannot access /api/v1/admin
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("reader can only read", func(t *testing.T) {
		// Create JWT with reader role
		claims := helpers.CreateJWTClaims(
			"reader-user",
			"test-issuer",
			[]string{"test-audience"},
			[]string{"reader"},
			time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "static-key-1")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		// Reader can GET /api/v1/users
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// Reader cannot POST to /api/v1/users
		resp, err = helpers.MakeRequestWithHeaders(http.MethodPost, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		// Reader cannot access /api/v1/admin
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("writer can write but not admin", func(t *testing.T) {
		// Create JWT with writer role
		claims := helpers.CreateJWTClaims(
			"writer-user",
			"test-issuer",
			[]string{"test-audience"},
			[]string{"writer"},
			time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "static-key-1")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		// Writer can POST to /api/v1/users
		resp, err := helpers.MakeRequestWithHeaders(http.MethodPost, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// Writer cannot access /api/v1/admin
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("unauthenticated request is rejected", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/api/v1/users", nil)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestE2E_RBAC_RoleHierarchy(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate test keys
	authSetup := helpers.SetupAuthForTesting(t)

	// Encode public key
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	// Create gateway configuration with role hierarchy
	cfg := createRoleHierarchyGatewayConfig(pubKeyPEM)

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18101"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("admin inherits user permissions", func(t *testing.T) {
		// Create JWT with admin role (which inherits user permissions)
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

		// Admin can access user-only endpoint
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/profile", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// Admin can access admin-only endpoint
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("user cannot access admin endpoints", func(t *testing.T) {
		// Create JWT with user role
		claims := helpers.CreateJWTClaims(
			"regular-user",
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

		// User can access user endpoint
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/profile", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// User cannot access admin endpoint
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

func TestE2E_RBAC_MultipleRoles(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate test keys
	authSetup := helpers.SetupAuthForTesting(t)

	// Encode public key
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	// Create gateway configuration
	cfg := createRBACAuthzGatewayConfig(pubKeyPEM)
	cfg.Spec.Listeners[0].Port = 18102

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18102"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("user with multiple roles has combined permissions", func(t *testing.T) {
		// Create JWT with both reader and writer roles
		claims := helpers.CreateJWTClaims(
			"multi-role-user",
			"test-issuer",
			[]string{"test-audience"},
			[]string{"reader", "writer"},
			time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "static-key-1")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		// Can read (from reader role)
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// Can write (from writer role)
		resp, err = helpers.MakeRequestWithHeaders(http.MethodPost, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// Still cannot access admin
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/admin", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

func TestE2E_RBAC_DenyPolicy(t *testing.T) {
	// Skip: This test requires authentication/authorization middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication/authorization middleware integration with gateway is not yet complete")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate test keys
	authSetup := helpers.SetupAuthForTesting(t)

	// Encode public key
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	// Create gateway configuration with deny policies
	cfg := createDenyPolicyGatewayConfig(pubKeyPEM)

	// Start gateway
	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	err = gw.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gw.Stop(ctx)
	})

	baseURL := "http://127.0.0.1:18103"

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("deny policy takes precedence", func(t *testing.T) {
		// Create JWT with user role (which has a deny policy for /api/v1/restricted)
		claims := helpers.CreateJWTClaims(
			"regular-user",
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

		// User can access /api/v1/users
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/users", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)

		// User is denied access to /api/v1/restricted (explicit deny)
		resp, err = helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/restricted", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("admin bypasses deny policy", func(t *testing.T) {
		// Create JWT with admin role (which has higher priority allow)
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

		// Admin can access /api/v1/restricted
		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/restricted", nil, headers)
		require.NoError(t, err)
		resp.Body.Close()
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})
}

// Helper functions to create gateway configurations using correct config types

func createRBACAuthzGatewayConfig(publicKeyPEM string) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18100

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
				{
					Name:      "reader-read",
					Roles:     []string{"reader"},
					Resources: []string{"/api/v1/*"},
					Actions:   []string{"GET"},
					Effect:    "allow",
					Priority:  40,
				},
				{
					Name:      "writer-write",
					Roles:     []string{"writer"},
					Resources: []string{"/api/v1/*"},
					Actions:   []string{"POST", "PUT", "PATCH", "DELETE"},
					Effect:    "allow",
					Priority:  40,
				},
				{
					Name:      "deny-admin-endpoints",
					Roles:     []string{"user", "reader", "writer"},
					Resources: []string{"/api/v1/admin", "/api/v1/admin/*"},
					Actions:   []string{"*"},
					Effect:    "deny",
					Priority:  200,
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

func createRoleHierarchyGatewayConfig(publicKeyPEM string) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18101

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

	// Configure RBAC authorization with role hierarchy
	cfg.Spec.Authorization = &config.AuthorizationConfig{
		Enabled:       true,
		DefaultPolicy: "deny",
		RBAC: &config.RBACConfig{
			Enabled: true,
			RoleHierarchy: map[string][]string{
				"admin": {"user", "reader", "writer"},
				"user":  {"reader"},
			},
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
					Name:      "user-profile",
					Roles:     []string{"user"},
					Resources: []string{"/api/v1/profile", "/api/v1/profile/*"},
					Actions:   []string{"GET", "PUT"},
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
			Name: "profile",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/profile"},
					Methods: []string{"GET", "PUT"},
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

func createDenyPolicyGatewayConfig(publicKeyPEM string) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18103

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

	// Configure RBAC authorization with deny policies
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
					Name:      "user-api",
					Roles:     []string{"user"},
					Resources: []string{"/api/v1/*"},
					Actions:   []string{"GET"},
					Effect:    "allow",
					Priority:  50,
				},
				{
					Name:      "deny-restricted",
					Roles:     []string{"user"},
					Resources: []string{"/api/v1/restricted", "/api/v1/restricted/*"},
					Actions:   []string{"*"},
					Effect:    "deny",
					Priority:  200,
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
					Methods: []string{"GET"},
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
			Name: "restricted",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/restricted"},
					Methods: []string{"GET"},
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

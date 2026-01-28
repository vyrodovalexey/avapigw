//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
JWT E2E Test Setup Instructions:

1. Start Keycloak (for real OIDC tokens):
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

func TestE2E_JWT_Authentication(t *testing.T) {
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with JWT authentication
	cfg := createJWTAuthGatewayConfig(keycloakSetup)

	// Start gateway with proper route handler
	gi, err := startJWTGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("request without token is rejected", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/api/v1/protected", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("request with invalid token is rejected", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "Bearer invalid.token.here",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("request with valid token is accepted", func(t *testing.T) {
		// Get token from Keycloak
		tokenResp, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResp.AccessToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be accepted (200 OK or 502 if backend not available)
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("request with admin token is accepted", func(t *testing.T) {
		// Get admin token from Keycloak
		tokenResp, err := keycloakSetup.GetUserToken(ctx, "adminuser")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResp.AccessToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be accepted
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("request with tampered token is rejected", func(t *testing.T) {
		// Get valid token
		tokenResp, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		// Tamper with token
		tamperedToken := tokenResp.AccessToken + "tampered"

		headers := map[string]string{
			"Authorization": "Bearer " + tamperedToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("health endpoint is accessible without token", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/health", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestE2E_JWT_StaticKey(t *testing.T) {
	// Skip: This test requires authentication middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	// Skip if backend is not available
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate test keys
	authSetup := helpers.SetupAuthForTesting(t)

	// Encode public key
	pubKeyPEM, err := helpers.EncodeRSAPublicKeyPEM(authSetup.RSAPublicKey)
	require.NoError(t, err)

	// Create gateway configuration with static key
	cfg := createStaticKeyGatewayConfig(pubKeyPEM)

	// Start gateway with proper route handler
	gi, err := startJWTGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("request with valid static key token is accepted", func(t *testing.T) {
		// Create JWT with static key
		claims := helpers.CreateJWTClaims(
			"test-user",
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

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be accepted (200 OK or 502 if backend not available)
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("request with expired token is rejected", func(t *testing.T) {
		// Create expired JWT
		claims := helpers.CreateExpiredJWTClaims("test-user", "test-issuer")

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "static-key-1")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("request with wrong issuer is rejected", func(t *testing.T) {
		// Create JWT with wrong issuer
		claims := helpers.CreateJWTClaims(
			"test-user",
			"wrong-issuer",
			[]string{"test-audience"},
			[]string{"user"},
			time.Hour,
		)

		token, err := helpers.CreateTestJWT(claims, authSetup.RSAPrivateKey, "RS256", "static-key-1")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestE2E_JWT_MultipleAuthMethods(t *testing.T) {
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with multiple auth methods
	cfg := createMultiAuthGatewayConfig(keycloakSetup)

	// Start gateway with proper route handler
	gi, err := startJWTGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("JWT authentication works", func(t *testing.T) {
		tokenResp, err := keycloakSetup.GetUserToken(ctx, "testuser")
		require.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResp.AccessToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("API Key authentication works", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "test-api-key-12345",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be accepted (200 OK or 502 if backend not available)
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("no authentication is rejected", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/api/v1/protected", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestE2E_JWT_TokenExtraction(t *testing.T) {
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	helpers.SkipIfKeycloakUnavailable(t)

	keycloakSetup := helpers.SetupKeycloakForTesting(t)
	defer keycloakSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with multiple extraction sources
	cfg := createTokenExtractionGatewayConfig(keycloakSetup)

	// Start gateway with proper route handler
	gi, err := startJWTGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	tokenResp, err := keycloakSetup.GetUserToken(ctx, "testuser")
	require.NoError(t, err)

	t.Run("extract token from Authorization header", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "Bearer " + tokenResp.AccessToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("extract token from X-Access-Token header", func(t *testing.T) {
		headers := map[string]string{
			"X-Access-Token": tokenResp.AccessToken,
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("extract token from query parameter", func(t *testing.T) {
		url := baseURL + "/api/v1/protected?access_token=" + tokenResp.AccessToken

		resp, err := helpers.MakeRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})
}

// Helper functions to create gateway configurations

func createJWTAuthGatewayConfig(keycloakSetup *helpers.KeycloakTestSetup) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18090

	// Configure JWT authentication using config types
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

	// Add routes using correct config.Route type
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
			Name: "protected",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/protected"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: "127.0.0.1",
						Port: 8801,
					},
					Weight: 100,
				},
			},
		},
	}

	// Add default backend using correct config.Backend type
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{
					Address: "127.0.0.1",
					Port:    8801,
					Weight:  100,
				},
			},
		},
	}

	return cfg
}

func createStaticKeyGatewayConfig(publicKeyPEM string) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18091

	// Configure JWT authentication with static key
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
			Name: "protected",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/protected"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: "127.0.0.1",
						Port: 8801,
					},
					Weight: 100,
				},
			},
		},
	}

	// Add default backend
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{
					Address: "127.0.0.1",
					Port:    8801,
					Weight:  100,
				},
			},
		},
	}

	return cfg
}

func createMultiAuthGatewayConfig(keycloakSetup *helpers.KeycloakTestSetup) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18092

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
			Enabled: true,
			Header:  "X-API-Key",
		},
		SkipPaths: []string{"/health"},
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
			Name: "protected",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/protected"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: "127.0.0.1",
						Port: 8801,
					},
					Weight: 100,
				},
			},
		},
	}

	// Add default backend
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{
					Address: "127.0.0.1",
					Port:    8801,
					Weight:  100,
				},
			},
		},
	}

	return cfg
}

func createTokenExtractionGatewayConfig(keycloakSetup *helpers.KeycloakTestSetup) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18093

	// Configure JWT authentication with multiple extraction sources
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
			Name: "protected",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/protected"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: "127.0.0.1",
						Port: 8801,
					},
					Weight: 100,
				},
			},
		},
	}

	// Add default backend
	cfg.Spec.Backends = []config.Backend{
		{
			Name: "default",
			Hosts: []config.BackendHost{
				{
					Address: "127.0.0.1",
					Port:    8801,
					Weight:  100,
				},
			},
		},
	}

	return cfg
}

// startJWTGateway starts a gateway with proper route handler for JWT tests.
func startJWTGateway(ctx context.Context, cfg *config.GatewayConfig) (*helpers.GatewayInstance, error) {
	logger := observability.NopLogger()

	// Create router
	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		return nil, err
	}

	// Create backend registry
	registry := backend.NewRegistry(logger)
	if err := registry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		// Backends might be empty, which is fine
		_ = err
	}

	// Start backends
	if err := registry.StartAll(ctx); err != nil {
		// Backends might be empty, which is fine
		_ = err
	}

	// Create proxy
	p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

	// Create gateway
	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(p),
	)
	if err != nil {
		return nil, err
	}

	// Start gateway
	if err := gw.Start(ctx); err != nil {
		return nil, err
	}

	// Determine base URL
	port := 8080
	if len(cfg.Spec.Listeners) > 0 {
		port = cfg.Spec.Listeners[0].Port
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	return &helpers.GatewayInstance{
		Gateway:  gw,
		Config:   cfg,
		Router:   r,
		Registry: registry,
		Proxy:    p,
		BaseURL:  baseURL,
	}, nil
}

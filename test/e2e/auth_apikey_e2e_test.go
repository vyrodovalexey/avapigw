//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
API Key E2E Test Setup Instructions:

1. For Vault-based API keys, start Vault:
   docker run -d --name vault-test \
     -p 8200:8200 \
     -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
     -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
     vault:latest

2. Start test backend:
   go run ./cmd/testbackend

3. Run E2E tests:
   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=myroot go test -tags=e2e ./test/e2e/...
*/

func TestE2E_APIKey_Authentication(t *testing.T) {
	// Skip: This test requires authentication middleware to be integrated with the gateway.
	// The gateway currently doesn't automatically apply authentication middleware based on configuration.
	// This test is designed to verify authentication behavior when the middleware is properly integrated.
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	// Skip if backend is not available
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with API Key authentication
	cfg := createAPIKeyAuthGatewayConfig()

	// Start gateway with proper route handler
	gi, err := startAPIKeyGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("request without API key is rejected", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/api/v1/protected", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("request with invalid API key is rejected", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "invalid-api-key",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("request with valid API key is accepted", func(t *testing.T) {
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

	t.Run("request with admin API key is accepted", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "admin-api-key-67890",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be accepted
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("health endpoint is accessible without API key", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, baseURL+"/health", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestE2E_APIKey_ExtractionSources(t *testing.T) {
	// Skip: This test requires authentication middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	// Skip if backend is not available
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with multiple extraction sources
	cfg := createAPIKeyExtractionGatewayConfig()

	// Start gateway with proper route handler
	gi, err := startAPIKeyGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("extract API key from X-API-Key header", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "test-api-key-12345",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("extract API key from Authorization header with ApiKey prefix", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "ApiKey test-api-key-12345",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("extract API key from query parameter", func(t *testing.T) {
		url := baseURL + "/api/v1/protected?api_key=test-api-key-12345"

		resp, err := helpers.MakeRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})
}

func TestE2E_APIKey_HashedKeys(t *testing.T) {
	// Skip: This test requires authentication middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	// Skip if backend is not available
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with hashed API keys
	cfg := createHashedAPIKeyGatewayConfig()

	// Start gateway with proper route handler
	gi, err := startAPIKeyGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("request with valid API key (hashed storage) is accepted", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "hashed-api-key-secret",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("request with wrong API key is rejected", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "wrong-api-key",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestE2E_APIKey_VaultStore(t *testing.T) {
	// Skip: This test requires authentication middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	helpers.SkipIfVaultUnavailable(t)

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
	vaultClientCfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	vaultClient, err := vault.New(vaultClientCfg, observability.NopLogger())
	require.NoError(t, err)
	defer vaultClient.Close()

	err = vaultClient.Authenticate(ctx)
	require.NoError(t, err)

	// Store test API keys in Vault
	testKeys := []struct {
		key    string
		id     string
		scopes []string
		roles  []string
	}{
		{
			key:    "vault-api-key-user",
			id:     "vault-user-key",
			scopes: []string{"read"},
			roles:  []string{"user"},
		},
		{
			key:    "vault-api-key-admin",
			id:     "vault-admin-key",
			scopes: []string{"read", "write", "admin"},
			roles:  []string{"admin"},
		},
	}

	for _, tk := range testKeys {
		keyHash := hashKey(tk.key)
		keyPath := "apikeys/" + keyHash

		keyData := map[string]interface{}{
			"id":      tk.id,
			"hash":    keyHash,
			"scopes":  tk.scopes,
			"roles":   tk.roles,
			"enabled": true,
		}

		err := vaultSetup.WriteSecret(keyPath, keyData)
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		for _, tk := range testKeys {
			keyHash := hashKey(tk.key)
			_ = vaultSetup.DeleteSecret("apikeys/" + keyHash)
		}
	})

	// Create gateway configuration with Vault API key store
	cfg := createVaultAPIKeyGatewayConfig(vaultCfg)

	// Start gateway with proper route handler
	gi, err := startAPIKeyGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("request with Vault-stored API key is accepted", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "vault-api-key-user",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("request with Vault-stored admin API key is accepted", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "vault-api-key-admin",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})

	t.Run("request with non-existent API key is rejected", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "non-existent-key",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestE2E_APIKey_RateLimiting(t *testing.T) {
	// Skip: This test requires authentication middleware to be integrated with the gateway.
	t.Skip("Skipping: Authentication middleware integration with gateway is not yet complete")

	// Skip if backend is not available
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create gateway configuration with rate-limited API keys
	cfg := createRateLimitedAPIKeyGatewayConfig()

	// Start gateway with proper route handler
	gi, err := startAPIKeyGateway(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	baseURL := gi.BaseURL

	// Wait for gateway to be ready
	err = helpers.WaitForReady(baseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("requests within rate limit are accepted", func(t *testing.T) {
		headers := map[string]string{
			"X-API-Key": "rate-limited-key",
		}

		// Make a few requests within the limit
		for i := 0; i < 3; i++ {
			resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, baseURL+"/api/v1/protected", nil, headers)
			require.NoError(t, err)
			resp.Body.Close()

			// Should be accepted (200 OK or 502 if backend not available)
			assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
				"Request %d: Expected 200 or 502, got %d", i+1, resp.StatusCode)
		}
	})
}

// Helper functions to create gateway configurations

func createAPIKeyAuthGatewayConfig() *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18094

	// Configure API Key authentication using config types
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled:       true,
			Header:        "X-API-Key",
			HashAlgorithm: "plaintext",
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

func createAPIKeyExtractionGatewayConfig() *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18095

	// Configure API Key authentication with multiple extraction sources
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled:       true,
			Header:        "X-API-Key",
			Query:         "api_key",
			HashAlgorithm: "plaintext",
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

func createHashedAPIKeyGatewayConfig() *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18096

	// Configure API Key authentication with hashed keys
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled:       true,
			Header:        "X-API-Key",
			HashAlgorithm: "sha256",
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

func createVaultAPIKeyGatewayConfig(vaultCfg helpers.VaultTestConfig) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18097

	// Configure API Key authentication with Vault store
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled:       true,
			Header:        "X-API-Key",
			HashAlgorithm: "sha256",
			VaultPath:     "apikeys",
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

func createRateLimitedAPIKeyGatewayConfig() *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Spec.Listeners[0].Port = 18098

	// Configure API Key authentication with rate limiting
	cfg.Spec.Authentication = &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled:       true,
			Header:        "X-API-Key",
			HashAlgorithm: "plaintext",
		},
		SkipPaths: []string{"/health"},
	}

	// Configure rate limiting at the gateway level
	cfg.Spec.RateLimit = &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             5,
		PerClient:         true,
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

// hashKey hashes a key using SHA-256.
func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// startAPIKeyGateway starts a gateway with proper route handler for API key tests.
func startAPIKeyGateway(ctx context.Context, cfg *config.GatewayConfig) (*helpers.GatewayInstance, error) {
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

package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Factory CreateClient Tests
// ============================================================================

func TestFactory_CreateClient(t *testing.T) {
	t.Run("creates client with token auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/lookup-self" {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":        "test-token",
						"ttl":       3600,
						"renewable": true,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
		}))
		defer server.Close()

		factoryConfig := &FactoryConfig{
			Address:    server.URL,
			AuthMethod: "token",
			Token:      "test-token",
			Timeout:    30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		client, err := factory.CreateClient(ctx)

		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.True(t, client.IsAuthenticated())
	})

	t.Run("creates client with token from environment", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/lookup-self" {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":        "env-token",
						"ttl":       3600,
						"renewable": true,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
		}))
		defer server.Close()

		// Set environment variable
		os.Setenv("VAULT_TOKEN", "env-token")
		defer os.Unsetenv("VAULT_TOKEN")

		factoryConfig := &FactoryConfig{
			Address:    server.URL,
			AuthMethod: "token",
			Token:      "", // Empty - should use env var
			Timeout:    30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		client, err := factory.CreateClient(ctx)

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("fails when token auth has no token", func(t *testing.T) {
		// Ensure env var is not set
		os.Unsetenv("VAULT_TOKEN")

		factoryConfig := &FactoryConfig{
			Address:    "http://vault:8200",
			AuthMethod: "token",
			Token:      "",
			Timeout:    30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		_, err := factory.CreateClient(ctx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is required")
	})

	t.Run("creates client with kubernetes auth", func(t *testing.T) {
		// This test will fail at authentication because we don't have a real K8s token
		// but it tests the auth method creation path
		factoryConfig := &FactoryConfig{
			Address:    "http://vault:8200",
			AuthMethod: "kubernetes",
			Role:       "test-role",
			MountPath:  "kubernetes",
			Timeout:    30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		_, err := factory.CreateClient(ctx)

		// Should fail at authentication (no K8s token file)
		require.Error(t, err)
	})

	t.Run("creates client with approle auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/approle/login" {
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "approle-token",
						"renewable":      true,
						"lease_duration": 3600,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
		}))
		defer server.Close()

		factoryConfig := &FactoryConfig{
			Address:         server.URL,
			AuthMethod:      "approle",
			AppRoleID:       "test-role-id",
			AppRoleSecretID: "test-secret-id",
			Timeout:         30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		client, err := factory.CreateClient(ctx)

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("creates client with approle secret from environment", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/approle/login" {
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "approle-token",
						"renewable":      true,
						"lease_duration": 3600,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
		}))
		defer server.Close()

		// Set environment variable
		os.Setenv("VAULT_APPROLE_SECRET_ID", "env-secret-id")
		defer os.Unsetenv("VAULT_APPROLE_SECRET_ID")

		factoryConfig := &FactoryConfig{
			Address:         server.URL,
			AuthMethod:      "approle",
			AppRoleID:       "test-role-id",
			AppRoleSecretID: "", // Empty - should use env var
			Timeout:         30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		client, err := factory.CreateClient(ctx)

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("fails when approle has no role_id", func(t *testing.T) {
		factoryConfig := &FactoryConfig{
			Address:         "http://vault:8200",
			AuthMethod:      "approle",
			AppRoleID:       "",
			AppRoleSecretID: "secret-id",
			Timeout:         30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		_, err := factory.CreateClient(ctx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "role_id is required")
	})

	t.Run("fails with unsupported auth method", func(t *testing.T) {
		factoryConfig := &FactoryConfig{
			Address:    "http://vault:8200",
			AuthMethod: "unsupported",
			Timeout:    30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		_, err := factory.CreateClient(ctx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported auth method")
	})

	t.Run("fails when authentication fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			response := map[string]interface{}{
				"errors": []string{"permission denied"},
			}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		factoryConfig := &FactoryConfig{
			Address:    server.URL,
			AuthMethod: "token",
			Token:      "invalid-token",
			Timeout:    30 * time.Second,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())

		ctx := context.Background()
		_, err := factory.CreateClient(ctx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to authenticate")
	})
}

// ============================================================================
// Factory CreateSecretManager Extended Tests
// ============================================================================

func TestFactory_CreateSecretManager_Extended(t *testing.T) {
	t.Run("creates secret manager with cache enabled", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		factoryConfig := &FactoryConfig{
			CacheEnabled: true,
			CacheTTL:     10 * time.Minute,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())
		manager := factory.CreateSecretManager(client)

		assert.NotNil(t, manager)
		assert.NotNil(t, manager.cache)
	})

	t.Run("creates secret manager with cache disabled", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)

		factoryConfig := &FactoryConfig{
			CacheEnabled: false,
		}

		factory := NewFactory(factoryConfig, zap.NewNop())
		manager := factory.CreateSecretManager(client)

		assert.NotNil(t, manager)
	})
}

// ============================================================================
// VaultService Tests
// ============================================================================

func TestNewVaultService(t *testing.T) {
	t.Run("creates vault service successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/lookup-self" {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":        "test-token",
						"ttl":       3600,
						"renewable": true,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
		}))
		defer server.Close()

		config := &FactoryConfig{
			Address:             server.URL,
			AuthMethod:          "token",
			Token:               "test-token",
			Timeout:             30 * time.Second,
			TokenRenewalEnabled: false,
		}

		ctx := context.Background()
		service, err := NewVaultService(ctx, config, zap.NewNop())

		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.NotNil(t, service.Client())
		assert.NotNil(t, service.SecretManager())
		assert.NotNil(t, service.KV2Client())
		assert.NotNil(t, service.CertificateManager())

		err = service.Close()
		assert.NoError(t, err)
	})

	t.Run("creates vault service with token renewal enabled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/lookup-self" {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":        "test-token",
						"ttl":       3600,
						"renewable": true,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
		}))
		defer server.Close()

		config := &FactoryConfig{
			Address:              server.URL,
			AuthMethod:           "token",
			Token:                "test-token",
			Timeout:              30 * time.Second,
			TokenRenewalEnabled:  true,
			TokenRenewalInterval: 5 * time.Minute, // Must be positive for NewTicker
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		service, err := NewVaultService(ctx, config, zap.NewNop())

		require.NoError(t, err)
		assert.NotNil(t, service)

		// Cancel context first to stop renewal manager
		cancel()
		time.Sleep(50 * time.Millisecond) // Give time for goroutines to stop

		err = service.Close()
		assert.NoError(t, err)
	})

	t.Run("fails when client creation fails", func(t *testing.T) {
		config := &FactoryConfig{
			Address:    "http://vault:8200",
			AuthMethod: "unsupported",
			Timeout:    30 * time.Second,
		}

		ctx := context.Background()
		_, err := NewVaultService(ctx, config, zap.NewNop())

		require.Error(t, err)
	})
}

// ============================================================================
// VaultService Close Extended Tests
// ============================================================================

func TestVaultService_Close_Extended(t *testing.T) {
	t.Run("closes all components", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/token/lookup-self" {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":        "test-token",
						"ttl":       3600,
						"renewable": true,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}
		}))
		defer server.Close()

		config := &FactoryConfig{
			Address:              server.URL,
			AuthMethod:           "token",
			Token:                "test-token",
			Timeout:              30 * time.Second,
			TokenRenewalEnabled:  true,
			TokenRenewalInterval: 5 * time.Minute, // Must be positive for NewTicker
		}

		ctx, cancel := context.WithCancel(context.Background())
		service, err := NewVaultService(ctx, config, zap.NewNop())
		require.NoError(t, err)

		// Cancel context first to stop renewal manager
		cancel()
		time.Sleep(50 * time.Millisecond) // Give time for goroutines to stop

		err = service.Close()
		assert.NoError(t, err)

		// Verify client is closed
		assert.True(t, service.client.closed)
	})
}

// ============================================================================
// VaultService Accessor Extended Tests
// ============================================================================

func TestVaultService_Accessors_Extended(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"id":        "test-token",
					"ttl":       3600,
					"renewable": true,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	config := &FactoryConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
		Timeout:    30 * time.Second,
	}

	ctx := context.Background()
	service, err := NewVaultService(ctx, config, zap.NewNop())
	require.NoError(t, err)
	defer service.Close()

	t.Run("Client returns client", func(t *testing.T) {
		assert.NotNil(t, service.Client())
	})

	t.Run("SecretManager returns secret manager", func(t *testing.T) {
		assert.NotNil(t, service.SecretManager())
	})

	t.Run("KV2Client returns KV2 client", func(t *testing.T) {
		assert.NotNil(t, service.KV2Client())
	})

	t.Run("CertificateManager returns certificate manager", func(t *testing.T) {
		assert.NotNil(t, service.CertificateManager())
	})
}

package auth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// mockVaultClientForJWT implements vault.Client for JWT testing.
type mockVaultClientForJWT struct {
	enabled   bool
	kvClient  *mockKVClientForJWT
	pkiClient *mockPKIClientForJWT
}

func newMockVaultClientForJWT(enabled bool) *mockVaultClientForJWT {
	return &mockVaultClientForJWT{
		enabled:   enabled,
		kvClient:  &mockKVClientForJWT{},
		pkiClient: &mockPKIClientForJWT{},
	}
}

func (m *mockVaultClientForJWT) IsEnabled() bool                      { return m.enabled }
func (m *mockVaultClientForJWT) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClientForJWT) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClientForJWT) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClientForJWT) PKI() vault.PKIClient         { return m.pkiClient }
func (m *mockVaultClientForJWT) KV() vault.KVClient           { return m.kvClient }
func (m *mockVaultClientForJWT) Transit() vault.TransitClient { return nil }
func (m *mockVaultClientForJWT) Close() error                 { return nil }

// mockKVClientForJWT implements vault.KVClient for JWT testing.
type mockKVClientForJWT struct {
	data    map[string]interface{}
	readErr error
}

func (m *mockKVClientForJWT) Read(_ context.Context, _, _ string) (map[string]interface{}, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	return m.data, nil
}

func (m *mockKVClientForJWT) Write(_ context.Context, _, _ string, _ map[string]interface{}) error {
	return nil
}

func (m *mockKVClientForJWT) Delete(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockKVClientForJWT) List(_ context.Context, _, _ string) ([]string, error) {
	return []string{}, nil
}

// mockPKIClientForJWT implements vault.PKIClient for JWT testing.
type mockPKIClientForJWT struct{}

func (m *mockPKIClientForJWT) IssueCertificate(_ context.Context, _ *vault.PKIIssueOptions) (*vault.Certificate, error) {
	return nil, nil
}

func (m *mockPKIClientForJWT) SignCSR(_ context.Context, _ []byte, _ *vault.PKISignOptions) (*vault.Certificate, error) {
	return nil, nil
}

func (m *mockPKIClientForJWT) GetCA(_ context.Context, _ string) (*x509.CertPool, error) {
	return nil, nil
}

func (m *mockPKIClientForJWT) GetCRL(_ context.Context, _ string) ([]byte, error) {
	return []byte{}, nil
}

func (m *mockPKIClientForJWT) RevokeCertificate(_ context.Context, _, _ string) error {
	return nil
}

func TestNewJWTProvider(t *testing.T) {
	t.Parallel()

	t.Run("creates provider with valid static config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "test-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "test-provider", provider.Name())
		assert.Equal(t, "jwt", provider.Type())
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		t.Parallel()

		_, err := NewJWTProvider("test-provider", nil)
		assert.Error(t, err)
	})

	t.Run("returns error when not enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled: false,
		}

		_, err := NewJWTProvider("test-provider", cfg)
		assert.Error(t, err)
	})

	t.Run("returns error for invalid config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: "invalid",
		}

		_, err := NewJWTProvider("test-provider", cfg)
		assert.Error(t, err)
	})

	t.Run("applies options", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "test-token",
		}

		metrics := NopMetrics()
		provider, err := NewJWTProvider("test-provider", cfg, WithMetrics(metrics))
		require.NoError(t, err)
		assert.NotNil(t, provider.metrics)
	})
}

func TestJWTProvider_ApplyHTTP(t *testing.T) {
	t.Parallel()

	t.Run("applies static token to request", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		assert.Equal(t, "Bearer my-jwt-token", req.Header.Get("Authorization"))
	})

	t.Run("uses custom header name", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
			HeaderName:  "X-Auth-Token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		assert.Equal(t, "Bearer my-jwt-token", req.Header.Get("X-Auth-Token"))
	})

	t.Run("uses custom header prefix", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:      true,
			TokenSource:  TokenSourceStatic,
			StaticToken:  "my-jwt-token",
			HeaderPrefix: "Token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		assert.Equal(t, "Token my-jwt-token", req.Header.Get("Authorization"))
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		err = provider.ApplyHTTP(context.Background(), req)
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestJWTProvider_ApplyGRPC(t *testing.T) {
	t.Parallel()

	t.Run("returns dial options with static token", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		opts, err := provider.ApplyGRPC(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, opts)
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		_, err = provider.ApplyGRPC(context.Background())
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestJWTProvider_Refresh(t *testing.T) {
	t.Parallel()

	t.Run("refreshes token successfully", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Refresh(context.Background())
		assert.NoError(t, err)
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		err = provider.Refresh(context.Background())
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestJWTProvider_Close(t *testing.T) {
	t.Parallel()

	t.Run("closes provider successfully", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)
	})

	t.Run("close is idempotent", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)
	})
}

func TestJWTProvider_TokenCaching(t *testing.T) {
	t.Parallel()

	t.Run("caches static token", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "my-jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		// First request
		req1, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req1)
		require.NoError(t, err)

		// Second request should use cached token
		req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req2)
		require.NoError(t, err)

		assert.Equal(t, req1.Header.Get("Authorization"), req2.Header.Get("Authorization"))
	})
}

func TestJWTProvider_OIDC(t *testing.T) {
	t.Parallel()

	t.Run("fetches token from OIDC provider", func(t *testing.T) {
		t.Parallel()

		// Create mock OIDC server
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"token_endpoint": "http://" + r.Host + "/token",
				})
				return
			}
			if r.URL.Path == "/token" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "oidc-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer discoveryServer.Close()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceOIDC,
			OIDC: &config.BackendOIDCConfig{
				IssuerURL:    discoveryServer.URL,
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		assert.Equal(t, "Bearer oidc-access-token", req.Header.Get("Authorization"))
	})

	t.Run("returns error for missing OIDC config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceOIDC,
			// Missing OIDC config
		}

		_, err := NewJWTProvider("test-provider", cfg)
		assert.Error(t, err)
	})
}

func TestJWTProvider_VaultToken(t *testing.T) {
	t.Parallel()

	t.Run("returns error when vault not available", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestJwtPerRPCCredentials(t *testing.T) {
	t.Parallel()

	t.Run("returns correct metadata", func(t *testing.T) {
		t.Parallel()

		creds := &jwtPerRPCCredentials{
			token:        "test-token",
			headerName:   "Authorization",
			headerPrefix: "Bearer",
		}

		metadata, err := creds.GetRequestMetadata(context.Background())
		require.NoError(t, err)

		assert.Equal(t, "Bearer test-token", metadata["authorization"])
	})

	t.Run("does not require transport security", func(t *testing.T) {
		t.Parallel()

		creds := &jwtPerRPCCredentials{}
		assert.False(t, creds.RequireTransportSecurity())
	})
}

func TestJWTProvider_GetEffectiveHeaderName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headerName string
		expected   string
	}{
		{
			name:       "default header name",
			headerName: "",
			expected:   "Authorization",
		},
		{
			name:       "custom header name",
			headerName: "X-Auth-Token",
			expected:   "X-Auth-Token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.BackendJWTAuthConfig{
				HeaderName: tt.headerName,
			}
			assert.Equal(t, tt.expected, cfg.GetEffectiveHeaderName())
		})
	}
}

func TestJWTProvider_GetEffectiveHeaderPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		headerPrefix string
		expected     string
	}{
		{
			name:         "default header prefix",
			headerPrefix: "",
			expected:     "Bearer",
		},
		{
			name:         "custom header prefix",
			headerPrefix: "Token",
			expected:     "Token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.BackendJWTAuthConfig{
				HeaderPrefix: tt.headerPrefix,
			}
			assert.Equal(t, tt.expected, cfg.GetEffectiveHeaderPrefix())
		})
	}
}

func TestJWTProvider_TokenSourceConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "static", TokenSourceStatic)
	assert.Equal(t, "vault", TokenSourceVault)
	assert.Equal(t, "oidc", TokenSourceOIDC)
}

func TestJWTProvider_DefaultConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 5*time.Minute, DefaultTokenCacheTTL)
	assert.Equal(t, 30*time.Second, DefaultTokenRefreshTime)
	assert.Equal(t, 30*time.Second, DefaultOIDCTimeout)
	assert.Equal(t, "Authorization", DefaultHeaderName)
	assert.Equal(t, "Bearer", DefaultHeaderPrefix)
}

func TestJWTProvider_VaultToken_WithMock(t *testing.T) {
	t.Parallel()

	t.Run("successfully retrieves token from vault", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.data = map[string]interface{}{
			"token": "vault-jwt-token",
		}

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		assert.Equal(t, "Bearer vault-jwt-token", req.Header.Get("Authorization"))
	})

	t.Run("caches token from vault", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.data = map[string]interface{}{
			"token": "vault-jwt-token",
		}

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		// First request
		req1, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req1)
		require.NoError(t, err)

		// Second request should use cached token
		req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req2)
		require.NoError(t, err)

		assert.Equal(t, req1.Header.Get("Authorization"), req2.Header.Get("Authorization"))
	})

	t.Run("returns error when vault read fails", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.readErr = errors.New("vault read error")

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error when token not found in vault secret", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.data = map[string]interface{}{
			"other_key": "some-value",
			// Missing "token" key
		}

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error for invalid vault path format", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "invalid-path-without-slash",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error when vault client is disabled", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(false)

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestJWTProvider_Refresh_WithVault(t *testing.T) {
	t.Parallel()

	t.Run("refresh clears cache and fetches new token from vault", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.data = map[string]interface{}{
			"token": "vault-jwt-token-1",
		}

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		// First, apply to cache token
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "Bearer vault-jwt-token-1", req.Header.Get("Authorization"))

		// Update mock data
		mockClient.kvClient.data = map[string]interface{}{
			"token": "vault-jwt-token-2",
		}

		// Refresh should clear cache and fetch new token
		err = provider.Refresh(context.Background())
		require.NoError(t, err)

		// Apply again and verify new token
		req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req2)
		require.NoError(t, err)
		assert.Equal(t, "Bearer vault-jwt-token-2", req2.Header.Get("Authorization"))
	})

	t.Run("refresh returns error when vault read fails", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.data = map[string]interface{}{
			"token": "vault-jwt-token",
		}

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		// First, apply to cache token
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		// Set error for next read
		mockClient.kvClient.readErr = errors.New("vault read error")

		// Refresh should fail
		err = provider.Refresh(context.Background())
		assert.Error(t, err)
	})
}

func TestJWTProvider_ApplyGRPC_WithVault(t *testing.T) {
	t.Parallel()

	t.Run("returns dial options with vault token", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.data = map[string]interface{}{
			"token": "vault-jwt-token",
		}

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		opts, err := provider.ApplyGRPC(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, opts)
	})

	t.Run("returns error when vault read fails", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.readErr = errors.New("vault read error")

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceVault,
			VaultPath:   "secret/jwt-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		_, err = provider.ApplyGRPC(context.Background())
		assert.Error(t, err)
	})
}

func TestJWTProvider_OIDC_WithVaultSecret(t *testing.T) {
	t.Parallel()

	t.Run("fetches client secret from vault for OIDC", func(t *testing.T) {
		t.Parallel()

		// Create mock OIDC server
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"token_endpoint": "http://" + r.Host + "/token",
				})
				return
			}
			if r.URL.Path == "/token" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "oidc-access-token-from-vault-secret",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer discoveryServer.Close()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.data = map[string]interface{}{
			"client_secret": "vault-client-secret",
		}

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceOIDC,
			OIDC: &config.BackendOIDCConfig{
				IssuerURL:             discoveryServer.URL,
				ClientID:              "test-client",
				ClientSecretVaultPath: "secret/oidc-secret",
			},
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		assert.Equal(t, "Bearer oidc-access-token-from-vault-secret", req.Header.Get("Authorization"))
	})

	t.Run("returns error when vault secret read fails for OIDC", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForJWT(true)
		mockClient.kvClient.readErr = errors.New("vault read error")

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceOIDC,
			OIDC: &config.BackendOIDCConfig{
				IssuerURL:             "http://example.com",
				ClientID:              "test-client",
				ClientSecretVaultPath: "secret/oidc-secret",
			},
		}

		provider, err := NewJWTProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestJWTProvider_OIDC_Errors(t *testing.T) {
	t.Parallel()

	t.Run("returns error when discovery fails", func(t *testing.T) {
		t.Parallel()

		// Create mock server that returns error
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}))
		defer discoveryServer.Close()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceOIDC,
			OIDC: &config.BackendOIDCConfig{
				IssuerURL:    discoveryServer.URL,
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error when token request fails", func(t *testing.T) {
		t.Parallel()

		// Create mock OIDC server
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"token_endpoint": "http://" + r.Host + "/token",
				})
				return
			}
			if r.URL.Path == "/token" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.NotFound(w, r)
		}))
		defer discoveryServer.Close()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceOIDC,
			OIDC: &config.BackendOIDCConfig{
				IssuerURL:    discoveryServer.URL,
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error when token response is invalid JSON", func(t *testing.T) {
		t.Parallel()

		// Create mock OIDC server
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"token_endpoint": "http://" + r.Host + "/token",
				})
				return
			}
			if r.URL.Path == "/token" {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte("invalid json"))
				return
			}
			http.NotFound(w, r)
		}))
		defer discoveryServer.Close()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceOIDC,
			OIDC: &config.BackendOIDCConfig{
				IssuerURL:    discoveryServer.URL,
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error when discovery document missing token_endpoint", func(t *testing.T) {
		t.Parallel()

		// Create mock OIDC server that returns discovery without token_endpoint
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"issuer": "http://example.com",
					// Missing token_endpoint
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer discoveryServer.Close()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceOIDC,
			OIDC: &config.BackendOIDCConfig{
				IssuerURL:    discoveryServer.URL,
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestJWTProvider_StaticToken_Errors(t *testing.T) {
	t.Parallel()

	t.Run("returns error when static token is empty", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "", // Empty token
		}

		_, err := NewJWTProvider("test-provider", cfg)
		assert.Error(t, err)
	})
}

func TestJWTProvider_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("handles concurrent HTTP requests safely", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "test-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
					_ = provider.ApplyHTTP(context.Background(), req)
				}
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("handles concurrent gRPC requests safely", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: TokenSourceStatic,
			StaticToken: "test-token",
		}

		provider, err := NewJWTProvider("test-provider", cfg)
		require.NoError(t, err)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					_, _ = provider.ApplyGRPC(context.Background())
				}
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

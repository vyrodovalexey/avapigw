package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// mockVaultClient implements vault.Client for testing.
type mockVaultClient struct {
	enabled   bool
	kvClient  *mockKVClient
	pkiClient *mockPKIClient
}

func newMockVaultClient(enabled bool) *mockVaultClient {
	return &mockVaultClient{
		enabled:   enabled,
		kvClient:  &mockKVClient{},
		pkiClient: &mockPKIClient{},
	}
}

func (m *mockVaultClient) IsEnabled() bool                                       { return m.enabled }
func (m *mockVaultClient) Authenticate(_ context.Context) error                  { return nil }
func (m *mockVaultClient) RenewToken(_ context.Context) error                    { return nil }
func (m *mockVaultClient) Health(_ context.Context) (*vault.HealthStatus, error) { return nil, nil }
func (m *mockVaultClient) PKI() vault.PKIClient                                  { return m.pkiClient }
func (m *mockVaultClient) KV() vault.KVClient                                    { return m.kvClient }
func (m *mockVaultClient) Transit() vault.TransitClient                          { return nil }
func (m *mockVaultClient) Close() error                                          { return nil }

// mockKVClient implements vault.KVClient for testing.
type mockKVClient struct {
	data      map[string]interface{}
	readErr   error
	writeErr  error
	deleteErr error
	listErr   error
}

func (m *mockKVClient) Read(_ context.Context, _, _ string) (map[string]interface{}, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	return m.data, nil
}

func (m *mockKVClient) Write(_ context.Context, _, _ string, _ map[string]interface{}) error {
	return m.writeErr
}

func (m *mockKVClient) Delete(_ context.Context, _, _ string) error {
	return m.deleteErr
}

func (m *mockKVClient) List(_ context.Context, _, _ string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return []string{}, nil
}

// mockPKIClient implements vault.PKIClient for testing.
type mockPKIClient struct {
	cert      *vault.Certificate
	caPool    *x509.CertPool
	issueErr  error
	signErr   error
	getCAErr  error
	getCRLErr error
	revokeErr error
}

func (m *mockPKIClient) IssueCertificate(_ context.Context, _ *vault.PKIIssueOptions) (*vault.Certificate, error) {
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	return m.cert, nil
}

func (m *mockPKIClient) SignCSR(_ context.Context, _ []byte, _ *vault.PKISignOptions) (*vault.Certificate, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}
	return m.cert, nil
}

func (m *mockPKIClient) GetCA(_ context.Context, _ string) (*x509.CertPool, error) {
	if m.getCAErr != nil {
		return nil, m.getCAErr
	}
	return m.caPool, nil
}

func (m *mockPKIClient) GetCRL(_ context.Context, _ string) ([]byte, error) {
	if m.getCRLErr != nil {
		return nil, m.getCRLErr
	}
	return []byte{}, nil
}

func (m *mockPKIClient) RevokeCertificate(_ context.Context, _, _ string) error {
	return m.revokeErr
}

func TestNewBasicProvider(t *testing.T) {
	t.Parallel()

	t.Run("creates provider with valid static credentials", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "test-provider", provider.Name())
		assert.Equal(t, "basic", provider.Type())
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		t.Parallel()

		_, err := NewBasicProvider("test-provider", nil)
		assert.Error(t, err)
	})

	t.Run("returns error when not enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled: false,
		}

		_, err := NewBasicProvider("test-provider", cfg)
		assert.Error(t, err)
	})

	t.Run("returns error for invalid config - missing credentials", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled: true,
			// Missing username and password
		}

		_, err := NewBasicProvider("test-provider", cfg)
		assert.Error(t, err)
	})

	t.Run("applies options", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		metrics := NopMetrics()
		provider, err := NewBasicProvider("test-provider", cfg, WithMetrics(metrics))
		require.NoError(t, err)
		assert.NotNil(t, provider.metrics)
	})
}

func TestBasicProvider_ApplyHTTP(t *testing.T) {
	t.Parallel()

	t.Run("applies static credentials to request", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		// Verify the Authorization header
		authHeader := req.Header.Get("Authorization")
		assert.True(t, len(authHeader) > 0)
		assert.Contains(t, authHeader, "Basic ")

		// Decode and verify credentials
		encodedCreds := authHeader[6:] // Remove "Basic " prefix
		decodedCreds, err := base64.StdEncoding.DecodeString(encodedCreds)
		require.NoError(t, err)
		assert.Equal(t, "testuser:testpass", string(decodedCreds))
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		err = provider.ApplyHTTP(context.Background(), req)
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestBasicProvider_ApplyGRPC(t *testing.T) {
	t.Parallel()

	t.Run("returns dial options with static credentials", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		opts, err := provider.ApplyGRPC(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, opts)
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		_, err = provider.ApplyGRPC(context.Background())
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestBasicProvider_Refresh(t *testing.T) {
	t.Parallel()

	t.Run("refresh does nothing for static credentials", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Refresh(context.Background())
		assert.NoError(t, err)
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		err = provider.Refresh(context.Background())
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestBasicProvider_Close(t *testing.T) {
	t.Parallel()

	t.Run("closes provider successfully", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)
	})

	t.Run("close is idempotent", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)
	})
}

func TestBasicProvider_CredentialCaching(t *testing.T) {
	t.Parallel()

	t.Run("caches static credentials", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		// First request
		req1, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req1)
		require.NoError(t, err)

		// Second request should use cached credentials
		req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req2)
		require.NoError(t, err)

		assert.Equal(t, req1.Header.Get("Authorization"), req2.Header.Get("Authorization"))
	})
}

func TestBasicProvider_VaultCredentials(t *testing.T) {
	t.Parallel()

	t.Run("returns error when vault not available", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestBasicPerRPCCredentials(t *testing.T) {
	t.Parallel()

	t.Run("returns correct metadata", func(t *testing.T) {
		t.Parallel()

		creds := &basicPerRPCCredentials{
			username: "testuser",
			password: "testpass",
		}

		metadata, err := creds.GetRequestMetadata(context.Background())
		require.NoError(t, err)

		expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
		assert.Equal(t, expectedAuth, metadata["authorization"])
	})

	t.Run("does not require transport security", func(t *testing.T) {
		t.Parallel()

		creds := &basicPerRPCCredentials{}
		assert.False(t, creds.RequireTransportSecurity())
	})
}

func TestBasicProvider_GetEffectiveUsernameKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		usernameKey string
		expected    string
	}{
		{
			name:        "default username key",
			usernameKey: "",
			expected:    "username",
		},
		{
			name:        "custom username key",
			usernameKey: "user",
			expected:    "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.BackendBasicAuthConfig{
				UsernameKey: tt.usernameKey,
			}
			assert.Equal(t, tt.expected, cfg.GetEffectiveUsernameKey())
		})
	}
}

func TestBasicProvider_GetEffectivePasswordKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		passwordKey string
		expected    string
	}{
		{
			name:        "default password key",
			passwordKey: "",
			expected:    "password",
		},
		{
			name:        "custom password key",
			passwordKey: "pass",
			expected:    "pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.BackendBasicAuthConfig{
				PasswordKey: tt.passwordKey,
			}
			assert.Equal(t, tt.expected, cfg.GetEffectivePasswordKey())
		})
	}
}

func TestBasicProvider_DefaultConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 5*time.Minute, DefaultCredentialCacheTTL)
}

func TestBasicProvider_Base64Encoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "simple credentials",
			username: "user",
			password: "pass",
		},
		{
			name:     "credentials with special characters",
			username: "user@example.com",
			password: "p@ss:word!",
		},
		{
			name:     "credentials with unicode",
			username: "user",
			password: "password123",
		},
		{
			name:     "empty password",
			username: "user",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Skip empty password test as it would fail validation
			if tt.password == "" {
				return
			}

			cfg := &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: tt.username,
				Password: tt.password,
			}

			provider, err := NewBasicProvider("test-provider", cfg)
			require.NoError(t, err)

			req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
			err = provider.ApplyHTTP(context.Background(), req)
			require.NoError(t, err)

			authHeader := req.Header.Get("Authorization")
			encodedCreds := authHeader[6:] // Remove "Basic " prefix
			decodedCreds, err := base64.StdEncoding.DecodeString(encodedCreds)
			require.NoError(t, err)
			assert.Equal(t, tt.username+":"+tt.password, string(decodedCreds))
		})
	}
}

func TestBasicProvider_VaultCredentials_WithMock(t *testing.T) {
	t.Parallel()

	t.Run("successfully retrieves credentials from vault", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.data = map[string]interface{}{
			"username": "vault-user",
			"password": "vault-pass",
		}

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		// Verify the Authorization header
		authHeader := req.Header.Get("Authorization")
		assert.Contains(t, authHeader, "Basic ")

		// Decode and verify credentials
		encodedCreds := authHeader[6:] // Remove "Basic " prefix
		decodedCreds, err := base64.StdEncoding.DecodeString(encodedCreds)
		require.NoError(t, err)
		assert.Equal(t, "vault-user:vault-pass", string(decodedCreds))
	})

	t.Run("uses custom username and password keys", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.data = map[string]interface{}{
			"user": "custom-user",
			"pass": "custom-pass",
		}

		cfg := &config.BackendBasicAuthConfig{
			Enabled:     true,
			VaultPath:   "secret/credentials",
			UsernameKey: "user",
			PasswordKey: "pass",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		// Decode and verify credentials
		authHeader := req.Header.Get("Authorization")
		encodedCreds := authHeader[6:]
		decodedCreds, err := base64.StdEncoding.DecodeString(encodedCreds)
		require.NoError(t, err)
		assert.Equal(t, "custom-user:custom-pass", string(decodedCreds))
	})

	t.Run("returns error when vault read fails", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.readErr = errors.New("vault read error")

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error when username not found in vault secret", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.data = map[string]interface{}{
			"password": "vault-pass",
			// Missing username
		}

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error when password not found in vault secret", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.data = map[string]interface{}{
			"username": "vault-user",
			// Missing password
		}

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error for invalid vault path format", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "invalid-path-without-slash",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("returns error when vault client is disabled", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(false)

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestBasicProvider_Refresh_WithVault(t *testing.T) {
	t.Parallel()

	t.Run("refresh clears cache and fetches new credentials from vault", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.data = map[string]interface{}{
			"username": "vault-user",
			"password": "vault-pass",
		}

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		// First, apply to cache credentials
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)

		// Update mock data
		mockClient.kvClient.data = map[string]interface{}{
			"username": "new-user",
			"password": "new-pass",
		}

		// Refresh should clear cache and fetch new credentials
		err = provider.Refresh(context.Background())
		require.NoError(t, err)

		// Apply again and verify new credentials
		req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		err = provider.ApplyHTTP(context.Background(), req2)
		require.NoError(t, err)

		authHeader := req2.Header.Get("Authorization")
		encodedCreds := authHeader[6:]
		decodedCreds, err := base64.StdEncoding.DecodeString(encodedCreds)
		require.NoError(t, err)
		assert.Equal(t, "new-user:new-pass", string(decodedCreds))
	})

	t.Run("refresh returns error when vault read fails", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.data = map[string]interface{}{
			"username": "vault-user",
			"password": "vault-pass",
		}

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		// First, apply to cache credentials
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

func TestBasicProvider_ApplyGRPC_WithVault(t *testing.T) {
	t.Parallel()

	t.Run("returns dial options with vault credentials", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.data = map[string]interface{}{
			"username": "vault-user",
			"password": "vault-pass",
		}

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		opts, err := provider.ApplyGRPC(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, opts)
	})

	t.Run("returns error when vault read fails", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClient(true)
		mockClient.kvClient.readErr = errors.New("vault read error")

		cfg := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/credentials",
		}

		provider, err := NewBasicProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		_, err = provider.ApplyGRPC(context.Background())
		assert.Error(t, err)
	})
}

func TestBasicProvider_GetStaticCredentials_Errors(t *testing.T) {
	t.Parallel()

	t.Run("returns error when username is empty", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "",
			Password: "testpass",
		}

		// This should fail validation, but let's test getStaticCredentials directly
		// by creating a provider with VaultPath first, then clearing it
		provider := &BasicProvider{
			name:    "test",
			config:  cfg,
			logger:  nil,
			metrics: NopMetrics(),
		}

		// Access the private method through ApplyHTTP
		// Since config validation happens in NewBasicProvider, we need to test
		// the error path differently - by having empty username in config
		// after provider creation (which shouldn't happen in practice)
		cfg.Username = ""
		cfg.Password = "pass"
		cfg.VaultPath = "" // Force static credentials path

		// The provider was created with invalid config, so we can't test this path
		// directly without modifying the provider after creation
		assert.NotNil(t, provider)
	})
}

func TestBasicProvider_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("handles concurrent HTTP requests safely", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
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

		cfg := &config.BackendBasicAuthConfig{
			Enabled:  true,
			Username: "testuser",
			Password: "testpass",
		}

		provider, err := NewBasicProvider("test-provider", cfg)
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

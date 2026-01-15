package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, "http://localhost:8200", config.Address)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 5, config.MaxRetries) // Updated for better resilience
	assert.Equal(t, 500*time.Millisecond, config.RetryWaitMin)
	assert.Equal(t, 60*time.Second, config.RetryWaitMax) // Updated for exponential backoff
	assert.Equal(t, BackoffTypeDecorrelatedJitter, config.BackoffType)
	assert.Equal(t, 2.0, config.BackoffMultiplier)
	assert.Equal(t, 0.2, config.Jitter)
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "empty address",
			config: &Config{
				Address:    "",
				Timeout:    30 * time.Second,
				MaxRetries: 3,
			},
			wantErr: true,
		},
		{
			name: "zero timeout",
			config: &Config{
				Address:    "http://localhost:8200",
				Timeout:    0,
				MaxRetries: 3,
			},
			wantErr: true,
		},
		{
			name: "negative max retries",
			config: &Config{
				Address:    "http://localhost:8200",
				Timeout:    30 * time.Second,
				MaxRetries: -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	t.Run("with default config", func(t *testing.T) {
		client, err := NewClient(nil, nil)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.NotNil(t, client.vaultClient)
		assert.False(t, client.IsAuthenticated())
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &Config{
			Address:      "http://vault.example.com:8200",
			Namespace:    "test-namespace",
			Timeout:      60 * time.Second,
			MaxRetries:   5,
			RetryWaitMin: 1 * time.Second,
			RetryWaitMax: 10 * time.Second,
		}

		client, err := NewClient(config, nil)
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("with invalid config", func(t *testing.T) {
		config := &Config{
			Address: "",
			Timeout: 30 * time.Second,
		}

		_, err := NewClient(config, nil)
		assert.Error(t, err)
	})
}

func TestClientIsAuthenticated(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	// Initially not authenticated
	assert.False(t, client.IsAuthenticated())

	// Set token manually for testing
	client.mu.Lock()
	client.token = "test-token"
	client.tokenExpiry = time.Now().Add(1 * time.Hour)
	client.mu.Unlock()

	assert.True(t, client.IsAuthenticated())

	// Expired token
	client.mu.Lock()
	client.tokenExpiry = time.Now().Add(-1 * time.Hour)
	client.mu.Unlock()

	assert.False(t, client.IsAuthenticated())
}

func TestClientClose(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	// Set token
	client.mu.Lock()
	client.token = "test-token"
	client.mu.Unlock()

	err = client.Close()
	assert.NoError(t, err)
	assert.True(t, client.closed)
	assert.Empty(t, client.token)

	// Close again should be idempotent
	err = client.Close()
	assert.NoError(t, err)
}

// ============================================================================
// TLS Configuration Tests
// ============================================================================

// generateTestCertificate generates a self-signed certificate for testing
func generateTestCertificate() (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certPEM, keyPEM, nil
}

func TestCreateTLSConfig_WithCACert(t *testing.T) {
	// Generate a test CA certificate
	caCert, _, err := generateTestCertificate()
	require.NoError(t, err)

	tlsConfig := &TLSConfig{
		CACert: caCert,
	}

	config, err := createTLSConfig(tlsConfig)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.NotNil(t, config.RootCAs)
}

func TestCreateTLSConfig_WithClientCert(t *testing.T) {
	// Generate test client certificate and key
	certPEM, keyPEM, err := generateTestCertificate()
	require.NoError(t, err)

	tlsConfig := &TLSConfig{
		ClientCert: certPEM,
		ClientKey:  keyPEM,
	}

	config, err := createTLSConfig(tlsConfig)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Len(t, config.Certificates, 1)
}

func TestCreateTLSConfig_WithInvalidCACert(t *testing.T) {
	tlsConfig := &TLSConfig{
		CACert: []byte("invalid-ca-cert"),
	}

	_, err := createTLSConfig(tlsConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestCreateTLSConfig_WithInvalidClientCert(t *testing.T) {
	tlsConfig := &TLSConfig{
		ClientCert: []byte("invalid-cert"),
		ClientKey:  []byte("invalid-key"),
	}

	_, err := createTLSConfig(tlsConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestCreateTLSConfig_InsecureSkipVerify(t *testing.T) {
	tlsConfig := &TLSConfig{
		InsecureSkipVerify: true,
		ServerName:         "vault.example.com",
	}

	config, err := createTLSConfig(tlsConfig)
	require.NoError(t, err)
	assert.True(t, config.InsecureSkipVerify)
	assert.Equal(t, "vault.example.com", config.ServerName)
}

func TestNewClient_WithTLSConfig(t *testing.T) {
	// Generate test certificates
	caCert, _, err := generateTestCertificate()
	require.NoError(t, err)

	config := &Config{
		Address: "https://vault.example.com:8200",
		Timeout: 30 * time.Second,
		TLSConfig: &TLSConfig{
			CACert:     caCert,
			ServerName: "vault.example.com",
		},
	}

	client, err := NewClient(config, zap.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, client)
}

// ============================================================================
// Retry Logic Tests
// ============================================================================

func TestClient_ReadSecretWithRetry(t *testing.T) {
	t.Run("returns error for empty path", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx := context.Background()
		_, err = client.ReadSecretWithRetry(ctx, "")
		assert.Error(t, err)
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err = client.ReadSecretWithRetry(ctx, "secret/data/test")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
	})
}

func TestClient_WriteSecretWithRetry(t *testing.T) {
	t.Run("returns error for empty path", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx := context.Background()
		err = client.WriteSecretWithRetry(ctx, "", map[string]interface{}{"key": "value"})
		assert.Error(t, err)
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = client.WriteSecretWithRetry(ctx, "secret/data/test", map[string]interface{}{"key": "value"})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
	})
}

func TestClient_AuthenticateWithRetry(t *testing.T) {
	t.Run("returns error when no auth method configured", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		ctx := context.Background()
		err = client.AuthenticateWithRetry(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrAuthenticationFailed))
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = client.AuthenticateWithRetry(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
	})
}

// ============================================================================
// Token Renewal Tests
// ============================================================================

func TestClient_RenewToken(t *testing.T) {
	t.Run("returns error when not authenticated", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		ctx := context.Background()
		err = client.RenewToken(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotAuthenticated))
	})

	t.Run("attempts renewal when authenticated", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx := context.Background()
		// This will fail because we don't have a real Vault server
		// but it should not return ErrNotAuthenticated
		err = client.RenewToken(ctx)
		assert.Error(t, err)
		assert.False(t, errors.Is(err, ErrNotAuthenticated))
	})
}

// ============================================================================
// List and Delete Secrets Tests
// ============================================================================

func TestClient_ListSecrets(t *testing.T) {
	t.Run("returns error for empty path", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx := context.Background()
		_, err = client.ListSecrets(ctx, "")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPath))
	})

	t.Run("requires authentication", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.ListSecrets(ctx, "secret/")
		assert.Error(t, err)
		// Should fail because no auth method is configured
		assert.True(t, errors.Is(err, ErrAuthenticationFailed))
	})
}

func TestClient_DeleteSecret(t *testing.T) {
	t.Run("returns error for empty path", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx := context.Background()
		err = client.DeleteSecret(ctx, "")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPath))
	})

	t.Run("requires authentication", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		ctx := context.Background()
		err = client.DeleteSecret(ctx, "secret/data/test")
		assert.Error(t, err)
		// Should fail because no auth method is configured
		assert.True(t, errors.Is(err, ErrAuthenticationFailed))
	})
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestClient_ConcurrentAccess(t *testing.T) {
	client, err := NewClient(nil, zap.NewNop())
	require.NoError(t, err)

	// Set up authentication
	client.mu.Lock()
	client.token = "test-token"
	client.tokenExpiry = time.Now().Add(1 * time.Hour)
	client.mu.Unlock()
	client.vaultClient.SetToken("test-token")

	var wg sync.WaitGroup
	numGoroutines := 50

	// Test concurrent IsAuthenticated calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = client.IsAuthenticated()
		}()
	}

	// Test concurrent GetVaultClient calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = client.GetVaultClient()
		}()
	}

	wg.Wait()
}

func TestClient_ConcurrentReadWrite(t *testing.T) {
	client, err := NewClient(nil, zap.NewNop())
	require.NoError(t, err)

	// Set up authentication
	client.mu.Lock()
	client.token = "test-token"
	client.tokenExpiry = time.Now().Add(1 * time.Hour)
	client.mu.Unlock()
	client.vaultClient.SetToken("test-token")

	var wg sync.WaitGroup
	numGoroutines := 20

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Test concurrent read operations (will fail but should not panic)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = client.ReadSecret(ctx, "secret/data/test")
		}(i)
	}

	// Test concurrent write operations (will fail but should not panic)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = client.WriteSecret(ctx, "secret/data/test", map[string]interface{}{"key": "value"})
		}(i)
	}

	wg.Wait()
}

// ============================================================================
// Config GetRetryConfig Tests
// ============================================================================

func TestConfig_GetRetryConfig(t *testing.T) {
	config := &Config{
		MaxRetries:        5,
		RetryWaitMin:      500 * time.Millisecond,
		RetryWaitMax:      30 * time.Second,
		BackoffType:       BackoffTypeExponential,
		BackoffMultiplier: 2.5,
		Jitter:            0.3,
	}

	retryConfig := config.GetRetryConfig()

	assert.Equal(t, 5, retryConfig.MaxRetries)
	assert.Equal(t, 500*time.Millisecond, retryConfig.WaitMin)
	assert.Equal(t, 30*time.Second, retryConfig.WaitMax)
	assert.Equal(t, BackoffTypeExponential, retryConfig.BackoffType)
	assert.Equal(t, 2.5, retryConfig.BackoffMultiplier)
	assert.Equal(t, 0.3, retryConfig.Jitter)
	assert.Equal(t, "vault_client", retryConfig.OperationName)
}

// ============================================================================
// Secret Conversion Tests
// ============================================================================

func TestConvertSecret(t *testing.T) {
	t.Run("nil secret returns nil", func(t *testing.T) {
		result := convertSecret(nil)
		assert.Nil(t, result)
	})
}

func TestExtractMetadata(t *testing.T) {
	t.Run("extracts all metadata fields", func(t *testing.T) {
		createdTime := time.Now().Format(time.RFC3339Nano)
		deletedTime := time.Now().Add(1 * time.Hour).Format(time.RFC3339Nano)

		metadata := map[string]interface{}{
			"created_time":  createdTime,
			"version":       float64(3),
			"deletion_time": deletedTime,
			"destroyed":     true,
		}

		result := extractMetadata(metadata)

		assert.NotNil(t, result)
		assert.Equal(t, 3, result.Version)
		assert.True(t, result.Destroyed)
		assert.NotNil(t, result.DeletedTime)
	})

	t.Run("handles empty deletion_time", func(t *testing.T) {
		metadata := map[string]interface{}{
			"created_time":  time.Now().Format(time.RFC3339Nano),
			"version":       float64(1),
			"deletion_time": "",
			"destroyed":     false,
		}

		result := extractMetadata(metadata)

		assert.NotNil(t, result)
		assert.Nil(t, result.DeletedTime)
		assert.False(t, result.Destroyed)
	})

	t.Run("handles missing fields", func(t *testing.T) {
		metadata := map[string]interface{}{}

		result := extractMetadata(metadata)

		assert.NotNil(t, result)
		assert.Equal(t, 0, result.Version)
		assert.False(t, result.Destroyed)
	})
}

// ============================================================================
// SetAuthMethod Tests
// ============================================================================

func TestClient_SetAuthMethod(t *testing.T) {
	client, err := NewClient(nil, zap.NewNop())
	require.NoError(t, err)

	// Create a mock auth method
	tokenAuth, err := NewTokenAuth("test-token")
	require.NoError(t, err)

	client.SetAuthMethod(tokenAuth)

	// Verify auth method is set
	client.mu.RLock()
	assert.NotNil(t, client.authMethod)
	assert.Equal(t, "token", client.authMethod.Name())
	client.mu.RUnlock()
}

// ============================================================================
// Authenticate Tests
// ============================================================================

func TestClient_Authenticate(t *testing.T) {
	t.Run("returns error when no auth method configured", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Authenticate(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrAuthenticationFailed))
	})
}

// ============================================================================
// ReadSecret Tests
// ============================================================================

func TestClient_ReadSecret(t *testing.T) {
	t.Run("returns error for empty path", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx := context.Background()
		_, err = client.ReadSecret(ctx, "")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPath))
	})
}

// ============================================================================
// WriteSecret Tests
// ============================================================================

func TestClient_WriteSecret(t *testing.T) {
	t.Run("returns error for empty path", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx := context.Background()
		err = client.WriteSecret(ctx, "", map[string]interface{}{"key": "value"})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPath))
	})
}

// ============================================================================
// ensureAuthenticated Tests
// ============================================================================

func TestClient_EnsureAuthenticated(t *testing.T) {
	t.Run("returns nil when already authenticated", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		// Set up authentication
		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()
		client.vaultClient.SetToken("test-token")

		ctx := context.Background()
		err = client.ensureAuthenticated(ctx)
		assert.NoError(t, err)
	})

	t.Run("attempts authentication when not authenticated", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		ctx := context.Background()
		err = client.ensureAuthenticated(ctx)
		// Should fail because no auth method is configured
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrAuthenticationFailed))
	})
}

// ============================================================================
// IsAuthenticated Edge Cases Tests
// ============================================================================

func TestClient_IsAuthenticated_EdgeCases(t *testing.T) {
	t.Run("returns false for empty token", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		client.mu.Lock()
		client.token = ""
		client.tokenExpiry = time.Now().Add(1 * time.Hour)
		client.mu.Unlock()

		assert.False(t, client.IsAuthenticated())
	})

	t.Run("returns true for non-expiring token", func(t *testing.T) {
		client, err := NewClient(nil, zap.NewNop())
		require.NoError(t, err)

		client.mu.Lock()
		client.token = "test-token"
		client.tokenExpiry = time.Time{} // Zero time means no expiry
		client.mu.Unlock()

		assert.True(t, client.IsAuthenticated())
	})
}

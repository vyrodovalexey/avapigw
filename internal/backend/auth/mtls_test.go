package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// createTestCertificates creates test certificate and key files for testing.
func createTestCertificates(t *testing.T) (certFile, keyFile, caFile string, cleanup func()) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "mtls-test-*")
	require.NoError(t, err)

	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Generate CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	// Generate client key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Generate client certificate
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "test-client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	// Write CA certificate
	caFile = filepath.Join(tempDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	err = os.WriteFile(caFile, caPEM, 0600)
	require.NoError(t, err)

	// Write client certificate
	certFile = filepath.Join(tempDir, "client.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	err = os.WriteFile(certFile, certPEM, 0600)
	require.NoError(t, err)

	// Write client key
	keyFile = filepath.Join(tempDir, "client-key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	err = os.WriteFile(keyFile, keyPEM, 0600)
	require.NoError(t, err)

	cleanup = func() {
		os.RemoveAll(tempDir)
	}

	return certFile, keyFile, caFile, cleanup
}

func TestNewMTLSProvider(t *testing.T) {
	t.Parallel()

	t.Run("creates provider with valid file config", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "test-provider", provider.Name())
		assert.Equal(t, "mtls", provider.Type())
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		t.Parallel()

		_, err := NewMTLSProvider("test-provider", nil)
		assert.Error(t, err)
	})

	t.Run("returns error when not enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: false,
		}

		_, err := NewMTLSProvider("test-provider", cfg)
		assert.Error(t, err)
	})

	t.Run("returns error for invalid config - missing cert files", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			// Missing CertFile and KeyFile
		}

		_, err := NewMTLSProvider("test-provider", cfg)
		assert.Error(t, err)
	})

	t.Run("applies options", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		metrics := NopMetrics()
		provider, err := NewMTLSProvider("test-provider", cfg, WithMetrics(metrics))
		require.NoError(t, err)
		assert.NotNil(t, provider.metrics)
	})
}

func TestMTLSProvider_ApplyHTTP(t *testing.T) {
	t.Parallel()

	t.Run("loads TLS config for HTTP request", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		err = provider.ApplyHTTP(context.Background(), req)
		require.NoError(t, err)
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		err = provider.ApplyHTTP(context.Background(), req)
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestMTLSProvider_ApplyGRPC(t *testing.T) {
	t.Parallel()

	t.Run("returns dial options with TLS credentials", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		opts, err := provider.ApplyGRPC(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, opts)
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		_, err = provider.ApplyGRPC(context.Background())
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestMTLSProvider_Refresh(t *testing.T) {
	t.Parallel()

	t.Run("refreshes certificate successfully", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Refresh(context.Background())
		assert.NoError(t, err)
	})

	t.Run("returns error when provider is closed", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)

		err = provider.Refresh(context.Background())
		assert.ErrorIs(t, err, ErrProviderClosed)
	})
}

func TestMTLSProvider_Close(t *testing.T) {
	t.Parallel()

	t.Run("closes provider successfully", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)
	})

	t.Run("close is idempotent", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)

		err = provider.Close()
		assert.NoError(t, err)
	})
}

func TestMTLSProvider_GetTLSConfig(t *testing.T) {
	t.Parallel()

	t.Run("returns TLS config with certificate", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		tlsConfig, err := provider.GetTLSConfig(context.Background())
		require.NoError(t, err)
		assert.NotNil(t, tlsConfig)
		assert.Len(t, tlsConfig.Certificates, 1)
	})

	t.Run("returns TLS config with CA", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, caFile, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		tlsConfig, err := provider.GetTLSConfig(context.Background())
		require.NoError(t, err)
		assert.NotNil(t, tlsConfig)
		assert.NotNil(t, tlsConfig.RootCAs)
	})

	t.Run("caches TLS config", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		tlsConfig1, err := provider.GetTLSConfig(context.Background())
		require.NoError(t, err)

		tlsConfig2, err := provider.GetTLSConfig(context.Background())
		require.NoError(t, err)

		// Should return cloned configs (not same pointer)
		assert.NotSame(t, tlsConfig1, tlsConfig2)
	})
}

func TestMTLSProvider_CertificateLoading(t *testing.T) {
	t.Parallel()

	t.Run("returns error for non-existent cert file", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: "/non/existent/cert.pem",
			KeyFile:  "/non/existent/key.pem",
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		_, err = provider.GetTLSConfig(context.Background())
		assert.Error(t, err)
	})

	t.Run("returns error for invalid cert file", func(t *testing.T) {
		t.Parallel()

		tempDir, err := os.MkdirTemp("", "mtls-test-invalid-*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		certFile := filepath.Join(tempDir, "invalid.pem")
		keyFile := filepath.Join(tempDir, "invalid-key.pem")

		err = os.WriteFile(certFile, []byte("invalid cert"), 0600)
		require.NoError(t, err)
		err = os.WriteFile(keyFile, []byte("invalid key"), 0600)
		require.NoError(t, err)

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		_, err = provider.GetTLSConfig(context.Background())
		assert.Error(t, err)
	})
}

func TestMTLSProvider_CALoading(t *testing.T) {
	t.Parallel()

	t.Run("returns error for non-existent CA file", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   "/non/existent/ca.pem",
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		_, err = provider.GetTLSConfig(context.Background())
		assert.Error(t, err)
	})

	t.Run("returns error for invalid CA file", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		tempDir, err := os.MkdirTemp("", "mtls-test-ca-*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		invalidCAFile := filepath.Join(tempDir, "invalid-ca.pem")
		err = os.WriteFile(invalidCAFile, []byte("invalid ca"), 0600)
		require.NoError(t, err)

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   invalidCAFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		_, err = provider.GetTLSConfig(context.Background())
		assert.Error(t, err)
	})
}

func TestMTLSProvider_TLSVersion(t *testing.T) {
	t.Parallel()

	t.Run("sets minimum TLS version to 1.2", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		tlsConfig, err := provider.GetTLSConfig(context.Background())
		require.NoError(t, err)
		assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	})
}

func TestMTLSProvider_DefaultConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 1*time.Hour, DefaultCertificateCacheTTL)
	assert.Equal(t, 10*time.Minute, DefaultCertRenewBefore)
}

func TestMTLSProvider_VaultCertificate(t *testing.T) {
	t.Parallel()

	t.Run("returns error when vault not available", func(t *testing.T) {
		t.Parallel()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
		require.NoError(t, err)

		_, err = provider.GetTLSConfig(context.Background())
		assert.Error(t, err)
	})

	t.Run("returns error when vault client is disabled", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForMTLS(false)

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		_, err = provider.GetTLSConfig(context.Background())
		assert.Error(t, err)
	})

	t.Run("returns error when vault config is nil", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForMTLS(true)

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault:   nil, // No vault config
		}

		// This should fail validation
		_, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		assert.Error(t, err)
	})

	t.Run("successfully loads certificate from vault", func(t *testing.T) {
		t.Parallel()

		// Create test certificates for the mock
		certPEM, keyPEM, x509Cert := createTestCertPEM(t)

		mockClient := newMockVaultClientForMTLS(true)
		mockClient.pkiClient.cert = &vault.Certificate{
			Certificate:    x509Cert,
			CertificatePEM: certPEM,
			PrivateKeyPEM:  keyPEM,
			SerialNumber:   "test-serial",
			Expiration:     time.Now().Add(24 * time.Hour),
		}

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		tlsConfig, err := provider.GetTLSConfig(context.Background())
		require.NoError(t, err)
		assert.NotNil(t, tlsConfig)
		assert.Len(t, tlsConfig.Certificates, 1)
	})

	t.Run("returns error when vault PKI issue fails", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForMTLS(true)
		mockClient.pkiClient.issueErr = errors.New("vault PKI error")

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		_, err = provider.GetTLSConfig(context.Background())
		assert.Error(t, err)
	})

	t.Run("loads CA from vault", func(t *testing.T) {
		t.Parallel()

		// Create test certificates for the mock
		certPEM, keyPEM, x509Cert := createTestCertPEM(t)

		mockClient := newMockVaultClientForMTLS(true)
		mockClient.pkiClient.cert = &vault.Certificate{
			Certificate:    x509Cert,
			CertificatePEM: certPEM,
			PrivateKeyPEM:  keyPEM,
			SerialNumber:   "test-serial",
			Expiration:     time.Now().Add(24 * time.Hour),
		}

		// Create CA pool
		caPool := x509.NewCertPool()
		caPool.AddCert(x509Cert)
		mockClient.pkiClient.caPool = caPool

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		tlsConfig, err := provider.GetTLSConfig(context.Background())
		require.NoError(t, err)
		assert.NotNil(t, tlsConfig)
		assert.NotNil(t, tlsConfig.RootCAs)
	})

	t.Run("handles vault TTL parsing", func(t *testing.T) {
		t.Parallel()

		// Create test certificates for the mock
		certPEM, keyPEM, x509Cert := createTestCertPEM(t)

		mockClient := newMockVaultClientForMTLS(true)
		mockClient.pkiClient.cert = &vault.Certificate{
			Certificate:    x509Cert,
			CertificatePEM: certPEM,
			PrivateKeyPEM:  keyPEM,
			SerialNumber:   "test-serial",
			Expiration:     time.Now().Add(24 * time.Hour),
		}

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
				TTL:        "24h",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		tlsConfig, err := provider.GetTLSConfig(context.Background())
		require.NoError(t, err)
		assert.NotNil(t, tlsConfig)
	})

	t.Run("returns error for invalid vault TTL", func(t *testing.T) {
		t.Parallel()

		mockClient := newMockVaultClientForMTLS(true)

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
				TTL:        "invalid-ttl",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		_, err = provider.GetTLSConfig(context.Background())
		assert.Error(t, err)
	})
}

func TestMTLSProvider_Refresh_WithVault(t *testing.T) {
	t.Parallel()

	t.Run("refresh clears cache and fetches new certificate from vault", func(t *testing.T) {
		t.Parallel()

		// Create test certificates for the mock
		certPEM, keyPEM, x509Cert := createTestCertPEM(t)

		mockClient := newMockVaultClientForMTLS(true)
		mockClient.pkiClient.cert = &vault.Certificate{
			Certificate:    x509Cert,
			CertificatePEM: certPEM,
			PrivateKeyPEM:  keyPEM,
			SerialNumber:   "test-serial-1",
			Expiration:     time.Now().Add(24 * time.Hour),
		}

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		// First, get TLS config to cache certificate
		_, err = provider.GetTLSConfig(context.Background())
		require.NoError(t, err)

		// Update mock to return new certificate
		certPEM2, keyPEM2, x509Cert2 := createTestCertPEM(t)
		mockClient.pkiClient.cert = &vault.Certificate{
			Certificate:    x509Cert2,
			CertificatePEM: certPEM2,
			PrivateKeyPEM:  keyPEM2,
			SerialNumber:   "test-serial-2",
			Expiration:     time.Now().Add(48 * time.Hour),
		}

		// Refresh should clear cache and fetch new certificate
		err = provider.Refresh(context.Background())
		require.NoError(t, err)
	})

	t.Run("refresh returns error when vault issue fails", func(t *testing.T) {
		t.Parallel()

		// Create test certificates for the mock
		certPEM, keyPEM, x509Cert := createTestCertPEM(t)

		mockClient := newMockVaultClientForMTLS(true)
		mockClient.pkiClient.cert = &vault.Certificate{
			Certificate:    x509Cert,
			CertificatePEM: certPEM,
			PrivateKeyPEM:  keyPEM,
			SerialNumber:   "test-serial",
			Expiration:     time.Now().Add(24 * time.Hour),
		}

		cfg := &config.BackendMTLSAuthConfig{
			Enabled: true,
			Vault: &config.VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
		}

		provider, err := NewMTLSProvider("test-provider", cfg, WithVaultClient(mockClient))
		require.NoError(t, err)

		// First, get TLS config to cache certificate
		_, err = provider.GetTLSConfig(context.Background())
		require.NoError(t, err)

		// Set error for next issue
		mockClient.pkiClient.issueErr = errors.New("vault PKI error")

		// Refresh should fail
		err = provider.Refresh(context.Background())
		assert.Error(t, err)
	})
}

func TestMTLSProvider_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("handles concurrent HTTP requests safely", func(t *testing.T) {
		t.Parallel()

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
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

		certFile, keyFile, _, cleanup := createTestCertificates(t)
		defer cleanup()

		cfg := &config.BackendMTLSAuthConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}

		provider, err := NewMTLSProvider("test-provider", cfg)
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

// mockVaultClientForMTLS implements vault.Client for mTLS testing.
type mockVaultClientForMTLS struct {
	enabled   bool
	kvClient  *mockKVClientForMTLS
	pkiClient *mockPKIClientForMTLS
}

func newMockVaultClientForMTLS(enabled bool) *mockVaultClientForMTLS {
	return &mockVaultClientForMTLS{
		enabled:   enabled,
		kvClient:  &mockKVClientForMTLS{},
		pkiClient: &mockPKIClientForMTLS{},
	}
}

func (m *mockVaultClientForMTLS) IsEnabled() bool                      { return m.enabled }
func (m *mockVaultClientForMTLS) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClientForMTLS) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClientForMTLS) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClientForMTLS) PKI() vault.PKIClient         { return m.pkiClient }
func (m *mockVaultClientForMTLS) KV() vault.KVClient           { return m.kvClient }
func (m *mockVaultClientForMTLS) Transit() vault.TransitClient { return nil }
func (m *mockVaultClientForMTLS) Close() error                 { return nil }

// mockKVClientForMTLS implements vault.KVClient for mTLS testing.
type mockKVClientForMTLS struct {
	data    map[string]interface{}
	readErr error
}

func (m *mockKVClientForMTLS) Read(_ context.Context, _, _ string) (map[string]interface{}, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	return m.data, nil
}

func (m *mockKVClientForMTLS) Write(_ context.Context, _, _ string, _ map[string]interface{}) error {
	return nil
}

func (m *mockKVClientForMTLS) Delete(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockKVClientForMTLS) List(_ context.Context, _, _ string) ([]string, error) {
	return []string{}, nil
}

// mockPKIClientForMTLS implements vault.PKIClient for mTLS testing.
type mockPKIClientForMTLS struct {
	cert     *vault.Certificate
	caPool   *x509.CertPool
	issueErr error
	getCAErr error
}

func (m *mockPKIClientForMTLS) IssueCertificate(_ context.Context, _ *vault.PKIIssueOptions) (*vault.Certificate, error) {
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	return m.cert, nil
}

func (m *mockPKIClientForMTLS) SignCSR(_ context.Context, _ []byte, _ *vault.PKISignOptions) (*vault.Certificate, error) {
	return m.cert, nil
}

func (m *mockPKIClientForMTLS) GetCA(_ context.Context, _ string) (*x509.CertPool, error) {
	if m.getCAErr != nil {
		return nil, m.getCAErr
	}
	return m.caPool, nil
}

func (m *mockPKIClientForMTLS) GetCRL(_ context.Context, _ string) ([]byte, error) {
	return []byte{}, nil
}

func (m *mockPKIClientForMTLS) RevokeCertificate(_ context.Context, _, _ string) error {
	return nil
}

// createTestCertPEM creates test certificate and key PEM strings for mocking.
func createTestCertPEM(t *testing.T) (certPEM, keyPEM string, cert *x509.Certificate) {
	t.Helper()

	// Generate key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Generate certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   "test.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err = x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	return certPEM, keyPEM, cert
}

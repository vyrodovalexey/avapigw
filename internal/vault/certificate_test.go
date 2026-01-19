package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewCertificateManager(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.client)
	assert.NotNil(t, manager.cache)
	assert.Equal(t, 5*time.Minute, manager.refreshInterval)
	assert.False(t, manager.stopped)
}

func TestCertificateManager_InvalidateCertificate(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	// Add a certificate entry to cache
	manager.mu.Lock()
	manager.cache["test/cert"] = &CertificateEntry{
		Path:      "test/cert",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	manager.mu.Unlock()

	// Verify it exists
	manager.mu.RLock()
	_, exists := manager.cache["test/cert"]
	manager.mu.RUnlock()
	assert.True(t, exists)

	// Invalidate
	manager.InvalidateCertificate("test/cert")

	// Verify it's gone
	manager.mu.RLock()
	_, exists = manager.cache["test/cert"]
	manager.mu.RUnlock()
	assert.False(t, exists)
}

func TestCertificateManager_ClearCache(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	// Add multiple entries
	manager.mu.Lock()
	manager.cache["cert1"] = &CertificateEntry{Path: "cert1"}
	manager.cache["cert2"] = &CertificateEntry{Path: "cert2"}
	manager.cache["cert3"] = &CertificateEntry{Path: "cert3"}
	manager.mu.Unlock()

	manager.mu.RLock()
	assert.Equal(t, 3, len(manager.cache))
	manager.mu.RUnlock()

	// Clear
	manager.ClearCache()

	manager.mu.RLock()
	assert.Equal(t, 0, len(manager.cache))
	manager.mu.RUnlock()
}

func TestCertificateManager_Close(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	// Add to cache
	manager.mu.Lock()
	manager.cache["test/cert"] = &CertificateEntry{Path: "test/cert"}
	manager.mu.Unlock()

	// Close
	err = manager.Close()
	assert.NoError(t, err)
	assert.True(t, manager.stopped)

	// Cache should be cleared
	manager.mu.RLock()
	assert.Equal(t, 0, len(manager.cache))
	manager.mu.RUnlock()

	// Close again should be idempotent
	err = manager.Close()
	assert.NoError(t, err)
}

func TestCertificateEntry(t *testing.T) {
	entry := &CertificateEntry{
		Certificate: nil,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Path:        "pki/issue/my-role",
	}

	assert.Equal(t, "pki/issue/my-role", entry.Path)
	assert.False(t, entry.ExpiresAt.IsZero())
}

func TestParseCertificatePEM_Invalid(t *testing.T) {
	// Invalid PEM data
	_, err := ParseCertificatePEM([]byte("not a valid PEM"))
	assert.Error(t, err)
}

func TestParsePrivateKeyPEM_Invalid(t *testing.T) {
	// Invalid PEM data
	_, err := ParsePrivateKeyPEM([]byte("not a valid PEM"))
	assert.Error(t, err)
}

// Test certificate PEM parsing with valid data
func TestParseCertificatePEM_Valid(t *testing.T) {
	// This is a self-signed test certificate (not for production use)
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96HtiXjnpL5GvPmwAMB
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMB
AAEwDQYJKoZIhvcNAQELBQADQQBVv5GXhNhQ7AAAAAAAAAAAAAAAAAAAAAAAAA==
-----END CERTIFICATE-----`)

	// This will fail because the certificate is malformed, but tests the parsing logic
	_, err := ParseCertificatePEM(certPEM)
	// We expect an error because this is a malformed test certificate
	assert.Error(t, err)
}

func TestParsePrivateKeyPEM_RSA(t *testing.T) {
	// Malformed RSA key for testing
	keyPEM := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALuj3oe2JeOekvka8+bAAwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAQA=
-----END RSA PRIVATE KEY-----`)

	// This will fail because the key is malformed, but tests the parsing logic
	_, err := ParsePrivateKeyPEM(keyPEM)
	assert.Error(t, err)
}

func TestParsePrivateKeyPEM_EC(t *testing.T) {
	// Malformed EC key for testing
	keyPEM := []byte(`-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBYr
-----END EC PRIVATE KEY-----`)

	_, err := ParsePrivateKeyPEM(keyPEM)
	assert.Error(t, err)
}

func TestParsePrivateKeyPEM_PKCS8(t *testing.T) {
	// Malformed PKCS8 key for testing
	keyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA
-----END PRIVATE KEY-----`)

	_, err := ParsePrivateKeyPEM(keyPEM)
	assert.Error(t, err)
}

func TestParsePrivateKeyPEM_UnsupportedType(t *testing.T) {
	keyPEM := []byte(`-----BEGIN UNKNOWN KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA
-----END UNKNOWN KEY-----`)

	_, err := ParsePrivateKeyPEM(keyPEM)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

// generateTestCertificateAndKey generates a self-signed certificate and key for testing
func generateTestCertificateAndKey() (certPEM, keyPEM []byte, err error) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

func TestCertificateManager_GetCertificate_CacheHit(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificateAndKey()
	require.NoError(t, err)

	// Parse the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	// Add to cache
	manager.mu.Lock()
	manager.cache["test/cert"] = &CertificateEntry{
		Certificate: &cert,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Path:        "test/cert",
	}
	manager.mu.Unlock()

	// Get from cache
	ctx := context.Background()
	result, err := manager.GetCertificate(ctx, "test/cert")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCertificateManager_GetCertificate_CacheMiss(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	ctx := context.Background()
	// This will fail because there's no Vault server
	_, err = manager.GetCertificate(ctx, "test/cert")
	assert.Error(t, err)
}

func TestCertificateManager_GetCertificate_ExpiredCache(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificateAndKey()
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	// Add expired entry to cache
	manager.mu.Lock()
	manager.cache["test/cert"] = &CertificateEntry{
		Certificate: &cert,
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // Expired
		Path:        "test/cert",
	}
	manager.mu.Unlock()

	ctx := context.Background()
	// This will try to fetch from Vault and fail
	_, err = manager.GetCertificate(ctx, "test/cert")
	assert.Error(t, err)
}

func TestCertificateManager_parseCertificateFromSecret(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificateAndKey()
	require.NoError(t, err)

	t.Run("valid secret with certificate and key", func(t *testing.T) {
		secret := &Secret{
			Data: map[string]interface{}{
				"certificate": string(certPEM),
				"private_key": string(keyPEM),
			},
		}

		cert, err := manager.parseCertificateFromSecret(secret)
		require.NoError(t, err)
		assert.NotNil(t, cert)
		assert.NotNil(t, cert.Leaf)
	})

	t.Run("valid secret with tls.crt and tls.key", func(t *testing.T) {
		secret := &Secret{
			Data: map[string]interface{}{
				"tls.crt": string(certPEM),
				"tls.key": string(keyPEM),
			},
		}

		cert, err := manager.parseCertificateFromSecret(secret)
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("nil secret", func(t *testing.T) {
		_, err := manager.parseCertificateFromSecret(nil)
		assert.Error(t, err)
	})

	t.Run("nil data", func(t *testing.T) {
		_, err := manager.parseCertificateFromSecret(&Secret{Data: nil})
		assert.Error(t, err)
	})

	t.Run("missing certificate", func(t *testing.T) {
		secret := &Secret{
			Data: map[string]interface{}{
				"private_key": string(keyPEM),
			},
		}

		_, err := manager.parseCertificateFromSecret(secret)
		assert.Error(t, err)
	})

	t.Run("missing key", func(t *testing.T) {
		secret := &Secret{
			Data: map[string]interface{}{
				"certificate": string(certPEM),
			},
		}

		_, err := manager.parseCertificateFromSecret(secret)
		assert.Error(t, err)
	})

	t.Run("invalid certificate", func(t *testing.T) {
		secret := &Secret{
			Data: map[string]interface{}{
				"certificate": "invalid cert",
				"private_key": string(keyPEM),
			},
		}

		_, err := manager.parseCertificateFromSecret(secret)
		assert.Error(t, err)
	})
}

func TestCertificateManager_getSecretValue(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	secret := &Secret{
		Data: map[string]interface{}{
			"certificate": "cert-value",
			"key":         "key-value",
			"empty":       "",
			"non_string":  123,
		},
	}

	t.Run("found first key", func(t *testing.T) {
		value, ok := manager.getSecretValue(secret, "certificate", "cert")
		assert.True(t, ok)
		assert.Equal(t, "cert-value", value)
	})

	t.Run("found second key", func(t *testing.T) {
		value, ok := manager.getSecretValue(secret, "missing", "key")
		assert.True(t, ok)
		assert.Equal(t, "key-value", value)
	})

	t.Run("not found", func(t *testing.T) {
		value, ok := manager.getSecretValue(secret, "missing1", "missing2")
		assert.False(t, ok)
		assert.Empty(t, value)
	})

	t.Run("empty value", func(t *testing.T) {
		value, ok := manager.getSecretValue(secret, "empty")
		assert.False(t, ok)
		assert.Empty(t, value)
	})

	t.Run("non-string value", func(t *testing.T) {
		value, ok := manager.getSecretValue(secret, "non_string")
		assert.False(t, ok)
		assert.Empty(t, value)
	})
}

func TestCertificateManager_TLSConfig(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	t.Run("empty paths", func(t *testing.T) {
		ctx := context.Background()
		_, err := manager.TLSConfig(ctx, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no certificate paths provided")
	})

	t.Run("with paths but no vault", func(t *testing.T) {
		ctx := context.Background()
		_, err := manager.TLSConfig(ctx, []string{"pki/issue/my-role"})
		assert.Error(t, err)
	})
}

func TestCertificateManager_TLSConfigWithCA(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	ctx := context.Background()
	// This will fail because there's no Vault server
	_, err = manager.TLSConfigWithCA(ctx, []string{"pki/issue/my-role"}, "pki/ca")
	assert.Error(t, err)
}

func TestCertificateManager_GetCertificateFunc(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	// Generate test certificate and add to cache
	certPEM, keyPEM, err := generateTestCertificateAndKey()
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	manager.mu.Lock()
	manager.cache["test/cert"] = &CertificateEntry{
		Certificate: &cert,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Path:        "test/cert",
	}
	manager.mu.Unlock()

	ctx := context.Background()
	getter := manager.GetCertificateFunc(ctx, "test/cert")
	assert.NotNil(t, getter)

	// Call the getter
	result, err := getter(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCertificateManager_GetClientCertificate(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 5*time.Minute, nil)

	// Generate test certificate and add to cache
	certPEM, keyPEM, err := generateTestCertificateAndKey()
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	manager.mu.Lock()
	manager.cache["test/cert"] = &CertificateEntry{
		Certificate: &cert,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Path:        "test/cert",
	}
	manager.mu.Unlock()

	ctx := context.Background()
	getter := manager.GetClientCertificate(ctx, "test/cert")
	assert.NotNil(t, getter)

	// Call the getter
	result, err := getter(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCertificateManager_WatchCertificate(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 100*time.Millisecond, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = manager.WatchCertificate(ctx, "test/cert")
	require.NoError(t, err)

	// Give the watcher time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop watcher
	cancel()

	// Give time for cleanup
	time.Sleep(50 * time.Millisecond)
}

func TestCertificateManager_WatchCertificate_StopChannel(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	manager := NewCertificateManager(client, 100*time.Millisecond, zap.NewNop())

	ctx := context.Background()
	err = manager.WatchCertificate(ctx, "test/cert")
	require.NoError(t, err)

	// Give the watcher time to start
	time.Sleep(50 * time.Millisecond)

	// Close the manager to stop watcher
	err = manager.Close()
	require.NoError(t, err)

	// Give time for cleanup
	time.Sleep(50 * time.Millisecond)
}

func TestNewCertificateManager_WithLogger(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	logger := zap.NewNop()
	manager := NewCertificateManager(client, 5*time.Minute, logger)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.logger)
}

func TestParseCertificatePEM_ValidCertificate(t *testing.T) {
	certPEM, _, err := generateTestCertificateAndKey()
	require.NoError(t, err)

	cert, err := ParseCertificatePEM(certPEM)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test.example.com", cert.Subject.CommonName)
}

func TestParsePrivateKeyPEM_ValidRSAKey(t *testing.T) {
	_, keyPEM, err := generateTestCertificateAndKey()
	require.NoError(t, err)

	key, err := ParsePrivateKeyPEM(keyPEM)
	require.NoError(t, err)
	assert.NotNil(t, key)

	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok)
}

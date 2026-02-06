// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// NewManager Tests - Additional Coverage
// ============================================================================

func TestNewManager_NilConfig_Final(t *testing.T) {
	manager, err := NewManager(context.Background(), nil)
	assert.NoError(t, err)
	assert.NotNil(t, manager)
	if manager != nil {
		_ = manager.Close()
	}
}

func TestNewManager_VaultModeWithoutConfig_Final(t *testing.T) {
	config := &ManagerConfig{
		Mode:  CertModeVault,
		Vault: nil,
	}

	_, err := NewManager(context.Background(), config)
	assert.Error(t, err)
}

func TestNewManager_UnknownMode_Final(t *testing.T) {
	config := &ManagerConfig{
		Mode: "unknown",
	}

	manager, err := NewManager(context.Background(), config)
	// Unknown mode should default to self-signed
	assert.NoError(t, err)
	assert.NotNil(t, manager)
	if manager != nil {
		_ = manager.Close()
	}
}

// ============================================================================
// Certificate Tests - Additional Coverage
// ============================================================================

func TestCertificate_IsValid_NilCertificate_Final(t *testing.T) {
	var cert *Certificate
	assert.False(t, cert.IsValid())
}

func TestCertificate_IsValid_NilX509Certificate_Final(t *testing.T) {
	cert := &Certificate{
		Certificate: nil,
	}
	assert.False(t, cert.IsValid())
}

func TestCertificate_IsExpiringSoon_NilCertificate_Final(t *testing.T) {
	var cert *Certificate
	assert.True(t, cert.IsExpiringSoon(time.Hour))
}

func TestCertificate_IsExpiringSoon_NilX509Certificate_Final(t *testing.T) {
	cert := &Certificate{
		Certificate: nil,
	}
	assert.True(t, cert.IsExpiringSoon(time.Hour))
}

func TestCertificate_TLSCertificate_NilCertificate_Final(t *testing.T) {
	var cert *Certificate
	_, err := cert.TLSCertificate()
	assert.Error(t, err)
}

func TestCertificate_TLSCertificate_EmptyPEM_Final(t *testing.T) {
	cert := &Certificate{
		CertificatePEM: nil,
		PrivateKeyPEM:  nil,
	}
	_, err := cert.TLSCertificate()
	assert.Error(t, err)
}

func TestCertificate_TLSCertificate_MissingPrivateKey_Final(t *testing.T) {
	cert := &Certificate{
		CertificatePEM: []byte("cert"),
		PrivateKeyPEM:  nil,
	}
	_, err := cert.TLSCertificate()
	assert.Error(t, err)
}

// ============================================================================
// SelfSignedProvider Tests - Additional Coverage
// ============================================================================

func TestSelfSignedProvider_GetCertificate_NilRequest_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	_, err = provider.GetCertificate(ctx, nil)
	assert.Error(t, err)
}

func TestSelfSignedProvider_GetCertificate_EmptyCommonName_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	_, err = provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "",
	})
	assert.Error(t, err)
}

func TestSelfSignedProvider_RotateCertificate_NilRequest_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	_, err = provider.RotateCertificate(ctx, nil)
	assert.Error(t, err)
}

func TestSelfSignedProvider_RotateCertificate_EmptyCommonName_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	_, err = provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "",
	})
	assert.Error(t, err)
}

func TestSelfSignedProvider_GetCA_Success_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	caPool, err := provider.GetCA(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, caPool)
}

func TestSelfSignedProvider_GetCertificate_CachedCert_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CertValidity: 24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName: "cached-test.example.com",
	}

	// First request
	cert1, err := provider.GetCertificate(ctx, req)
	require.NoError(t, err)

	// Second request should return cached cert
	cert2, err := provider.GetCertificate(ctx, req)
	require.NoError(t, err)

	// Should be the same certificate (cached)
	assert.Equal(t, cert1.SerialNumber, cert2.SerialNumber)
}

func TestSelfSignedProvider_GetCertificate_WithAllOptions_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CertValidity: 24 * time.Hour,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName:  "all-options.example.com",
		DNSNames:    []string{"alt1.example.com", "alt2.example.com"},
		IPAddresses: []string{"127.0.0.1", "192.168.1.1"},
		TTL:         12 * time.Hour,
	}

	cert, err := provider.GetCertificate(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, "all-options.example.com", cert.Certificate.Subject.CommonName)
	assert.Len(t, cert.Certificate.DNSNames, 2)
	assert.Len(t, cert.Certificate.IPAddresses, 2)
}

func TestSelfSignedProvider_Close_Multiple_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)

	// Close multiple times should not panic
	err = provider.Close()
	assert.NoError(t, err)

	err = provider.Close()
	assert.NoError(t, err)
}

// ============================================================================
// SelfSignedProviderConfig Tests - Additional Coverage
// ============================================================================

func TestSelfSignedProviderConfig_AllDefaults_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{})
	require.NoError(t, err)
	defer provider.Close()

	p := provider.(*selfSignedProvider)
	assert.Equal(t, DefaultCACommonName, p.config.CACommonName)
	assert.Equal(t, DefaultCAValidity, p.config.CAValidity)
	assert.Equal(t, DefaultCertValidity, p.config.CertValidity)
	assert.Equal(t, DefaultRotateBefore, p.config.RotateBefore)
	assert.Equal(t, DefaultKeySize, p.config.KeySize)
	assert.Equal(t, []string{DefaultOrganization}, p.config.Organization)
}

func TestSelfSignedProviderConfig_CustomValues_Final(t *testing.T) {
	config := &SelfSignedProviderConfig{
		CACommonName:    "Custom CA",
		CAValidity:      365 * 24 * time.Hour,
		CertValidity:    30 * 24 * time.Hour,
		RotateBefore:    7 * 24 * time.Hour,
		KeySize:         4096,
		Organization:    []string{"Custom Org"},
		SecretName:      "custom-secret",
		SecretNamespace: "custom-namespace",
	}

	provider, err := NewSelfSignedProvider(config)
	require.NoError(t, err)
	defer provider.Close()

	p := provider.(*selfSignedProvider)
	assert.Equal(t, "Custom CA", p.config.CACommonName)
	assert.Equal(t, 365*24*time.Hour, p.config.CAValidity)
	assert.Equal(t, 30*24*time.Hour, p.config.CertValidity)
	assert.Equal(t, 7*24*time.Hour, p.config.RotateBefore)
	assert.Equal(t, 4096, p.config.KeySize)
	assert.Equal(t, []string{"Custom Org"}, p.config.Organization)
	assert.Equal(t, "custom-secret", p.config.SecretName)
	assert.Equal(t, "custom-namespace", p.config.SecretNamespace)
}

// ============================================================================
// Context Cancellation Tests - Additional Coverage
// ============================================================================

func TestSelfSignedProvider_GetCertificate_ContextCanceledDuringGeneration_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout
	time.Sleep(10 * time.Millisecond)

	_, err = provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "timeout-test.example.com",
	})
	assert.Error(t, err)
}

func TestSelfSignedProvider_RotateCertificate_ContextCanceledDuringGeneration_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout
	time.Sleep(10 * time.Millisecond)

	_, err = provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "timeout-test.example.com",
	})
	assert.Error(t, err)
}

// ============================================================================
// TLSCertificate Tests - Additional Coverage
// ============================================================================

func TestCertificate_TLSCertificate_ValidCert_Final(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "tls-test.example.com",
	})
	require.NoError(t, err)

	tlsCert, err := cert.TLSCertificate()
	assert.NoError(t, err)
	assert.NotNil(t, tlsCert)
	assert.NotEmpty(t, tlsCert.Certificate)
}

// ============================================================================
// generateSerialNumber Tests - Additional Coverage
// ============================================================================

func TestGenerateSerialNumber_Uniqueness_Final(t *testing.T) {
	serials := make(map[string]bool)

	for i := 0; i < 100; i++ {
		serial, err := generateSerialNumber()
		require.NoError(t, err)
		require.NotNil(t, serial)

		serialStr := serial.String()
		assert.False(t, serials[serialStr], "duplicate serial number generated")
		serials[serialStr] = true
	}
}

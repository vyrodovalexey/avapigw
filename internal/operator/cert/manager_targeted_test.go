// Package cert provides targeted unit tests for coverage improvement.
// Target: 90%+ statement coverage.
package cert

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// TLSCertificate Tests - Improve from 83.3% to 90%+
// ============================================================================

func TestCertificate_TLSCertificate_Valid_Targeted(t *testing.T) {
	// Create a self-signed provider to get a valid certificate
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	// Test TLSCertificate
	tlsCert, err := cert.TLSCertificate()
	assert.NoError(t, err)
	assert.NotNil(t, tlsCert)
	assert.IsType(t, &tls.Certificate{}, tlsCert)
}

func TestCertificate_TLSCertificate_NilCertificate_Targeted(t *testing.T) {
	var cert *Certificate = nil

	tlsCert, err := cert.TLSCertificate()
	assert.Error(t, err)
	assert.Nil(t, tlsCert)
	assert.Contains(t, err.Error(), "certificate or private key is missing")
}

func TestCertificate_TLSCertificate_EmptyCertificatePEM_Targeted(t *testing.T) {
	cert := &Certificate{
		CertificatePEM: []byte{},
		PrivateKeyPEM:  []byte("test-key"),
	}

	tlsCert, err := cert.TLSCertificate()
	assert.Error(t, err)
	assert.Nil(t, tlsCert)
	assert.Contains(t, err.Error(), "certificate or private key is missing")
}

func TestCertificate_TLSCertificate_EmptyPrivateKeyPEM_Targeted(t *testing.T) {
	cert := &Certificate{
		CertificatePEM: []byte("test-cert"),
		PrivateKeyPEM:  []byte{},
	}

	tlsCert, err := cert.TLSCertificate()
	assert.Error(t, err)
	assert.Nil(t, tlsCert)
	assert.Contains(t, err.Error(), "certificate or private key is missing")
}

func TestCertificate_TLSCertificate_InvalidPEM_Targeted(t *testing.T) {
	cert := &Certificate{
		CertificatePEM: []byte("invalid-cert-pem"),
		PrivateKeyPEM:  []byte("invalid-key-pem"),
	}

	tlsCert, err := cert.TLSCertificate()
	assert.Error(t, err)
	assert.Nil(t, tlsCert)
	assert.Contains(t, err.Error(), "failed to create TLS certificate")
}

// ============================================================================
// NewManager Tests - Improve from 85.7% to 90%+
// ============================================================================

func TestNewManager_NilConfig_Targeted(t *testing.T) {
	ctx := context.Background()

	manager, err := NewManager(ctx, nil)
	assert.NoError(t, err)
	assert.NotNil(t, manager)

	// Should default to self-signed
	defer manager.Close()
}

func TestNewManager_SelfSignedMode_Targeted(t *testing.T) {
	ctx := context.Background()

	manager, err := NewManager(ctx, &ManagerConfig{
		Mode: CertModeSelfSigned,
		SelfSigned: &SelfSignedProviderConfig{
			CACommonName: "test-ca",
			CAValidity:   24 * time.Hour,
			CertValidity: 1 * time.Hour,
			RotateBefore: 30 * time.Minute,
			KeySize:      2048,
			Organization: []string{"test"},
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, manager)
	defer manager.Close()
}

func TestNewManager_VaultModeNilConfig_Targeted(t *testing.T) {
	ctx := context.Background()

	manager, err := NewManager(ctx, &ManagerConfig{
		Mode:  CertModeVault,
		Vault: nil,
	})
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "vault configuration required")
}

func TestNewManager_VaultModeWithConfig_Targeted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	manager, err := NewManager(ctx, &ManagerConfig{
		Mode: CertModeVault,
		Vault: &VaultProviderConfig{
			Address:  "http://localhost:8200",
			PKIMount: "pki",
			Role:     "operator",
		},
	})
	// Should fail due to connection timeout
	assert.Error(t, err)
	assert.Nil(t, manager)
}

func TestNewManager_UnknownModeDefaultsToSelfSigned_Targeted(t *testing.T) {
	ctx := context.Background()

	manager, err := NewManager(ctx, &ManagerConfig{
		Mode: CertificateMode("unknown"),
	})
	assert.NoError(t, err)
	assert.NotNil(t, manager)
	defer manager.Close()
}

func TestNewManager_EmptyModeDefaultsToSelfSigned_Targeted(t *testing.T) {
	ctx := context.Background()

	manager, err := NewManager(ctx, &ManagerConfig{
		Mode: "",
	})
	assert.NoError(t, err)
	assert.NotNil(t, manager)
	defer manager.Close()
}

// ============================================================================
// generateCA Tests - Improve from 76.5% to 90%+
// ============================================================================

func TestSelfSignedProvider_GenerateCA_Success_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	defer provider.Close()
}

func TestSelfSignedProvider_GenerateCA_DefaultConfig_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(nil)
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	defer provider.Close()
}

func TestSelfSignedProvider_GenerateCA_CustomOrganization_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "custom-ca",
		CAValidity:   48 * time.Hour,
		CertValidity: 2 * time.Hour,
		RotateBefore: 1 * time.Hour,
		KeySize:      4096,
		Organization: []string{"Custom Org", "Sub Org"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	defer provider.Close()
}

// ============================================================================
// issueCertificate Tests - Improve from 79.1% to 90%+
// ============================================================================

func TestSelfSignedProvider_IssueCertificate_WithDNSNames_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost", "test.example.com", "*.example.com"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, 3, len(cert.Certificate.DNSNames))
}

func TestSelfSignedProvider_IssueCertificate_WithIPAddresses_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName:  "test-server",
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{"127.0.0.1", "::1", "192.168.1.1"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, 3, len(cert.Certificate.IPAddresses))
}

func TestSelfSignedProvider_IssueCertificate_WithInvalidIPAddress_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName:  "test-server",
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{"invalid-ip", "127.0.0.1"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	// Only valid IP should be added
	assert.Equal(t, 1, len(cert.Certificate.IPAddresses))
}

func TestSelfSignedProvider_IssueCertificate_WithCustomTTL_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	customTTL := 30 * time.Minute
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
		TTL:        customTTL,
	})
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Check that expiration is approximately customTTL from now
	expectedExpiration := time.Now().Add(customTTL)
	assert.WithinDuration(t, expectedExpiration, cert.Expiration, 5*time.Second)
}

func TestSelfSignedProvider_IssueCertificate_ContextCanceled_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestSelfSignedProvider_IssueCertificate_ProviderClosed_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)

	// Close the provider
	provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "certificate provider is closed")
}

func TestSelfSignedProvider_IssueCertificate_NilRequest_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, nil)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestSelfSignedProvider_IssueCertificate_EmptyCommonName_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "",
		DNSNames:   []string{"localhost"},
	})
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "common name is required")
}

// ============================================================================
// Certificate caching tests
// ============================================================================

func TestSelfSignedProvider_CertificateCaching_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	// Get certificate first time
	cert1, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	// Get certificate second time - should return cached
	cert2, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	// Should be the same certificate (cached)
	assert.Equal(t, cert1.SerialNumber, cert2.SerialNumber)
}

// ============================================================================
// RotateCertificate tests
// ============================================================================

func TestSelfSignedProvider_RotateCertificate_Success_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	// Get initial certificate
	cert1, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	// Rotate certificate
	cert2, err := provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	// Should be a different certificate
	assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber)
}

func TestSelfSignedProvider_RotateCertificate_ContextCanceled_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cert, err := provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestSelfSignedProvider_RotateCertificate_ProviderClosed_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	provider.Close()

	ctx := context.Background()
	cert, err := provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	assert.Error(t, err)
	assert.Nil(t, cert)
}

// ============================================================================
// GetCA tests
// ============================================================================

func TestSelfSignedProvider_GetCA_Success_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	caPool, err := provider.GetCA(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, caPool)
}

func TestSelfSignedProvider_GetCA_ProviderClosed_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	provider.Close()

	ctx := context.Background()
	caPool, err := provider.GetCA(ctx)
	assert.Error(t, err)
	assert.Nil(t, caPool)
}

// ============================================================================
// Certificate validity tests
// ============================================================================

func TestCertificate_IsExpiringSoon_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	// Should not be expiring soon (within 30 minutes)
	assert.False(t, cert.IsExpiringSoon(30*time.Minute))

	// Should be expiring soon (within 2 hours)
	assert.True(t, cert.IsExpiringSoon(2*time.Hour))
}

func TestCertificate_IsExpiringSoon_NilCertificate_Targeted(t *testing.T) {
	var cert *Certificate = nil
	assert.True(t, cert.IsExpiringSoon(time.Hour))
}

func TestCertificate_IsExpiringSoon_NilX509Certificate_Targeted(t *testing.T) {
	cert := &Certificate{
		Certificate: nil,
	}
	assert.True(t, cert.IsExpiringSoon(time.Hour))
}

func TestCertificate_IsValid_Targeted(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "test-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: 1 * time.Hour,
		RotateBefore: 30 * time.Minute,
		KeySize:      2048,
		Organization: []string{"test"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	require.NoError(t, err)

	assert.True(t, cert.IsValid())
}

func TestCertificate_IsValid_NilCertificate_Targeted(t *testing.T) {
	var cert *Certificate = nil
	assert.False(t, cert.IsValid())
}

func TestCertificate_IsValid_NilX509Certificate_Targeted(t *testing.T) {
	cert := &Certificate{
		Certificate: nil,
	}
	assert.False(t, cert.IsValid())
}

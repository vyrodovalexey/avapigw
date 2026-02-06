// Package cert provides lifecycle tests for self-signed certificate operations.
package cert

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// issueCertificate Tests - Improve from 79.1% to 90%+
// ============================================================================

func TestSelfSignedProvider_IssueCertificate_WithIPAddresses(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName:  "test.example.com",
		DNSNames:    []string{"test.example.com", "localhost"},
		IPAddresses: []string{"127.0.0.1", "::1"},
	})
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)
	assert.NotEmpty(t, cert.CAChainPEM)
	assert.True(t, cert.IsValid())
	assert.Equal(t, 2, len(cert.Certificate.IPAddresses))
}

func TestSelfSignedProvider_IssueCertificate_WithInvalidIP(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName:  "test.example.com",
		IPAddresses: []string{"not-an-ip", "127.0.0.1"},
	})
	require.NoError(t, err)
	assert.NotNil(t, cert)
	// Invalid IP should be skipped, only valid one should be present
	assert.Equal(t, 1, len(cert.Certificate.IPAddresses))
}

func TestSelfSignedProvider_IssueCertificate_WithCustomTTL(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CertValidity: 24 * time.Hour,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test.example.com",
		TTL:        1 * time.Hour, // Custom TTL shorter than default
	})
	require.NoError(t, err)
	assert.NotNil(t, cert)

	// Certificate should expire within ~1 hour (with some tolerance)
	expiresIn := time.Until(cert.Expiration)
	assert.True(t, expiresIn <= 1*time.Hour+time.Minute)
	assert.True(t, expiresIn > 59*time.Minute)
}

func TestSelfSignedProvider_IssueCertificate_CachedCert(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CertValidity: 24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	// First call - generates new cert
	cert1, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "cached-test.example.com",
		DNSNames:   []string{"cached-test.example.com"},
	})
	require.NoError(t, err)

	// Second call - should return cached cert
	cert2, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "cached-test.example.com",
		DNSNames:   []string{"cached-test.example.com"},
	})
	require.NoError(t, err)

	// Should be the same certificate (cached)
	assert.Equal(t, cert1.SerialNumber, cert2.SerialNumber)
}

func TestSelfSignedProvider_IssueCertificate_RotateExpiring(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CertValidity: 2 * time.Second,  // Very short validity
		RotateBefore: 10 * time.Second, // Rotate before is longer than validity
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	// First call - generates new cert
	cert1, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "expiring-test.example.com",
	})
	require.NoError(t, err)

	// The cert is already "expiring soon" because RotateBefore > CertValidity
	// So the second call should generate a new cert
	cert2, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "expiring-test.example.com",
	})
	require.NoError(t, err)

	// Should be different certificates (rotated)
	assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber)
}

func TestSelfSignedProvider_IssueCertificate_NoDNSNames(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "no-dns.example.com",
		// No DNSNames
	})
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Empty(t, cert.Certificate.DNSNames)
}

// ============================================================================
// generateCA Tests - Improve from 76.5% to 90%+
// ============================================================================

func TestSelfSignedProvider_GenerateCA_CustomConfig(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		CACommonName: "Custom CA",
		CAValidity:   48 * time.Hour,
		KeySize:      2048,
		Organization: []string{"Custom Org", "Custom Unit"},
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	caPool, err := provider.GetCA(ctx)
	require.NoError(t, err)
	assert.NotNil(t, caPool)
}

func TestSelfSignedProvider_GenerateCA_DefaultConfig(t *testing.T) {
	provider, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	caPool, err := provider.GetCA(ctx)
	require.NoError(t, err)
	assert.NotNil(t, caPool)
}

// ============================================================================
// GetCertificate edge cases
// ============================================================================

func TestSelfSignedProvider_GetCertificate_ClosedProvider(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)

	// Close the provider
	err = provider.Close()
	require.NoError(t, err)

	ctx := context.Background()
	_, err = provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test.example.com",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestSelfSignedProvider_GetCertificate_NilRequest(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	_, err = provider.GetCertificate(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestSelfSignedProvider_GetCertificate_EmptyCommonName(t *testing.T) {
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
	assert.Contains(t, err.Error(), "common name is required")
}

// ============================================================================
// RotateCertificate Tests
// ============================================================================

func TestSelfSignedProvider_RotateCertificate_ClosedProvider(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)

	err = provider.Close()
	require.NoError(t, err)

	ctx := context.Background()
	_, err = provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "test.example.com",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestSelfSignedProvider_RotateCertificate_NilRequest(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	_, err = provider.RotateCertificate(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestSelfSignedProvider_RotateCertificate_Success(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	// Get initial cert
	cert1, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "rotate-test.example.com",
		DNSNames:   []string{"rotate-test.example.com"},
	})
	require.NoError(t, err)

	// Rotate
	cert2, err := provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "rotate-test.example.com",
		DNSNames:   []string{"rotate-test.example.com"},
	})
	require.NoError(t, err)

	// Should be different certificates
	assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber)
}

// ============================================================================
// GetCA Tests
// ============================================================================

func TestSelfSignedProvider_GetCA_ClosedProvider(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)

	err = provider.Close()
	require.NoError(t, err)

	ctx := context.Background()
	_, err = provider.GetCA(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

// ============================================================================
// TLSCertificate Tests
// ============================================================================

func TestCertificate_TLSCertificate_Success(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "tls-test.example.com",
		DNSNames:   []string{"tls-test.example.com"},
	})
	require.NoError(t, err)

	tlsCert, err := cert.TLSCertificate()
	require.NoError(t, err)
	assert.NotNil(t, tlsCert)
}

func TestCertificate_TLSCertificate_NilCert(t *testing.T) {
	var cert *Certificate
	_, err := cert.TLSCertificate()
	assert.Error(t, err)
}

func TestCertificate_TLSCertificate_EmptyPEM(t *testing.T) {
	cert := &Certificate{}
	_, err := cert.TLSCertificate()
	assert.Error(t, err)
}

// ============================================================================
// Close Tests
// ============================================================================

func TestSelfSignedProvider_Close_Idempotent(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	require.NoError(t, err)

	err = provider.Close()
	assert.NoError(t, err)

	// Second close should also succeed
	err = provider.Close()
	assert.NoError(t, err)
}

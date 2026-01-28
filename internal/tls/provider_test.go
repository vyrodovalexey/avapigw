package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateEventType_String(t *testing.T) {
	tests := []struct {
		eventType CertificateEventType
		expected  string
	}{
		{CertificateEventLoaded, "loaded"},
		{CertificateEventReloaded, "reloaded"},
		{CertificateEventExpiring, "expiring"},
		{CertificateEventError, "error"},
		{CertificateEventType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.eventType.String())
		})
	}
}

func TestExtractCertificateInfo(t *testing.T) {
	// Generate a test certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"test.example.com", "alt.example.com"},
		EmailAddresses:        []string{"test@example.com"},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	info := ExtractCertificateInfo(cert)

	assert.NotNil(t, info)
	assert.Contains(t, info.Subject, "test.example.com")
	assert.Equal(t, "12345", info.SerialNumber)
	assert.Contains(t, info.DNSNames, "test.example.com")
	assert.Contains(t, info.DNSNames, "alt.example.com")
	assert.Contains(t, info.EmailAddresses, "test@example.com")
	assert.False(t, info.IsCA)
}

func TestExtractCertificateInfo_Nil(t *testing.T) {
	info := ExtractCertificateInfo(nil)
	assert.Nil(t, info)
}

func TestNopProvider(t *testing.T) {
	provider := NewNopProvider()
	ctx := context.Background()

	// GetCertificate should return ErrCertificateNotFound
	cert, err := provider.GetCertificate(ctx, nil)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrCertificateNotFound)

	// GetClientCA should return nil
	pool, err := provider.GetClientCA(ctx)
	assert.Nil(t, pool)
	assert.NoError(t, err)

	// Watch should return a closed channel
	ch := provider.Watch(ctx)
	_, ok := <-ch
	assert.False(t, ok, "channel should be closed")

	// Close should succeed
	err = provider.Close()
	assert.NoError(t, err)

	// After close, GetCertificate should return ErrProviderClosed
	cert, err = provider.GetCertificate(ctx, nil)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrProviderClosed)

	// After close, GetClientCA should return ErrProviderClosed
	pool, err = provider.GetClientCA(ctx)
	assert.Nil(t, pool)
	assert.ErrorIs(t, err, ErrProviderClosed)
}

func TestNopProvider_ImplementsInterface(t *testing.T) {
	var _ CertificateProvider = (*NopProvider)(nil)
}

func TestCertificateEvent(t *testing.T) {
	cert := &tls.Certificate{}
	testErr := assert.AnError

	event := CertificateEvent{
		Type:        CertificateEventReloaded,
		Certificate: cert,
		Error:       testErr,
		Message:     "test message",
	}

	assert.Equal(t, CertificateEventReloaded, event.Type)
	assert.Equal(t, cert, event.Certificate)
	assert.Equal(t, testErr, event.Error)
	assert.Equal(t, "test message", event.Message)
}

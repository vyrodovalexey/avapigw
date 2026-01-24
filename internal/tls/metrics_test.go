package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics("test")

	assert.NotNil(t, m)
	assert.NotNil(t, m.connectionsTotal)
	assert.NotNil(t, m.handshakeDuration)
	assert.NotNil(t, m.certificateExpiry)
	assert.NotNil(t, m.certificateReload)
	assert.NotNil(t, m.handshakeErrors)
	assert.NotNil(t, m.clientCertValidation)
	assert.NotNil(t, m.registry)
}

func TestNewMetrics_DefaultNamespace(t *testing.T) {
	m := NewMetrics("")

	// Should use "gateway" as default namespace
	assert.NotNil(t, m)
}

func TestNewMetrics_WithRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics("test", WithRegistry(registry))

	assert.Equal(t, registry, m.Registry())
}

func TestMetrics_RecordConnection(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordConnection(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLSModeSimple)
	m.RecordConnection(tls.VersionTLS13, tls.TLS_AES_256_GCM_SHA384, TLSModeMutual)
}

func TestMetrics_RecordHandshakeDuration(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordHandshakeDuration(100*time.Millisecond, tls.VersionTLS12, TLSModeSimple)
	m.RecordHandshakeDuration(50*time.Millisecond, tls.VersionTLS13, TLSModeMutual)
}

func TestMetrics_UpdateCertificateExpiry(t *testing.T) {
	m := NewMetrics("test")

	// Generate a test certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Should not panic
	m.UpdateCertificateExpiry(cert, "server")
	m.UpdateCertificateExpiry(nil, "server") // nil should be handled
}

func TestMetrics_UpdateCertificateExpiryFromTLS(t *testing.T) {
	m := NewMetrics("test")

	// Generate a test certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
	}

	// Should not panic
	m.UpdateCertificateExpiryFromTLS(tlsCert, "server")
	m.UpdateCertificateExpiryFromTLS(nil, "server")                                             // nil should be handled
	m.UpdateCertificateExpiryFromTLS(&tls.Certificate{}, "server")                              // empty should be handled
	m.UpdateCertificateExpiryFromTLS(&tls.Certificate{Certificate: [][]byte{{0x00}}}, "server") // invalid should be handled
}

func TestMetrics_RecordCertificateReload(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordCertificateReload(true)
	m.RecordCertificateReload(false)
}

func TestMetrics_RecordHandshakeError(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordHandshakeError("certificate_error")
	m.RecordHandshakeError("timeout")
}

func TestMetrics_RecordClientCertValidation(t *testing.T) {
	m := NewMetrics("test")

	// Should not panic
	m.RecordClientCertValidation(true, "")
	m.RecordClientCertValidation(false, "expired")
	m.RecordClientCertValidation(false, "not_allowed")
}

func TestMetrics_Describe(t *testing.T) {
	m := NewMetrics("test")

	ch := make(chan *prometheus.Desc, 100)
	m.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	// Should have descriptions for all metrics
	assert.Greater(t, count, 0)
}

func TestMetrics_Collect(t *testing.T) {
	m := NewMetrics("test")

	// Record some metrics
	m.RecordConnection(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLSModeSimple)
	m.RecordCertificateReload(true)

	ch := make(chan prometheus.Metric, 100)
	m.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	// Should have collected metrics
	assert.Greater(t, count, 0)
}

func TestNopMetrics(t *testing.T) {
	m := NewNopMetrics()

	// All methods should be no-ops and not panic
	m.RecordConnection(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLSModeSimple)
	m.RecordHandshakeDuration(100*time.Millisecond, tls.VersionTLS12, TLSModeSimple)
	m.UpdateCertificateExpiry(nil, "server")
	m.UpdateCertificateExpiryFromTLS(nil, "server")
	m.RecordCertificateReload(true)
	m.RecordHandshakeError("test")
	m.RecordClientCertValidation(true, "")
}

func TestNopMetrics_ImplementsInterface(t *testing.T) {
	var _ MetricsRecorder = (*NopMetrics)(nil)
}

func TestMetrics_ImplementsInterface(t *testing.T) {
	var _ MetricsRecorder = (*Metrics)(nil)
}

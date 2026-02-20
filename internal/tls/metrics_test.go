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
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	// Use a custom registry to avoid singleton behavior in tests
	registry := prometheus.NewRegistry()
	m := NewMetrics("test", WithRegistry(registry))

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
	m := NewMetrics("test_conn", WithRegistry(prometheus.NewRegistry()))

	m.RecordConnection(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLSModeSimple)
	m.RecordConnection(tls.VersionTLS13, tls.TLS_AES_256_GCM_SHA384, TLSModeMutual)

	// Verify connections were recorded
	tls12Count := testutil.ToFloat64(m.connectionsTotal.WithLabelValues(
		TLSVersionName(tls.VersionTLS12),
		CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
		string(TLSModeSimple),
	))
	assert.Equal(t, float64(1), tls12Count, "TLS 1.2 connection should be recorded")

	tls13Count := testutil.ToFloat64(m.connectionsTotal.WithLabelValues(
		TLSVersionName(tls.VersionTLS13),
		CipherSuiteName(tls.TLS_AES_256_GCM_SHA384),
		string(TLSModeMutual),
	))
	assert.Equal(t, float64(1), tls13Count, "TLS 1.3 connection should be recorded")
}

func TestMetrics_RecordHandshakeDuration(t *testing.T) {
	m := NewMetrics("test_handshake", WithRegistry(prometheus.NewRegistry()))

	m.RecordHandshakeDuration(100*time.Millisecond, tls.VersionTLS12, TLSModeSimple)
	m.RecordHandshakeDuration(50*time.Millisecond, tls.VersionTLS13, TLSModeMutual)

	// Verify histogram has observations
	count := testutil.CollectAndCount(m.handshakeDuration)
	assert.Greater(t, count, 0, "handshakeDuration should have observations")
}

func TestMetrics_UpdateCertificateExpiry(t *testing.T) {
	m := NewMetrics("test", WithRegistry(prometheus.NewRegistry()))

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

	m.UpdateCertificateExpiry(cert, "server")

	// Verify expiry was recorded
	expiryVal := testutil.ToFloat64(m.certificateExpiry.WithLabelValues("test.example.com", "server"))
	assert.Greater(t, expiryVal, float64(0), "certificate expiry should be positive for valid cert")

	// nil should be handled gracefully
	m.UpdateCertificateExpiry(nil, "server")
}

func TestMetrics_UpdateCertificateExpiryFromTLS(t *testing.T) {
	m := NewMetrics("test", WithRegistry(prometheus.NewRegistry()))

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
	m := NewMetrics("test_reload", WithRegistry(prometheus.NewRegistry()))

	m.RecordCertificateReload(true)
	successCount := testutil.ToFloat64(m.certificateReload.WithLabelValues("success"))
	assert.Equal(t, float64(1), successCount, "success reload should be 1")

	m.RecordCertificateReload(false)
	failureCount := testutil.ToFloat64(m.certificateReload.WithLabelValues("failure"))
	assert.Equal(t, float64(1), failureCount, "failure reload should be 1")
}

func TestMetrics_RecordHandshakeError(t *testing.T) {
	m := NewMetrics("test_hs_err", WithRegistry(prometheus.NewRegistry()))

	m.RecordHandshakeError("certificate_error")
	certErrCount := testutil.ToFloat64(m.handshakeErrors.WithLabelValues("certificate_error"))
	assert.Equal(t, float64(1), certErrCount, "certificate_error should be 1")

	m.RecordHandshakeError("timeout")
	timeoutCount := testutil.ToFloat64(m.handshakeErrors.WithLabelValues("timeout"))
	assert.Equal(t, float64(1), timeoutCount, "timeout should be 1")
}

func TestMetrics_RecordClientCertValidation(t *testing.T) {
	m := NewMetrics("test_client_cert", WithRegistry(prometheus.NewRegistry()))

	m.RecordClientCertValidation(true, "")
	successCount := testutil.ToFloat64(m.clientCertValidation.WithLabelValues("success"))
	assert.Equal(t, float64(1), successCount, "success validation should be 1")

	m.RecordClientCertValidation(false, "expired")
	expiredCount := testutil.ToFloat64(m.clientCertValidation.WithLabelValues("expired"))
	assert.Equal(t, float64(1), expiredCount, "expired validation should be 1")

	m.RecordClientCertValidation(false, "not_allowed")
	notAllowedCount := testutil.ToFloat64(m.clientCertValidation.WithLabelValues("not_allowed"))
	assert.Equal(t, float64(1), notAllowedCount, "not_allowed validation should be 1")
}

func TestMetrics_Describe(t *testing.T) {
	m := NewMetrics("test", WithRegistry(prometheus.NewRegistry()))

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
	m := NewMetrics("test", WithRegistry(prometheus.NewRegistry()))

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
	require.NotNil(t, m, "NewNopMetrics() should not return nil")

	// All methods should be no-ops and not panic
	m.RecordConnection(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLSModeSimple)
	m.RecordHandshakeDuration(100*time.Millisecond, tls.VersionTLS12, TLSModeSimple)
	m.UpdateCertificateExpiry(nil, "server")
	m.UpdateCertificateExpiryFromTLS(nil, "server")
	m.RecordCertificateReload(true)
	m.RecordHandshakeError("test")
	m.RecordClientCertValidation(true, "")

	// Verify NopMetrics satisfies the interface
	var recorder MetricsRecorder = m
	assert.NotNil(t, recorder, "NopMetrics should satisfy MetricsRecorder interface")
}

func TestNopMetrics_ImplementsInterface(t *testing.T) {
	var _ MetricsRecorder = (*NopMetrics)(nil)
}

func TestMetrics_ImplementsInterface(t *testing.T) {
	var _ MetricsRecorder = (*Metrics)(nil)
}

func TestMetrics_Init(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics("test_init", WithRegistry(registry))

	// Init should not panic
	assert.NotPanics(t, func() {
		m.Init()
	})

	// Verify metrics are pre-populated by gathering from registry
	mfs, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)

	// Init should be idempotent
	assert.NotPanics(t, func() {
		m.Init()
	})
}

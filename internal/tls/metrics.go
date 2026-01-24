package tls

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for TLS operations.
type Metrics struct {
	connectionsTotal     *prometheus.CounterVec
	handshakeDuration    *prometheus.HistogramVec
	certificateExpiry    *prometheus.GaugeVec
	certificateReload    *prometheus.CounterVec
	handshakeErrors      *prometheus.CounterVec
	clientCertValidation *prometheus.CounterVec

	registry *prometheus.Registry
	mu       sync.RWMutex
}

// MetricsOption is a functional option for configuring Metrics.
type MetricsOption func(*Metrics)

// WithRegistry sets a custom Prometheus registry.
func WithRegistry(registry *prometheus.Registry) MetricsOption {
	return func(m *Metrics) {
		m.registry = registry
	}
}

// NewMetrics creates a new Metrics instance with the given namespace.
func NewMetrics(namespace string, opts ...MetricsOption) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	m := &Metrics{}

	for _, opt := range opts {
		opt(m)
	}

	if m.registry == nil {
		m.registry = prometheus.NewRegistry()
	}

	m.connectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "connections_total",
			Help:      "Total number of TLS connections by version, cipher suite, and mode",
		},
		[]string{"version", "cipher", "mode"},
	)

	m.handshakeDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "handshake_duration_seconds",
			Help:      "TLS handshake duration in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"version", "mode"},
	)

	m.certificateExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "certificate_expiry_seconds",
			Help:      "Time until certificate expiry in seconds",
		},
		[]string{"subject", "type"},
	)

	m.certificateReload = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "certificate_reload_total",
			Help:      "Total number of certificate reload attempts by status",
		},
		[]string{"status"},
	)

	m.handshakeErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "handshake_errors_total",
			Help:      "Total number of TLS handshake errors by reason",
		},
		[]string{"reason"},
	)

	m.clientCertValidation = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "client_cert_validation_total",
			Help:      "Total number of client certificate validations by result",
		},
		[]string{"result"},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.connectionsTotal,
		m.handshakeDuration,
		m.certificateExpiry,
		m.certificateReload,
		m.handshakeErrors,
		m.clientCertValidation,
	)

	return m
}

// RecordConnection records a successful TLS connection.
func (m *Metrics) RecordConnection(version uint16, cipherSuite uint16, mode TLSMode) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versionName := TLSVersionName(version)
	cipherName := CipherSuiteName(cipherSuite)
	m.connectionsTotal.WithLabelValues(versionName, cipherName, string(mode)).Inc()
}

// RecordHandshakeDuration records the duration of a TLS handshake.
func (m *Metrics) RecordHandshakeDuration(duration time.Duration, version uint16, mode TLSMode) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versionName := TLSVersionName(version)
	m.handshakeDuration.WithLabelValues(versionName, string(mode)).Observe(duration.Seconds())
}

// UpdateCertificateExpiry updates the certificate expiry metric.
func (m *Metrics) UpdateCertificateExpiry(cert *x509.Certificate, certType string) {
	if cert == nil {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	expirySeconds := time.Until(cert.NotAfter).Seconds()
	subject := cert.Subject.CommonName
	if subject == "" {
		subject = cert.Subject.String()
	}

	m.certificateExpiry.WithLabelValues(subject, certType).Set(expirySeconds)
}

// UpdateCertificateExpiryFromTLS updates the certificate expiry metric from a tls.Certificate.
func (m *Metrics) UpdateCertificateExpiryFromTLS(cert *tls.Certificate, certType string) {
	if cert == nil || len(cert.Certificate) == 0 {
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	m.UpdateCertificateExpiry(x509Cert, certType)
}

// RecordCertificateReload records a certificate reload attempt.
func (m *Metrics) RecordCertificateReload(success bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := "success"
	if !success {
		status = "failure"
	}
	m.certificateReload.WithLabelValues(status).Inc()
}

// RecordHandshakeError records a TLS handshake error.
func (m *Metrics) RecordHandshakeError(reason string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.handshakeErrors.WithLabelValues(reason).Inc()
}

// RecordClientCertValidation records a client certificate validation result.
func (m *Metrics) RecordClientCertValidation(success bool, reason string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := "success"
	if !success {
		result = reason
	}
	m.clientCertValidation.WithLabelValues(result).Inc()
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// Describe implements prometheus.Collector.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.connectionsTotal.Describe(ch)
	m.handshakeDuration.Describe(ch)
	m.certificateExpiry.Describe(ch)
	m.certificateReload.Describe(ch)
	m.handshakeErrors.Describe(ch)
	m.clientCertValidation.Describe(ch)
}

// Collect implements prometheus.Collector.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.connectionsTotal.Collect(ch)
	m.handshakeDuration.Collect(ch)
	m.certificateExpiry.Collect(ch)
	m.certificateReload.Collect(ch)
	m.handshakeErrors.Collect(ch)
	m.clientCertValidation.Collect(ch)
}

// NopMetrics is a no-op implementation of metrics for testing.
type NopMetrics struct{}

// NewNopMetrics creates a new NopMetrics instance.
func NewNopMetrics() *NopMetrics {
	return &NopMetrics{}
}

// RecordConnection is a no-op.
func (m *NopMetrics) RecordConnection(_ uint16, _ uint16, _ TLSMode) {}

// RecordHandshakeDuration is a no-op.
func (m *NopMetrics) RecordHandshakeDuration(_ time.Duration, _ uint16, _ TLSMode) {}

// UpdateCertificateExpiry is a no-op.
func (m *NopMetrics) UpdateCertificateExpiry(_ *x509.Certificate, _ string) {}

// UpdateCertificateExpiryFromTLS is a no-op.
func (m *NopMetrics) UpdateCertificateExpiryFromTLS(_ *tls.Certificate, _ string) {}

// RecordCertificateReload is a no-op.
func (m *NopMetrics) RecordCertificateReload(_ bool) {}

// RecordHandshakeError is a no-op.
func (m *NopMetrics) RecordHandshakeError(_ string) {}

// RecordClientCertValidation is a no-op.
func (m *NopMetrics) RecordClientCertValidation(_ bool, _ string) {}

// MetricsRecorder defines the interface for recording TLS metrics.
type MetricsRecorder interface {
	RecordConnection(version uint16, cipherSuite uint16, mode TLSMode)
	RecordHandshakeDuration(duration time.Duration, version uint16, mode TLSMode)
	UpdateCertificateExpiry(cert *x509.Certificate, certType string)
	UpdateCertificateExpiryFromTLS(cert *tls.Certificate, certType string)
	RecordCertificateReload(success bool)
	RecordHandshakeError(reason string)
	RecordClientCertValidation(success bool, reason string)
}

// Ensure implementations satisfy the interface.
var (
	_ MetricsRecorder = (*Metrics)(nil)
	_ MetricsRecorder = (*NopMetrics)(nil)
)

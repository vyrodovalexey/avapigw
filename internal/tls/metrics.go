package tls

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// defaultTLSMetrics holds the singleton Metrics instance registered with the default global registry.
// This ensures metrics are only registered once with the default Prometheus registry,
// avoiding duplicate registration panics.
var (
	defaultTLSMetrics     *Metrics
	defaultTLSMetricsOnce sync.Once
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
// When not set, metrics are automatically registered with the default global registry via promauto.
func WithRegistry(registry *prometheus.Registry) MetricsOption {
	return func(m *Metrics) {
		m.registry = registry
	}
}

// NewMetrics creates a new Metrics instance with the given namespace.
// By default, metrics are registered with the default global Prometheus registry via promauto
// using a singleton pattern to avoid duplicate registration panics.
// Use WithRegistry to register with a custom registry instead.
func NewMetrics(namespace string, opts ...MetricsOption) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	m := &Metrics{}

	for _, opt := range opts {
		opt(m)
	}

	// When a custom registry is provided, create a new Metrics instance with that registry.
	// Otherwise, return the singleton instance registered with the default global registry.
	if m.registry != nil {
		factory := promauto.With(m.registry)
		m.initWithFactory(namespace, factory)
		return m
	}

	// Use singleton pattern for the default global registry to prevent duplicate registration.
	defaultTLSMetricsOnce.Do(func() {
		defaultTLSMetrics = &Metrics{}
		factory := promauto.With(prometheus.DefaultRegisterer)
		defaultTLSMetrics.initWithFactory(namespace, factory)
	})

	return defaultTLSMetrics
}

// initWithFactory initializes all metrics using the given promauto factory.
func (m *Metrics) initWithFactory(namespace string, factory promauto.Factory) {
	m.connectionsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "connections_total",
			Help:      "Total number of TLS connections by version, cipher suite, and mode",
		},
		[]string{"version", "cipher", "mode"},
	)

	m.handshakeDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "handshake_duration_seconds",
			Help:      "TLS handshake duration in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"version", "mode"},
	)

	m.certificateExpiry = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "certificate_expiry_seconds",
			Help:      "Time until certificate expiry in seconds",
		},
		[]string{"subject", "type"},
	)

	m.certificateReload = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "certificate_reload_total",
			Help:      "Total number of certificate reload attempts by status",
		},
		[]string{"status"},
	)

	m.handshakeErrors = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "handshake_errors_total",
			Help:      "Total number of TLS handshake errors by reason",
		},
		[]string{"reason"},
	)

	m.clientCertValidation = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "tls",
			Name:      "client_cert_validation_total",
			Help:      "Total number of client certificate validations by result",
		},
		[]string{"result"},
	)
}

// Init pre-populates common label combinations with zero values so
// that TLS Vec metrics appear in /metrics output immediately after
// startup. Prometheus *Vec types only emit metric lines after
// WithLabelValues() is called at least once. This method is
// idempotent and safe to call multiple times.
func (m *Metrics) Init() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := []string{"1.2", "1.3"}
	modes := []string{"server", "client", "mtls"}
	for _, v := range versions {
		for _, mode := range modes {
			m.handshakeDuration.WithLabelValues(v, mode)
		}
	}

	handshakeErrorReasons := []string{
		"timeout",
		"protocol_error",
		"certificate_error",
	}
	for _, reason := range handshakeErrorReasons {
		m.handshakeErrors.WithLabelValues(reason)
	}

	certValidationResults := []string{
		"success",
		"failure",
		"expired",
		"revoked",
	}
	for _, result := range certValidationResults {
		m.clientCertValidation.WithLabelValues(result)
	}
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

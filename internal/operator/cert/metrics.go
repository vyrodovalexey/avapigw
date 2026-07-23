// Package cert provides certificate management for the operator.
package cert

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metric label constants.
const (
	metricsNamespace = "avapigw_operator"
	metricsSubsystem = "cert"
	labelProvider    = "provider"
	subsystemWebhook = "webhook"
)

// Provider label values shared across metrics and providers.
const (
	providerSelfSigned = "selfsigned"
	providerVault      = "vault"
	providerFile       = "file"
)

// Result label values shared across metrics.
const (
	labelResult   = "result"
	resultSuccess = "success"
	resultError   = "error"
)

// pemTypeCertificate is the PEM block type for X.509 certificates.
const pemTypeCertificate = "CERTIFICATE"

// CertMetrics holds Prometheus metrics for certificate operations.
type CertMetrics struct {
	issuedTotal     *prometheus.CounterVec
	rotationsTotal  *prometheus.CounterVec
	errorsTotal     *prometheus.CounterVec
	expirySeconds   *prometheus.GaugeVec
	caReuseTotal    *prometheus.CounterVec
	secretSyncTotal *prometheus.CounterVec
}

var (
	certMetricsInstance *CertMetrics
	certMetricsOnce     sync.Once
)

// InitCertMetrics initializes the singleton cert metrics instance with the given
// Prometheus registerer. If registerer is nil, metrics are registered with the
// default registerer. Must be called before GetCertMetrics for metrics to appear
// on the correct registry; subsequent calls are no-ops (sync.Once).
func InitCertMetrics(registerer prometheus.Registerer) {
	certMetricsOnce.Do(func() {
		if registerer == nil {
			registerer = prometheus.DefaultRegisterer
		}
		certMetricsInstance = newCertMetricsWithFactory(promauto.With(registerer))
	})
}

// GetCertMetrics returns the singleton cert metrics instance.
// If InitCertMetrics has not been called, metrics are lazily
// initialized with the default registerer.
func GetCertMetrics() *CertMetrics {
	InitCertMetrics(nil)
	return certMetricsInstance
}

// InitCertVecMetrics pre-populates all CertMetrics vector metrics with common label
// combinations so they appear on /metrics immediately with zero values.
func InitCertVecMetrics() {
	m := GetCertMetrics()

	providers := []string{providerSelfSigned, providerVault, providerFile}
	operations := []string{"issue", "rotate", "renew", "load"}

	for _, p := range providers {
		// issuedTotal: provider
		m.issuedTotal.WithLabelValues(p)
		// rotationsTotal: provider
		m.rotationsTotal.WithLabelValues(p)
		// caReuseTotal: provider
		m.caReuseTotal.WithLabelValues(p)
		// errorsTotal: provider × operation
		for _, op := range operations {
			m.errorsTotal.WithLabelValues(p, op)
		}
	}

	for _, op := range []string{"get", "create", "update"} {
		for _, r := range []string{resultSuccess, resultError} {
			m.secretSyncTotal.WithLabelValues(op, r)
		}
	}
}

// newCertMetricsWithFactory creates cert metrics using the given promauto factory.
func newCertMetricsWithFactory(factory promauto.Factory) *CertMetrics {
	return &CertMetrics{
		issuedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "issued_total",
				Help: "Total number of " +
					"certificates issued",
			},
			[]string{labelProvider},
		),
		rotationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "rotations_total",
				Help: "Total number of " +
					"certificate rotations",
			},
			[]string{labelProvider},
		),
		errorsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "errors_total",
				Help: "Total number of " +
					"certificate errors",
			},
			[]string{labelProvider, "operation"},
		),
		expirySeconds: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "expiry_seconds",
				Help: "Time until certificate " +
					"expiry in seconds",
			},
			[]string{"common_name"},
		),
		caReuseTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "ca_reuse_total",
				Help: "Total number of times a persisted " +
					"CA was reused instead of generating a new one",
			},
			[]string{labelProvider},
		),
		secretSyncTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "secret_sync_total",
				Help: "Total number of certificate Secret " +
					"persistence operations",
			},
			[]string{"operation", labelResult},
		),
	}
}

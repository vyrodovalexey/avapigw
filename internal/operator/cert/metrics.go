// Package cert provides certificate management for the operator.
package cert

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// CertMetrics holds Prometheus metrics for certificate operations.
type CertMetrics struct {
	issuedTotal    *prometheus.CounterVec
	rotationsTotal *prometheus.CounterVec
	errorsTotal    *prometheus.CounterVec
	expirySeconds  *prometheus.GaugeVec
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

	providers := []string{"selfsigned", "vault"}
	operations := []string{"issue", "rotate", "renew"}

	for _, p := range providers {
		// issuedTotal: provider
		m.issuedTotal.WithLabelValues(p)
		// rotationsTotal: provider
		m.rotationsTotal.WithLabelValues(p)
		// errorsTotal: provider × operation
		for _, op := range operations {
			m.errorsTotal.WithLabelValues(p, op)
		}
	}
}

// newCertMetricsWithFactory creates cert metrics using the given promauto factory.
func newCertMetricsWithFactory(factory promauto.Factory) *CertMetrics {
	return &CertMetrics{
		issuedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "cert",
				Name:      "issued_total",
				Help: "Total number of " +
					"certificates issued",
			},
			[]string{"provider"},
		),
		rotationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "cert",
				Name:      "rotations_total",
				Help: "Total number of " +
					"certificate rotations",
			},
			[]string{"provider"},
		),
		errorsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "cert",
				Name:      "errors_total",
				Help: "Total number of " +
					"certificate errors",
			},
			[]string{"provider", "operation"},
		),
		expirySeconds: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "avapigw_operator",
				Subsystem: "cert",
				Name:      "expiry_seconds",
				Help: "Time until certificate " +
					"expiry in seconds",
			},
			[]string{"common_name"},
		),
	}
}

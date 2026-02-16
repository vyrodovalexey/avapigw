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

// GetCertMetrics returns the singleton cert metrics instance.
func GetCertMetrics() *CertMetrics {
	certMetricsOnce.Do(func() {
		certMetricsInstance = &CertMetrics{
			issuedTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw_operator",
					Subsystem: "cert",
					Name:      "issued_total",
					Help: "Total number of " +
						"certificates issued",
				},
				[]string{"provider"},
			),
			rotationsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw_operator",
					Subsystem: "cert",
					Name:      "rotations_total",
					Help: "Total number of " +
						"certificate rotations",
				},
				[]string{"provider"},
			),
			errorsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw_operator",
					Subsystem: "cert",
					Name:      "errors_total",
					Help: "Total number of " +
						"certificate errors",
				},
				[]string{"provider", "operation"},
			),
			expirySeconds: promauto.NewGaugeVec(
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
	})
	return certMetricsInstance
}

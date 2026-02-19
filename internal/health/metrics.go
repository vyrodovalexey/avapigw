// Package health provides health check and readiness probe endpoints.
package health

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// HealthMetrics holds Prometheus metrics for health checks.
type HealthMetrics struct {
	checksTotal *prometheus.CounterVec
	checkStatus *prometheus.GaugeVec
}

var (
	healthMetricsInstance *HealthMetrics
	healthMetricsOnce     sync.Once
)

// GetHealthMetrics returns the singleton health metrics instance.
func GetHealthMetrics() *HealthMetrics {
	healthMetricsOnce.Do(func() {
		healthMetricsInstance = &HealthMetrics{
			checksTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "health",
					Name:      "checks_total",
					Help: "Total number of " +
						"health checks performed",
				},
				[]string{"type"},
			),
			checkStatus: promauto.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "gateway",
					Subsystem: "health",
					Name:      "check_status",
					Help: "Current health check " +
						"status (1=healthy, 0=unhealthy)",
				},
				[]string{"check"},
			),
		}
	})
	return healthMetricsInstance
}

// MustRegister registers all health metric collectors with the given
// Prometheus registry. This is needed because promauto registers
// metrics with the default global registry, but the gateway serves
// /metrics from a custom registry. Calling MustRegister bridges the
// two so health metrics appear on the gateway's metrics endpoint.
func (m *HealthMetrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.checksTotal,
		m.checkStatus,
	)
}

// Init pre-initializes common label combinations with zero values so
// that metrics appear in /metrics output immediately after startup.
// Prometheus *Vec types only emit metric lines after WithLabelValues()
// is called at least once. This method is idempotent and safe to call
// multiple times.
func (m *HealthMetrics) Init() {
	for _, checkType := range []string{"liveness", "readiness"} {
		m.checksTotal.WithLabelValues(checkType)
	}
	for _, check := range []string{"overall", "backend"} {
		m.checkStatus.WithLabelValues(check)
	}
}

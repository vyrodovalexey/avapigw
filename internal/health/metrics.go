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

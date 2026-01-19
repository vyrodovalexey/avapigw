// Package health provides health check endpoints for the API Gateway.
package health

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// Namespace is the metrics namespace.
	Namespace = "avapigw"
	// Subsystem is the metrics subsystem.
	Subsystem = "health"
)

var (
	// HealthCheckTotal counts total health check executions.
	HealthCheckTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: Subsystem,
			Name:      "check_total",
			Help:      "Total number of health check executions",
		},
		[]string{"name", "status"},
	)

	// HealthCheckDuration measures health check duration.
	HealthCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: Subsystem,
			Name:      "check_duration_seconds",
			Help:      "Health check duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"name"},
	)

	// HealthCheckStatus shows current health check status.
	HealthCheckStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: Subsystem,
			Name:      "check_status",
			Help:      "Current health check status (1=healthy, 0=unhealthy)",
		},
		[]string{"name"},
	)

	// OverallHealthStatus shows overall health status.
	OverallHealthStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: Subsystem,
			Name:      "status",
			Help:      "Overall health status (1=healthy, 0=unhealthy)",
		},
	)

	// DependencyHealthStatus shows dependency health status.
	DependencyHealthStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: Subsystem,
			Name:      "dependency_status",
			Help:      "Dependency health status (1=healthy, 0=unhealthy)",
		},
		[]string{"dependency", "type"},
	)

	// UptimeSeconds shows the uptime in seconds.
	UptimeSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: Subsystem,
			Name:      "uptime_seconds",
			Help:      "Service uptime in seconds",
		},
	)
)

// RecordHealthCheck records a health check execution.
func RecordHealthCheck(name string, healthy bool, duration float64) {
	status := "healthy"
	statusValue := 1.0
	if !healthy {
		status = "unhealthy"
		statusValue = 0.0
	}

	HealthCheckTotal.WithLabelValues(name, status).Inc()
	HealthCheckDuration.WithLabelValues(name).Observe(duration)
	HealthCheckStatus.WithLabelValues(name).Set(statusValue)
}

// SetOverallHealthStatus sets the overall health status.
func SetOverallHealthStatus(healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	OverallHealthStatus.Set(value)
}

// SetDependencyHealthStatus sets a dependency health status.
func SetDependencyHealthStatus(dependency, depType string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	DependencyHealthStatus.WithLabelValues(dependency, depType).Set(value)
}

// SetUptimeSeconds sets the uptime in seconds.
func SetUptimeSeconds(seconds float64) {
	UptimeSeconds.Set(seconds)
}

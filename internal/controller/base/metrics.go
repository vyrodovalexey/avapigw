// Package base provides a generic base controller framework for Kubernetes operators.
package base

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricResultSuccess is the label value for successful reconciliations.
const MetricResultSuccess = "success"

// MetricResultError is the label value for failed reconciliations.
const MetricResultError = "error"

// ControllerMetrics holds Prometheus metrics for a controller.
type ControllerMetrics struct {
	// ReconcileDuration tracks the duration of reconciliations.
	ReconcileDuration *prometheus.HistogramVec

	// ReconcileTotal tracks the total number of reconciliations.
	ReconcileTotal *prometheus.CounterVec

	// controllerName is the name of the controller for logging.
	controllerName string
}

// ObserveReconcile records metrics for a reconciliation.
func (m *ControllerMetrics) ObserveReconcile(duration float64, success bool) {
	result := MetricResultSuccess
	if !success {
		result = MetricResultError
	}
	m.ReconcileDuration.WithLabelValues(result).Observe(duration)
	m.ReconcileTotal.WithLabelValues(result).Inc()
}

// MetricsRegistry manages controller metrics registration.
// It ensures metrics are registered only once and provides thread-safe access.
type MetricsRegistry struct {
	mu         sync.RWMutex
	metrics    map[string]*ControllerMetrics
	registerer prometheus.Registerer
}

// NewMetricsRegistry creates a new MetricsRegistry with the given registerer.
func NewMetricsRegistry(registerer prometheus.Registerer) *MetricsRegistry {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	return &MetricsRegistry{
		metrics:    make(map[string]*ControllerMetrics),
		registerer: registerer,
	}
}

// RegisterController registers metrics for a controller and returns the ControllerMetrics.
// If metrics are already registered for this controller, returns the existing metrics.
// The controllerName should be lowercase and use underscores (e.g., "gateway", "httproute").
func (r *MetricsRegistry) RegisterController(controllerName string) *ControllerMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Return existing metrics if already registered
	if m, exists := r.metrics[controllerName]; exists {
		return m
	}

	// Create new metrics
	reconcileDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      controllerName + "_reconcile_duration_seconds",
			Help:      "Duration of " + controllerName + " reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	reconcileTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      controllerName + "_reconcile_total",
			Help:      "Total number of " + controllerName + " reconciliations",
		},
		[]string{"result"},
	)

	// Register with Prometheus
	r.registerer.MustRegister(reconcileDuration, reconcileTotal)

	metrics := &ControllerMetrics{
		ReconcileDuration: reconcileDuration,
		ReconcileTotal:    reconcileTotal,
		controllerName:    controllerName,
	}

	r.metrics[controllerName] = metrics
	return metrics
}

// GetMetrics returns the metrics for a controller, or nil if not registered.
func (r *MetricsRegistry) GetMetrics(controllerName string) *ControllerMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.metrics[controllerName]
}

// DefaultMetricsRegistry is the global metrics registry instance.
// Controllers should use this registry to register their metrics.
var DefaultMetricsRegistry = NewMetricsRegistry(prometheus.DefaultRegisterer)

// MustRegisterControllerMetrics registers metrics for a controller using the default registry.
// Panics if registration fails.
func MustRegisterControllerMetrics(controllerName string) *ControllerMetrics {
	return DefaultMetricsRegistry.RegisterController(controllerName)
}

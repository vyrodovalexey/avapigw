// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TransformMetrics contains Prometheus metrics for transform operations.
type TransformMetrics struct {
	operationsTotal   *prometheus.CounterVec
	operationDuration *prometheus.HistogramVec
	errorsTotal       *prometheus.CounterVec
}

var (
	transformMetricsInstance *TransformMetrics
	transformMetricsOnce     sync.Once
)

// GetTransformMetrics returns the singleton transform metrics instance.
func GetTransformMetrics() *TransformMetrics {
	transformMetricsOnce.Do(func() {
		transformMetricsInstance = &TransformMetrics{
			operationsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "transform",
					Name:      "operations_total",
					Help:      "Total number of transform operations",
				},
				[]string{"direction", "result"},
			),
			operationDuration: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Namespace: "gateway",
					Subsystem: "transform",
					Name:      "operation_duration_seconds",
					Help:      "Duration of transform operations in seconds",
					Buckets: []float64{
						.0001, .0005, .001, .005,
						.01, .025, .05, .1,
					},
				},
				[]string{"direction"},
			),
			errorsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "gateway",
					Subsystem: "transform",
					Name:      "errors_total",
					Help:      "Total number of transform errors",
				},
				[]string{"direction", "error_type"},
			),
		}
	})
	return transformMetricsInstance
}

// MustRegister registers all transform metric collectors with the given
// Prometheus registry. This is needed because promauto registers
// metrics with the default global registry, but the gateway serves
// /metrics from a custom registry. Calling MustRegister bridges the
// two so transform metrics appear on the gateway's metrics endpoint.
func (m *TransformMetrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.operationsTotal,
		m.operationDuration,
		m.errorsTotal,
	)
}

// Init pre-initializes common label combinations with zero values so that
// metrics appear in /metrics output immediately after startup. Prometheus
// *Vec types only emit metric lines after WithLabelValues() is called at
// least once. This method is idempotent and safe to call multiple times.
func (m *TransformMetrics) Init() {
	for _, dir := range []string{"request", "response"} {
		for _, result := range []string{"success", "error", "passthrough"} {
			m.operationsTotal.WithLabelValues(dir, result)
		}
		m.operationDuration.WithLabelValues(dir)
		for _, errType := range []string{"config", "template", "validation", "general"} {
			m.errorsTotal.WithLabelValues(dir, errType)
		}
	}
}

// RecordOperation records a transform operation.
func (m *TransformMetrics) RecordOperation(direction, result string) {
	m.operationsTotal.WithLabelValues(direction, result).Inc()
}

// RecordError records a transform error.
func (m *TransformMetrics) RecordError(direction, errorType string) {
	m.errorsTotal.WithLabelValues(direction, errorType).Inc()
}

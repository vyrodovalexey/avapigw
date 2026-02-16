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

// RecordOperation records a transform operation.
func (m *TransformMetrics) RecordOperation(direction, result string) {
	m.operationsTotal.WithLabelValues(direction, result).Inc()
}

// RecordError records a transform error.
func (m *TransformMetrics) RecordError(direction, errorType string) {
	m.errorsTotal.WithLabelValues(direction, errorType).Inc()
}

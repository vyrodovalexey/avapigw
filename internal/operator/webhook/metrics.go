// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// WebhookMetrics holds Prometheus metrics for webhook operations.
type WebhookMetrics struct {
	validationsTotal   *prometheus.CounterVec
	validationDuration *prometheus.HistogramVec
	validationWarnings *prometheus.CounterVec
}

var (
	webhookMetricsInstance *WebhookMetrics
	webhookMetricsOnce     sync.Once
)

// InitWebhookMetrics initializes the singleton webhook metrics instance with the
// given Prometheus registerer. If registerer is nil, metrics are registered with
// the default registerer. Must be called before GetWebhookMetrics for metrics to
// appear on the correct registry; subsequent calls are no-ops (sync.Once).
func InitWebhookMetrics(registerer prometheus.Registerer) {
	webhookMetricsOnce.Do(func() {
		if registerer == nil {
			registerer = prometheus.DefaultRegisterer
		}
		webhookMetricsInstance = newWebhookMetricsWithFactory(promauto.With(registerer))
	})
}

// GetWebhookMetrics returns the singleton webhook metrics
// instance. If InitWebhookMetrics has not been called, metrics
// are lazily initialized with the default registerer.
func GetWebhookMetrics() *WebhookMetrics {
	InitWebhookMetrics(nil)
	return webhookMetricsInstance
}

// newWebhookMetricsWithFactory creates webhook metrics using the given promauto factory.
func newWebhookMetricsWithFactory(factory promauto.Factory) *WebhookMetrics {
	return &WebhookMetrics{
		validationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name:      "validations_total",
				Help: "Total number of " +
					"webhook validations",
			},
			[]string{"resource", "operation", "result"},
		),
		validationDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name: "validation_duration" +
					"_seconds",
				Help: "Duration of webhook " +
					"validation operations",
				Buckets: []float64{
					.001, .005, .01, .025,
					.05, .1, .25, .5, 1,
				},
			},
			[]string{"resource", "operation"},
		),
		validationWarnings: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name: "validation_warnings" +
					"_total",
				Help: "Total number of " +
					"webhook validation warnings",
			},
			[]string{"resource"},
		),
	}
}

// InitWebhookVecMetrics pre-populates all WebhookMetrics vector metrics with common
// label combinations so they appear on /metrics immediately with zero values.
func InitWebhookVecMetrics() {
	m := GetWebhookMetrics()

	resources := []string{"APIRoute", "GRPCRoute", "Backend", "GRPCBackend"}
	operations := []string{"CREATE", "UPDATE", "DELETE"}
	results := []string{"allowed", "denied"}

	for _, res := range resources {
		// validationsTotal: resource × operation × result
		for _, op := range operations {
			for _, r := range results {
				m.validationsTotal.WithLabelValues(res, op, r)
			}
			// validationDuration: resource × operation
			m.validationDuration.WithLabelValues(res, op)
		}
		// validationWarnings: resource
		m.validationWarnings.WithLabelValues(res)
	}
}

// RecordValidation records a webhook validation result.
func (m *WebhookMetrics) RecordValidation(
	resource, operation, result string,
	duration time.Duration,
	warningCount int,
) {
	m.validationsTotal.WithLabelValues(
		resource, operation, result,
	).Inc()
	m.validationDuration.WithLabelValues(
		resource, operation,
	).Observe(duration.Seconds())

	if warningCount > 0 {
		m.validationWarnings.WithLabelValues(
			resource,
		).Add(float64(warningCount))
	}
}

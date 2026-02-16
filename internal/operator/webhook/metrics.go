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

// GetWebhookMetrics returns the singleton webhook metrics
// instance.
func GetWebhookMetrics() *WebhookMetrics {
	webhookMetricsOnce.Do(func() {
		webhookMetricsInstance = &WebhookMetrics{
			validationsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw_operator",
					Subsystem: "webhook",
					Name:      "validations_total",
					Help: "Total number of " +
						"webhook validations",
				},
				[]string{"resource", "operation", "result"},
			),
			validationDuration: promauto.NewHistogramVec(
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
			validationWarnings: promauto.NewCounterVec(
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
	})
	return webhookMetricsInstance
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

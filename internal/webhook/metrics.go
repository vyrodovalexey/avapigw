// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metric label values for webhook operations.
const (
	// ResultSuccess indicates a successful webhook operation.
	ResultSuccess = "success"
	// ResultError indicates a failed webhook operation.
	ResultError = "error"
	// ResultDenied indicates a denied webhook operation (validation failed).
	ResultDenied = "denied"

	// OperationValidateCreate is the create validation operation.
	OperationValidateCreate = "validate_create"
	// OperationValidateUpdate is the update validation operation.
	OperationValidateUpdate = "validate_update"
	// OperationValidateDelete is the delete validation operation.
	OperationValidateDelete = "validate_delete"
	// OperationMutate is the mutation operation.
	OperationMutate = "mutate"
)

// Prometheus metrics for webhook operations.
var (
	// webhookValidationTotal counts total webhook validation requests.
	webhookValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "webhook",
			Name:      "validation_total",
			Help:      "Total number of webhook validation requests",
		},
		[]string{"resource", "operation", "result"},
	)

	// webhookMutationTotal counts total webhook mutation requests.
	webhookMutationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "webhook",
			Name:      "mutation_total",
			Help:      "Total number of webhook mutation requests",
		},
		[]string{"resource", "result"},
	)

	// webhookDurationSeconds measures webhook operation duration.
	webhookDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "webhook",
			Name:      "duration_seconds",
			Help:      "Duration of webhook operations in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"resource", "operation"},
	)

	// webhookErrorsTotal counts webhook errors by type.
	webhookErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "webhook",
			Name:      "errors_total",
			Help:      "Total number of webhook errors by error type",
		},
		[]string{"resource", "operation", "error_type"},
	)

	// webhookInFlight tracks the number of webhook requests currently being processed.
	webhookInFlight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "avapigw",
			Subsystem: "webhook",
			Name:      "in_flight",
			Help:      "Number of webhook requests currently being processed",
		},
		[]string{"resource", "operation"},
	)
)

// RecordValidation records a webhook validation metric.
// Includes panic recovery for safety.
func RecordValidation(resource, operation, result string) {
	defer func() {
		// Silently recover from any panic in metrics recording
		// This ensures metrics issues don't crash the application
		_ = recover()
	}()

	if webhookValidationTotal == nil {
		return
	}

	webhookValidationTotal.WithLabelValues(resource, operation, result).Inc()
}

// RecordMutation records a webhook mutation metric.
// Includes panic recovery for safety.
func RecordMutation(resource, result string) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if webhookMutationTotal == nil {
		return
	}

	webhookMutationTotal.WithLabelValues(resource, result).Inc()
}

// RecordDuration records the duration of a webhook operation.
// Includes panic recovery for safety.
func RecordDuration(resource, operation string, duration time.Duration) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if webhookDurationSeconds == nil {
		return
	}

	webhookDurationSeconds.WithLabelValues(resource, operation).Observe(duration.Seconds())
}

// RecordError records a webhook error metric.
// Includes panic recovery for safety.
func RecordError(resource, operation, errorType string) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if webhookErrorsTotal == nil {
		return
	}

	webhookErrorsTotal.WithLabelValues(resource, operation, errorType).Inc()
}

// IncrementInFlight increments the in-flight counter for a webhook operation.
// Includes panic recovery for safety.
func IncrementInFlight(resource, operation string) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if webhookInFlight == nil {
		return
	}

	webhookInFlight.WithLabelValues(resource, operation).Inc()
}

// DecrementInFlight decrements the in-flight counter for a webhook operation.
// Includes panic recovery for safety.
func DecrementInFlight(resource, operation string) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if webhookInFlight == nil {
		return
	}

	webhookInFlight.WithLabelValues(resource, operation).Dec()
}

// WebhookTimer is a helper for timing webhook operations.
type WebhookTimer struct {
	resource  string
	operation string
	startTime time.Time
}

// NewWebhookTimer creates a new webhook timer and increments the in-flight counter.
func NewWebhookTimer(resource, operation string) *WebhookTimer {
	IncrementInFlight(resource, operation)
	return &WebhookTimer{
		resource:  resource,
		operation: operation,
		startTime: time.Now(),
	}
}

// ObserveDuration records the duration and decrements the in-flight counter.
// This should be called with defer immediately after creating the timer.
func (t *WebhookTimer) ObserveDuration() {
	DecrementInFlight(t.resource, t.operation)
	RecordDuration(t.resource, t.operation, time.Since(t.startTime))
}

// ObserveDurationWithResult records the duration, result, and decrements the in-flight counter.
// This is useful when you want to record the result along with the duration.
func (t *WebhookTimer) ObserveDurationWithResult(result string, isValidation bool) {
	DecrementInFlight(t.resource, t.operation)
	RecordDuration(t.resource, t.operation, time.Since(t.startTime))
	if isValidation {
		RecordValidation(t.resource, t.operation, result)
	} else {
		RecordMutation(t.resource, result)
	}
}

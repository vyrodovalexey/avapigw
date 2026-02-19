// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ControllerMetrics contains Prometheus metrics for controllers.
// Prometheus metric types (Counter, Gauge, Histogram) are goroutine-safe,
// so no additional synchronization is needed for metric operations.
type ControllerMetrics struct {
	reconcileDuration         *prometheus.HistogramVec
	reconcileTotal            *prometheus.CounterVec
	reconcileErrors           *prometheus.CounterVec
	resourcesTotal            *prometheus.GaugeVec
	resourceCondition         *prometheus.GaugeVec
	finalizerOperations       *prometheus.CounterVec
	ingressResourcesProcessed *prometheus.CounterVec
	ingressConversionErrors   *prometheus.CounterVec
}

// Metric label constants.
const (
	labelController = "controller"
	labelResult     = "result"
	labelKind       = "kind"
	labelNamespace  = "namespace"
	labelName       = "name"
	labelCondition  = "condition"
	labelOperation  = "operation"
)

// Result constants for reconciliation metrics.
const (
	ResultSuccess  = "success"
	ResultError    = "error"
	ResultRequeue  = "requeue"
	ResultCanceled = "canceled"
)

// Operation constants for finalizer metrics.
const (
	OperationAdd    = "add"
	OperationRemove = "remove"
)

var (
	globalMetrics     *ControllerMetrics
	globalMetricsOnce sync.Once
)

// GetControllerMetrics returns the global controller metrics instance.
// It initializes the metrics on first call (singleton pattern).
func GetControllerMetrics() *ControllerMetrics {
	globalMetricsOnce.Do(func() {
		globalMetrics = newControllerMetrics()
	})
	return globalMetrics
}

// newControllerMetrics creates a new ControllerMetrics instance.
func newControllerMetrics() *ControllerMetrics {
	return &ControllerMetrics{
		reconcileDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw_operator",
				Name:      "reconcile_duration_seconds",
				Help:      "Duration of reconciliation operations in seconds",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
			},
			[]string{labelController},
		),
		reconcileTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Name:      "reconcile_total",
				Help:      "Total number of reconciliation operations",
			},
			[]string{labelController, labelResult},
		),
		reconcileErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Name:      "reconcile_errors_total",
				Help:      "Total number of reconciliation errors",
			},
			[]string{labelController},
		),
		resourcesTotal: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "avapigw_operator",
				Name:      "resources_total",
				Help:      "Total number of resources by kind and namespace",
			},
			[]string{labelKind, labelNamespace},
		),
		resourceCondition: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "avapigw_operator",
				Name:      "resource_condition",
				Help:      "Current condition status of resources (1=True, 0=False, -1=Unknown)",
			},
			[]string{labelKind, labelName, labelNamespace, labelCondition},
		),
		finalizerOperations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Name:      "finalizer_operations_total",
				Help:      "Total number of finalizer operations",
			},
			[]string{labelController, labelOperation},
		),
		ingressResourcesProcessed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Name:      "ingress_resources_processed_total",
				Help:      "Total number of Ingress resources processed by the controller",
			},
			[]string{labelResult},
		),
		ingressConversionErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Name:      "ingress_conversion_errors_total",
				Help:      "Total number of Ingress-to-gateway conversion errors",
			},
			[]string{labelNamespace, labelName},
		),
	}
}

// RecordReconcileDuration records the duration of a reconciliation operation.
func (m *ControllerMetrics) RecordReconcileDuration(controller string, duration time.Duration) {
	m.reconcileDuration.WithLabelValues(controller).Observe(duration.Seconds())
}

// RecordReconcileResult records the result of a reconciliation operation.
func (m *ControllerMetrics) RecordReconcileResult(controller, result string) {
	m.reconcileTotal.WithLabelValues(controller, result).Inc()
}

// RecordReconcileError records a reconciliation error.
func (m *ControllerMetrics) RecordReconcileError(controller string) {
	m.reconcileErrors.WithLabelValues(controller).Inc()
}

// SetResourceCount sets the total count of resources for a kind in a namespace.
func (m *ControllerMetrics) SetResourceCount(kind, namespace string, count float64) {
	m.resourcesTotal.WithLabelValues(kind, namespace).Set(count)
}

// SetResourceCondition sets the condition status for a resource.
// Status values: 1 = True, 0 = False, -1 = Unknown.
func (m *ControllerMetrics) SetResourceCondition(kind, name, namespace, condition string, status float64) {
	m.resourceCondition.WithLabelValues(kind, name, namespace, condition).Set(status)
}

// RecordFinalizerOperation records a finalizer operation.
func (m *ControllerMetrics) RecordFinalizerOperation(controller, operation string) {
	m.finalizerOperations.WithLabelValues(controller, operation).Inc()
}

// RecordIngressProcessed records a processed Ingress resource with the given result.
func (m *ControllerMetrics) RecordIngressProcessed(result string) {
	m.ingressResourcesProcessed.WithLabelValues(result).Inc()
}

// RecordIngressConversionError records an Ingress conversion error.
func (m *ControllerMetrics) RecordIngressConversionError(namespace, name string) {
	m.ingressConversionErrors.WithLabelValues(namespace, name).Inc()
}

// DeleteResourceConditionMetrics deletes all condition metrics for a resource.
// This should be called when a resource is deleted.
func (m *ControllerMetrics) DeleteResourceConditionMetrics(kind, name, namespace string) {
	// Delete metrics for common conditions
	conditions := []string{"Ready", "Valid", "Healthy"}
	for _, condition := range conditions {
		m.resourceCondition.DeleteLabelValues(kind, name, namespace, condition)
	}
}

// ConditionStatusToFloat converts a condition status string to a float64 value.
// Returns 1 for "True", 0 for "False", -1 for "Unknown" or any other value.
func ConditionStatusToFloat(status string) float64 {
	switch status {
	case "True":
		return 1
	case "False":
		return 0
	default:
		return -1
	}
}

// ReconcileTimer is a helper for timing reconciliation operations.
type ReconcileTimer struct {
	controller string
	startTime  time.Time
	metrics    *ControllerMetrics
}

// NewReconcileTimer creates a new ReconcileTimer.
func NewReconcileTimer(controller string) *ReconcileTimer {
	return &ReconcileTimer{
		controller: controller,
		startTime:  time.Now(),
		metrics:    GetControllerMetrics(),
	}
}

// ObserveDuration records the duration since the timer was created.
func (t *ReconcileTimer) ObserveDuration() {
	t.metrics.RecordReconcileDuration(t.controller, time.Since(t.startTime))
}

// RecordSuccess records a successful reconciliation.
func (t *ReconcileTimer) RecordSuccess() {
	t.ObserveDuration()
	t.metrics.RecordReconcileResult(t.controller, ResultSuccess)
}

// RecordError records a failed reconciliation.
func (t *ReconcileTimer) RecordError() {
	t.ObserveDuration()
	t.metrics.RecordReconcileResult(t.controller, ResultError)
	t.metrics.RecordReconcileError(t.controller)
}

// RecordRequeue records a requeued reconciliation.
func (t *ReconcileTimer) RecordRequeue() {
	t.ObserveDuration()
	t.metrics.RecordReconcileResult(t.controller, ResultRequeue)
}

// RecordCanceled records a canceled reconciliation.
func (t *ReconcileTimer) RecordCanceled() {
	t.ObserveDuration()
	t.metrics.RecordReconcileResult(t.controller, ResultCanceled)
}

// StatusUpdateMetrics tracks status update operations.
// Prometheus metric types are goroutine-safe, so no additional
// synchronization is needed for metric operations.
type StatusUpdateMetrics struct {
	updateDuration *prometheus.HistogramVec
	updateTotal    *prometheus.CounterVec
	updateErrors   *prometheus.CounterVec
}

var (
	statusUpdateMetrics     *StatusUpdateMetrics
	statusUpdateMetricsOnce sync.Once
)

// GetStatusUpdateMetrics returns the global status update metrics instance.
func GetStatusUpdateMetrics() *StatusUpdateMetrics {
	statusUpdateMetricsOnce.Do(func() {
		statusUpdateMetrics = &StatusUpdateMetrics{
			updateDuration: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Namespace: "avapigw_operator",
					Name:      "status_update_duration_seconds",
					Help:      "Duration of status update operations in seconds",
					Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
				},
				[]string{labelKind},
			),
			updateTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw_operator",
					Name:      "status_update_total",
					Help:      "Total number of status update operations",
				},
				[]string{labelKind, labelResult},
			),
			updateErrors: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw_operator",
					Name:      "status_update_errors_total",
					Help:      "Total number of status update errors",
				},
				[]string{labelKind},
			),
		}
	})
	return statusUpdateMetrics
}

// RecordStatusUpdate records a status update operation.
func (m *StatusUpdateMetrics) RecordStatusUpdate(kind string, duration time.Duration, success bool) {
	m.updateDuration.WithLabelValues(kind).Observe(duration.Seconds())
	result := ResultSuccess
	if !success {
		result = ResultError
		m.updateErrors.WithLabelValues(kind).Inc()
	}
	m.updateTotal.WithLabelValues(kind, result).Inc()
}

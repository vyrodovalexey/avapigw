// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// controllerTracerName is the OpenTelemetry tracer name for controller operations.
const controllerTracerName = "avapigw-operator/controller"

// Reconcilable is the interface that all CRD resources must implement
// to be reconciled by the base reconciler helper.
type Reconcilable interface {
	client.Object
	GetConditions() []avapigwv1alpha1.Condition
	SetConditions([]avapigwv1alpha1.Condition)
	GetGeneration() int64
	SetObservedGeneration(int64)
}

// ReconcileCallbacks provides resource-specific logic for the base reconciler.
// Each controller implements this interface to supply its own reconcile/cleanup behavior.
type ReconcileCallbacks struct {
	// ResourceKind is the kind name for logging and metrics (e.g., "APIRoute").
	ResourceKind string

	// ControllerName is the controller name for metrics (e.g., "apiroute").
	ControllerName string

	// FinalizerName is the finalizer to manage on the resource.
	FinalizerName string

	// NewResource returns a new empty instance of the resource for Get calls.
	NewResource func() Reconcilable

	// Reconcile performs the resource-specific reconciliation logic.
	Reconcile func(ctx context.Context, resource Reconcilable) error

	// Cleanup performs the resource-specific cleanup logic during deletion.
	Cleanup func(ctx context.Context, resource Reconcilable) error

	// UpdateStatus updates the resource status after successful reconciliation.
	UpdateStatus func(ctx context.Context, updater *StatusUpdater, resource Reconcilable) error

	// UpdateFailureStatus updates the resource status after a reconciliation failure.
	UpdateFailureStatus func(
		ctx context.Context, updater *StatusUpdater, resource Reconcilable, reconcileErr error,
	) error

	// RecordSuccessEvent records a success event on the resource.
	RecordSuccessEvent func(recorder record.EventRecorder, resource Reconcilable)

	// RecordFailureEvent records a failure event on the resource.
	RecordFailureEvent func(recorder record.EventRecorder, resource Reconcilable, err error)

	// SetSuccessMetrics sets metrics for a successful reconciliation.
	SetSuccessMetrics func(metrics *ControllerMetrics, resource Reconcilable)

	// SetFailureMetrics sets metrics for a failed reconciliation.
	SetFailureMetrics func(metrics *ControllerMetrics, resource Reconcilable)

	// IsApplied checks whether the resource is present in the gRPC server's in-memory state.
	// This is optional. When set, it is used to detect cold start conditions: after an operator
	// restart, resources may appear Ready in Kubernetes but are missing from the gRPC server's
	// in-memory maps. If IsApplied returns false for a Ready resource, reconciliation is forced.
	IsApplied func(ctx context.Context, resource Reconcilable) bool
}

// BaseReconcile performs the common reconciliation flow for all CRD controllers.
// It handles: fetch resource, check deletion, add/remove finalizer, reconcile,
// update status, record events, and update metrics.
//
//nolint:gocognit,gocyclo // Reconciliation flow requires sequential steps with error handling at each stage
func BaseReconcile(
	ctx context.Context,
	k8sClient client.Client,
	statusUpdater *StatusUpdater,
	recorder record.EventRecorder,
	req ctrl.Request,
	cb *ReconcileCallbacks,
) (ctrl.Result, error) {
	tracer := otel.Tracer(controllerTracerName)
	ctx, span := tracer.Start(ctx, "Reconcile."+cb.ResourceKind,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("k8s.resource.kind", cb.ResourceKind),
			attribute.String("k8s.resource.name", req.Name),
			attribute.String("k8s.resource.namespace", req.Namespace),
		),
	)
	defer span.End()

	timer := NewReconcileTimer(cb.ControllerName)
	metrics := GetControllerMetrics()
	logger := log.FromContext(ctx)
	logger.Info("reconciling "+cb.ResourceKind, "name", req.Name, "namespace", req.Namespace)

	// Fetch the resource
	resource := cb.NewResource()
	if err := k8sClient.Get(ctx, req.NamespacedName, resource); err != nil {
		if errors.IsNotFound(err) {
			logger.Info(cb.ResourceKind+" not found, ignoring", "name", req.Name)
			metrics.DeleteResourceConditionMetrics(cb.ResourceKind, req.Name, req.Namespace)
			timer.RecordSuccess()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get "+cb.ResourceKind)
		timer.RecordError()
		return ctrl.Result{}, err
	}

	// Check if the object is being deleted
	if !resource.GetDeletionTimestamp().IsZero() {
		result, err := baseHandleDeletion(ctx, k8sClient, recorder, resource, cb, metrics)
		if err != nil {
			timer.RecordError()
		} else {
			metrics.DeleteResourceConditionMetrics(cb.ResourceKind, resource.GetName(), resource.GetNamespace())
			timer.RecordSuccess()
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(resource, cb.FinalizerName) {
		original := resource.DeepCopyObject().(client.Object)
		controllerutil.AddFinalizer(resource, cb.FinalizerName)
		if err := k8sClient.Patch(ctx, resource, client.MergeFrom(original)); err != nil {
			logger.Error(err, "failed to add finalizer")
			timer.RecordError()
			return ctrl.Result{}, err
		}
		metrics.RecordFinalizerOperation(cb.ControllerName, OperationAdd)
		// The Patch triggers a watch event automatically; no explicit requeue needed.
		timer.RecordSuccess()
		return ctrl.Result{}, nil
	}

	// Generation-based reconciliation skip (Task B3): if the resource has already been
	// reconciled for this generation and is in a Ready state, skip reconciliation.
	// However, after an operator restart the in-memory route maps are empty. If the
	// resource is Ready in K8s but not present in the gRPC server's memory, force
	// reconciliation to restore the in-memory state.
	if isResourceReady(resource) {
		if cb.IsApplied != nil && !cb.IsApplied(ctx, resource) {
			logger.Info("forcing "+cb.ResourceKind+" reconciliation after restart, "+
				"resource is Ready but not applied in memory",
				"name", resource.GetName(),
				"namespace", resource.GetNamespace(),
				"generation", resource.GetGeneration(),
			)
		} else {
			logger.V(1).Info("skipping "+cb.ResourceKind+" reconciliation, already up-to-date",
				"generation", resource.GetGeneration(),
			)
			timer.RecordSuccess()
			return ctrl.Result{}, nil
		}
	}

	// Reconcile the resource
	if err := cb.Reconcile(ctx, resource); err != nil {
		logger.Error(err, "failed to reconcile "+cb.ResourceKind)
		if cb.UpdateFailureStatus != nil {
			if statusErr := cb.UpdateFailureStatus(ctx, statusUpdater, resource, err); statusErr != nil {
				logger.Error(statusErr, "failed to update status after reconcile failure")
			}
		}
		cb.RecordFailureEvent(recorder, resource, err)
		if cb.SetFailureMetrics != nil {
			cb.SetFailureMetrics(metrics, resource)
		}
		timer.RecordError()
		return ctrl.Result{RequeueAfter: RequeueAfterReconcileFailure}, err
	}

	// Update status
	if err := cb.UpdateStatus(ctx, statusUpdater, resource); err != nil {
		logger.Error(err, "failed to update status, will retry")
		timer.RecordRequeue()
		return ctrl.Result{RequeueAfter: RequeueAfterStatusUpdateFailure}, nil
	}
	cb.RecordSuccessEvent(recorder, resource)

	// Update condition metrics
	if cb.SetSuccessMetrics != nil {
		cb.SetSuccessMetrics(metrics, resource)
	}
	timer.RecordSuccess()

	return ctrl.Result{}, nil
}

// baseHandleDeletion handles the deletion of a resource with finalizer cleanup.
func baseHandleDeletion(
	ctx context.Context,
	k8sClient client.Client,
	recorder record.EventRecorder,
	resource Reconcilable,
	cb *ReconcileCallbacks,
	metrics *ControllerMetrics,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(resource, cb.FinalizerName) {
		// Perform cleanup
		if err := cb.Cleanup(ctx, resource); err != nil {
			logger.Error(err, "failed to cleanup "+cb.ResourceKind)
			recorder.Event(resource, "Warning", EventReasonCleanupFailed, err.Error())
			return ctrl.Result{RequeueAfter: RequeueAfterCleanupFailure}, err
		}

		// Remove finalizer
		original := resource.DeepCopyObject().(client.Object)
		controllerutil.RemoveFinalizer(resource, cb.FinalizerName)
		if err := k8sClient.Patch(ctx, resource, client.MergeFrom(original)); err != nil {
			logger.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}

		metrics.RecordFinalizerOperation(cb.ControllerName, OperationRemove)
		recorder.Event(resource, "Normal", EventReasonDeleted, deletionMessage(cb.ResourceKind))
	}

	return ctrl.Result{}, nil
}

// deletionMessage returns the appropriate deletion message for a resource kind.
func deletionMessage(kind string) string {
	switch kind {
	case "Backend", "GRPCBackend":
		return MessageBackendDeleted
	default:
		return MessageRouteDeleted
	}
}

// isResourceReady checks if a resource has been reconciled for the current generation
// and is in a Ready=True state. Used for generation-based reconciliation skip (Task B3).
func isResourceReady(resource Reconcilable) bool {
	for _, c := range resource.GetConditions() {
		if string(c.Type) == readyConditionType &&
			c.Status == metav1.ConditionTrue &&
			c.ObservedGeneration == resource.GetGeneration() {
			return true
		}
	}
	return false
}

// readyConditionType is the condition type string for Ready status.
const readyConditionType = "Ready"

// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

const (
	// BackendFinalizerName is the finalizer name for Backend resources.
	BackendFinalizerName = "backend.avapigw.io/finalizer"
)

// BackendReconciler reconciles a Backend object.
type BackendReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=backends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=backends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=backends/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation of Backend resources.
func (r *BackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	timer := NewReconcileTimer("backend")
	metrics := GetControllerMetrics()
	logger := log.FromContext(ctx)
	logger.Info("reconciling Backend", "name", req.Name, "namespace", req.Namespace)

	// Fetch the Backend instance
	backend := &avapigwv1alpha1.Backend{}
	if err := r.Get(ctx, req.NamespacedName, backend); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Backend not found, ignoring", "name", req.Name)
			// Clean up metrics for deleted resource
			metrics.DeleteResourceConditionMetrics("Backend", req.Name, req.Namespace)
			timer.RecordSuccess()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get Backend")
		timer.RecordError()
		return ctrl.Result{}, err
	}

	// Check if the object is being deleted
	if !backend.ObjectMeta.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, backend)
		if err != nil {
			timer.RecordError()
		} else {
			// Clean up metrics for deleted resource
			metrics.DeleteResourceConditionMetrics("Backend", backend.Name, backend.Namespace)
			timer.RecordSuccess()
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(backend, BackendFinalizerName) {
		controllerutil.AddFinalizer(backend, BackendFinalizerName)
		if err := r.Update(ctx, backend); err != nil {
			logger.Error(err, "failed to add finalizer")
			timer.RecordError()
			return ctrl.Result{}, err
		}
		metrics.RecordFinalizerOperation("backend", OperationAdd)
		timer.RecordRequeue()
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the Backend
	if err := r.reconcileBackend(ctx, backend); err != nil {
		logger.Error(err, "failed to reconcile Backend")
		reason := string(avapigwv1alpha1.ReasonReconcileFailed)
		totalHosts := len(backend.Spec.Hosts)
		statusErr := r.StatusUpdater.UpdateBackendStatus(
			ctx, backend, false, false, reason, err.Error(), totalHosts,
		)
		if statusErr != nil {
			logger.Error(statusErr, "failed to update status after reconcile failure")
		}
		r.Recorder.Event(backend, "Warning", EventReasonReconcileFailed, err.Error())
		// Update condition metrics
		metrics.SetResourceCondition("Backend", backend.Name, backend.Namespace, "Ready", 0)
		metrics.SetResourceCondition("Backend", backend.Name, backend.Namespace, "Healthy", 0)
		timer.RecordError()
		return ctrl.Result{RequeueAfter: RequeueAfterReconcileFailure}, err
	}

	// Update status
	reason := string(avapigwv1alpha1.ReasonReconciled)
	totalHosts := len(backend.Spec.Hosts)
	statusErr := r.StatusUpdater.UpdateBackendStatus(
		ctx, backend, true, true, reason, MessageBackendApplied, totalHosts,
	)
	if statusErr != nil {
		// Status update failed, requeue to retry. Return nil error to avoid exponential backoff
		// since this is a transient issue that will be resolved on the next reconcile.
		logger.Error(statusErr, "failed to update status, will retry")
		timer.RecordRequeue()
		return ctrl.Result{RequeueAfter: RequeueAfterStatusUpdateFailure}, nil
	}
	r.Recorder.Event(backend, "Normal", EventReasonReconciled, MessageBackendApplied)

	// Update condition metrics
	metrics.SetResourceCondition("Backend", backend.Name, backend.Namespace, "Ready", 1)
	metrics.SetResourceCondition("Backend", backend.Name, backend.Namespace, "Healthy", 1)
	timer.RecordSuccess()

	return ctrl.Result{}, nil
}

// handleDeletion handles the deletion of a Backend.
func (r *BackendReconciler) handleDeletion(ctx context.Context, backend *avapigwv1alpha1.Backend) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	metrics := GetControllerMetrics()

	if controllerutil.ContainsFinalizer(backend, BackendFinalizerName) {
		// Perform cleanup
		if err := r.cleanupBackend(ctx, backend); err != nil {
			logger.Error(err, "failed to cleanup Backend")
			r.Recorder.Event(backend, "Warning", EventReasonCleanupFailed, err.Error())
			return ctrl.Result{RequeueAfter: RequeueAfterCleanupFailure}, err
		}

		// Remove finalizer
		controllerutil.RemoveFinalizer(backend, BackendFinalizerName)
		if err := r.Update(ctx, backend); err != nil {
			logger.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}

		metrics.RecordFinalizerOperation("backend", OperationRemove)
		r.Recorder.Event(backend, "Normal", EventReasonDeleted, MessageBackendDeleted)
	}

	return ctrl.Result{}, nil
}

// reconcileBackend reconciles the Backend configuration.
func (r *BackendReconciler) reconcileBackend(ctx context.Context, backend *avapigwv1alpha1.Backend) error {
	// Convert Backend spec to JSON
	configJSON, err := json.Marshal(backend.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal Backend spec: %w", err)
	}

	// Apply configuration to gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyBackend(ctx, backend.Name, backend.Namespace, configJSON); err != nil {
			return fmt.Errorf("failed to apply Backend to gateway: %w", err)
		}
	}

	return nil
}

// cleanupBackend cleans up the Backend configuration.
func (r *BackendReconciler) cleanupBackend(ctx context.Context, backend *avapigwv1alpha1.Backend) error {
	// Delete configuration from gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteBackend(ctx, backend.Name, backend.Namespace); err != nil {
			return fmt.Errorf("failed to delete Backend from gateway: %w", err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *BackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.Backend{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

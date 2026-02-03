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
	// GRPCBackendFinalizerName is the finalizer name for GRPCBackend resources.
	GRPCBackendFinalizerName = "grpcbackend.avapigw.io/finalizer"
)

// GRPCBackendReconciler reconciles a GRPCBackend object.
type GRPCBackendReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=grpcbackends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=grpcbackends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=grpcbackends/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation of GRPCBackend resources.
func (r *GRPCBackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	timer := NewReconcileTimer("grpcbackend")
	metrics := GetControllerMetrics()
	logger := log.FromContext(ctx)
	logger.Info("reconciling GRPCBackend", "name", req.Name, "namespace", req.Namespace)

	// Fetch the GRPCBackend instance
	grpcBackend := &avapigwv1alpha1.GRPCBackend{}
	if err := r.Get(ctx, req.NamespacedName, grpcBackend); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("GRPCBackend not found, ignoring", "name", req.Name)
			// Clean up metrics for deleted resource
			metrics.DeleteResourceConditionMetrics("GRPCBackend", req.Name, req.Namespace)
			timer.RecordSuccess()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get GRPCBackend")
		timer.RecordError()
		return ctrl.Result{}, err
	}

	// Check if the object is being deleted
	if !grpcBackend.ObjectMeta.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, grpcBackend)
		if err != nil {
			timer.RecordError()
		} else {
			// Clean up metrics for deleted resource
			metrics.DeleteResourceConditionMetrics("GRPCBackend", grpcBackend.Name, grpcBackend.Namespace)
			timer.RecordSuccess()
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(grpcBackend, GRPCBackendFinalizerName) {
		controllerutil.AddFinalizer(grpcBackend, GRPCBackendFinalizerName)
		if err := r.Update(ctx, grpcBackend); err != nil {
			logger.Error(err, "failed to add finalizer")
			timer.RecordError()
			return ctrl.Result{}, err
		}
		metrics.RecordFinalizerOperation("grpcbackend", OperationAdd)
		timer.RecordRequeue()
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the GRPCBackend
	if err := r.reconcileGRPCBackend(ctx, grpcBackend); err != nil {
		logger.Error(err, "failed to reconcile GRPCBackend")
		reason := string(avapigwv1alpha1.ReasonReconcileFailed)
		totalHosts := len(grpcBackend.Spec.Hosts)
		statusErr := r.StatusUpdater.UpdateBackendStatus(
			ctx, grpcBackend, false, false, reason, err.Error(), totalHosts,
		)
		if statusErr != nil {
			logger.Error(statusErr, "failed to update status after reconcile failure")
		}
		r.Recorder.Event(grpcBackend, "Warning", EventReasonReconcileFailed, err.Error())
		// Update condition metrics
		metrics.SetResourceCondition("GRPCBackend", grpcBackend.Name, grpcBackend.Namespace, "Ready", 0)
		metrics.SetResourceCondition("GRPCBackend", grpcBackend.Name, grpcBackend.Namespace, "Healthy", 0)
		timer.RecordError()
		return ctrl.Result{RequeueAfter: RequeueAfterReconcileFailure}, err
	}

	// Update status
	reason := string(avapigwv1alpha1.ReasonReconciled)
	totalHosts := len(grpcBackend.Spec.Hosts)
	statusErr := r.StatusUpdater.UpdateBackendStatus(
		ctx, grpcBackend, true, true, reason, MessageBackendApplied, totalHosts,
	)
	if statusErr != nil {
		// Status update failed, requeue to retry. Return nil error to avoid exponential backoff
		// since this is a transient issue that will be resolved on the next reconcile.
		logger.Error(statusErr, "failed to update status, will retry")
		timer.RecordRequeue()
		return ctrl.Result{RequeueAfter: RequeueAfterStatusUpdateFailure}, nil
	}
	r.Recorder.Event(grpcBackend, "Normal", EventReasonReconciled, MessageBackendApplied)

	// Update condition metrics
	metrics.SetResourceCondition("GRPCBackend", grpcBackend.Name, grpcBackend.Namespace, "Ready", 1)
	metrics.SetResourceCondition("GRPCBackend", grpcBackend.Name, grpcBackend.Namespace, "Healthy", 1)
	timer.RecordSuccess()

	return ctrl.Result{}, nil
}

// handleDeletion handles the deletion of a GRPCBackend.
func (r *GRPCBackendReconciler) handleDeletion(
	ctx context.Context,
	grpcBackend *avapigwv1alpha1.GRPCBackend,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	metrics := GetControllerMetrics()

	if controllerutil.ContainsFinalizer(grpcBackend, GRPCBackendFinalizerName) {
		// Perform cleanup
		if err := r.cleanupGRPCBackend(ctx, grpcBackend); err != nil {
			logger.Error(err, "failed to cleanup GRPCBackend")
			r.Recorder.Event(grpcBackend, "Warning", EventReasonCleanupFailed, err.Error())
			return ctrl.Result{RequeueAfter: RequeueAfterCleanupFailure}, err
		}

		// Remove finalizer
		controllerutil.RemoveFinalizer(grpcBackend, GRPCBackendFinalizerName)
		if err := r.Update(ctx, grpcBackend); err != nil {
			logger.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}

		metrics.RecordFinalizerOperation("grpcbackend", OperationRemove)
		r.Recorder.Event(grpcBackend, "Normal", EventReasonDeleted, MessageBackendDeleted)
	}

	return ctrl.Result{}, nil
}

// reconcileGRPCBackend reconciles the GRPCBackend configuration.
func (r *GRPCBackendReconciler) reconcileGRPCBackend(
	ctx context.Context,
	grpcBackend *avapigwv1alpha1.GRPCBackend,
) error {
	// Convert GRPCBackend spec to JSON
	configJSON, err := json.Marshal(grpcBackend.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal GRPCBackend spec: %w", err)
	}

	// Apply configuration to gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyGRPCBackend(ctx, grpcBackend.Name, grpcBackend.Namespace, configJSON); err != nil {
			return fmt.Errorf("failed to apply GRPCBackend to gateway: %w", err)
		}
	}

	return nil
}

// cleanupGRPCBackend cleans up the GRPCBackend configuration.
func (r *GRPCBackendReconciler) cleanupGRPCBackend(
	ctx context.Context,
	grpcBackend *avapigwv1alpha1.GRPCBackend,
) error {
	// Delete configuration from gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteGRPCBackend(ctx, grpcBackend.Name, grpcBackend.Namespace); err != nil {
			return fmt.Errorf("failed to delete GRPCBackend from gateway: %w", err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GRPCBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.GRPCBackend{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

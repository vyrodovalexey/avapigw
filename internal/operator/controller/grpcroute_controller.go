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
	// GRPCRouteFinalizerName is the finalizer name for GRPCRoute resources.
	GRPCRouteFinalizerName = "grpcroute.avapigw.io/finalizer"
)

// GRPCRouteReconciler reconciles a GRPCRoute object.
type GRPCRouteReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=grpcroutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=grpcroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=grpcroutes/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation of GRPCRoute resources.
func (r *GRPCRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	timer := NewReconcileTimer("grpcroute")
	metrics := GetControllerMetrics()
	logger := log.FromContext(ctx)
	logger.Info("reconciling GRPCRoute", "name", req.Name, "namespace", req.Namespace)

	// Fetch the GRPCRoute instance
	grpcRoute := &avapigwv1alpha1.GRPCRoute{}
	if err := r.Get(ctx, req.NamespacedName, grpcRoute); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("GRPCRoute not found, ignoring", "name", req.Name)
			// Clean up metrics for deleted resource
			metrics.DeleteResourceConditionMetrics("GRPCRoute", req.Name, req.Namespace)
			timer.RecordSuccess()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get GRPCRoute")
		timer.RecordError()
		return ctrl.Result{}, err
	}

	// Check if the object is being deleted
	if !grpcRoute.ObjectMeta.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, grpcRoute)
		if err != nil {
			timer.RecordError()
		} else {
			// Clean up metrics for deleted resource
			metrics.DeleteResourceConditionMetrics("GRPCRoute", grpcRoute.Name, grpcRoute.Namespace)
			timer.RecordSuccess()
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(grpcRoute, GRPCRouteFinalizerName) {
		controllerutil.AddFinalizer(grpcRoute, GRPCRouteFinalizerName)
		if err := r.Update(ctx, grpcRoute); err != nil {
			logger.Error(err, "failed to add finalizer")
			timer.RecordError()
			return ctrl.Result{}, err
		}
		metrics.RecordFinalizerOperation("grpcroute", OperationAdd)
		timer.RecordRequeue()
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the GRPCRoute
	if err := r.reconcileGRPCRoute(ctx, grpcRoute); err != nil {
		logger.Error(err, "failed to reconcile GRPCRoute")
		reason := string(avapigwv1alpha1.ReasonReconcileFailed)
		statusErr := r.StatusUpdater.UpdateRouteStatus(ctx, grpcRoute, false, reason, err.Error())
		if statusErr != nil {
			logger.Error(statusErr, "failed to update status after reconcile failure")
		}
		r.Recorder.Event(grpcRoute, "Warning", EventReasonReconcileFailed, err.Error())
		// Update condition metric
		metrics.SetResourceCondition("GRPCRoute", grpcRoute.Name, grpcRoute.Namespace, "Ready", 0)
		timer.RecordError()
		return ctrl.Result{RequeueAfter: RequeueAfterReconcileFailure}, err
	}

	// Update status
	reason := string(avapigwv1alpha1.ReasonReconciled)
	if err := r.StatusUpdater.UpdateRouteStatus(ctx, grpcRoute, true, reason, MessageRouteApplied); err != nil {
		// Status update failed, requeue to retry. Return nil error to avoid exponential backoff
		// since this is a transient issue that will be resolved on the next reconcile.
		logger.Error(err, "failed to update status, will retry")
		timer.RecordRequeue()
		return ctrl.Result{RequeueAfter: RequeueAfterStatusUpdateFailure}, nil
	}
	r.Recorder.Event(grpcRoute, "Normal", EventReasonReconciled, MessageRouteApplied)

	// Update condition metric
	metrics.SetResourceCondition("GRPCRoute", grpcRoute.Name, grpcRoute.Namespace, "Ready", 1)
	timer.RecordSuccess()

	return ctrl.Result{}, nil
}

// handleDeletion handles the deletion of a GRPCRoute.
func (r *GRPCRouteReconciler) handleDeletion(
	ctx context.Context,
	grpcRoute *avapigwv1alpha1.GRPCRoute,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	metrics := GetControllerMetrics()

	if controllerutil.ContainsFinalizer(grpcRoute, GRPCRouteFinalizerName) {
		// Perform cleanup
		if err := r.cleanupGRPCRoute(ctx, grpcRoute); err != nil {
			logger.Error(err, "failed to cleanup GRPCRoute")
			r.Recorder.Event(grpcRoute, "Warning", EventReasonCleanupFailed, err.Error())
			return ctrl.Result{RequeueAfter: RequeueAfterCleanupFailure}, err
		}

		// Remove finalizer
		controllerutil.RemoveFinalizer(grpcRoute, GRPCRouteFinalizerName)
		if err := r.Update(ctx, grpcRoute); err != nil {
			logger.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}

		metrics.RecordFinalizerOperation("grpcroute", OperationRemove)
		r.Recorder.Event(grpcRoute, "Normal", EventReasonDeleted, MessageRouteDeleted)
	}

	return ctrl.Result{}, nil
}

// reconcileGRPCRoute reconciles the GRPCRoute configuration.
func (r *GRPCRouteReconciler) reconcileGRPCRoute(ctx context.Context, grpcRoute *avapigwv1alpha1.GRPCRoute) error {
	// Convert GRPCRoute spec to JSON
	configJSON, err := json.Marshal(grpcRoute.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal GRPCRoute spec: %w", err)
	}

	// Apply configuration to gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyGRPCRoute(ctx, grpcRoute.Name, grpcRoute.Namespace, configJSON); err != nil {
			return fmt.Errorf("failed to apply GRPCRoute to gateway: %w", err)
		}
	}

	return nil
}

// cleanupGRPCRoute cleans up the GRPCRoute configuration.
func (r *GRPCRouteReconciler) cleanupGRPCRoute(ctx context.Context, grpcRoute *avapigwv1alpha1.GRPCRoute) error {
	// Delete configuration from gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteGRPCRoute(ctx, grpcRoute.Name, grpcRoute.Namespace); err != nil {
			return fmt.Errorf("failed to delete GRPCRoute from gateway: %w", err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GRPCRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.GRPCRoute{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

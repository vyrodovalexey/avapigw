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
	// APIRouteFinalizerName is the finalizer name for APIRoute resources.
	APIRouteFinalizerName = "apiroute.avapigw.io/finalizer"
)

// APIRouteReconciler reconciles an APIRoute object.
type APIRouteReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=apiroutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=apiroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=apiroutes/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation of APIRoute resources.
func (r *APIRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	timer := NewReconcileTimer("apiroute")
	metrics := GetControllerMetrics()
	logger := log.FromContext(ctx)
	logger.Info("reconciling APIRoute", "name", req.Name, "namespace", req.Namespace)

	// Initialize StatusUpdater if not set (for direct Reconcile calls without SetupWithManager)
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	// Fetch the APIRoute instance
	apiRoute := &avapigwv1alpha1.APIRoute{}
	if err := r.Get(ctx, req.NamespacedName, apiRoute); err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return without error
			logger.Info("APIRoute not found, ignoring", "name", req.Name)
			// Clean up metrics for deleted resource
			metrics.DeleteResourceConditionMetrics("APIRoute", req.Name, req.Namespace)
			timer.RecordSuccess()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get APIRoute")
		timer.RecordError()
		return ctrl.Result{}, err
	}

	// Check if the object is being deleted
	if !apiRoute.ObjectMeta.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, apiRoute)
		if err != nil {
			timer.RecordError()
		} else {
			// Clean up metrics for deleted resource
			metrics.DeleteResourceConditionMetrics("APIRoute", apiRoute.Name, apiRoute.Namespace)
			timer.RecordSuccess()
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(apiRoute, APIRouteFinalizerName) {
		controllerutil.AddFinalizer(apiRoute, APIRouteFinalizerName)
		if err := r.Update(ctx, apiRoute); err != nil {
			logger.Error(err, "failed to add finalizer")
			timer.RecordError()
			return ctrl.Result{}, err
		}
		metrics.RecordFinalizerOperation("apiroute", OperationAdd)
		timer.RecordRequeue()
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the APIRoute
	if err := r.reconcileAPIRoute(ctx, apiRoute); err != nil {
		logger.Error(err, "failed to reconcile APIRoute")
		reason := string(avapigwv1alpha1.ReasonReconcileFailed)
		if statusErr := r.StatusUpdater.UpdateRouteStatus(ctx, apiRoute, false, reason, err.Error()); statusErr != nil {
			logger.Error(statusErr, "failed to update status after reconcile failure")
		}
		r.Recorder.Event(apiRoute, "Warning", EventReasonReconcileFailed, err.Error())
		// Update condition metric
		metrics.SetResourceCondition("APIRoute", apiRoute.Name, apiRoute.Namespace, "Ready", 0)
		timer.RecordError()
		return ctrl.Result{RequeueAfter: RequeueAfterReconcileFailure}, err
	}

	// Update status
	reason := string(avapigwv1alpha1.ReasonReconciled)
	if err := r.StatusUpdater.UpdateRouteStatus(ctx, apiRoute, true, reason, MessageRouteApplied); err != nil {
		// Status update failed, requeue to retry. Return nil error to avoid exponential backoff
		// since this is a transient issue that will be resolved on the next reconcile.
		logger.Error(err, "failed to update status, will retry")
		timer.RecordRequeue()
		return ctrl.Result{RequeueAfter: RequeueAfterStatusUpdateFailure}, nil
	}
	r.Recorder.Event(apiRoute, "Normal", EventReasonReconciled, MessageRouteApplied)

	// Update condition metric
	metrics.SetResourceCondition("APIRoute", apiRoute.Name, apiRoute.Namespace, "Ready", 1)
	timer.RecordSuccess()

	return ctrl.Result{}, nil
}

// handleDeletion handles the deletion of an APIRoute.
func (r *APIRouteReconciler) handleDeletion(
	ctx context.Context,
	apiRoute *avapigwv1alpha1.APIRoute,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	metrics := GetControllerMetrics()

	if controllerutil.ContainsFinalizer(apiRoute, APIRouteFinalizerName) {
		// Perform cleanup
		if err := r.cleanupAPIRoute(ctx, apiRoute); err != nil {
			logger.Error(err, "failed to cleanup APIRoute")
			r.Recorder.Event(apiRoute, "Warning", EventReasonCleanupFailed, err.Error())
			return ctrl.Result{RequeueAfter: RequeueAfterCleanupFailure}, err
		}

		// Remove finalizer
		controllerutil.RemoveFinalizer(apiRoute, APIRouteFinalizerName)
		if err := r.Update(ctx, apiRoute); err != nil {
			logger.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}

		metrics.RecordFinalizerOperation("apiroute", OperationRemove)
		r.Recorder.Event(apiRoute, "Normal", EventReasonDeleted, MessageRouteDeleted)
	}

	return ctrl.Result{}, nil
}

// reconcileAPIRoute reconciles the APIRoute configuration.
func (r *APIRouteReconciler) reconcileAPIRoute(ctx context.Context, apiRoute *avapigwv1alpha1.APIRoute) error {
	// Convert APIRoute spec to JSON
	configJSON, err := json.Marshal(apiRoute.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal APIRoute spec: %w", err)
	}

	// Apply configuration to gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyAPIRoute(ctx, apiRoute.Name, apiRoute.Namespace, configJSON); err != nil {
			return fmt.Errorf("failed to apply APIRoute to gateway: %w", err)
		}
	}

	return nil
}

// cleanupAPIRoute cleans up the APIRoute configuration.
func (r *APIRouteReconciler) cleanupAPIRoute(ctx context.Context, apiRoute *avapigwv1alpha1.APIRoute) error {
	// Delete configuration from gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteAPIRoute(ctx, apiRoute.Name, apiRoute.Namespace); err != nil {
			return fmt.Errorf("failed to delete APIRoute from gateway: %w", err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.APIRoute{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

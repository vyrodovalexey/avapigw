// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
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
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *APIRouteReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   "APIRoute",
		ControllerName: "apiroute",
		FinalizerName:  APIRouteFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.APIRoute{}
		},
		Reconcile: func(ctx context.Context, resource Reconcilable) error {
			return r.reconcileAPIRoute(ctx, resource.(*avapigwv1alpha1.APIRoute))
		},
		Cleanup: func(ctx context.Context, resource Reconcilable) error {
			return r.cleanupAPIRoute(ctx, resource.(*avapigwv1alpha1.APIRoute))
		},
		UpdateStatus: func(ctx context.Context, updater *StatusUpdater, resource Reconcilable) error {
			reason := string(avapigwv1alpha1.ReasonReconciled)
			return updater.UpdateRouteStatus(ctx, resource.(RouteStatusUpdatable), true, reason, MessageRouteApplied)
		},
		UpdateFailureStatus: func(
			ctx context.Context, updater *StatusUpdater, resource Reconcilable, reconcileErr error,
		) error {
			reason := string(avapigwv1alpha1.ReasonReconcileFailed)
			return updater.UpdateRouteStatus(
				ctx, resource.(RouteStatusUpdatable), false, reason, reconcileErr.Error(),
			)
		},
		RecordSuccessEvent: func(recorder record.EventRecorder, resource Reconcilable) {
			recorder.Event(resource, "Normal", EventReasonReconciled, MessageRouteApplied)
		},
		RecordFailureEvent: func(recorder record.EventRecorder, resource Reconcilable, err error) {
			recorder.Event(resource, "Warning", EventReasonReconcileFailed, err.Error())
		},
		SetSuccessMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition("APIRoute", resource.GetName(), resource.GetNamespace(), "Ready", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition("APIRoute", resource.GetName(), resource.GetNamespace(), "Ready", 0)
		},
	}
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
	// Initialize StatusUpdater if not already set (Task B2: only in SetupWithManager)
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

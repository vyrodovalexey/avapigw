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
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *GRPCRouteReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   "GRPCRoute",
		ControllerName: "grpcroute",
		FinalizerName:  GRPCRouteFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.GRPCRoute{}
		},
		Reconcile: func(ctx context.Context, resource Reconcilable) error {
			return r.reconcileGRPCRoute(ctx, resource.(*avapigwv1alpha1.GRPCRoute))
		},
		Cleanup: func(ctx context.Context, resource Reconcilable) error {
			return r.cleanupGRPCRoute(ctx, resource.(*avapigwv1alpha1.GRPCRoute))
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
			metrics.SetResourceCondition("GRPCRoute", resource.GetName(), resource.GetNamespace(), "Ready", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition("GRPCRoute", resource.GetName(), resource.GetNamespace(), "Ready", 0)
		},
	}
}

// reconcileGRPCRoute reconciles the GRPCRoute configuration.
func (r *GRPCRouteReconciler) reconcileGRPCRoute(ctx context.Context, grpcRoute *avapigwv1alpha1.GRPCRoute) error {
	configJSON, err := json.Marshal(grpcRoute.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal GRPCRoute spec: %w", err)
	}

	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyGRPCRoute(ctx, grpcRoute.Name, grpcRoute.Namespace, configJSON); err != nil {
			return fmt.Errorf("failed to apply GRPCRoute to gateway: %w", err)
		}
	}

	return nil
}

// cleanupGRPCRoute cleans up the GRPCRoute configuration.
func (r *GRPCRouteReconciler) cleanupGRPCRoute(ctx context.Context, grpcRoute *avapigwv1alpha1.GRPCRoute) error {
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteGRPCRoute(ctx, grpcRoute.Name, grpcRoute.Namespace); err != nil {
			return fmt.Errorf("failed to delete GRPCRoute from gateway: %w", err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GRPCRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set (Task B2: only in SetupWithManager)
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

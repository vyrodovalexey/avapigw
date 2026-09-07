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
	// MCPRouteFinalizerName is the finalizer name for MCPRoute resources.
	MCPRouteFinalizerName = "mcproute.avapigw.io/finalizer"
)

// MCPRouteReconciler reconciles an MCPRoute object.
type MCPRouteReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=mcproutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=mcproutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=mcproutes/finalizers,verbs=update

// Reconcile handles reconciliation of MCPRoute resources.
func (r *MCPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *MCPRouteReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   KindMCPRoute,
		ControllerName: "mcproute",
		FinalizerName:  MCPRouteFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.MCPRoute{}
		},
		Reconcile: func(ctx context.Context, resource Reconcilable) error {
			return r.reconcileMCPRoute(ctx, resource.(*avapigwv1alpha1.MCPRoute))
		},
		Cleanup: func(ctx context.Context, resource Reconcilable) error {
			return r.cleanupMCPRoute(ctx, resource.(*avapigwv1alpha1.MCPRoute))
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
			metrics.SetResourceCondition(KindMCPRoute, resource.GetName(), resource.GetNamespace(), "Ready", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition(KindMCPRoute, resource.GetName(), resource.GetNamespace(), "Ready", 0)
		},
		IsApplied: func(_ context.Context, resource Reconcilable) bool {
			if r.GRPCServer == nil {
				return true
			}
			return r.GRPCServer.HasMCPRoute(resource.GetName(), resource.GetNamespace())
		},
	}
}

// reconcileMCPRoute reconciles the MCPRoute configuration.
func (r *MCPRouteReconciler) reconcileMCPRoute(
	ctx context.Context, mcpRoute *avapigwv1alpha1.MCPRoute,
) error {
	configJSON, err := json.Marshal(mcpRoute.Spec)
	if err != nil {
		r.Recorder.Eventf(mcpRoute, "Warning", EventReasonReconcileFailed,
			"Failed to marshal MCPRoute spec: %v", err)
		return fmt.Errorf("failed to marshal MCPRoute spec: %w", err)
	}

	// Inject the resource name into the JSON spec.
	// CRD specs don't have a "name" field (it's in ObjectMeta), but the gateway
	// config types expect a "name" field for route identification.
	configJSON, err = injectName(configJSON, mcpRoute.Name)
	if err != nil {
		r.Recorder.Eventf(mcpRoute, "Warning", EventReasonReconcileFailed,
			"Failed to inject name into MCPRoute spec: %v", err)
		return fmt.Errorf("failed to inject name into MCPRoute spec: %w", err)
	}

	if r.GRPCServer != nil {
		err := r.GRPCServer.ApplyMCPRoute(ctx, mcpRoute.Name, mcpRoute.Namespace, configJSON)
		if err != nil {
			r.Recorder.Eventf(mcpRoute, "Warning", EventReasonReconcileFailed,
				"Failed to apply MCPRoute to gateway: %v", err)
			return fmt.Errorf("failed to apply MCPRoute to gateway: %w", err)
		}
		r.Recorder.Event(mcpRoute, "Normal", EventReasonConfigApplied,
			"MCPRoute configuration applied to gateway")
	}

	return nil
}

// cleanupMCPRoute cleans up the MCPRoute configuration.
func (r *MCPRouteReconciler) cleanupMCPRoute(
	ctx context.Context, mcpRoute *avapigwv1alpha1.MCPRoute,
) error {
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteMCPRoute(ctx, mcpRoute.Name, mcpRoute.Namespace); err != nil {
			r.Recorder.Eventf(mcpRoute, "Warning", EventReasonCleanupFailed,
				"Failed to delete MCPRoute from gateway: %v", err)
			return fmt.Errorf("failed to delete MCPRoute from gateway: %w", err)
		}
		r.Recorder.Event(mcpRoute, "Normal", EventReasonDeleted,
			"MCPRoute configuration removed from gateway")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MCPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.MCPRoute{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

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
	// GraphQLRouteFinalizerName is the finalizer name for GraphQLRoute resources.
	GraphQLRouteFinalizerName = "graphqlroute.avapigw.io/finalizer"
)

// GraphQLRouteReconciler reconciles a GraphQLRoute object.
type GraphQLRouteReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=graphqlroutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=graphqlroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=graphqlroutes/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation of GraphQLRoute resources.
func (r *GraphQLRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *GraphQLRouteReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   "GraphQLRoute",
		ControllerName: "graphqlroute",
		FinalizerName:  GraphQLRouteFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.GraphQLRoute{}
		},
		Reconcile: func(ctx context.Context, resource Reconcilable) error {
			return r.reconcileGraphQLRoute(ctx, resource.(*avapigwv1alpha1.GraphQLRoute))
		},
		Cleanup: func(ctx context.Context, resource Reconcilable) error {
			return r.cleanupGraphQLRoute(ctx, resource.(*avapigwv1alpha1.GraphQLRoute))
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
			metrics.SetResourceCondition("GraphQLRoute", resource.GetName(), resource.GetNamespace(), "Ready", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition("GraphQLRoute", resource.GetName(), resource.GetNamespace(), "Ready", 0)
		},
		IsApplied: func(_ context.Context, resource Reconcilable) bool {
			if r.GRPCServer == nil {
				return true
			}
			return r.GRPCServer.HasGraphQLRoute(resource.GetName(), resource.GetNamespace())
		},
	}
}

// reconcileGraphQLRoute reconciles the GraphQLRoute configuration.
func (r *GraphQLRouteReconciler) reconcileGraphQLRoute(
	ctx context.Context, graphqlRoute *avapigwv1alpha1.GraphQLRoute,
) error {
	configJSON, err := json.Marshal(graphqlRoute.Spec)
	if err != nil {
		r.Recorder.Eventf(graphqlRoute, "Warning", EventReasonReconcileFailed,
			"Failed to marshal GraphQLRoute spec: %v", err)
		return fmt.Errorf("failed to marshal GraphQLRoute spec: %w", err)
	}

	// Inject the resource name into the JSON spec.
	// CRD specs don't have a "name" field (it's in ObjectMeta), but the gateway
	// config types expect a "name" field for route identification.
	configJSON, err = injectName(configJSON, graphqlRoute.Name)
	if err != nil {
		r.Recorder.Eventf(graphqlRoute, "Warning", EventReasonReconcileFailed,
			"Failed to inject name into GraphQLRoute spec: %v", err)
		return fmt.Errorf("failed to inject name into GraphQLRoute spec: %w", err)
	}

	if r.GRPCServer != nil {
		err := r.GRPCServer.ApplyGraphQLRoute(ctx, graphqlRoute.Name, graphqlRoute.Namespace, configJSON)
		if err != nil {
			r.Recorder.Eventf(graphqlRoute, "Warning", EventReasonReconcileFailed,
				"Failed to apply GraphQLRoute to gateway: %v", err)
			return fmt.Errorf("failed to apply GraphQLRoute to gateway: %w", err)
		}
		r.Recorder.Event(graphqlRoute, "Normal", EventReasonConfigApplied,
			"GraphQLRoute configuration applied to gateway")
	}

	return nil
}

// cleanupGraphQLRoute cleans up the GraphQLRoute configuration.
func (r *GraphQLRouteReconciler) cleanupGraphQLRoute(
	ctx context.Context, graphqlRoute *avapigwv1alpha1.GraphQLRoute,
) error {
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteGraphQLRoute(ctx, graphqlRoute.Name, graphqlRoute.Namespace); err != nil {
			r.Recorder.Eventf(graphqlRoute, "Warning", EventReasonCleanupFailed,
				"Failed to delete GraphQLRoute from gateway: %v", err)
			return fmt.Errorf("failed to delete GraphQLRoute from gateway: %w", err)
		}
		r.Recorder.Event(graphqlRoute, "Normal", EventReasonDeleted,
			"GraphQLRoute configuration removed from gateway")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GraphQLRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.GraphQLRoute{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

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
	// GraphQLBackendFinalizerName is the finalizer name for GraphQLBackend resources.
	GraphQLBackendFinalizerName = "graphqlbackend.avapigw.io/finalizer"
)

// GraphQLBackendReconciler reconciles a GraphQLBackend object.
type GraphQLBackendReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=graphqlbackends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=graphqlbackends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=graphqlbackends/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation of GraphQLBackend resources.
func (r *GraphQLBackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *GraphQLBackendReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   "GraphQLBackend",
		ControllerName: "graphqlbackend",
		FinalizerName:  GraphQLBackendFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.GraphQLBackend{}
		},
		Reconcile: func(ctx context.Context, resource Reconcilable) error {
			return r.reconcileGraphQLBackend(ctx, resource.(*avapigwv1alpha1.GraphQLBackend))
		},
		Cleanup: func(ctx context.Context, resource Reconcilable) error {
			return r.cleanupGraphQLBackend(ctx, resource.(*avapigwv1alpha1.GraphQLBackend))
		},
		UpdateStatus: func(ctx context.Context, updater *StatusUpdater, resource Reconcilable) error {
			backend := resource.(*avapigwv1alpha1.GraphQLBackend)
			reason := string(avapigwv1alpha1.ReasonReconciled)
			totalHosts := len(backend.Spec.Hosts)
			return updater.UpdateBackendStatus(
				ctx, backend, true, true, reason, MessageBackendApplied, totalHosts,
			)
		},
		UpdateFailureStatus: func(
			ctx context.Context, updater *StatusUpdater, resource Reconcilable, reconcileErr error,
		) error {
			backend := resource.(*avapigwv1alpha1.GraphQLBackend)
			reason := string(avapigwv1alpha1.ReasonReconcileFailed)
			totalHosts := len(backend.Spec.Hosts)
			return updater.UpdateBackendStatus(
				ctx, backend, false, false, reason, reconcileErr.Error(), totalHosts,
			)
		},
		RecordSuccessEvent: func(recorder record.EventRecorder, resource Reconcilable) {
			recorder.Event(resource, "Normal", EventReasonReconciled, MessageBackendApplied)
		},
		RecordFailureEvent: func(recorder record.EventRecorder, resource Reconcilable, err error) {
			recorder.Event(resource, "Warning", EventReasonReconcileFailed, err.Error())
		},
		SetSuccessMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition("GraphQLBackend", resource.GetName(), resource.GetNamespace(), "Ready", 1)
			metrics.SetResourceCondition("GraphQLBackend", resource.GetName(), resource.GetNamespace(), "Healthy", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition("GraphQLBackend", resource.GetName(), resource.GetNamespace(), "Ready", 0)
			metrics.SetResourceCondition("GraphQLBackend", resource.GetName(), resource.GetNamespace(), "Healthy", 0)
		},
		IsApplied: func(_ context.Context, resource Reconcilable) bool {
			if r.GRPCServer == nil {
				return true
			}
			return r.GRPCServer.HasGraphQLBackend(resource.GetName(), resource.GetNamespace())
		},
	}
}

// reconcileGraphQLBackend reconciles the GraphQLBackend configuration.
func (r *GraphQLBackendReconciler) reconcileGraphQLBackend(
	ctx context.Context,
	graphqlBackend *avapigwv1alpha1.GraphQLBackend,
) error {
	configJSON, err := json.Marshal(graphqlBackend.Spec)
	if err != nil {
		r.Recorder.Eventf(graphqlBackend, "Warning", EventReasonReconcileFailed,
			"Failed to marshal GraphQLBackend spec: %v", err)
		return fmt.Errorf("failed to marshal GraphQLBackend spec: %w", err)
	}

	// Inject the resource name into the JSON spec.
	// CRD specs don't have a "name" field (it's in ObjectMeta), but the gateway
	// config types expect a "name" field for backend identification.
	configJSON, err = injectName(configJSON, graphqlBackend.Name)
	if err != nil {
		r.Recorder.Eventf(graphqlBackend, "Warning", EventReasonReconcileFailed,
			"Failed to inject name into GraphQLBackend spec: %v", err)
		return fmt.Errorf("failed to inject name into GraphQLBackend spec: %w", err)
	}

	if r.GRPCServer != nil {
		err := r.GRPCServer.ApplyGraphQLBackend(
			ctx, graphqlBackend.Name, graphqlBackend.Namespace, configJSON,
		)
		if err != nil {
			r.Recorder.Eventf(graphqlBackend, "Warning", EventReasonReconcileFailed,
				"Failed to apply GraphQLBackend to gateway: %v", err)
			return fmt.Errorf("failed to apply GraphQLBackend to gateway: %w", err)
		}
		r.Recorder.Event(graphqlBackend, "Normal", EventReasonConfigApplied,
			"GraphQLBackend configuration applied to gateway")
	}

	return nil
}

// cleanupGraphQLBackend cleans up the GraphQLBackend configuration.
func (r *GraphQLBackendReconciler) cleanupGraphQLBackend(
	ctx context.Context,
	graphqlBackend *avapigwv1alpha1.GraphQLBackend,
) error {
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteGraphQLBackend(ctx, graphqlBackend.Name, graphqlBackend.Namespace); err != nil {
			r.Recorder.Eventf(graphqlBackend, "Warning", EventReasonCleanupFailed,
				"Failed to delete GraphQLBackend from gateway: %v", err)
			return fmt.Errorf("failed to delete GraphQLBackend from gateway: %w", err)
		}
		r.Recorder.Event(graphqlBackend, "Normal", EventReasonDeleted,
			"GraphQLBackend configuration removed from gateway")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GraphQLBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.GraphQLBackend{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

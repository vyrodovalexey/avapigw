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
	// MCPBackendFinalizerName is the finalizer name for MCPBackend resources.
	MCPBackendFinalizerName = "mcpbackend.avapigw.io/finalizer"
)

// MCPBackendReconciler reconciles an MCPBackend object.
type MCPBackendReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=mcpbackends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=mcpbackends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=mcpbackends/finalizers,verbs=update

// Reconcile handles reconciliation of MCPBackend resources.
func (r *MCPBackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *MCPBackendReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   KindMCPBackend,
		ControllerName: "mcpbackend",
		FinalizerName:  MCPBackendFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.MCPBackend{}
		},
		Reconcile: func(ctx context.Context, resource Reconcilable) error {
			return r.reconcileMCPBackend(ctx, resource.(*avapigwv1alpha1.MCPBackend))
		},
		Cleanup: func(ctx context.Context, resource Reconcilable) error {
			return r.cleanupMCPBackend(ctx, resource.(*avapigwv1alpha1.MCPBackend))
		},
		UpdateStatus: func(ctx context.Context, updater *StatusUpdater, resource Reconcilable) error {
			backend := resource.(*avapigwv1alpha1.MCPBackend)
			reason := string(avapigwv1alpha1.ReasonReconciled)
			totalHosts := len(backend.Spec.Hosts)
			return updater.UpdateBackendStatus(
				ctx, backend, true, true, reason, MessageBackendApplied, totalHosts,
			)
		},
		UpdateFailureStatus: func(
			ctx context.Context, updater *StatusUpdater, resource Reconcilable, reconcileErr error,
		) error {
			backend := resource.(*avapigwv1alpha1.MCPBackend)
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
			metrics.SetResourceCondition(KindMCPBackend, resource.GetName(), resource.GetNamespace(), "Ready", 1)
			metrics.SetResourceCondition(KindMCPBackend, resource.GetName(), resource.GetNamespace(), "Healthy", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition(KindMCPBackend, resource.GetName(), resource.GetNamespace(), "Ready", 0)
			metrics.SetResourceCondition(KindMCPBackend, resource.GetName(), resource.GetNamespace(), "Healthy", 0)
		},
		IsApplied: func(_ context.Context, resource Reconcilable) bool {
			if r.GRPCServer == nil {
				return true
			}
			return r.GRPCServer.HasMCPBackend(resource.GetName(), resource.GetNamespace())
		},
	}
}

// reconcileMCPBackend reconciles the MCPBackend configuration.
func (r *MCPBackendReconciler) reconcileMCPBackend(
	ctx context.Context,
	mcpBackend *avapigwv1alpha1.MCPBackend,
) error {
	configJSON, err := json.Marshal(mcpBackend.Spec)
	if err != nil {
		r.Recorder.Eventf(mcpBackend, "Warning", EventReasonReconcileFailed,
			"Failed to marshal MCPBackend spec: %v", err)
		return fmt.Errorf("failed to marshal MCPBackend spec: %w", err)
	}

	// Inject the resource name into the JSON spec.
	// CRD specs don't have a "name" field (it's in ObjectMeta), but the gateway
	// config types expect a "name" field for backend identification.
	configJSON, err = injectName(configJSON, mcpBackend.Name)
	if err != nil {
		r.Recorder.Eventf(mcpBackend, "Warning", EventReasonReconcileFailed,
			"Failed to inject name into MCPBackend spec: %v", err)
		return fmt.Errorf("failed to inject name into MCPBackend spec: %w", err)
	}

	if r.GRPCServer != nil {
		err := r.GRPCServer.ApplyMCPBackend(
			ctx, mcpBackend.Name, mcpBackend.Namespace, configJSON,
		)
		if err != nil {
			r.Recorder.Eventf(mcpBackend, "Warning", EventReasonReconcileFailed,
				"Failed to apply MCPBackend to gateway: %v", err)
			return fmt.Errorf("failed to apply MCPBackend to gateway: %w", err)
		}
		r.Recorder.Event(mcpBackend, "Normal", EventReasonConfigApplied,
			"MCPBackend configuration applied to gateway")
	}

	return nil
}

// cleanupMCPBackend cleans up the MCPBackend configuration.
func (r *MCPBackendReconciler) cleanupMCPBackend(
	ctx context.Context,
	mcpBackend *avapigwv1alpha1.MCPBackend,
) error {
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteMCPBackend(ctx, mcpBackend.Name, mcpBackend.Namespace); err != nil {
			r.Recorder.Eventf(mcpBackend, "Warning", EventReasonCleanupFailed,
				"Failed to delete MCPBackend from gateway: %v", err)
			return fmt.Errorf("failed to delete MCPBackend from gateway: %w", err)
		}
		r.Recorder.Event(mcpBackend, "Normal", EventReasonDeleted,
			"MCPBackend configuration removed from gateway")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MCPBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.MCPBackend{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

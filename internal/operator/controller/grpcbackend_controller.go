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
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *GRPCBackendReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   "GRPCBackend",
		ControllerName: "grpcbackend",
		FinalizerName:  GRPCBackendFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.GRPCBackend{}
		},
		Reconcile: func(ctx context.Context, resource Reconcilable) error {
			return r.reconcileGRPCBackend(ctx, resource.(*avapigwv1alpha1.GRPCBackend))
		},
		Cleanup: func(ctx context.Context, resource Reconcilable) error {
			return r.cleanupGRPCBackend(ctx, resource.(*avapigwv1alpha1.GRPCBackend))
		},
		UpdateStatus: func(ctx context.Context, updater *StatusUpdater, resource Reconcilable) error {
			backend := resource.(*avapigwv1alpha1.GRPCBackend)
			reason := string(avapigwv1alpha1.ReasonReconciled)
			totalHosts := len(backend.Spec.Hosts)
			return updater.UpdateBackendStatus(
				ctx, backend, true, true, reason, MessageBackendApplied, totalHosts,
			)
		},
		UpdateFailureStatus: func(
			ctx context.Context, updater *StatusUpdater, resource Reconcilable, reconcileErr error,
		) error {
			backend := resource.(*avapigwv1alpha1.GRPCBackend)
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
			metrics.SetResourceCondition("GRPCBackend", resource.GetName(), resource.GetNamespace(), "Ready", 1)
			metrics.SetResourceCondition("GRPCBackend", resource.GetName(), resource.GetNamespace(), "Healthy", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition("GRPCBackend", resource.GetName(), resource.GetNamespace(), "Ready", 0)
			metrics.SetResourceCondition("GRPCBackend", resource.GetName(), resource.GetNamespace(), "Healthy", 0)
		},
		IsApplied: func(_ context.Context, resource Reconcilable) bool {
			if r.GRPCServer == nil {
				return true
			}
			return r.GRPCServer.HasGRPCBackend(resource.GetName(), resource.GetNamespace())
		},
	}
}

// reconcileGRPCBackend reconciles the GRPCBackend configuration.
func (r *GRPCBackendReconciler) reconcileGRPCBackend(
	ctx context.Context,
	grpcBackend *avapigwv1alpha1.GRPCBackend,
) error {
	configJSON, err := json.Marshal(grpcBackend.Spec)
	if err != nil {
		r.Recorder.Eventf(grpcBackend, "Warning", EventReasonReconcileFailed,
			"Failed to marshal GRPCBackend spec: %v", err)
		return fmt.Errorf("failed to marshal GRPCBackend spec: %w", err)
	}

	// Inject the resource name into the JSON spec.
	// CRD specs don't have a "name" field (it's in ObjectMeta), but the gateway
	// config types expect a "name" field for backend identification.
	configJSON, err = injectName(configJSON, grpcBackend.Name)
	if err != nil {
		r.Recorder.Eventf(grpcBackend, "Warning", EventReasonReconcileFailed,
			"Failed to inject name into GRPCBackend spec: %v", err)
		return fmt.Errorf("failed to inject name into GRPCBackend spec: %w", err)
	}

	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyGRPCBackend(ctx, grpcBackend.Name, grpcBackend.Namespace, configJSON); err != nil {
			r.Recorder.Eventf(grpcBackend, "Warning", EventReasonReconcileFailed,
				"Failed to apply GRPCBackend to gateway: %v", err)
			return fmt.Errorf("failed to apply GRPCBackend to gateway: %w", err)
		}
		r.Recorder.Event(grpcBackend, "Normal", EventReasonConfigApplied,
			"GRPCBackend configuration applied to gateway")
	}

	return nil
}

// cleanupGRPCBackend cleans up the GRPCBackend configuration.
func (r *GRPCBackendReconciler) cleanupGRPCBackend(
	ctx context.Context,
	grpcBackend *avapigwv1alpha1.GRPCBackend,
) error {
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteGRPCBackend(ctx, grpcBackend.Name, grpcBackend.Namespace); err != nil {
			r.Recorder.Eventf(grpcBackend, "Warning", EventReasonCleanupFailed,
				"Failed to delete GRPCBackend from gateway: %v", err)
			return fmt.Errorf("failed to delete GRPCBackend from gateway: %w", err)
		}
		r.Recorder.Event(grpcBackend, "Normal", EventReasonDeleted,
			"GRPCBackend configuration removed from gateway")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GRPCBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set (Task B2: only in SetupWithManager)
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

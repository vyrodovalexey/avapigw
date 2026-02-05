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
	// BackendFinalizerName is the finalizer name for Backend resources.
	BackendFinalizerName = "backend.avapigw.io/finalizer"
)

// BackendReconciler reconciles a Backend object.
type BackendReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	GRPCServer    *operatorgrpc.Server
	StatusUpdater *StatusUpdater
}

// +kubebuilder:rbac:groups=avapigw.io,resources=backends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.io,resources=backends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.io,resources=backends/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation of Backend resources.
func (r *BackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *BackendReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   "Backend",
		ControllerName: "backend",
		FinalizerName:  BackendFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.Backend{}
		},
		Reconcile: func(ctx context.Context, resource Reconcilable) error {
			return r.reconcileBackend(ctx, resource.(*avapigwv1alpha1.Backend))
		},
		Cleanup: func(ctx context.Context, resource Reconcilable) error {
			return r.cleanupBackend(ctx, resource.(*avapigwv1alpha1.Backend))
		},
		UpdateStatus: func(ctx context.Context, updater *StatusUpdater, resource Reconcilable) error {
			backend := resource.(*avapigwv1alpha1.Backend)
			reason := string(avapigwv1alpha1.ReasonReconciled)
			totalHosts := len(backend.Spec.Hosts)
			return updater.UpdateBackendStatus(
				ctx, backend, true, true, reason, MessageBackendApplied, totalHosts,
			)
		},
		UpdateFailureStatus: func(
			ctx context.Context, updater *StatusUpdater, resource Reconcilable, reconcileErr error,
		) error {
			backend := resource.(*avapigwv1alpha1.Backend)
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
			metrics.SetResourceCondition("Backend", resource.GetName(), resource.GetNamespace(), "Ready", 1)
			metrics.SetResourceCondition("Backend", resource.GetName(), resource.GetNamespace(), "Healthy", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition("Backend", resource.GetName(), resource.GetNamespace(), "Ready", 0)
			metrics.SetResourceCondition("Backend", resource.GetName(), resource.GetNamespace(), "Healthy", 0)
		},
	}
}

// reconcileBackend reconciles the Backend configuration.
func (r *BackendReconciler) reconcileBackend(ctx context.Context, backend *avapigwv1alpha1.Backend) error {
	configJSON, err := json.Marshal(backend.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal Backend spec: %w", err)
	}

	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyBackend(ctx, backend.Name, backend.Namespace, configJSON); err != nil {
			return fmt.Errorf("failed to apply Backend to gateway: %w", err)
		}
	}

	return nil
}

// cleanupBackend cleans up the Backend configuration.
func (r *BackendReconciler) cleanupBackend(ctx context.Context, backend *avapigwv1alpha1.Backend) error {
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteBackend(ctx, backend.Name, backend.Namespace); err != nil {
			return fmt.Errorf("failed to delete Backend from gateway: %w", err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *BackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set (Task B2: only in SetupWithManager)
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.Backend{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

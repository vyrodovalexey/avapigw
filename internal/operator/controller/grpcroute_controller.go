// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile handles reconciliation of GRPCRoute resources.
func (r *GRPCRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *GRPCRouteReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   KindGRPCRoute,
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
			metrics.SetResourceCondition(KindGRPCRoute, resource.GetName(), resource.GetNamespace(), "Ready", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition(KindGRPCRoute, resource.GetName(), resource.GetNamespace(), "Ready", 0)
		},
		IsApplied: func(_ context.Context, resource Reconcilable) bool {
			if r.GRPCServer == nil {
				return true
			}
			return r.GRPCServer.HasGRPCRoute(resource.GetName(), resource.GetNamespace())
		},
		ReferencesExternalConfig: func(resource Reconcilable) bool {
			return grpcRouteConfigMapName(resource.(*avapigwv1alpha1.GRPCRoute)) != ""
		},
	}
}

// reconcileGRPCRoute reconciles the GRPCRoute configuration.
func (r *GRPCRouteReconciler) reconcileGRPCRoute(ctx context.Context, grpcRoute *avapigwv1alpha1.GRPCRoute) error {
	// Resolve any ConfigMap-referenced proto descriptors into inline content so
	// the gateway receives a self-contained, validatable configuration.
	if err := resolveProtoValidation(
		ctx, r.Client, grpcRoute.Namespace, grpcRoute.Spec.ProtoValidation,
	); err != nil {
		r.Recorder.Eventf(grpcRoute, "Warning", EventReasonReconcileFailed,
			"Failed to resolve proto validation descriptor: %v", err)
		return fmt.Errorf("failed to resolve proto validation descriptor: %w", err)
	}

	// Rewrite deprecated CRD field shapes (authorization cache sentinel,
	// legacy CSP/HSTS header strings) into the gateway-consumable shape.
	if converted := normalizeRouteSpecShared(grpcRoute.Spec.Authorization, grpcRoute.Spec.Security); converted > 0 {
		GetControllerMetrics().RecordLegacyFieldConversions(KindGRPCRoute, converted)
		log.FromContext(ctx).Info("converted deprecated GRPCRoute spec fields to gateway shape",
			"name", grpcRoute.Name, "namespace", grpcRoute.Namespace, "converted_fields", converted)
	}

	configJSON, err := json.Marshal(grpcRoute.Spec)
	if err != nil {
		r.Recorder.Eventf(grpcRoute, "Warning", EventReasonReconcileFailed,
			"Failed to marshal GRPCRoute spec: %v", err)
		return fmt.Errorf("failed to marshal GRPCRoute spec: %w", err)
	}

	// Inject the resource name into the JSON spec.
	// CRD specs don't have a "name" field (it's in ObjectMeta), but the gateway
	// config types expect a "name" field for route identification.
	configJSON, err = injectName(configJSON, grpcRoute.Name)
	if err != nil {
		r.Recorder.Eventf(grpcRoute, "Warning", EventReasonReconcileFailed,
			"Failed to inject name into GRPCRoute spec: %v", err)
		return fmt.Errorf("failed to inject name into GRPCRoute spec: %w", err)
	}

	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyGRPCRoute(ctx, grpcRoute.Name, grpcRoute.Namespace, configJSON); err != nil {
			r.Recorder.Eventf(grpcRoute, "Warning", EventReasonReconcileFailed,
				"Failed to apply GRPCRoute to gateway: %v", err)
			return fmt.Errorf("failed to apply GRPCRoute to gateway: %w", err)
		}
		r.Recorder.Event(grpcRoute, "Normal", EventReasonConfigApplied,
			"GRPCRoute configuration applied to gateway")
	}

	return nil
}

// cleanupGRPCRoute cleans up the GRPCRoute configuration.
func (r *GRPCRouteReconciler) cleanupGRPCRoute(ctx context.Context, grpcRoute *avapigwv1alpha1.GRPCRoute) error {
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteGRPCRoute(ctx, grpcRoute.Name, grpcRoute.Namespace); err != nil {
			r.Recorder.Eventf(grpcRoute, "Warning", EventReasonCleanupFailed,
				"Failed to delete GRPCRoute from gateway: %v", err)
			return fmt.Errorf("failed to delete GRPCRoute from gateway: %w", err)
		}
		r.Recorder.Event(grpcRoute, "Normal", EventReasonDeleted,
			"GRPCRoute configuration removed from gateway")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GRPCRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set (Task B2: only in SetupWithManager)
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	// Index GRPCRoutes by their referenced proto descriptor ConfigMap so
	// ConfigMap edits re-reconcile exactly the routes that inline it.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &avapigwv1alpha1.GRPCRoute{},
		grpcRouteConfigMapIndexField, func(obj client.Object) []string {
			route, ok := obj.(*avapigwv1alpha1.GRPCRoute)
			if !ok {
				return nil
			}
			return configMapIndexValues(grpcRouteConfigMapName(route))
		}); err != nil {
		return fmt.Errorf("failed to index GRPCRoute ConfigMap references: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.GRPCRoute{}).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(
			configMapMapFunc(r.Client, KindGRPCRoute, grpcRouteConfigMapIndexField,
				func() client.ObjectList { return &avapigwv1alpha1.GRPCRouteList{} }),
		)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

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
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile handles reconciliation of APIRoute resources.
func (r *APIRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return BaseReconcile(ctx, r.Client, r.StatusUpdater, r.Recorder, req, r.callbacks())
}

// callbacks returns the resource-specific callbacks for the base reconciler.
func (r *APIRouteReconciler) callbacks() *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   KindAPIRoute,
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
			metrics.SetResourceCondition(KindAPIRoute, resource.GetName(), resource.GetNamespace(), "Ready", 1)
		},
		SetFailureMetrics: func(metrics *ControllerMetrics, resource Reconcilable) {
			metrics.SetResourceCondition(KindAPIRoute, resource.GetName(), resource.GetNamespace(), "Ready", 0)
		},
		IsApplied: func(_ context.Context, resource Reconcilable) bool {
			if r.GRPCServer == nil {
				return true
			}
			return r.GRPCServer.HasAPIRoute(resource.GetName(), resource.GetNamespace())
		},
		ReferencesExternalConfig: func(resource Reconcilable) bool {
			return apiRouteConfigMapName(resource.(*avapigwv1alpha1.APIRoute)) != ""
		},
	}
}

// reconcileAPIRoute reconciles the APIRoute configuration.
func (r *APIRouteReconciler) reconcileAPIRoute(ctx context.Context, apiRoute *avapigwv1alpha1.APIRoute) error {
	// Resolve any ConfigMap-referenced OpenAPI specs into inline content so the
	// gateway (which has no cluster access) receives a self-contained,
	// validatable configuration.
	if err := r.resolveValidationRefs(ctx, apiRoute); err != nil {
		r.Recorder.Eventf(apiRoute, "Warning", EventReasonReconcileFailed,
			"Failed to resolve OpenAPI validation spec: %v", err)
		return fmt.Errorf("failed to resolve OpenAPI validation spec: %w", err)
	}

	// Rewrite deprecated CRD field shapes (authorization cache sentinel,
	// legacy CSP/HSTS header strings) into the gateway-consumable shape.
	if converted := normalizeRouteSpecShared(apiRoute.Spec.Authorization, apiRoute.Spec.Security); converted > 0 {
		GetControllerMetrics().RecordLegacyFieldConversions(KindAPIRoute, converted)
		log.FromContext(ctx).Info("converted deprecated APIRoute spec fields to gateway shape",
			"name", apiRoute.Name, "namespace", apiRoute.Namespace, "converted_fields", converted)
	}

	// Convert APIRoute spec to JSON
	configJSON, err := json.Marshal(apiRoute.Spec)
	if err != nil {
		r.Recorder.Eventf(apiRoute, "Warning", EventReasonReconcileFailed,
			"Failed to marshal APIRoute spec: %v", err)
		return fmt.Errorf("failed to marshal APIRoute spec: %w", err)
	}

	// Inject the resource name into the JSON spec.
	// CRD specs don't have a "name" field (it's in ObjectMeta), but the gateway
	// config types expect a "name" field for route identification.
	configJSON, err = injectName(configJSON, apiRoute.Name)
	if err != nil {
		r.Recorder.Eventf(apiRoute, "Warning", EventReasonReconcileFailed,
			"Failed to inject name into APIRoute spec: %v", err)
		return fmt.Errorf("failed to inject name into APIRoute spec: %w", err)
	}

	// Apply configuration to gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.ApplyAPIRoute(ctx, apiRoute.Name, apiRoute.Namespace, configJSON); err != nil {
			r.Recorder.Eventf(apiRoute, "Warning", EventReasonReconcileFailed,
				"Failed to apply APIRoute to gateway: %v", err)
			return fmt.Errorf("failed to apply APIRoute to gateway: %w", err)
		}
		r.Recorder.Event(apiRoute, "Normal", EventReasonConfigApplied,
			"APIRoute configuration applied to gateway")
	}

	return nil
}

// resolveValidationRefs resolves ConfigMap-referenced OpenAPI validation specs
// on the route (route-level and per-match rule) into inline content.
func (r *APIRouteReconciler) resolveValidationRefs(
	ctx context.Context, apiRoute *avapigwv1alpha1.APIRoute,
) error {
	return resolveOpenAPIValidation(ctx, r.Client, apiRoute.Namespace, apiRoute.Spec.OpenAPIValidation)
}

// cleanupAPIRoute cleans up the APIRoute configuration.
func (r *APIRouteReconciler) cleanupAPIRoute(ctx context.Context, apiRoute *avapigwv1alpha1.APIRoute) error {
	// Delete configuration from gRPC server
	if r.GRPCServer != nil {
		if err := r.GRPCServer.DeleteAPIRoute(ctx, apiRoute.Name, apiRoute.Namespace); err != nil {
			r.Recorder.Eventf(apiRoute, "Warning", EventReasonCleanupFailed,
				"Failed to delete APIRoute from gateway: %v", err)
			return fmt.Errorf("failed to delete APIRoute from gateway: %w", err)
		}
		r.Recorder.Event(apiRoute, "Normal", EventReasonDeleted,
			"APIRoute configuration removed from gateway")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize StatusUpdater if not already set (Task B2: only in SetupWithManager)
	if r.StatusUpdater == nil {
		r.StatusUpdater = NewStatusUpdater(r.Client)
	}

	// Index APIRoutes by their referenced OpenAPI spec ConfigMap so ConfigMap
	// edits re-reconcile exactly the routes that inline the spec content.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &avapigwv1alpha1.APIRoute{},
		apiRouteConfigMapIndexField, func(obj client.Object) []string {
			route, ok := obj.(*avapigwv1alpha1.APIRoute)
			if !ok {
				return nil
			}
			return configMapIndexValues(apiRouteConfigMapName(route))
		}); err != nil {
		return fmt.Errorf("failed to index APIRoute ConfigMap references: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.APIRoute{}).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(
			configMapMapFunc(r.Client, KindAPIRoute, apiRouteConfigMapIndexField,
				func() client.ObjectList { return &avapigwv1alpha1.APIRouteList{} }),
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

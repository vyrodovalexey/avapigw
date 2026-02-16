// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

// IngressReconciler reconciles networking.k8s.io/v1 Ingress objects
// that are assigned to the avapigw IngressClass.
type IngressReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	GRPCServer          *operatorgrpc.Server
	IngressStatusUpdate *IngressStatusUpdater
	Converter           *IngressConverter
	IngressClassName    string
}

// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses/finalizers,verbs=update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles reconciliation of Ingress resources.
// It follows the BaseReconcile pattern: fetch, check class, handle deletion,
// add finalizer, reconcile, update status, record events, and update metrics.
//
//nolint:gocognit,cyclop // complex reconciliation with class matching and multi-resource apply
func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	timer := NewReconcileTimer(ingressControllerName)
	metrics := GetControllerMetrics()
	logger := log.FromContext(ctx)
	logger.Info("reconciling "+ingressResourceKind, "name", req.Name, "namespace", req.Namespace)

	// Fetch the Ingress instance
	ingress := &networkingv1.Ingress{}
	if err := r.Get(ctx, req.NamespacedName, ingress); err != nil {
		if errors.IsNotFound(err) {
			logger.Info(ingressResourceKind+" not found, ignoring", "name", req.Name)
			metrics.DeleteResourceConditionMetrics(ingressResourceKind, req.Name, req.Namespace)
			timer.RecordSuccess()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get "+ingressResourceKind)
		timer.RecordError()
		return ctrl.Result{}, err
	}

	// Check if this Ingress belongs to our IngressClass
	if !r.matchesIngressClass(ingress) {
		logger.Info(ingressResourceKind+" does not match IngressClass, ignoring",
			"name", req.Name,
			"expected", r.IngressClassName,
		)
		return ctrl.Result{}, nil
	}

	// Handle deletion
	if !ingress.ObjectMeta.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, ingress)
		if err != nil {
			timer.RecordError()
		} else {
			metrics.DeleteResourceConditionMetrics(ingressResourceKind, ingress.Name, ingress.Namespace)
			timer.RecordSuccess()
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(ingress, IngressFinalizerName) {
		original := ingress.DeepCopy()
		controllerutil.AddFinalizer(ingress, IngressFinalizerName)
		if err := r.Patch(ctx, ingress, client.MergeFrom(original)); err != nil {
			logger.Error(err, "failed to add finalizer")
			timer.RecordError()
			return ctrl.Result{}, err
		}
		metrics.RecordFinalizerOperation(ingressControllerName, OperationAdd)
		// The Patch triggers a watch event automatically; no explicit requeue needed.
		timer.RecordSuccess()
		return ctrl.Result{}, nil
	}

	// Generation-based reconciliation skip: if the Ingress has already been
	// reconciled for this generation, skip reconciliation.
	if isIngressReady(ingress) {
		logger.V(1).Info("skipping "+ingressResourceKind+" reconciliation, already up-to-date",
			"generation", ingress.Generation,
		)
		timer.RecordSuccess()
		return ctrl.Result{}, nil
	}

	// Reconcile the Ingress
	if err := r.reconcileIngress(ctx, ingress); err != nil {
		logger.Error(err, "failed to reconcile "+ingressResourceKind)
		r.Recorder.Event(ingress, "Warning", EventReasonIngressReconcileFailed, err.Error())
		metrics.SetResourceCondition(ingressResourceKind, ingress.Name, ingress.Namespace, "Ready", 0)
		metrics.RecordIngressProcessed(ResultError)
		timer.RecordError()
		return ctrl.Result{RequeueAfter: RequeueAfterReconcileFailure}, err
	}

	// Update Ingress LoadBalancer status
	if r.IngressStatusUpdate != nil {
		if err := r.IngressStatusUpdate.UpdateIngressStatus(ctx, ingress); err != nil {
			logger.Error(err, "failed to update Ingress status, will retry")
			timer.RecordRequeue()
			return ctrl.Result{RequeueAfter: RequeueAfterStatusUpdateFailure}, nil
		}
	}

	// Update observed generation annotation to enable generation-based skip
	if err := r.updateObservedGeneration(ctx, ingress); err != nil {
		logger.Error(err, "failed to update observed generation annotation")
		// Non-fatal: reconciliation succeeded, annotation tracking is best-effort
	}

	r.Recorder.Event(ingress, "Normal", EventReasonIngressReconciled, MessageIngressApplied)
	metrics.SetResourceCondition(ingressResourceKind, ingress.Name, ingress.Namespace, "Ready", 1)
	metrics.RecordIngressProcessed(ResultSuccess)
	timer.RecordSuccess()

	return ctrl.Result{}, nil
}

// ingressResourceKind is the resource kind name for logging and metrics.
const ingressResourceKind = "Ingress"

// ingressControllerName is the controller name for metrics.
const ingressControllerName = "ingress"

// matchesIngressClass checks whether the Ingress is assigned to our IngressClass.
// It checks both spec.ingressClassName and the legacy kubernetes.io/ingress.class annotation.
func (r *IngressReconciler) matchesIngressClass(ingress *networkingv1.Ingress) bool {
	// Check spec.ingressClassName first (preferred)
	if ingress.Spec.IngressClassName != nil {
		return *ingress.Spec.IngressClassName == r.IngressClassName
	}

	// Fall back to legacy annotation
	if annotations := ingress.Annotations; annotations != nil {
		if className, ok := annotations[AnnotationIngressClass]; ok {
			return className == r.IngressClassName
		}
	}

	return false
}

// handleDeletion handles the deletion of an Ingress resource.
// It removes all applied routes and backends from the gRPC server and removes the finalizer.
func (r *IngressReconciler) handleDeletion(
	ctx context.Context,
	ingress *networkingv1.Ingress,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	metrics := GetControllerMetrics()

	if controllerutil.ContainsFinalizer(ingress, IngressFinalizerName) {
		// Perform cleanup
		if err := r.cleanupIngress(ctx, ingress); err != nil {
			logger.Error(err, "failed to cleanup Ingress")
			r.Recorder.Event(ingress, "Warning", EventReasonIngressCleanupFailed, err.Error())
			return ctrl.Result{RequeueAfter: RequeueAfterCleanupFailure}, err
		}

		// Remove finalizer
		original := ingress.DeepCopy()
		controllerutil.RemoveFinalizer(ingress, IngressFinalizerName)
		if err := r.Patch(ctx, ingress, client.MergeFrom(original)); err != nil {
			logger.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}

		metrics.RecordFinalizerOperation(ingressControllerName, OperationRemove)
		r.Recorder.Event(ingress, "Normal", EventReasonIngressDeleted, MessageIngressDeleted)
	}

	return ctrl.Result{}, nil
}

// reconcileIngress converts the Ingress to gateway configuration and applies it.
// nolint:gocognit // Complexity is justified: handles both HTTP and gRPC resources with proper error handling
func (r *IngressReconciler) reconcileIngress(
	ctx context.Context,
	ingress *networkingv1.Ingress,
) error {
	logger := log.FromContext(ctx)

	// Convert Ingress to gateway configuration
	converted, err := r.Converter.ConvertIngress(ingress)
	if err != nil {
		GetControllerMetrics().RecordIngressConversionError(ingress.Namespace, ingress.Name)
		r.Recorder.Event(ingress, "Warning", EventReasonIngressConversionFailed,
			fmt.Sprintf("%s: %v", MessageIngressConversionFailed, err))
		return fmt.Errorf("failed to convert Ingress: %w", err)
	}

	// Apply routes to gRPC server
	if r.GRPCServer != nil {
		// Apply HTTP routes
		for routeKey, routeJSON := range converted.Routes {
			if err := r.GRPCServer.ApplyAPIRoute(ctx, routeKey, ingress.Namespace, routeJSON); err != nil {
				return fmt.Errorf("failed to apply route %s: %w", routeKey, err)
			}
			logger.V(1).Info("applied route", "key", routeKey)
		}

		// Apply HTTP backends
		for backendKey, backendJSON := range converted.Backends {
			if err := r.GRPCServer.ApplyBackend(ctx, backendKey, ingress.Namespace, backendJSON); err != nil {
				return fmt.Errorf("failed to apply backend %s: %w", backendKey, err)
			}
			logger.V(1).Info("applied backend", "key", backendKey)
		}

		// Apply gRPC routes
		for routeKey, routeJSON := range converted.GRPCRoutes {
			if err := r.GRPCServer.ApplyGRPCRoute(ctx, routeKey, ingress.Namespace, routeJSON); err != nil {
				return fmt.Errorf("failed to apply gRPC route %s: %w", routeKey, err)
			}
			logger.V(1).Info("applied gRPC route", "key", routeKey)
		}

		// Apply gRPC backends
		for backendKey, backendJSON := range converted.GRPCBackends {
			if err := r.GRPCServer.ApplyGRPCBackend(ctx, backendKey, ingress.Namespace, backendJSON); err != nil {
				return fmt.Errorf("failed to apply gRPC backend %s: %w", backendKey, err)
			}
			logger.V(1).Info("applied gRPC backend", "key", backendKey)
		}
	}

	// Track applied routes in annotation for cleanup
	if err := r.updateAppliedRoutesAnnotation(ctx, ingress, converted); err != nil {
		logger.Error(err, "failed to update applied routes annotation")
		r.Recorder.Event(ingress, "Warning", "AnnotationUpdateFailed",
			fmt.Sprintf("failed to update applied routes annotation: %v", err))
		// Non-fatal: routes are applied, annotation tracking is best-effort
	}

	logger.Info("Ingress reconciled",
		"routes", len(converted.Routes),
		"backends", len(converted.Backends),
		"grpcRoutes", len(converted.GRPCRoutes),
		"grpcBackends", len(converted.GRPCBackends),
	)

	return nil
}

// cleanupIngress removes all routes and backends that were applied from this Ingress.
// nolint:gocognit,gocyclo // Complexity justified: handles cleanup of both HTTP and gRPC resources
func (r *IngressReconciler) cleanupIngress(
	ctx context.Context,
	ingress *networkingv1.Ingress,
) error {
	logger := log.FromContext(ctx)

	if r.GRPCServer == nil {
		return nil
	}

	// Get previously applied route/backend keys from annotation
	routeKeys, backendKeys, grpcRouteKeys, grpcBackendKeys := r.getAppliedKeys(ingress)

	// If no tracked keys, re-derive them from the Ingress spec
	if len(routeKeys) == 0 && len(backendKeys) == 0 && len(grpcRouteKeys) == 0 && len(grpcBackendKeys) == 0 {
		converted, err := r.Converter.ConvertIngress(ingress)
		if err != nil {
			return fmt.Errorf("failed to convert Ingress for cleanup: %w", err)
		}
		routeKeys = sortedMapKeys(converted.Routes)
		backendKeys = sortedMapKeys(converted.Backends)
		grpcRouteKeys = sortedMapKeys(converted.GRPCRoutes)
		grpcBackendKeys = sortedMapKeys(converted.GRPCBackends)
	}

	// Delete HTTP routes
	for _, key := range routeKeys {
		if err := r.GRPCServer.DeleteAPIRoute(ctx, key, ingress.Namespace); err != nil {
			logger.Error(err, "failed to delete route during cleanup", "key", key)
			return fmt.Errorf("failed to delete route %s: %w", key, err)
		}
		logger.V(1).Info("deleted route", "key", key)
	}

	// Delete HTTP backends
	for _, key := range backendKeys {
		if err := r.GRPCServer.DeleteBackend(ctx, key, ingress.Namespace); err != nil {
			logger.Error(err, "failed to delete backend during cleanup", "key", key)
			return fmt.Errorf("failed to delete backend %s: %w", key, err)
		}
		logger.V(1).Info("deleted backend", "key", key)
	}

	// Delete gRPC routes
	for _, key := range grpcRouteKeys {
		if err := r.GRPCServer.DeleteGRPCRoute(ctx, key, ingress.Namespace); err != nil {
			logger.Error(err, "failed to delete gRPC route during cleanup", "key", key)
			return fmt.Errorf("failed to delete gRPC route %s: %w", key, err)
		}
		logger.V(1).Info("deleted gRPC route", "key", key)
	}

	// Delete gRPC backends
	for _, key := range grpcBackendKeys {
		if err := r.GRPCServer.DeleteGRPCBackend(ctx, key, ingress.Namespace); err != nil {
			logger.Error(err, "failed to delete gRPC backend during cleanup", "key", key)
			return fmt.Errorf("failed to delete gRPC backend %s: %w", key, err)
		}
		logger.V(1).Info("deleted gRPC backend", "key", key)
	}

	logger.Info("Ingress cleanup completed",
		"routes_deleted", len(routeKeys),
		"backends_deleted", len(backendKeys),
		"grpc_routes_deleted", len(grpcRouteKeys),
		"grpc_backends_deleted", len(grpcBackendKeys),
	)

	return nil
}

// updateAppliedRoutesAnnotation stores the applied route and backend keys
// in an annotation on the Ingress for later cleanup.
func (r *IngressReconciler) updateAppliedRoutesAnnotation(
	ctx context.Context,
	ingress *networkingv1.Ingress,
	converted *ConvertedConfig,
) error {
	routeKeys := make([]string, 0, len(converted.Routes))
	for key := range converted.Routes {
		routeKeys = append(routeKeys, key)
	}

	backendKeys := make([]string, 0, len(converted.Backends))
	for key := range converted.Backends {
		backendKeys = append(backendKeys, key)
	}

	grpcRouteKeys := make([]string, 0, len(converted.GRPCRoutes))
	for key := range converted.GRPCRoutes {
		grpcRouteKeys = append(grpcRouteKeys, key)
	}

	grpcBackendKeys := make([]string, 0, len(converted.GRPCBackends))
	for key := range converted.GRPCBackends {
		grpcBackendKeys = append(grpcBackendKeys, key)
	}

	// Encode as "routes:key1,key2;backends:key3,key4;grpcRoutes:key5,key6;grpcBackends:key7,key8"
	value := fmt.Sprintf("routes:%s;backends:%s;grpcRoutes:%s;grpcBackends:%s",
		strings.Join(routeKeys, ","),
		strings.Join(backendKeys, ","),
		strings.Join(grpcRouteKeys, ","),
		strings.Join(grpcBackendKeys, ","),
	)

	original := ingress.DeepCopy()

	if ingress.Annotations == nil {
		ingress.Annotations = make(map[string]string)
	}
	ingress.Annotations[AnnotationAppliedRoutes] = value

	return r.Patch(ctx, ingress, client.MergeFrom(original))
}

// parseKeysPart extracts keys from a part like "prefix:key1,key2".
func parseKeysPart(part, prefix string) []string {
	if !strings.HasPrefix(part, prefix) {
		return nil
	}
	keysStr := strings.TrimPrefix(part, prefix)
	if keysStr == "" {
		return nil
	}
	return splitCSV(keysStr)
}

// getAppliedKeys parses the applied routes annotation to retrieve
// previously applied route and backend keys.
func (r *IngressReconciler) getAppliedKeys(
	ingress *networkingv1.Ingress,
) (routeKeys, backendKeys, grpcRouteKeys, grpcBackendKeys []string) {
	if ingress.Annotations == nil {
		return nil, nil, nil, nil
	}

	value, ok := ingress.Annotations[AnnotationAppliedRoutes]
	if !ok || value == "" {
		return nil, nil, nil, nil
	}

	// Parse "routes:key1,key2;backends:key3,key4;grpcRoutes:key5,key6;grpcBackends:key7,key8"
	parts := strings.Split(value, ";")
	for _, part := range parts {
		switch {
		case strings.HasPrefix(part, "routes:"):
			routeKeys = parseKeysPart(part, "routes:")
		case strings.HasPrefix(part, "backends:"):
			backendKeys = parseKeysPart(part, "backends:")
		case strings.HasPrefix(part, "grpcRoutes:"):
			grpcRouteKeys = parseKeysPart(part, "grpcRoutes:")
		case strings.HasPrefix(part, "grpcBackends:"):
			grpcBackendKeys = parseKeysPart(part, "grpcBackends:")
		}
	}

	return routeKeys, backendKeys, grpcRouteKeys, grpcBackendKeys
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize converter if not set
	if r.Converter == nil {
		r.Converter = NewIngressConverter()
	}

	// Initialize IngressStatusUpdater if not set
	if r.IngressStatusUpdate == nil {
		r.IngressStatusUpdate = NewIngressStatusUpdater(r.Client, "")
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		WithEventFilter(r.ingressClassPredicate()).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: MaxConcurrentReconciles,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				RateLimiterBaseDelay,
				RateLimiterMaxDelay,
			),
		}).
		Complete(r)
}

// ingressClassPredicate returns a predicate that filters Ingress resources
// to only those matching our IngressClass.
func (r *IngressReconciler) ingressClassPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(object client.Object) bool {
		ingress, ok := object.(*networkingv1.Ingress)
		if !ok {
			return false
		}
		return r.matchesIngressClass(ingress)
	})
}

// isIngressReady checks if an Ingress has already been reconciled for the current generation.
// Since Ingress is a native K8s resource without CRD conditions, we track the observed
// generation via an annotation.
func isIngressReady(ingress *networkingv1.Ingress) bool {
	if ingress.Annotations == nil {
		return false
	}
	observedStr, ok := ingress.Annotations[AnnotationObservedGeneration]
	if !ok {
		return false
	}
	observed, err := strconv.ParseInt(observedStr, 10, 64)
	if err != nil {
		return false
	}
	return observed == ingress.Generation
}

// updateObservedGeneration updates the observed generation annotation on the Ingress
// after a successful reconciliation.
func (r *IngressReconciler) updateObservedGeneration(
	ctx context.Context,
	ingress *networkingv1.Ingress,
) error {
	original := ingress.DeepCopy()

	if ingress.Annotations == nil {
		ingress.Annotations = make(map[string]string)
	}
	ingress.Annotations[AnnotationObservedGeneration] = strconv.FormatInt(ingress.Generation, 10)

	return r.Patch(ctx, ingress, client.MergeFrom(original))
}

// sortedMapKeys returns the keys of a map[string][]byte in sorted order
// for deterministic iteration.
func sortedMapKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

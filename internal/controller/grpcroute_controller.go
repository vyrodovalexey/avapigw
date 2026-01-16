// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/controller/base"
	"github.com/vyrodovalexey/avapigw/internal/controller/route"
)

// Compile-time check that GRPCRoute implements route.RouteWithParentRefs
var _ route.RouteWithParentRefs = &avapigwv1alpha1.GRPCRoute{}

// Local aliases for constants to maintain backward compatibility.
// These reference the centralized constants from constants.go.
const (
	grpcRouteFinalizer        = GRPCRouteFinalizerName
	grpcRouteReconcileTimeout = GRPCRouteReconcileTimeout
)

// GRPCRouteReconciler reconciles a GRPCRoute object
type GRPCRouteReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy

	// Base reconciler components
	metrics          *base.ControllerMetrics
	finalizerHandler *base.FinalizerHandler
}

// getRequeueStrategy returns the requeue strategy, initializing with defaults if needed.
// Uses sync.Once to ensure thread-safe initialization and prevent race conditions
// when multiple goroutines access the strategy concurrently.
func (r *GRPCRouteReconciler) getRequeueStrategy() *RequeueStrategy {
	r.requeueStrategyOnce.Do(func() {
		if r.RequeueStrategy == nil {
			r.RequeueStrategy = DefaultRequeueStrategy()
		}
	})
	return r.RequeueStrategy
}

// initBaseComponents initializes the base controller components.
// This is called automatically during reconciliation but can also be called
// explicitly for testing purposes.
func (r *GRPCRouteReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("grpcroute")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, grpcRouteFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *GRPCRouteReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles GRPCRoute reconciliation
func (r *GRPCRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, grpcRouteReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling GRPCRoute",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the GRPCRoute instance
	grpcRoute, result, err := r.fetchGRPCRoute(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if grpcRoute == nil {
		return result, nil
	}

	// Handle deletion
	if !grpcRoute.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, grpcRoute)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Ensure finalizer and reconcile
	return r.ensureFinalizerAndReconcileGRPCRoute(ctx, grpcRoute, strategy, resourceKey, &reconcileErr)
}

// fetchGRPCRoute fetches the GRPCRoute instance and handles not-found errors.
func (r *GRPCRouteReconciler) fetchGRPCRoute(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.GRPCRoute, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	grpcRoute := &avapigwv1alpha1.GRPCRoute{}
	if err := r.Get(ctx, req.NamespacedName, grpcRoute); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("GRPCRoute not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getGRPCRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get GRPCRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return grpcRoute, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcileGRPCRoute ensures the finalizer is present and performs reconciliation.
func (r *GRPCRouteReconciler) ensureFinalizerAndReconcileGRPCRoute(
	ctx context.Context,
	grpcRoute *avapigwv1alpha1.GRPCRoute,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Add finalizer if not present
	if !r.finalizerHandler.HasFinalizer(grpcRoute) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, grpcRoute)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(grpcRoute, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	// Reconcile the GRPCRoute
	if err := r.reconcileGRPCRoute(ctx, grpcRoute); err != nil {
		*reconcileErr = ClassifyError("reconcileGRPCRoute", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile GRPCRoute",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
			"userActionRequired", (*reconcileErr).UserActionRequired,
		)
		r.Recorder.Event(grpcRoute, corev1.EventTypeWarning, string((*reconcileErr).Type)+"Error", err.Error())
		return r.handleGRPCRouteReconcileError(*reconcileErr, strategy, resourceKey)
	}

	strategy.ResetFailureCount(resourceKey)
	logger.Info("GRPCRoute reconciled successfully", "name", grpcRoute.Name, "namespace", grpcRoute.Namespace)
	return strategy.ForSuccess(), nil
}

// handleGRPCRouteReconcileError returns the appropriate result based on error type.
func (r *GRPCRouteReconciler) handleGRPCRouteReconcileError(
	reconcileErr *ReconcileError,
	strategy *RequeueStrategy,
	resourceKey string,
) (ctrl.Result, error) {
	switch reconcileErr.Type {
	case ErrorTypeValidation:
		return strategy.ForValidationError(), reconcileErr
	case ErrorTypePermanent:
		return strategy.ForPermanentError(), reconcileErr
	case ErrorTypeDependency:
		return strategy.ForDependencyErrorWithBackoff(resourceKey), reconcileErr
	default:
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
}

// handleDeletion handles GRPCRoute deletion
func (r *GRPCRouteReconciler) handleDeletion(
	ctx context.Context,
	grpcRoute *avapigwv1alpha1.GRPCRoute,
) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(grpcRoute).String()

	if r.finalizerHandler.HasFinalizer(grpcRoute) {
		// Perform cleanup
		logger.Info("Performing cleanup for GRPCRoute deletion",
			"name", grpcRoute.Name,
			"namespace", grpcRoute.Namespace,
		)

		// Record event
		r.Recorder.Event(grpcRoute, corev1.EventTypeNormal, "Deleting", "GRPCRoute is being deleted")

		// Remove finalizer
		if _, err := r.finalizerHandler.RemoveFinalizer(ctx, grpcRoute); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
}

// reconcileGRPCRoute performs the main reconciliation logic
func (r *GRPCRouteReconciler) reconcileGRPCRoute(ctx context.Context, grpcRoute *avapigwv1alpha1.GRPCRoute) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(grpcRoute).String()

	// Validate parent references (Gateways)
	parentStatuses, err := r.validateParentRefs(ctx, grpcRoute)
	if err != nil {
		reconcileErr := ClassifyError("validateParentRefs", resourceKey, err)
		logger.Error(reconcileErr, "Failed to validate parent references",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	// Validate backend references
	if err := r.validateBackendRefs(ctx, grpcRoute); err != nil {
		// Log but continue - backend validation errors are not fatal
		reconcileErr := ClassifyError("validateBackendRefs", resourceKey, err)
		logger.Info("Backend validation warning, continuing with reconciliation",
			"error", err.Error(),
			"errorType", reconcileErr.Type,
		)
		// Continue with status update even if backends are invalid
	}

	// Update route status with parent statuses
	grpcRoute.Status.Parents = parentStatuses

	// Update status
	if err := r.Status().Update(ctx, grpcRoute); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update GRPCRoute status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(grpcRoute, corev1.EventTypeNormal, EventReasonReconciled, "GRPCRoute reconciled successfully")
	return nil
}

// validateParentRefs validates parent references and returns parent statuses
func (r *GRPCRouteReconciler) validateParentRefs(
	ctx context.Context,
	grpcRoute *avapigwv1alpha1.GRPCRoute,
) ([]avapigwv1alpha1.RouteParentStatus, error) {
	parentStatuses := make([]avapigwv1alpha1.RouteParentStatus, 0, len(grpcRoute.Spec.ParentRefs))

	for _, parentRef := range grpcRoute.Spec.ParentRefs {
		parentStatus, err := r.validateSingleGRPCParentRef(ctx, grpcRoute, parentRef)
		if err != nil {
			return nil, err
		}
		parentStatuses = append(parentStatuses, parentStatus)
	}

	return parentStatuses, nil
}

// validateSingleGRPCParentRef validates a single parent reference and returns its status.
func (r *GRPCRouteReconciler) validateSingleGRPCParentRef(
	ctx context.Context,
	grpcRoute *avapigwv1alpha1.GRPCRoute,
	parentRef avapigwv1alpha1.ParentRef,
) (avapigwv1alpha1.RouteParentStatus, error) {
	logger := log.FromContext(ctx)
	parentStatus := avapigwv1alpha1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: GatewayControllerName,
	}

	namespace := grpcRoute.Namespace
	if parentRef.Namespace != nil {
		namespace = *parentRef.Namespace
	}

	gateway := &avapigwv1alpha1.Gateway{}
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: parentRef.Name}, gateway)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Parent Gateway not found", "gateway", parentRef.Name, "namespace", namespace)
			parentStatus.Conditions = r.buildGRPCNotFoundConditions(namespace, parentRef.Name)
			return parentStatus, nil
		}
		return parentStatus, fmt.Errorf("failed to get Gateway %s/%s: %w", namespace, parentRef.Name, err)
	}

	parentStatus.Conditions = r.buildGRPCListenerMatchConditions(grpcRoute, gateway, parentRef)
	return parentStatus, nil
}

// buildGRPCNotFoundConditions builds conditions for a not-found gateway.
func (r *GRPCRouteReconciler) buildGRPCNotFoundConditions(namespace, name string) []avapigwv1alpha1.Condition {
	return []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionTypeAccepted,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             string(avapigwv1alpha1.ReasonNoMatchingParent),
			Message:            fmt.Sprintf("Gateway %s/%s not found", namespace, name),
		},
	}
}

// buildGRPCListenerMatchConditions builds conditions based on listener match validation.
func (r *GRPCRouteReconciler) buildGRPCListenerMatchConditions(
	grpcRoute *avapigwv1alpha1.GRPCRoute,
	gateway *avapigwv1alpha1.Gateway,
	parentRef avapigwv1alpha1.ParentRef,
) []avapigwv1alpha1.Condition {
	accepted, message := r.validateListenerMatch(grpcRoute, gateway, parentRef)
	if accepted {
		return []avapigwv1alpha1.Condition{
			{
				Type:               avapigwv1alpha1.ConditionTypeAccepted,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             string(avapigwv1alpha1.ReasonAccepted),
				Message:            "Route accepted by Gateway",
			},
			{
				Type:               avapigwv1alpha1.ConditionTypeResolvedRefs,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             string(avapigwv1alpha1.ReasonResolvedRefs),
				Message:            "All references resolved",
			},
		}
	}
	return []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionTypeAccepted,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             string(avapigwv1alpha1.ReasonNotAllowedByListeners),
			Message:            message,
		},
	}
}

// validateListenerMatch validates that the route matches a listener on the gateway
func (r *GRPCRouteReconciler) validateListenerMatch(
	grpcRoute *avapigwv1alpha1.GRPCRoute,
	gateway *avapigwv1alpha1.Gateway,
	parentRef avapigwv1alpha1.ParentRef,
) (matches bool, reason string) {
	// If a specific section (listener) is specified, validate it
	if parentRef.SectionName != nil {
		return r.validateSpecificListener(grpcRoute, gateway, *parentRef.SectionName)
	}

	// No specific listener, check if any GRPC/GRPCS listener matches
	return r.findMatchingGRPCListener(grpcRoute, gateway)
}

// validateSpecificListener validates a specific named listener for GRPC protocol compatibility.
func (r *GRPCRouteReconciler) validateSpecificListener(
	grpcRoute *avapigwv1alpha1.GRPCRoute,
	gateway *avapigwv1alpha1.Gateway,
	listenerName string,
) (matches bool, reason string) {
	for _, listener := range gateway.Spec.Listeners {
		if listener.Name != listenerName {
			continue
		}
		// Check protocol compatibility
		if !r.isGRPCProtocol(listener.Protocol) {
			return false, fmt.Sprintf("Listener %s does not support gRPC protocol", listenerName)
		}
		// Check hostname match
		if !r.hostnameMatches(grpcRoute.Spec.Hostnames, listener.Hostname) {
			return false, fmt.Sprintf("No matching hostname for listener %s", listenerName)
		}
		return true, ""
	}
	return false, fmt.Sprintf("Listener %s not found on Gateway", listenerName)
}

// findMatchingGRPCListener finds any GRPC/GRPCS listener that matches the route.
func (r *GRPCRouteReconciler) findMatchingGRPCListener(
	grpcRoute *avapigwv1alpha1.GRPCRoute,
	gateway *avapigwv1alpha1.Gateway,
) (matches bool, reason string) {
	for _, listener := range gateway.Spec.Listeners {
		if r.isGRPCProtocol(listener.Protocol) && r.hostnameMatches(grpcRoute.Spec.Hostnames, listener.Hostname) {
			return true, ""
		}
	}
	return false, "No matching GRPC/GRPCS listener found on Gateway"
}

// isGRPCProtocol checks if the protocol is GRPC or GRPCS.
func (r *GRPCRouteReconciler) isGRPCProtocol(protocol avapigwv1alpha1.ProtocolType) bool {
	return protocol == avapigwv1alpha1.ProtocolGRPC || protocol == avapigwv1alpha1.ProtocolGRPCS
}

// hostnameMatches checks if route hostnames match the listener hostname.
// This method delegates to the shared route.HostnameMatches function.
func (r *GRPCRouteReconciler) hostnameMatches(
	routeHostnames []avapigwv1alpha1.Hostname,
	listenerHostname *avapigwv1alpha1.Hostname,
) bool {
	return route.HostnameMatches(routeHostnames, listenerHostname)
}

// validateBackendRefs validates backend references for the GRPCRoute.
// It extracts backend refs from all rules and delegates validation to the shared validator.
func (r *GRPCRouteReconciler) validateBackendRefs(ctx context.Context, grpcRoute *avapigwv1alpha1.GRPCRoute) error {
	backendRefs := r.extractBackendRefs(grpcRoute)
	validator := route.NewBackendRefValidator(r.Client, r.Recorder)
	return validator.ValidateBackendRefs(ctx, grpcRoute, backendRefs)
}

// extractBackendRefs extracts all backend references from a GRPCRoute's rules.
func (r *GRPCRouteReconciler) extractBackendRefs(grpcRoute *avapigwv1alpha1.GRPCRoute) []route.BackendRefInfo {
	var refs []route.BackendRefInfo
	for _, rule := range grpcRoute.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			refs = append(refs, route.BackendRefInfo{
				Name:      backendRef.Name,
				Namespace: backendRef.Namespace,
				Kind:      backendRef.Kind,
				Group:     backendRef.Group,
			})
		}
	}
	return refs
}

// SetupWithManager sets up the controller with the Manager
func (r *GRPCRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.GRPCRoute{}).
		Watches(
			&avapigwv1alpha1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(r.findGRPCRoutesForGateway),
		).
		Watches(
			&avapigwv1alpha1.Backend{},
			handler.EnqueueRequestsFromMapFunc(r.findGRPCRoutesForBackend),
		).
		Complete(r)
}

// findGRPCRoutesForGateway finds GRPCRoutes that reference a Gateway.
// Uses field indexers for efficient filtered lookups.
func (r *GRPCRouteReconciler) findGRPCRoutesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var grpcRoutes avapigwv1alpha1.GRPCRouteList
	if err := r.List(ctx, &grpcRoutes, client.MatchingFields{GRPCRouteGatewayIndexField: gatewayKey}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(grpcRoutes.Items))
	for _, grpcRoute := range grpcRoutes.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: grpcRoute.Namespace,
				Name:      grpcRoute.Name,
			},
		})
	}

	return requests
}

// findGRPCRoutesForBackend finds GRPCRoutes that reference a Backend.
// Uses field indexers for efficient filtered lookups.
func (r *GRPCRouteReconciler) findGRPCRoutesForBackend(ctx context.Context, obj client.Object) []reconcile.Request {
	backend := obj.(*avapigwv1alpha1.Backend)

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var grpcRoutes avapigwv1alpha1.GRPCRouteList
	if err := r.List(ctx, &grpcRoutes, client.MatchingFields{GRPCRouteBackendIndexField: backendKey}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(grpcRoutes.Items))
	for _, grpcRoute := range grpcRoutes.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: grpcRoute.Namespace,
				Name:      grpcRoute.Name,
			},
		})
	}

	return requests
}

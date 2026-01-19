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

// Compile-time check that HTTPRoute implements route.RouteWithParentRefs
var _ route.RouteWithParentRefs = &avapigwv1alpha1.HTTPRoute{}

// Local aliases for constants to maintain backward compatibility.
// These reference the centralized constants from constants.go.
const (
	httpRouteFinalizer = HTTPRouteFinalizerName

	// HTTPRouteControllerName is the name of the HTTPRoute controller.
	// Used in RouteParentStatus to identify which controller accepted the route.
	HTTPRouteControllerName = GatewayControllerName

	httpRouteReconcileTimeout = HTTPRouteReconcileTimeout
)

// HTTPRouteReconciler reconciles a HTTPRoute object
type HTTPRouteReconciler struct {
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
func (r *HTTPRouteReconciler) getRequeueStrategy() *RequeueStrategy {
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
func (r *HTTPRouteReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("httproute")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, httpRouteFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *HTTPRouteReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles HTTPRoute reconciliation
func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, httpRouteReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling HTTPRoute",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the HTTPRoute instance
	httpRoute, result, err := r.fetchHTTPRoute(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if httpRoute == nil {
		return result, nil
	}

	// Handle deletion
	if !httpRoute.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, httpRoute)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Ensure finalizer and reconcile
	return r.ensureFinalizerAndReconcileHTTPRoute(ctx, httpRoute, strategy, resourceKey, &reconcileErr)
}

// fetchHTTPRoute fetches the HTTPRoute instance and handles not-found errors.
func (r *HTTPRouteReconciler) fetchHTTPRoute(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.HTTPRoute, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	httpRoute := &avapigwv1alpha1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, httpRoute); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("HTTPRoute not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getHTTPRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get HTTPRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return httpRoute, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcileHTTPRoute ensures the finalizer is present and performs reconciliation.
func (r *HTTPRouteReconciler) ensureFinalizerAndReconcileHTTPRoute(
	ctx context.Context,
	httpRoute *avapigwv1alpha1.HTTPRoute,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Add finalizer if not present
	if !r.finalizerHandler.HasFinalizer(httpRoute) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, httpRoute)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(httpRoute, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	// Reconcile the HTTPRoute
	if err := r.reconcileHTTPRoute(ctx, httpRoute); err != nil {
		*reconcileErr = ClassifyError("reconcileHTTPRoute", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile HTTPRoute",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
			"userActionRequired", (*reconcileErr).UserActionRequired,
		)
		r.Recorder.Event(httpRoute, corev1.EventTypeWarning, string((*reconcileErr).Type)+"Error", err.Error())
		return r.handleHTTPRouteReconcileError(*reconcileErr, strategy, resourceKey)
	}

	strategy.ResetFailureCount(resourceKey)
	logger.Info("HTTPRoute reconciled successfully", "name", httpRoute.Name, "namespace", httpRoute.Namespace)
	return strategy.ForSuccess(), nil
}

// handleHTTPRouteReconcileError returns the appropriate result based on error type.
func (r *HTTPRouteReconciler) handleHTTPRouteReconcileError(
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

// handleDeletion handles HTTPRoute deletion
func (r *HTTPRouteReconciler) handleDeletion(
	ctx context.Context,
	httpRoute *avapigwv1alpha1.HTTPRoute,
) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(httpRoute).String()

	if r.finalizerHandler.HasFinalizer(httpRoute) {
		// Perform cleanup
		logger.Info("Performing cleanup for HTTPRoute deletion",
			"name", httpRoute.Name,
			"namespace", httpRoute.Namespace,
		)

		// Record event
		r.Recorder.Event(httpRoute, corev1.EventTypeNormal, "Deleting", "HTTPRoute is being deleted")

		// Remove finalizer
		if _, err := r.finalizerHandler.RemoveFinalizer(ctx, httpRoute); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
}

// reconcileHTTPRoute performs the main reconciliation logic
func (r *HTTPRouteReconciler) reconcileHTTPRoute(ctx context.Context, httpRoute *avapigwv1alpha1.HTTPRoute) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(httpRoute).String()

	// Validate parent references (Gateways)
	parentStatuses, err := r.validateParentRefs(ctx, httpRoute)
	if err != nil {
		reconcileErr := ClassifyError("validateParentRefs", resourceKey, err)
		logger.Error(reconcileErr, "Failed to validate parent references",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	// Validate backend references
	if err := r.validateBackendRefs(ctx, httpRoute); err != nil {
		// Log but continue - backend validation errors are not fatal
		reconcileErr := ClassifyError("validateBackendRefs", resourceKey, err)
		logger.Info("Backend validation warning, continuing with reconciliation",
			"error", err.Error(),
			"errorType", reconcileErr.Type,
		)
		// Continue with status update even if backends are invalid
	}

	// Update route status with parent statuses
	httpRoute.Status.Parents = parentStatuses

	// Update status
	if err := r.Status().Update(ctx, httpRoute); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update HTTPRoute status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(httpRoute, corev1.EventTypeNormal, "Reconciled", "HTTPRoute reconciled successfully")
	return nil
}

// validateParentRefs validates parent references and returns parent statuses
func (r *HTTPRouteReconciler) validateParentRefs(
	ctx context.Context,
	httpRoute *avapigwv1alpha1.HTTPRoute,
) ([]avapigwv1alpha1.RouteParentStatus, error) {
	parentStatuses := make([]avapigwv1alpha1.RouteParentStatus, 0, len(httpRoute.Spec.ParentRefs))

	for _, parentRef := range httpRoute.Spec.ParentRefs {
		parentStatus, err := r.validateSingleHTTPParentRef(ctx, httpRoute, parentRef)
		if err != nil {
			return nil, err
		}
		parentStatuses = append(parentStatuses, parentStatus)
	}

	return parentStatuses, nil
}

// validateSingleHTTPParentRef validates a single parent reference and returns its status.
func (r *HTTPRouteReconciler) validateSingleHTTPParentRef(
	ctx context.Context,
	httpRoute *avapigwv1alpha1.HTTPRoute,
	parentRef avapigwv1alpha1.ParentRef,
) (avapigwv1alpha1.RouteParentStatus, error) {
	logger := log.FromContext(ctx)
	parentStatus := avapigwv1alpha1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: HTTPRouteControllerName,
	}

	namespace := httpRoute.Namespace
	if parentRef.Namespace != nil {
		namespace = *parentRef.Namespace
	}

	gateway := &avapigwv1alpha1.Gateway{}
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: parentRef.Name}, gateway)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Parent Gateway not found", "gateway", parentRef.Name, "namespace", namespace)
			parentStatus.Conditions = r.buildHTTPNotFoundConditions(namespace, parentRef.Name)
			return parentStatus, nil
		}
		return parentStatus, fmt.Errorf("failed to get Gateway %s/%s: %w", namespace, parentRef.Name, err)
	}

	parentStatus.Conditions = r.buildHTTPListenerMatchConditions(httpRoute, gateway, parentRef)
	return parentStatus, nil
}

// buildHTTPNotFoundConditions builds conditions for a not-found gateway.
func (r *HTTPRouteReconciler) buildHTTPNotFoundConditions(namespace, name string) []avapigwv1alpha1.Condition {
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

// buildHTTPListenerMatchConditions builds conditions based on listener match validation.
func (r *HTTPRouteReconciler) buildHTTPListenerMatchConditions(
	httpRoute *avapigwv1alpha1.HTTPRoute,
	gateway *avapigwv1alpha1.Gateway,
	parentRef avapigwv1alpha1.ParentRef,
) []avapigwv1alpha1.Condition {
	accepted, message := r.validateListenerMatch(httpRoute, gateway, parentRef)
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
func (r *HTTPRouteReconciler) validateListenerMatch(
	httpRoute *avapigwv1alpha1.HTTPRoute,
	gateway *avapigwv1alpha1.Gateway,
	parentRef avapigwv1alpha1.ParentRef,
) (matches bool, reason string) {
	// If a specific section (listener) is specified, validate it
	if parentRef.SectionName != nil {
		return r.validateSpecificListener(httpRoute, gateway, *parentRef.SectionName)
	}

	// No specific listener, check if any HTTP/HTTPS listener matches
	return r.findMatchingHTTPListener(httpRoute, gateway)
}

// validateSpecificListener validates a specific named listener for HTTP protocol compatibility.
func (r *HTTPRouteReconciler) validateSpecificListener(
	httpRoute *avapigwv1alpha1.HTTPRoute,
	gateway *avapigwv1alpha1.Gateway,
	listenerName string,
) (matches bool, reason string) {
	for _, listener := range gateway.Spec.Listeners {
		if listener.Name != listenerName {
			continue
		}
		// Check protocol compatibility
		if !r.isHTTPProtocol(listener.Protocol) {
			return false, fmt.Sprintf("Listener %s does not support HTTP protocol", listenerName)
		}
		// Check hostname match
		if !r.hostnameMatches(httpRoute.Spec.Hostnames, listener.Hostname) {
			return false, fmt.Sprintf("No matching hostname for listener %s", listenerName)
		}
		return true, ""
	}
	return false, fmt.Sprintf("Listener %s not found on Gateway", listenerName)
}

// findMatchingHTTPListener finds any HTTP/HTTPS listener that matches the route.
func (r *HTTPRouteReconciler) findMatchingHTTPListener(
	httpRoute *avapigwv1alpha1.HTTPRoute,
	gateway *avapigwv1alpha1.Gateway,
) (matches bool, reason string) {
	for _, listener := range gateway.Spec.Listeners {
		if r.isHTTPProtocol(listener.Protocol) && r.hostnameMatches(httpRoute.Spec.Hostnames, listener.Hostname) {
			return true, ""
		}
	}
	return false, "No matching HTTP/HTTPS listener found on Gateway"
}

// isHTTPProtocol checks if the protocol is HTTP or HTTPS.
func (r *HTTPRouteReconciler) isHTTPProtocol(protocol avapigwv1alpha1.ProtocolType) bool {
	return protocol == avapigwv1alpha1.ProtocolHTTP || protocol == avapigwv1alpha1.ProtocolHTTPS
}

// hostnameMatches checks if route hostnames match the listener hostname.
// This method delegates to the shared route.HostnameMatches function.
func (r *HTTPRouteReconciler) hostnameMatches(
	routeHostnames []avapigwv1alpha1.Hostname,
	listenerHostname *avapigwv1alpha1.Hostname,
) bool {
	return route.HostnameMatches(routeHostnames, listenerHostname)
}

// validateBackendRefs validates backend references for the HTTPRoute.
// It extracts backend refs from all rules and delegates validation to the shared validator.
func (r *HTTPRouteReconciler) validateBackendRefs(ctx context.Context, httpRoute *avapigwv1alpha1.HTTPRoute) error {
	backendRefs := route.ExtractBackendRefsFromRoute(httpRoute)
	validator := route.NewBackendRefValidator(r.Client, r.Recorder)
	return validator.ValidateBackendRefs(ctx, httpRoute, backendRefs)
}

// SetupWithManager sets up the controller with the Manager
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.HTTPRoute{}).
		Watches(
			&avapigwv1alpha1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(r.findHTTPRoutesForGateway),
		).
		Watches(
			&avapigwv1alpha1.Backend{},
			handler.EnqueueRequestsFromMapFunc(r.findHTTPRoutesForBackend),
		).
		Complete(r)
}

// findHTTPRoutesForGateway finds HTTPRoutes that reference a Gateway
// Uses field indexers for efficient filtered lookups
func (r *HTTPRouteReconciler) findHTTPRoutesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var httpRoutes avapigwv1alpha1.HTTPRouteList
	if err := r.List(ctx, &httpRoutes, client.MatchingFields{HTTPRouteGatewayIndexField: gatewayKey}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(httpRoutes.Items))
	for _, route := range httpRoutes.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: route.Namespace,
				Name:      route.Name,
			},
		})
	}

	return requests
}

// findHTTPRoutesForBackend finds HTTPRoutes that reference a Backend
// Uses field indexers for efficient filtered lookups
func (r *HTTPRouteReconciler) findHTTPRoutesForBackend(ctx context.Context, obj client.Object) []reconcile.Request {
	backend := obj.(*avapigwv1alpha1.Backend)

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var httpRoutes avapigwv1alpha1.HTTPRouteList
	if err := r.List(ctx, &httpRoutes, client.MatchingFields{HTTPRouteBackendIndexField: backendKey}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(httpRoutes.Items))
	for _, route := range httpRoutes.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: route.Namespace,
				Name:      route.Name,
			},
		})
	}

	return requests
}

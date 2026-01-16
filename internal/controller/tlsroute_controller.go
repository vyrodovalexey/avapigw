// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
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

// Compile-time check that TLSRoute implements route.RouteWithParentRefs
var _ route.RouteWithParentRefs = &avapigwv1alpha1.TLSRoute{}

// Local aliases for constants to maintain backward compatibility.
// These reference the centralized constants from constants.go.
const (
	tlsRouteFinalizer        = TLSRouteFinalizerName
	tlsRouteReconcileTimeout = TLSRouteReconcileTimeout
)

// TLSRouteReconciler reconciles a TLSRoute object
type TLSRouteReconciler struct {
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
func (r *TLSRouteReconciler) getRequeueStrategy() *RequeueStrategy {
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
func (r *TLSRouteReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("tlsroute")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, tlsRouteFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *TLSRouteReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles TLSRoute reconciliation
func (r *TLSRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, tlsRouteReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling TLSRoute",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	tlsRoute, result, err := r.fetchTLSRoute(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if tlsRoute == nil {
		return result, nil
	}

	if !tlsRoute.DeletionTimestamp.IsZero() {
		result, delErr := r.handleDeletion(ctx, tlsRoute)
		if delErr == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, delErr
	}

	return r.ensureFinalizerAndReconcileTLSRoute(ctx, tlsRoute, strategy, resourceKey, &reconcileErr, logger)
}

// fetchTLSRoute fetches the TLSRoute instance and handles not-found errors.
func (r *TLSRouteReconciler) fetchTLSRoute(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.TLSRoute, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	tlsRoute := &avapigwv1alpha1.TLSRoute{}
	if err := r.Get(ctx, req.NamespacedName, tlsRoute); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("TLSRoute not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getTLSRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get TLSRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return tlsRoute, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcileTLSRoute ensures the finalizer is present and performs reconciliation.
func (r *TLSRouteReconciler) ensureFinalizerAndReconcileTLSRoute(
	ctx context.Context,
	tlsRoute *avapigwv1alpha1.TLSRoute,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
	logger logr.Logger,
) (ctrl.Result, error) {
	if !r.finalizerHandler.HasFinalizer(tlsRoute) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, tlsRoute)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(tlsRoute, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	if err := r.reconcileTLSRoute(ctx, tlsRoute); err != nil {
		*reconcileErr = ClassifyError("reconcileTLSRoute", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile TLSRoute",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
			"userActionRequired", (*reconcileErr).UserActionRequired,
		)
		r.Recorder.Event(tlsRoute, corev1.EventTypeWarning, string((*reconcileErr).Type)+"Error", err.Error())
		return r.handleTLSRouteReconcileError(*reconcileErr, strategy, resourceKey)
	}

	strategy.ResetFailureCount(resourceKey)
	logger.Info("TLSRoute reconciled successfully", "name", tlsRoute.Name, "namespace", tlsRoute.Namespace)
	return strategy.ForSuccess(), nil
}

// handleTLSRouteReconcileError returns the appropriate result based on error type.
func (r *TLSRouteReconciler) handleTLSRouteReconcileError(
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

// handleDeletion handles TLSRoute deletion
func (r *TLSRouteReconciler) handleDeletion(
	ctx context.Context,
	tlsRoute *avapigwv1alpha1.TLSRoute,
) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(tlsRoute).String()

	if r.finalizerHandler.HasFinalizer(tlsRoute) {
		// Perform cleanup
		logger.Info("Performing cleanup for TLSRoute deletion",
			"name", tlsRoute.Name,
			"namespace", tlsRoute.Namespace,
		)

		// Record event
		r.Recorder.Event(tlsRoute, corev1.EventTypeNormal, "Deleting", "TLSRoute is being deleted")

		// Remove finalizer
		if _, err := r.finalizerHandler.RemoveFinalizer(ctx, tlsRoute); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
}

// reconcileTLSRoute performs the main reconciliation logic
func (r *TLSRouteReconciler) reconcileTLSRoute(ctx context.Context, tlsRoute *avapigwv1alpha1.TLSRoute) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(tlsRoute).String()

	// Validate parent references (Gateways)
	parentStatuses, err := r.validateParentRefs(ctx, tlsRoute)
	if err != nil {
		reconcileErr := ClassifyError("validateParentRefs", resourceKey, err)
		logger.Error(reconcileErr, "Failed to validate parent references",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	// Validate backend references
	if err := r.validateBackendRefs(ctx, tlsRoute); err != nil {
		// Log but continue - backend validation errors are not fatal
		reconcileErr := ClassifyError("validateBackendRefs", resourceKey, err)
		logger.Info("Backend validation warning, continuing with reconciliation",
			"error", err.Error(),
			"errorType", reconcileErr.Type,
		)
		// Continue with status update even if backends are invalid
	}

	// Update route status with parent statuses
	tlsRoute.Status.Parents = parentStatuses

	// Update status
	if err := r.Status().Update(ctx, tlsRoute); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update TLSRoute status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(tlsRoute, corev1.EventTypeNormal, EventReasonReconciled, "TLSRoute reconciled successfully")
	return nil
}

// validateParentRefs validates parent references and returns parent statuses
func (r *TLSRouteReconciler) validateParentRefs(
	ctx context.Context,
	tlsRoute *avapigwv1alpha1.TLSRoute,
) ([]avapigwv1alpha1.RouteParentStatus, error) {
	parentStatuses := make([]avapigwv1alpha1.RouteParentStatus, 0, len(tlsRoute.Spec.ParentRefs))

	for _, parentRef := range tlsRoute.Spec.ParentRefs {
		parentStatus, err := r.validateSingleParentRef(ctx, tlsRoute, parentRef)
		if err != nil {
			return nil, err
		}
		parentStatuses = append(parentStatuses, parentStatus)
	}

	return parentStatuses, nil
}

// validateSingleParentRef validates a single parent reference and returns its status.
func (r *TLSRouteReconciler) validateSingleParentRef(
	ctx context.Context,
	tlsRoute *avapigwv1alpha1.TLSRoute,
	parentRef avapigwv1alpha1.ParentRef,
) (avapigwv1alpha1.RouteParentStatus, error) {
	logger := log.FromContext(ctx)
	parentStatus := avapigwv1alpha1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: GatewayControllerName,
	}

	namespace := tlsRoute.Namespace
	if parentRef.Namespace != nil {
		namespace = *parentRef.Namespace
	}

	gateway := &avapigwv1alpha1.Gateway{}
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: parentRef.Name}, gateway)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Parent Gateway not found", "gateway", parentRef.Name, "namespace", namespace)
			parentStatus.Conditions = r.buildRejectedCondition(avapigwv1alpha1.ReasonNoMatchingParent,
				fmt.Sprintf("Gateway %s/%s not found", namespace, parentRef.Name))
			return parentStatus, nil
		}
		return parentStatus, fmt.Errorf("failed to get Gateway %s/%s: %w", namespace, parentRef.Name, err)
	}

	accepted, message := r.validateListenerMatch(tlsRoute, gateway, parentRef)
	if accepted {
		parentStatus.Conditions = r.buildAcceptedConditions()
	} else {
		parentStatus.Conditions = r.buildRejectedCondition(avapigwv1alpha1.ReasonNotAllowedByListeners, message)
	}

	return parentStatus, nil
}

// buildAcceptedConditions builds the conditions for an accepted route.
func (r *TLSRouteReconciler) buildAcceptedConditions() []avapigwv1alpha1.Condition {
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

// buildRejectedCondition builds a condition for a rejected route.
func (r *TLSRouteReconciler) buildRejectedCondition(
	reason avapigwv1alpha1.ConditionReason,
	message string,
) []avapigwv1alpha1.Condition {
	return []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionTypeAccepted,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             string(reason),
			Message:            message,
		},
	}
}

// validateListenerMatch validates that the route matches a listener on the gateway.
// Returns whether the match is valid and a reason message if not.
func (r *TLSRouteReconciler) validateListenerMatch(
	tlsRoute *avapigwv1alpha1.TLSRoute,
	gateway *avapigwv1alpha1.Gateway,
	parentRef avapigwv1alpha1.ParentRef,
) (valid bool, reason string) {
	// If a specific section (listener) is specified, validate it
	if parentRef.SectionName != nil {
		return r.validateSpecificListener(tlsRoute, gateway, *parentRef.SectionName)
	}

	// No specific listener, check if any TLS listener matches
	return r.validateAnyTLSListener(tlsRoute, gateway)
}

// validateSpecificListener validates that a specific listener matches the route
func (r *TLSRouteReconciler) validateSpecificListener(
	tlsRoute *avapigwv1alpha1.TLSRoute,
	gateway *avapigwv1alpha1.Gateway,
	listenerName string,
) (valid bool, reason string) {
	for _, listener := range gateway.Spec.Listeners {
		if listener.Name != listenerName {
			continue
		}
		// Check protocol compatibility
		if listener.Protocol != avapigwv1alpha1.ProtocolTLS {
			return false, fmt.Sprintf("Listener %s does not support TLS protocol", listenerName)
		}
		// Check hostname match
		if !r.hostnameMatches(tlsRoute.Spec.Hostnames, listener.Hostname) {
			return false, fmt.Sprintf("No matching hostname for listener %s", listenerName)
		}
		return true, ""
	}
	return false, fmt.Sprintf("Listener %s not found on Gateway", listenerName)
}

// validateAnyTLSListener checks if any TLS listener on the gateway matches the route
func (r *TLSRouteReconciler) validateAnyTLSListener(
	tlsRoute *avapigwv1alpha1.TLSRoute,
	gateway *avapigwv1alpha1.Gateway,
) (valid bool, reason string) {
	for _, listener := range gateway.Spec.Listeners {
		if listener.Protocol != avapigwv1alpha1.ProtocolTLS {
			continue
		}
		if r.hostnameMatches(tlsRoute.Spec.Hostnames, listener.Hostname) {
			return true, ""
		}
	}
	return false, "No matching TLS listener found on Gateway"
}

// hostnameMatches checks if route hostnames match the listener hostname.
// This method delegates to the shared route.HostnameMatches function.
func (r *TLSRouteReconciler) hostnameMatches(
	routeHostnames []avapigwv1alpha1.Hostname,
	listenerHostname *avapigwv1alpha1.Hostname,
) bool {
	return route.HostnameMatches(routeHostnames, listenerHostname)
}

// validateBackendRefs validates backend references for the TLSRoute.
// It extracts backend refs from all rules and delegates validation to the shared validator.
func (r *TLSRouteReconciler) validateBackendRefs(ctx context.Context, tlsRoute *avapigwv1alpha1.TLSRoute) error {
	backendRefs := r.extractBackendRefs(tlsRoute)
	validator := route.NewBackendRefValidator(r.Client, r.Recorder)
	return validator.ValidateBackendRefs(ctx, tlsRoute, backendRefs)
}

// extractBackendRefs extracts all backend references from a TLSRoute's rules.
func (r *TLSRouteReconciler) extractBackendRefs(tlsRoute *avapigwv1alpha1.TLSRoute) []route.BackendRefInfo {
	var refs []route.BackendRefInfo
	for _, rule := range tlsRoute.Spec.Rules {
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
func (r *TLSRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.TLSRoute{}).
		Watches(
			&avapigwv1alpha1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(r.findTLSRoutesForGateway),
		).
		Watches(
			&avapigwv1alpha1.Backend{},
			handler.EnqueueRequestsFromMapFunc(r.findTLSRoutesForBackend),
		).
		Complete(r)
}

// findTLSRoutesForGateway finds TLSRoutes that reference a Gateway.
// Uses field indexers for efficient filtered lookups.
func (r *TLSRouteReconciler) findTLSRoutesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var tlsRoutes avapigwv1alpha1.TLSRouteList
	if err := r.List(ctx, &tlsRoutes, client.MatchingFields{TLSRouteGatewayIndexField: gatewayKey}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(tlsRoutes.Items))
	for _, tlsRoute := range tlsRoutes.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: tlsRoute.Namespace,
				Name:      tlsRoute.Name,
			},
		})
	}

	return requests
}

// findTLSRoutesForBackend finds TLSRoutes that reference a Backend.
// Uses field indexers for efficient filtered lookups.
func (r *TLSRouteReconciler) findTLSRoutesForBackend(ctx context.Context, obj client.Object) []reconcile.Request {
	backend := obj.(*avapigwv1alpha1.Backend)

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var tlsRoutes avapigwv1alpha1.TLSRouteList
	if err := r.List(ctx, &tlsRoutes, client.MatchingFields{TLSRouteBackendIndexField: backendKey}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(tlsRoutes.Items))
	for _, tlsRoute := range tlsRoutes.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: tlsRoute.Namespace,
				Name:      tlsRoute.Name,
			},
		})
	}

	return requests
}

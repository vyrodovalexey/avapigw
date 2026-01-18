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

// Compile-time check that TCPRoute implements route.RouteWithParentRefs
var _ route.RouteWithParentRefs = &avapigwv1alpha1.TCPRoute{}

// Local aliases for constants to maintain backward compatibility.
// These reference the centralized constants from constants.go.
const (
	tcpRouteFinalizer        = TCPRouteFinalizerName
	tcpRouteReconcileTimeout = TCPRouteReconcileTimeout
)

// TCPRouteReconciler reconciles a TCPRoute object
type TCPRouteReconciler struct {
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
func (r *TCPRouteReconciler) getRequeueStrategy() *RequeueStrategy {
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
func (r *TCPRouteReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("tcproute")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, tcpRouteFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *TCPRouteReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tcproutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tcproutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tcproutes/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles TCPRoute reconciliation
func (r *TCPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, tcpRouteReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling TCPRoute",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	tcpRoute, result, err := r.fetchTCPRoute(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if tcpRoute == nil {
		return result, nil
	}

	if !tcpRoute.DeletionTimestamp.IsZero() {
		result, delErr := r.handleDeletion(ctx, tcpRoute)
		if delErr == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, delErr
	}

	return r.ensureFinalizerAndReconcileTCPRoute(ctx, tcpRoute, strategy, resourceKey, &reconcileErr, logger)
}

// fetchTCPRoute fetches the TCPRoute instance and handles not-found errors.
func (r *TCPRouteReconciler) fetchTCPRoute(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.TCPRoute, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	tcpRoute := &avapigwv1alpha1.TCPRoute{}
	if err := r.Get(ctx, req.NamespacedName, tcpRoute); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("TCPRoute not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getTCPRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get TCPRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return tcpRoute, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcileTCPRoute ensures the finalizer is present and performs reconciliation.
func (r *TCPRouteReconciler) ensureFinalizerAndReconcileTCPRoute(
	ctx context.Context,
	tcpRoute *avapigwv1alpha1.TCPRoute,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
	logger logr.Logger,
) (ctrl.Result, error) {
	if !r.finalizerHandler.HasFinalizer(tcpRoute) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, tcpRoute)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(tcpRoute, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	if err := r.reconcileTCPRoute(ctx, tcpRoute); err != nil {
		*reconcileErr = ClassifyError("reconcileTCPRoute", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile TCPRoute",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
			"userActionRequired", (*reconcileErr).UserActionRequired,
		)
		r.Recorder.Event(tcpRoute, corev1.EventTypeWarning, string((*reconcileErr).Type)+"Error", err.Error())
		return r.handleTCPRouteReconcileError(*reconcileErr, strategy, resourceKey)
	}

	strategy.ResetFailureCount(resourceKey)
	logger.Info("TCPRoute reconciled successfully", "name", tcpRoute.Name, "namespace", tcpRoute.Namespace)
	return strategy.ForSuccess(), nil
}

// handleTCPRouteReconcileError returns the appropriate result based on error type.
func (r *TCPRouteReconciler) handleTCPRouteReconcileError(
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

// handleDeletion handles TCPRoute deletion
func (r *TCPRouteReconciler) handleDeletion(
	ctx context.Context,
	tcpRoute *avapigwv1alpha1.TCPRoute,
) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(tcpRoute).String()

	if r.finalizerHandler.HasFinalizer(tcpRoute) {
		// Perform cleanup
		logger.Info("Performing cleanup for TCPRoute deletion",
			"name", tcpRoute.Name,
			"namespace", tcpRoute.Namespace,
		)

		// Record event
		r.Recorder.Event(tcpRoute, corev1.EventTypeNormal, "Deleting", "TCPRoute is being deleted")

		// Remove finalizer
		if _, err := r.finalizerHandler.RemoveFinalizer(ctx, tcpRoute); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
}

// reconcileTCPRoute performs the main reconciliation logic
func (r *TCPRouteReconciler) reconcileTCPRoute(ctx context.Context, tcpRoute *avapigwv1alpha1.TCPRoute) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(tcpRoute).String()

	// Validate parent references (Gateways)
	parentStatuses, err := r.validateParentRefs(ctx, tcpRoute)
	if err != nil {
		reconcileErr := ClassifyError("validateParentRefs", resourceKey, err)
		logger.Error(reconcileErr, "Failed to validate parent references",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	// Validate backend references
	if err := r.validateBackendRefs(ctx, tcpRoute); err != nil {
		// Log but continue - backend validation errors are not fatal
		reconcileErr := ClassifyError("validateBackendRefs", resourceKey, err)
		logger.Info("Backend validation warning, continuing with reconciliation",
			"error", err.Error(),
			"errorType", reconcileErr.Type,
		)
		// Continue with status update even if backends are invalid
	}

	// Update route status with parent statuses
	tcpRoute.Status.Parents = parentStatuses

	// Update status
	if err := r.Status().Update(ctx, tcpRoute); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update TCPRoute status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(tcpRoute, corev1.EventTypeNormal, EventReasonReconciled, "TCPRoute reconciled successfully")
	return nil
}

// buildAcceptedConditions builds the conditions for an accepted route.
func (r *TCPRouteReconciler) buildAcceptedConditions() []avapigwv1alpha1.Condition {
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
func (r *TCPRouteReconciler) buildRejectedCondition(
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

// validateSingleParentRef validates a single parent reference and returns its status.
func (r *TCPRouteReconciler) validateSingleParentRef(
	ctx context.Context,
	tcpRoute *avapigwv1alpha1.TCPRoute,
	parentRef avapigwv1alpha1.ParentRef,
) (avapigwv1alpha1.RouteParentStatus, error) {
	logger := log.FromContext(ctx)
	parentStatus := avapigwv1alpha1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: GatewayControllerName,
	}

	namespace := tcpRoute.Namespace
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

	accepted, message := r.validateListenerMatch(gateway, parentRef)
	if accepted {
		parentStatus.Conditions = r.buildAcceptedConditions()
	} else {
		parentStatus.Conditions = r.buildRejectedCondition(avapigwv1alpha1.ReasonNotAllowedByListeners, message)
	}

	return parentStatus, nil
}

// validateParentRefs validates parent references and returns parent statuses
func (r *TCPRouteReconciler) validateParentRefs(
	ctx context.Context,
	tcpRoute *avapigwv1alpha1.TCPRoute,
) ([]avapigwv1alpha1.RouteParentStatus, error) {
	parentStatuses := make([]avapigwv1alpha1.RouteParentStatus, 0, len(tcpRoute.Spec.ParentRefs))

	for _, parentRef := range tcpRoute.Spec.ParentRefs {
		parentStatus, err := r.validateSingleParentRef(ctx, tcpRoute, parentRef)
		if err != nil {
			return nil, err
		}
		parentStatuses = append(parentStatuses, parentStatus)
	}

	return parentStatuses, nil
}

// validateListenerMatch validates that the route matches a listener on the gateway
func (r *TCPRouteReconciler) validateListenerMatch(
	gateway *avapigwv1alpha1.Gateway,
	parentRef avapigwv1alpha1.ParentRef,
) (matches bool, reason string) {
	// If a specific section (listener) is specified, validate it
	if parentRef.SectionName != nil {
		return r.validateSpecificTCPListener(gateway, *parentRef.SectionName, parentRef.Port)
	}

	// No specific listener, check if any TCP listener matches
	return r.findMatchingTCPListener(gateway, parentRef.Port)
}

// validateSpecificTCPListener validates a specific named listener for TCP protocol compatibility.
func (r *TCPRouteReconciler) validateSpecificTCPListener(
	gateway *avapigwv1alpha1.Gateway,
	listenerName string,
	port *int32,
) (matches bool, reason string) {
	for _, listener := range gateway.Spec.Listeners {
		if listener.Name != listenerName {
			continue
		}
		// Check protocol compatibility
		if listener.Protocol != avapigwv1alpha1.ProtocolTCP {
			return false, fmt.Sprintf("Listener %s does not support TCP protocol", listenerName)
		}
		// Check port match if specified
		if port != nil && int32(listener.Port) != *port {
			return false, fmt.Sprintf("Port %d does not match listener %s port %d", *port, listenerName, listener.Port)
		}
		return true, ""
	}
	return false, fmt.Sprintf("Listener %s not found on Gateway", listenerName)
}

// findMatchingTCPListener finds any TCP listener that matches the route.
func (r *TCPRouteReconciler) findMatchingTCPListener(
	gateway *avapigwv1alpha1.Gateway,
	port *int32,
) (matches bool, reason string) {
	for _, listener := range gateway.Spec.Listeners {
		if listener.Protocol != avapigwv1alpha1.ProtocolTCP {
			continue
		}
		// Check port match if specified
		if port != nil && int32(listener.Port) != *port {
			continue
		}
		return true, ""
	}
	return false, "No matching TCP listener found on Gateway"
}

// validateBackendRefs validates backend references for the TCPRoute.
// It extracts backend refs from all rules and delegates validation to the shared validator.
func (r *TCPRouteReconciler) validateBackendRefs(ctx context.Context, tcpRoute *avapigwv1alpha1.TCPRoute) error {
	backendRefs := route.ExtractBackendRefsFromRoute(tcpRoute)
	validator := route.NewBackendRefValidator(r.Client, r.Recorder)
	return validator.ValidateBackendRefs(ctx, tcpRoute, backendRefs)
}

// SetupWithManager sets up the controller with the Manager
func (r *TCPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.TCPRoute{}).
		Watches(
			&avapigwv1alpha1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(r.findTCPRoutesForGateway),
		).
		Watches(
			&avapigwv1alpha1.Backend{},
			handler.EnqueueRequestsFromMapFunc(r.findTCPRoutesForBackend),
		).
		Complete(r)
}

// findTCPRoutesForGateway finds TCPRoutes that reference a Gateway.
// Uses field indexers for efficient filtered lookups.
func (r *TCPRouteReconciler) findTCPRoutesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var tcpRoutes avapigwv1alpha1.TCPRouteList
	if err := r.List(ctx, &tcpRoutes, client.MatchingFields{TCPRouteGatewayIndexField: gatewayKey}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(tcpRoutes.Items))
	for _, tcpRoute := range tcpRoutes.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: tcpRoute.Namespace,
				Name:      tcpRoute.Name,
			},
		})
	}

	return requests
}

// findTCPRoutesForBackend finds TCPRoutes that reference a Backend.
// Uses field indexers for efficient filtered lookups.
func (r *TCPRouteReconciler) findTCPRoutesForBackend(ctx context.Context, obj client.Object) []reconcile.Request {
	backend := obj.(*avapigwv1alpha1.Backend)

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var tcpRoutes avapigwv1alpha1.TCPRouteList
	if err := r.List(ctx, &tcpRoutes, client.MatchingFields{TCPRouteBackendIndexField: backendKey}); err != nil {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(tcpRoutes.Items))
	for _, tcpRoute := range tcpRoutes.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: tcpRoute.Namespace,
				Name:      tcpRoute.Name,
			},
		})
	}

	return requests
}

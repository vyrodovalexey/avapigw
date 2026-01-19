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
)

// Local aliases for constants to maintain backward compatibility.
// These reference the centralized constants from constants.go.
const (
	gatewayFinalizer = GatewayFinalizerName
	reconcileTimeout = GatewayReconcileTimeout
	listPageSize     = DefaultListPageSize
)

// GatewayReconciler reconciles a Gateway object
type GatewayReconciler struct {
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
func (r *GatewayReconciler) getRequeueStrategy() *RequeueStrategy {
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
func (r *GatewayReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("gateway")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, gatewayFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *GatewayReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tcproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles Gateway reconciliation
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling Gateway",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the Gateway instance
	gateway, result, err := r.fetchGateway(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if gateway == nil {
		return result, nil
	}

	// Handle deletion
	if !gateway.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, gateway)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Ensure finalizer and reconcile
	return r.ensureFinalizerAndReconcileGateway(ctx, gateway, strategy, resourceKey, &reconcileErr)
}

// fetchGateway fetches the Gateway instance and handles not-found errors.
func (r *GatewayReconciler) fetchGateway(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.Gateway, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	gateway := &avapigwv1alpha1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, gateway); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Gateway not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getGateway", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get Gateway",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return gateway, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcileGateway ensures the finalizer is present and performs reconciliation.
func (r *GatewayReconciler) ensureFinalizerAndReconcileGateway(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Add finalizer if not present
	if !r.finalizerHandler.HasFinalizer(gateway) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, gateway)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(gateway, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	// Reconcile the Gateway
	if err := r.reconcileGateway(ctx, gateway); err != nil {
		*reconcileErr = ClassifyError("reconcileGateway", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile Gateway",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
			"userActionRequired", (*reconcileErr).UserActionRequired,
		)
		r.Recorder.Event(gateway, corev1.EventTypeWarning, string((*reconcileErr).Type)+"Error", err.Error())
		return r.handleGatewayReconcileError(*reconcileErr, strategy, resourceKey)
	}

	strategy.ResetFailureCount(resourceKey)
	logger.Info("Gateway reconciled successfully", "name", gateway.Name, "namespace", gateway.Namespace)
	return strategy.ForSuccess(), nil
}

// handleGatewayReconcileError returns the appropriate result based on error type.
func (r *GatewayReconciler) handleGatewayReconcileError(
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

// handleDeletion handles Gateway deletion
func (r *GatewayReconciler) handleDeletion(ctx context.Context, gateway *avapigwv1alpha1.Gateway) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(gateway).String()

	if r.finalizerHandler.HasFinalizer(gateway) {
		// Perform cleanup
		logger.Info("Performing cleanup for Gateway deletion",
			"name", gateway.Name,
			"namespace", gateway.Namespace,
		)

		// Record event
		r.Recorder.Event(gateway, corev1.EventTypeNormal, "Deleting", "Gateway is being deleted")

		// Remove finalizer
		if _, err := r.finalizerHandler.RemoveFinalizer(ctx, gateway); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
}

// reconcileGateway performs the main reconciliation logic
func (r *GatewayReconciler) reconcileGateway(ctx context.Context, gateway *avapigwv1alpha1.Gateway) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(gateway).String()

	r.initGatewayStatus(gateway)

	// Validate and resolve TLS config references
	if err := r.validateTLSConfigs(ctx, gateway); err != nil {
		return r.handleTLSValidationError(ctx, gateway, resourceKey, err, logger)
	}

	// Update listener statuses
	if err := r.updateListenerStatuses(ctx, gateway); err != nil {
		reconcileErr := NewInternalError("updateListenerStatuses", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update listener statuses", "errorType", reconcileErr.Type)
		return reconcileErr
	}

	// Count and update attached routes
	if err := r.updateAttachedRouteCounts(ctx, gateway, resourceKey, logger); err != nil {
		return err
	}

	// Finalize gateway status
	return r.finalizeGatewayStatus(ctx, gateway, resourceKey, logger)
}

// initGatewayStatus initializes the gateway status for reconciliation.
func (r *GatewayReconciler) initGatewayStatus(gateway *avapigwv1alpha1.Gateway) {
	gateway.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	gateway.Status.ObservedGeneration = gateway.Generation
	gateway.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}
}

// handleTLSValidationError handles TLS validation errors.
func (r *GatewayReconciler) handleTLSValidationError(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
	resourceKey string,
	err error,
	logger logr.Logger,
) error {
	var reconcileErr *ReconcileError
	if errors.IsNotFound(err) {
		reconcileErr = NewDependencyError("validateTLSConfigs", resourceKey, err)
	} else {
		reconcileErr = NewValidationError("validateTLSConfigs", resourceKey, err)
	}

	logger.Error(reconcileErr, "TLS configuration validation failed", "errorType", reconcileErr.Type)

	r.setCondition(gateway, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse,
		string(avapigwv1alpha1.ReasonInvalidRef), err.Error())
	gateway.Status.Phase = avapigwv1alpha1.PhaseStatusError

	if statusErr := r.updateStatus(ctx, gateway); statusErr != nil {
		logger.Error(statusErr, "Failed to update status after TLS validation error")
	}
	return reconcileErr
}

// updateAttachedRouteCounts counts and updates attached routes for each listener.
func (r *GatewayReconciler) updateAttachedRouteCounts(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
	resourceKey string,
	logger logr.Logger,
) error {
	attachedRoutes, err := r.countAttachedRoutes(ctx, gateway)
	if err != nil {
		reconcileErr := ClassifyError("countAttachedRoutes", resourceKey, err)
		logger.Error(reconcileErr, "Failed to count attached routes", "errorType", reconcileErr.Type)
		return reconcileErr
	}

	for i := range gateway.Status.Listeners {
		listenerName := gateway.Status.Listeners[i].Name
		if count, ok := attachedRoutes[listenerName]; ok {
			gateway.Status.Listeners[i].AttachedRoutes = count
		}
	}
	return nil
}

// finalizeGatewayStatus sets final conditions and updates the gateway status.
func (r *GatewayReconciler) finalizeGatewayStatus(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
	resourceKey string,
	logger logr.Logger,
) error {
	r.updateAddresses(gateway)

	r.setCondition(gateway, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonAccepted), "Gateway configuration accepted")
	r.setCondition(gateway, avapigwv1alpha1.ConditionTypeProgrammed, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonProgrammed), "Gateway listeners configured")

	gateway.Status.Phase = avapigwv1alpha1.PhaseStatusReady
	gateway.Status.ListenersCount = safeIntToInt32(len(gateway.Spec.Listeners))

	if err := r.updateStatus(ctx, gateway); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update Gateway status", "errorType", reconcileErr.Type)
		return reconcileErr
	}

	r.Recorder.Event(gateway, corev1.EventTypeNormal, "Reconciled", "Gateway reconciled successfully")
	return nil
}

// validateTLSConfigs validates TLS configuration references
func (r *GatewayReconciler) validateTLSConfigs(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
) error {
	for _, listener := range gateway.Spec.Listeners {
		if listener.TLS == nil {
			continue
		}

		for _, certRef := range listener.TLS.CertificateRefs {
			namespace := gateway.Namespace
			if certRef.Namespace != nil {
				namespace = *certRef.Namespace
			}

			// Try to find as TLSConfig
			tlsConfig := &avapigwv1alpha1.TLSConfig{}
			err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: certRef.Name}, tlsConfig)
			if err != nil {
				if !errors.IsNotFound(err) {
					return fmt.Errorf("failed to get TLSConfig %s/%s: %w", namespace, certRef.Name, err)
				}

				// Try as Secret
				secret := &corev1.Secret{}
				secretKey := client.ObjectKey{Namespace: namespace, Name: certRef.Name}
				if err := r.Get(ctx, secretKey, secret); err != nil {
					return fmt.Errorf(
						"certificate reference %s/%s not found as TLSConfig or Secret",
						namespace, certRef.Name,
					)
				}
			}
		}
	}

	return nil
}

// updateListenerStatuses updates the status of each listener.
// Note: Currently always returns nil, but error return is kept for API stability
// and potential future validation logic.
//
//nolint:unparam // error return kept for API stability and future validation logic
func (r *GatewayReconciler) updateListenerStatuses(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
) error {
	logger := log.FromContext(ctx)
	logger.V(1).Info("Updating listener statuses", "listenerCount", len(gateway.Spec.Listeners))

	listenerStatuses := make([]avapigwv1alpha1.ListenerStatus, 0, len(gateway.Spec.Listeners))

	for _, listener := range gateway.Spec.Listeners {
		status := avapigwv1alpha1.ListenerStatus{
			Name:           listener.Name,
			AttachedRoutes: 0,
		}

		// Set supported kinds based on protocol
		group := avapigwv1alpha1.GroupVersion.Group
		switch listener.Protocol {
		case avapigwv1alpha1.ProtocolHTTP, avapigwv1alpha1.ProtocolHTTPS:
			status.SupportedKinds = []avapigwv1alpha1.RouteGroupKind{
				{Group: &group, Kind: "HTTPRoute"},
			}
		case avapigwv1alpha1.ProtocolGRPC, avapigwv1alpha1.ProtocolGRPCS:
			status.SupportedKinds = []avapigwv1alpha1.RouteGroupKind{
				{Group: &group, Kind: "GRPCRoute"},
			}
		case avapigwv1alpha1.ProtocolTCP:
			status.SupportedKinds = []avapigwv1alpha1.RouteGroupKind{
				{Group: &group, Kind: "TCPRoute"},
			}
		case avapigwv1alpha1.ProtocolTLS:
			status.SupportedKinds = []avapigwv1alpha1.RouteGroupKind{
				{Group: &group, Kind: "TLSRoute"},
			}
		}

		// Set listener conditions
		status.Conditions = []avapigwv1alpha1.Condition{
			{
				Type:               avapigwv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             string(avapigwv1alpha1.ReasonReady),
				Message:            "Listener is ready",
			},
		}

		listenerStatuses = append(listenerStatuses, status)
	}

	gateway.Status.Listeners = listenerStatuses
	return nil
}

// countAttachedRoutes counts routes attached to each listener
// Uses field indexers for efficient filtered lookups instead of listing all routes
func (r *GatewayReconciler) countAttachedRoutes(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
) (map[string]int32, error) {
	counts := make(map[string]int32)

	// Initialize counts for all listeners
	for _, listener := range gateway.Spec.Listeners {
		counts[listener.Name] = 0
	}

	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	// Count each route type
	if err := r.countHTTPRoutes(ctx, gateway, gatewayKey, counts); err != nil {
		return nil, err
	}
	if err := r.countGRPCRoutes(ctx, gateway, gatewayKey, counts); err != nil {
		return nil, err
	}
	if err := r.countTCPRoutes(ctx, gateway, gatewayKey, counts); err != nil {
		return nil, err
	}
	if err := r.countTLSRoutes(ctx, gateway, gatewayKey, counts); err != nil {
		return nil, err
	}

	return counts, nil
}

// countHTTPRoutes counts HTTPRoutes attached to the gateway.
func (r *GatewayReconciler) countHTTPRoutes(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
	gatewayKey string,
	counts map[string]int32,
) error {
	var httpRoutes avapigwv1alpha1.HTTPRouteList
	if err := r.List(ctx, &httpRoutes, client.MatchingFields{HTTPRouteGatewayIndexField: gatewayKey}); err != nil {
		return fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}
	for _, route := range httpRoutes.Items {
		r.countRouteParentRefs(gateway, &route, route.Spec.ParentRefs, counts)
	}
	return nil
}

// countGRPCRoutes counts GRPCRoutes attached to the gateway.
func (r *GatewayReconciler) countGRPCRoutes(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
	gatewayKey string,
	counts map[string]int32,
) error {
	var grpcRoutes avapigwv1alpha1.GRPCRouteList
	if err := r.List(ctx, &grpcRoutes, client.MatchingFields{GRPCRouteGatewayIndexField: gatewayKey}); err != nil {
		return fmt.Errorf("failed to list GRPCRoutes: %w", err)
	}
	for _, route := range grpcRoutes.Items {
		r.countRouteParentRefs(gateway, &route, route.Spec.ParentRefs, counts)
	}
	return nil
}

// countTCPRoutes counts TCPRoutes attached to the gateway.
func (r *GatewayReconciler) countTCPRoutes(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
	gatewayKey string,
	counts map[string]int32,
) error {
	var tcpRoutes avapigwv1alpha1.TCPRouteList
	if err := r.List(ctx, &tcpRoutes, client.MatchingFields{TCPRouteGatewayIndexField: gatewayKey}); err != nil {
		return fmt.Errorf("failed to list TCPRoutes: %w", err)
	}
	for _, route := range tcpRoutes.Items {
		r.countRouteParentRefs(gateway, &route, route.Spec.ParentRefs, counts)
	}
	return nil
}

// countTLSRoutes counts TLSRoutes attached to the gateway.
func (r *GatewayReconciler) countTLSRoutes(
	ctx context.Context,
	gateway *avapigwv1alpha1.Gateway,
	gatewayKey string,
	counts map[string]int32,
) error {
	var tlsRoutes avapigwv1alpha1.TLSRouteList
	if err := r.List(ctx, &tlsRoutes, client.MatchingFields{TLSRouteGatewayIndexField: gatewayKey}); err != nil {
		return fmt.Errorf("failed to list TLSRoutes: %w", err)
	}
	for _, route := range tlsRoutes.Items {
		r.countRouteParentRefs(gateway, &route, route.Spec.ParentRefs, counts)
	}
	return nil
}

// countRouteParentRefs counts parent refs for a single route.
func (r *GatewayReconciler) countRouteParentRefs(
	gateway *avapigwv1alpha1.Gateway,
	route client.Object,
	parentRefs []avapigwv1alpha1.ParentRef,
	counts map[string]int32,
) {
	for _, parentRef := range parentRefs {
		if r.matchesGateway(gateway, route, parentRef) {
			listenerName := r.getListenerName(parentRef)
			if listenerName != "" {
				counts[listenerName]++
			} else {
				// Route matches all listeners
				for name := range counts {
					counts[name]++
				}
			}
		}
	}
}

// matchesGateway checks if a route's parent ref matches this gateway
func (r *GatewayReconciler) matchesGateway(
	gateway *avapigwv1alpha1.Gateway,
	route client.Object,
	parentRef avapigwv1alpha1.ParentRef,
) bool {
	namespace := route.GetNamespace()
	if parentRef.Namespace != nil {
		namespace = *parentRef.Namespace
	}

	return namespace == gateway.Namespace && parentRef.Name == gateway.Name
}

// getListenerName extracts the listener name from a parent ref
func (r *GatewayReconciler) getListenerName(parentRef avapigwv1alpha1.ParentRef) string {
	if parentRef.SectionName != nil {
		return *parentRef.SectionName
	}
	return ""
}

// updateAddresses updates the gateway addresses in status
func (r *GatewayReconciler) updateAddresses(gateway *avapigwv1alpha1.Gateway) {
	addresses := make([]avapigwv1alpha1.GatewayStatusAddress, 0, len(gateway.Spec.Addresses))

	for _, addr := range gateway.Spec.Addresses {
		addresses = append(addresses, avapigwv1alpha1.GatewayStatusAddress(addr))
	}

	gateway.Status.Addresses = addresses
}

// setCondition sets a condition on the gateway status
func (r *GatewayReconciler) setCondition(
	gateway *avapigwv1alpha1.Gateway,
	conditionType avapigwv1alpha1.ConditionType,
	status metav1.ConditionStatus,
	reason, message string,
) {
	gateway.Status.SetCondition(conditionType, status, reason, message)
}

// updateStatus updates the gateway status
func (r *GatewayReconciler) updateStatus(ctx context.Context, gateway *avapigwv1alpha1.Gateway) error {
	return r.Status().Update(ctx, gateway)
}

// SetupWithManager sets up the controller with the Manager
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.Gateway{}).
		Watches(
			&avapigwv1alpha1.TLSConfig{},
			handler.EnqueueRequestsFromMapFunc(r.findGatewaysForTLSConfig),
		).
		Watches(
			&avapigwv1alpha1.HTTPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.findGatewaysForRoute),
		).
		Watches(
			&avapigwv1alpha1.GRPCRoute{},
			handler.EnqueueRequestsFromMapFunc(r.findGatewaysForRoute),
		).
		Watches(
			&avapigwv1alpha1.TCPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.findGatewaysForRoute),
		).
		Watches(
			&avapigwv1alpha1.TLSRoute{},
			handler.EnqueueRequestsFromMapFunc(r.findGatewaysForRoute),
		).
		Complete(r)
}

// findGatewaysForTLSConfig finds gateways that reference a TLSConfig.
// Uses pagination to handle large numbers of gateways efficiently.
func (r *GatewayReconciler) findGatewaysForTLSConfig(ctx context.Context, obj client.Object) []reconcile.Request {
	tlsConfig, ok := obj.(*avapigwv1alpha1.TLSConfig)
	if !ok {
		return nil
	}

	logger := log.FromContext(ctx)
	var requests []reconcile.Request

	// Use pagination to list gateways
	var continueToken string
	for {
		gateways, token, err := r.listGatewayPage(ctx, continueToken)
		if err != nil {
			logger.Error(err, "Failed to list gateways for TLSConfig watch")
			return requests
		}

		// Check each gateway for TLSConfig references
		for i := range gateways {
			if r.gatewayReferencesTLSConfig(&gateways[i], tlsConfig.Namespace, tlsConfig.Name) {
				requests = append(requests, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Namespace: gateways[i].Namespace,
						Name:      gateways[i].Name,
					},
				})
			}
		}

		// Check if there are more pages
		continueToken = token
		if continueToken == "" {
			break
		}
	}

	return requests
}

// listGatewayPage lists a single page of gateways with the given continue token.
// Returns the list of gateways, the next continue token, and any error.
func (r *GatewayReconciler) listGatewayPage(
	ctx context.Context,
	continueToken string,
) ([]avapigwv1alpha1.Gateway, string, error) {
	var gateways avapigwv1alpha1.GatewayList
	listOpts := []client.ListOption{
		client.Limit(listPageSize),
	}
	if continueToken != "" {
		listOpts = append(listOpts, client.Continue(continueToken))
	}

	if err := r.List(ctx, &gateways, listOpts...); err != nil {
		return nil, "", err
	}

	return gateways.Items, gateways.GetContinue(), nil
}

// gatewayReferencesTLSConfig checks if a gateway references the specified TLSConfig.
func (r *GatewayReconciler) gatewayReferencesTLSConfig(
	gateway *avapigwv1alpha1.Gateway,
	tlsConfigNamespace, tlsConfigName string,
) bool {
	for _, listener := range gateway.Spec.Listeners {
		if r.listenerReferencesTLSConfig(gateway.Namespace, &listener, tlsConfigNamespace, tlsConfigName) {
			return true
		}
	}
	return false
}

// listenerReferencesTLSConfig checks if a listener references the specified TLSConfig.
func (r *GatewayReconciler) listenerReferencesTLSConfig(
	gatewayNamespace string,
	listener *avapigwv1alpha1.Listener,
	tlsConfigNamespace, tlsConfigName string,
) bool {
	if listener.TLS == nil {
		return false
	}

	for _, certRef := range listener.TLS.CertificateRefs {
		if certRefMatchesTLSConfig(gatewayNamespace, &certRef, tlsConfigNamespace, tlsConfigName) {
			return true
		}
	}
	return false
}

// certRefMatchesTLSConfig checks if a certificate reference matches the specified TLSConfig.
func certRefMatchesTLSConfig(
	defaultNamespace string,
	certRef *avapigwv1alpha1.SecretObjectReference,
	tlsConfigNamespace, tlsConfigName string,
) bool {
	namespace := defaultNamespace
	if certRef.Namespace != nil {
		namespace = *certRef.Namespace
	}
	return namespace == tlsConfigNamespace && certRef.Name == tlsConfigName
}

// findGatewaysForRoute finds gateways that a route references
func (r *GatewayReconciler) findGatewaysForRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	var parentRefs []avapigwv1alpha1.ParentRef

	switch route := obj.(type) {
	case *avapigwv1alpha1.HTTPRoute:
		parentRefs = route.Spec.ParentRefs
	case *avapigwv1alpha1.GRPCRoute:
		parentRefs = route.Spec.ParentRefs
	case *avapigwv1alpha1.TCPRoute:
		parentRefs = route.Spec.ParentRefs
	case *avapigwv1alpha1.TLSRoute:
		parentRefs = route.Spec.ParentRefs
	default:
		return nil
	}

	requests := make([]reconcile.Request, 0, len(parentRefs))
	for _, parentRef := range parentRefs {
		namespace := obj.GetNamespace()
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}

		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: namespace,
				Name:      parentRef.Name,
			},
		})
	}

	return requests
}

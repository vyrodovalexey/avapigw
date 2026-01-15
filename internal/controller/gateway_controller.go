// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

const (
	gatewayFinalizer = "avapigw.vyrodovalexey.github.com/gateway-finalizer"

	// reconcileTimeout is the maximum duration for a single reconciliation
	reconcileTimeout = 30 * time.Second

	// listPageSize is the page size for paginated list operations in watch handlers
	listPageSize = 100
)

// Prometheus metrics for Gateway controller
var (
	gatewayReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "gateway_reconcile_duration_seconds",
			Help:      "Duration of Gateway reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	gatewayReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "gateway_reconcile_total",
			Help:      "Total number of Gateway reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(gatewayReconcileDuration, gatewayReconcileTotal)
}

// GatewayReconciler reconciles a Gateway object
type GatewayReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy
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

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch;create;update;patch;delete
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
	// Add timeout to prevent hanging
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.NamespacedName.String()

	// Track reconciliation metrics
	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		duration := time.Since(start).Seconds()
		result := "success"
		if reconcileErr != nil {
			result = "error"
		}
		gatewayReconcileDuration.WithLabelValues(result).Observe(duration)
		gatewayReconcileTotal.WithLabelValues(result).Inc()
	}()

	logger.Info("Reconciling Gateway",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the Gateway instance
	gateway := &avapigwv1alpha1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, gateway); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Gateway not found, ignoring")
			// Clean up failure tracking for deleted resources
			strategy.ResetFailureCount(resourceKey)
			return ctrl.Result{}, nil
		}
		// Classify and handle the error
		reconcileErr = ClassifyError("getGateway", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get Gateway",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}

	// Handle deletion
	if !gateway.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, gateway)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(gateway, gatewayFinalizer) {
		controllerutil.AddFinalizer(gateway, gatewayFinalizer)
		if err := r.Update(ctx, gateway); err != nil {
			reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to add finalizer",
				"errorType", reconcileErr.Type,
			)
			r.Recorder.Event(gateway, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
		return strategy.ForImmediateRequeue(), nil
	}

	// Reconcile the Gateway
	if err := r.reconcileGateway(ctx, gateway); err != nil {
		reconcileErr = ClassifyError("reconcileGateway", resourceKey, err)
		logger.Error(reconcileErr, "Failed to reconcile Gateway",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
			"userActionRequired", reconcileErr.UserActionRequired,
		)
		r.Recorder.Event(gateway, corev1.EventTypeWarning, string(reconcileErr.Type)+"Error", err.Error())

		// Return appropriate result based on error type
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

	// Success - reset failure count and requeue for periodic reconciliation
	strategy.ResetFailureCount(resourceKey)
	logger.Info("Gateway reconciled successfully", "name", req.Name, "namespace", req.Namespace)
	return strategy.ForSuccess(), nil
}

// handleDeletion handles Gateway deletion
func (r *GatewayReconciler) handleDeletion(ctx context.Context, gateway *avapigwv1alpha1.Gateway) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(gateway).String()

	if controllerutil.ContainsFinalizer(gateway, gatewayFinalizer) {
		// Perform cleanup
		logger.Info("Performing cleanup for Gateway deletion",
			"name", gateway.Name,
			"namespace", gateway.Namespace,
		)

		// Record event
		r.Recorder.Event(gateway, corev1.EventTypeNormal, "Deleting", "Gateway is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(gateway, gatewayFinalizer)
		if err := r.Update(ctx, gateway); err != nil {
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

	// Update status to reconciling
	gateway.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	gateway.Status.ObservedGeneration = gateway.Generation
	gateway.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}

	// Validate and resolve TLS config references
	if err := r.validateTLSConfigs(ctx, gateway); err != nil {
		// Determine if this is a validation or dependency error
		var reconcileErr *ReconcileError
		if errors.IsNotFound(err) {
			reconcileErr = NewDependencyError("validateTLSConfigs", resourceKey, err)
		} else {
			reconcileErr = NewValidationError("validateTLSConfigs", resourceKey, err)
		}

		logger.Error(reconcileErr, "TLS configuration validation failed",
			"errorType", reconcileErr.Type,
		)

		r.setCondition(gateway, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonInvalidRef), err.Error())
		gateway.Status.Phase = avapigwv1alpha1.PhaseStatusError

		// Update status even on error
		if statusErr := r.updateStatus(ctx, gateway); statusErr != nil {
			logger.Error(statusErr, "Failed to update status after TLS validation error")
		}
		return reconcileErr
	}

	// Update listener statuses
	if err := r.updateListenerStatuses(ctx, gateway); err != nil {
		reconcileErr := NewInternalError("updateListenerStatuses", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update listener statuses",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	// Count attached routes
	attachedRoutes, err := r.countAttachedRoutes(ctx, gateway)
	if err != nil {
		reconcileErr := ClassifyError("countAttachedRoutes", resourceKey, err)
		logger.Error(reconcileErr, "Failed to count attached routes",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	// Update listener attached route counts
	for i := range gateway.Status.Listeners {
		listenerName := gateway.Status.Listeners[i].Name
		if count, ok := attachedRoutes[listenerName]; ok {
			gateway.Status.Listeners[i].AttachedRoutes = count
		}
	}

	// Update addresses
	r.updateAddresses(gateway)

	// Set conditions
	r.setCondition(gateway, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonAccepted), "Gateway configuration accepted")
	r.setCondition(gateway, avapigwv1alpha1.ConditionTypeProgrammed, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonProgrammed), "Gateway listeners configured")

	gateway.Status.Phase = avapigwv1alpha1.PhaseStatusReady
	gateway.Status.ListenersCount = int32(len(gateway.Spec.Listeners))

	// Update status
	if err := r.updateStatus(ctx, gateway); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update Gateway status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(gateway, corev1.EventTypeNormal, "Reconciled", "Gateway reconciled successfully")
	return nil
}

// validateTLSConfigs validates TLS configuration references
func (r *GatewayReconciler) validateTLSConfigs(ctx context.Context, gateway *avapigwv1alpha1.Gateway) error {
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
				if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: certRef.Name}, secret); err != nil {
					return fmt.Errorf("certificate reference %s/%s not found as TLSConfig or Secret", namespace, certRef.Name)
				}
			}
		}
	}

	return nil
}

// updateListenerStatuses updates the status of each listener
func (r *GatewayReconciler) updateListenerStatuses(ctx context.Context, gateway *avapigwv1alpha1.Gateway) error {
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
func (r *GatewayReconciler) countAttachedRoutes(ctx context.Context, gateway *avapigwv1alpha1.Gateway) (map[string]int32, error) {
	counts := make(map[string]int32)

	// Initialize counts for all listeners
	for _, listener := range gateway.Spec.Listeners {
		counts[listener.Name] = 0
	}

	// Create the index key for this gateway
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	// Count HTTPRoutes using field index for efficient lookup
	var httpRoutes avapigwv1alpha1.HTTPRouteList
	if err := r.List(ctx, &httpRoutes, client.MatchingFields{HTTPRouteGatewayIndexField: gatewayKey}); err != nil {
		return nil, fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}
	for _, route := range httpRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			if r.matchesGateway(gateway, &route, parentRef) {
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

	// Count GRPCRoutes using field index
	var grpcRoutes avapigwv1alpha1.GRPCRouteList
	if err := r.List(ctx, &grpcRoutes, client.MatchingFields{GRPCRouteGatewayIndexField: gatewayKey}); err != nil {
		return nil, fmt.Errorf("failed to list GRPCRoutes: %w", err)
	}
	for _, route := range grpcRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			if r.matchesGateway(gateway, &route, parentRef) {
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

	// Count TCPRoutes using field index
	var tcpRoutes avapigwv1alpha1.TCPRouteList
	if err := r.List(ctx, &tcpRoutes, client.MatchingFields{TCPRouteGatewayIndexField: gatewayKey}); err != nil {
		return nil, fmt.Errorf("failed to list TCPRoutes: %w", err)
	}
	for _, route := range tcpRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			if r.matchesGateway(gateway, &route, parentRef) {
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

	// Count TLSRoutes using field index
	var tlsRoutes avapigwv1alpha1.TLSRouteList
	if err := r.List(ctx, &tlsRoutes, client.MatchingFields{TLSRouteGatewayIndexField: gatewayKey}); err != nil {
		return nil, fmt.Errorf("failed to list TLSRoutes: %w", err)
	}
	for _, route := range tlsRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			if r.matchesGateway(gateway, &route, parentRef) {
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

	return counts, nil
}

// matchesGateway checks if a route's parent ref matches this gateway
func (r *GatewayReconciler) matchesGateway(gateway *avapigwv1alpha1.Gateway, route client.Object, parentRef avapigwv1alpha1.ParentRef) bool {
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
		statusAddr := avapigwv1alpha1.GatewayStatusAddress{
			Type:  addr.Type,
			Value: addr.Value,
		}
		addresses = append(addresses, statusAddr)
	}

	gateway.Status.Addresses = addresses
}

// setCondition sets a condition on the gateway status
func (r *GatewayReconciler) setCondition(gateway *avapigwv1alpha1.Gateway, conditionType avapigwv1alpha1.ConditionType, status metav1.ConditionStatus, reason, message string) {
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

// findGatewaysForTLSConfig finds gateways that reference a TLSConfig
// Uses pagination to handle large numbers of gateways efficiently
func (r *GatewayReconciler) findGatewaysForTLSConfig(ctx context.Context, obj client.Object) []reconcile.Request {
	tlsConfig, ok := obj.(*avapigwv1alpha1.TLSConfig)
	if !ok {
		return nil
	}
	var requests []reconcile.Request
	logger := log.FromContext(ctx)

	// Use pagination to list gateways
	var continueToken string
	for {
		var gateways avapigwv1alpha1.GatewayList
		listOpts := []client.ListOption{
			client.Limit(listPageSize),
		}
		if continueToken != "" {
			listOpts = append(listOpts, client.Continue(continueToken))
		}

		if err := r.List(ctx, &gateways, listOpts...); err != nil {
			logger.Error(err, "Failed to list gateways for TLSConfig watch")
			return requests
		}

		for _, gateway := range gateways.Items {
			for _, listener := range gateway.Spec.Listeners {
				if listener.TLS != nil {
					for _, certRef := range listener.TLS.CertificateRefs {
						namespace := gateway.Namespace
						if certRef.Namespace != nil {
							namespace = *certRef.Namespace
						}
						if namespace == tlsConfig.Namespace && certRef.Name == tlsConfig.Name {
							requests = append(requests, reconcile.Request{
								NamespacedName: client.ObjectKey{
									Namespace: gateway.Namespace,
									Name:      gateway.Name,
								},
							})
							break
						}
					}
				}
			}
		}

		// Check if there are more pages
		continueToken = gateways.GetContinue()
		if continueToken == "" {
			break
		}
	}

	return requests
}

// findGatewaysForRoute finds gateways that a route references
func (r *GatewayReconciler) findGatewaysForRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	var requests []reconcile.Request
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
		return requests
	}

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

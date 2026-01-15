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
	tlsRouteFinalizer = "avapigw.vyrodovalexey.github.com/tlsroute-finalizer"

	// tlsRouteReconcileTimeout is the maximum duration for a single TLSRoute reconciliation
	tlsRouteReconcileTimeout = 30 * time.Second
)

// Prometheus metrics for TLSRoute controller
var (
	tlsRouteReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "tlsroute_reconcile_duration_seconds",
			Help:      "Duration of TLSRoute reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	tlsRouteReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "tlsroute_reconcile_total",
			Help:      "Total number of TLSRoute reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(tlsRouteReconcileDuration, tlsRouteReconcileTotal)
}

// TLSRouteReconciler reconciles a TLSRoute object
type TLSRouteReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy
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

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles TLSRoute reconciliation
func (r *TLSRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add timeout to prevent hanging reconciliations
	ctx, cancel := context.WithTimeout(ctx, tlsRouteReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	// Track reconciliation metrics
	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		duration := time.Since(start).Seconds()
		result := MetricResultSuccess
		if reconcileErr != nil {
			result = MetricResultError
		}
		tlsRouteReconcileDuration.WithLabelValues(result).Observe(duration)
		tlsRouteReconcileTotal.WithLabelValues(result).Inc()
	}()

	logger.Info("Reconciling TLSRoute",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the TLSRoute instance
	tlsRoute := &avapigwv1alpha1.TLSRoute{}
	if err := r.Get(ctx, req.NamespacedName, tlsRoute); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("TLSRoute not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return ctrl.Result{}, nil
		}
		reconcileErr = ClassifyError("getTLSRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get TLSRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}

	// Handle deletion
	if !tlsRoute.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, tlsRoute)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(tlsRoute, tlsRouteFinalizer) {
		controllerutil.AddFinalizer(tlsRoute, tlsRouteFinalizer)
		if err := r.Update(ctx, tlsRoute); err != nil {
			reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to add finalizer",
				"errorType", reconcileErr.Type,
			)
			r.Recorder.Event(tlsRoute, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
		return strategy.ForImmediateRequeue(), nil
	}

	// Reconcile the TLSRoute
	if err := r.reconcileTLSRoute(ctx, tlsRoute); err != nil {
		reconcileErr = ClassifyError("reconcileTLSRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to reconcile TLSRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
			"userActionRequired", reconcileErr.UserActionRequired,
		)
		r.Recorder.Event(tlsRoute, corev1.EventTypeWarning, string(reconcileErr.Type)+"Error", err.Error())

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

	// Success - reset failure count
	strategy.ResetFailureCount(resourceKey)
	logger.Info("TLSRoute reconciled successfully", "name", req.Name, "namespace", req.Namespace)
	return strategy.ForSuccess(), nil
}

// handleDeletion handles TLSRoute deletion
func (r *TLSRouteReconciler) handleDeletion(ctx context.Context, tlsRoute *avapigwv1alpha1.TLSRoute) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(tlsRoute).String()

	if controllerutil.ContainsFinalizer(tlsRoute, tlsRouteFinalizer) {
		// Perform cleanup
		logger.Info("Performing cleanup for TLSRoute deletion",
			"name", tlsRoute.Name,
			"namespace", tlsRoute.Namespace,
		)

		// Record event
		r.Recorder.Event(tlsRoute, corev1.EventTypeNormal, "Deleting", "TLSRoute is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(tlsRoute, tlsRouteFinalizer)
		if err := r.Update(ctx, tlsRoute); err != nil {
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

	// Validate parent references (Gateways)
	parentStatuses, err := r.validateParentRefs(ctx, tlsRoute)
	if err != nil {
		logger.Error(err, "Failed to validate parent references")
		return err
	}

	// Validate backend references
	if err := r.validateBackendRefs(ctx, tlsRoute); err != nil {
		logger.Error(err, "Failed to validate backend references")
		// Continue with status update even if backends are invalid
	}

	// Update route status with parent statuses
	tlsRoute.Status.Parents = parentStatuses

	// Update status
	if err := r.Status().Update(ctx, tlsRoute); err != nil {
		logger.Error(err, "Failed to update TLSRoute status")
		return err
	}

	r.Recorder.Event(tlsRoute, corev1.EventTypeNormal, "Reconciled", "TLSRoute reconciled successfully")
	return nil
}

// validateParentRefs validates parent references and returns parent statuses
func (r *TLSRouteReconciler) validateParentRefs(ctx context.Context, tlsRoute *avapigwv1alpha1.TLSRoute) ([]avapigwv1alpha1.RouteParentStatus, error) {
	logger := log.FromContext(ctx)
	parentStatuses := make([]avapigwv1alpha1.RouteParentStatus, 0, len(tlsRoute.Spec.ParentRefs))

	for _, parentRef := range tlsRoute.Spec.ParentRefs {
		parentStatus := avapigwv1alpha1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: "avapigw.vyrodovalexey.github.com/gateway-controller",
		}

		// Determine namespace
		namespace := tlsRoute.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}

		// Get the Gateway
		gateway := &avapigwv1alpha1.Gateway{}
		err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: parentRef.Name}, gateway)
		if err != nil {
			if errors.IsNotFound(err) {
				logger.Info("Parent Gateway not found", "gateway", parentRef.Name, "namespace", namespace)
				parentStatus.Conditions = []avapigwv1alpha1.Condition{
					{
						Type:               avapigwv1alpha1.ConditionTypeAccepted,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: metav1.Now(),
						Reason:             string(avapigwv1alpha1.ReasonNoMatchingParent),
						Message:            fmt.Sprintf("Gateway %s/%s not found", namespace, parentRef.Name),
					},
				}
				parentStatuses = append(parentStatuses, parentStatus)
				continue
			}
			return nil, fmt.Errorf("failed to get Gateway %s/%s: %w", namespace, parentRef.Name, err)
		}

		// Validate listener match
		accepted, message := r.validateListenerMatch(tlsRoute, gateway, parentRef)
		if accepted {
			parentStatus.Conditions = []avapigwv1alpha1.Condition{
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
		} else {
			parentStatus.Conditions = []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionTypeAccepted,
					Status:             metav1.ConditionFalse,
					LastTransitionTime: metav1.Now(),
					Reason:             string(avapigwv1alpha1.ReasonNotAllowedByListeners),
					Message:            message,
				},
			}
		}

		parentStatuses = append(parentStatuses, parentStatus)
	}

	return parentStatuses, nil
}

// validateListenerMatch validates that the route matches a listener on the gateway.
// Returns whether the match is valid and a reason message if not.
func (r *TLSRouteReconciler) validateListenerMatch(tlsRoute *avapigwv1alpha1.TLSRoute, gateway *avapigwv1alpha1.Gateway, parentRef avapigwv1alpha1.ParentRef) (valid bool, reason string) {
	// If a specific section (listener) is specified, validate it
	if parentRef.SectionName != nil {
		listenerName := *parentRef.SectionName
		for _, listener := range gateway.Spec.Listeners {
			if listener.Name == listenerName {
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
		}
		return false, fmt.Sprintf("Listener %s not found on Gateway", listenerName)
	}

	// No specific listener, check if any TLS listener matches
	for _, listener := range gateway.Spec.Listeners {
		if listener.Protocol == avapigwv1alpha1.ProtocolTLS {
			if r.hostnameMatches(tlsRoute.Spec.Hostnames, listener.Hostname) {
				return true, ""
			}
		}
	}

	return false, "No matching TLS listener found on Gateway"
}

// hostnameMatches checks if route hostnames match the listener hostname
func (r *TLSRouteReconciler) hostnameMatches(routeHostnames []avapigwv1alpha1.Hostname, listenerHostname *avapigwv1alpha1.Hostname) bool {
	// If listener has no hostname, it matches all
	if listenerHostname == nil {
		return true
	}

	// If route has no hostnames, it matches all listeners
	if len(routeHostnames) == 0 {
		return true
	}

	listenerHost := string(*listenerHostname)
	for _, routeHostname := range routeHostnames {
		routeHost := string(routeHostname)
		if r.hostnameMatch(routeHost, listenerHost) {
			return true
		}
	}

	return false
}

// hostnameMatch checks if two hostnames match (supporting wildcards)
func (r *TLSRouteReconciler) hostnameMatch(routeHost, listenerHost string) bool {
	// Exact match
	if routeHost == listenerHost {
		return true
	}

	// Wildcard matching
	if listenerHost != "" && listenerHost[0] == '*' {
		suffix := listenerHost[1:]
		if routeHost != "" && routeHost[0] == '*' {
			return routeHost[1:] == suffix
		}
		if len(routeHost) > len(suffix) {
			return routeHost[len(routeHost)-len(suffix):] == suffix
		}
	}

	if routeHost != "" && routeHost[0] == '*' {
		suffix := routeHost[1:]
		if len(listenerHost) > len(suffix) {
			return listenerHost[len(listenerHost)-len(suffix):] == suffix
		}
	}

	return false
}

// validateBackendRefs validates backend references
func (r *TLSRouteReconciler) validateBackendRefs(ctx context.Context, tlsRoute *avapigwv1alpha1.TLSRoute) error {
	logger := log.FromContext(ctx)

	for _, rule := range tlsRoute.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			namespace := tlsRoute.Namespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}

			kind := BackendKindService
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}

			group := ""
			if backendRef.Group != nil {
				group = *backendRef.Group
			}

			// Check based on kind
			switch {
			case group == "" && kind == BackendKindService:
				// Kubernetes Service
				svc := &corev1.Service{}
				if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: backendRef.Name}, svc); err != nil {
					if errors.IsNotFound(err) {
						logger.Info("Backend Service not found", "service", backendRef.Name, "namespace", namespace)
						r.Recorder.Event(tlsRoute, corev1.EventTypeWarning, "BackendNotFound",
							fmt.Sprintf("Service %s/%s not found", namespace, backendRef.Name))
						continue
					}
					return fmt.Errorf("failed to get Service %s/%s: %w", namespace, backendRef.Name, err)
				}
			case group == avapigwv1alpha1.GroupVersion.Group && kind == BackendKindBackend:
				// Custom Backend resource
				backend := &avapigwv1alpha1.Backend{}
				if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: backendRef.Name}, backend); err != nil {
					if errors.IsNotFound(err) {
						logger.Info("Backend not found", "backend", backendRef.Name, "namespace", namespace)
						r.Recorder.Event(tlsRoute, corev1.EventTypeWarning, "BackendNotFound",
							fmt.Sprintf("Backend %s/%s not found", namespace, backendRef.Name))
						continue
					}
					return fmt.Errorf("failed to get Backend %s/%s: %w", namespace, backendRef.Name, err)
				}
			default:
				logger.Info("Unsupported backend kind", "group", group, "kind", kind)
			}
		}
	}

	return nil
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

// findTLSRoutesForGateway finds TLSRoutes that reference a Gateway
func (r *TLSRouteReconciler) findTLSRoutesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)
	var requests []reconcile.Request

	var tlsRoutes avapigwv1alpha1.TLSRouteList
	if err := r.List(ctx, &tlsRoutes); err != nil {
		return requests
	}

	for _, route := range tlsRoutes.Items {
		for _, parentRef := range route.Spec.ParentRefs {
			namespace := route.Namespace
			if parentRef.Namespace != nil {
				namespace = *parentRef.Namespace
			}
			if namespace == gateway.Namespace && parentRef.Name == gateway.Name {
				requests = append(requests, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Namespace: route.Namespace,
						Name:      route.Name,
					},
				})
				break
			}
		}
	}

	return requests
}

// findTLSRoutesForBackend finds TLSRoutes that reference a Backend
func (r *TLSRouteReconciler) findTLSRoutesForBackend(ctx context.Context, obj client.Object) []reconcile.Request {
	backend := obj.(*avapigwv1alpha1.Backend)
	var requests []reconcile.Request

	var tlsRoutes avapigwv1alpha1.TLSRouteList
	if err := r.List(ctx, &tlsRoutes); err != nil {
		return requests
	}

	for _, route := range tlsRoutes.Items {
		for _, rule := range route.Spec.Rules {
			for _, backendRef := range rule.BackendRefs {
				namespace := route.Namespace
				if backendRef.Namespace != nil {
					namespace = *backendRef.Namespace
				}
				kind := BackendKindService
				if backendRef.Kind != nil {
					kind = *backendRef.Kind
				}
				if kind == BackendKindBackend && namespace == backend.Namespace && backendRef.Name == backend.Name {
					requests = append(requests, reconcile.Request{
						NamespacedName: client.ObjectKey{
							Namespace: route.Namespace,
							Name:      route.Name,
						},
					})
					break
				}
			}
		}
	}

	return requests
}

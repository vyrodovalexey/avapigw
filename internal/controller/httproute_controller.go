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
	httpRouteFinalizer = "avapigw.vyrodovalexey.github.com/httproute-finalizer"

	// HTTPRouteControllerName is the name of the HTTPRoute controller.
	// Used in RouteParentStatus to identify which controller accepted the route.
	HTTPRouteControllerName = "avapigw.vyrodovalexey.github.com/gateway-controller"

	// httpRouteReconcileTimeout is the maximum duration for a single HTTPRoute reconciliation
	httpRouteReconcileTimeout = 30 * time.Second
)

// Prometheus metrics for HTTPRoute controller
var (
	httpRouteReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "httproute_reconcile_duration_seconds",
			Help:      "Duration of HTTPRoute reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	httpRouteReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "httproute_reconcile_total",
			Help:      "Total number of HTTPRoute reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(httpRouteReconcileDuration, httpRouteReconcileTotal)
}

// HTTPRouteReconciler reconciles a HTTPRoute object
type HTTPRouteReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy
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

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles HTTPRoute reconciliation
func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add timeout to prevent hanging reconciliations
	ctx, cancel := context.WithTimeout(ctx, httpRouteReconcileTimeout)
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
		httpRouteReconcileDuration.WithLabelValues(result).Observe(duration)
		httpRouteReconcileTotal.WithLabelValues(result).Inc()
	}()

	logger.Info("Reconciling HTTPRoute",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the HTTPRoute instance
	httpRoute := &avapigwv1alpha1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, httpRoute); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("HTTPRoute not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return ctrl.Result{}, nil
		}
		reconcileErr = ClassifyError("getHTTPRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get HTTPRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}

	// Handle deletion
	if !httpRoute.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, httpRoute)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(httpRoute, httpRouteFinalizer) {
		controllerutil.AddFinalizer(httpRoute, httpRouteFinalizer)
		if err := r.Update(ctx, httpRoute); err != nil {
			reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to add finalizer",
				"errorType", reconcileErr.Type,
			)
			r.Recorder.Event(httpRoute, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
		return strategy.ForImmediateRequeue(), nil
	}

	// Reconcile the HTTPRoute
	if err := r.reconcileHTTPRoute(ctx, httpRoute); err != nil {
		reconcileErr = ClassifyError("reconcileHTTPRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to reconcile HTTPRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
			"userActionRequired", reconcileErr.UserActionRequired,
		)
		r.Recorder.Event(httpRoute, corev1.EventTypeWarning, string(reconcileErr.Type)+"Error", err.Error())

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
	logger.Info("HTTPRoute reconciled successfully", "name", req.Name, "namespace", req.Namespace)
	return strategy.ForSuccess(), nil
}

// handleDeletion handles HTTPRoute deletion
func (r *HTTPRouteReconciler) handleDeletion(ctx context.Context, httpRoute *avapigwv1alpha1.HTTPRoute) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(httpRoute).String()

	if controllerutil.ContainsFinalizer(httpRoute, httpRouteFinalizer) {
		// Perform cleanup
		logger.Info("Performing cleanup for HTTPRoute deletion",
			"name", httpRoute.Name,
			"namespace", httpRoute.Namespace,
		)

		// Record event
		r.Recorder.Event(httpRoute, corev1.EventTypeNormal, "Deleting", "HTTPRoute is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(httpRoute, httpRouteFinalizer)
		if err := r.Update(ctx, httpRoute); err != nil {
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
func (r *HTTPRouteReconciler) validateParentRefs(ctx context.Context, httpRoute *avapigwv1alpha1.HTTPRoute) ([]avapigwv1alpha1.RouteParentStatus, error) {
	logger := log.FromContext(ctx)
	var parentStatuses []avapigwv1alpha1.RouteParentStatus

	for _, parentRef := range httpRoute.Spec.ParentRefs {
		parentStatus := avapigwv1alpha1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: HTTPRouteControllerName,
		}

		// Determine namespace
		namespace := httpRoute.Namespace
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
		accepted, message := r.validateListenerMatch(httpRoute, gateway, parentRef)
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

// validateListenerMatch validates that the route matches a listener on the gateway
func (r *HTTPRouteReconciler) validateListenerMatch(httpRoute *avapigwv1alpha1.HTTPRoute, gateway *avapigwv1alpha1.Gateway, parentRef avapigwv1alpha1.ParentRef) (bool, string) {
	// If a specific section (listener) is specified, validate it
	if parentRef.SectionName != nil {
		listenerName := *parentRef.SectionName
		for _, listener := range gateway.Spec.Listeners {
			if listener.Name == listenerName {
				// Check protocol compatibility
				if listener.Protocol != avapigwv1alpha1.ProtocolHTTP && listener.Protocol != avapigwv1alpha1.ProtocolHTTPS {
					return false, fmt.Sprintf("Listener %s does not support HTTP protocol", listenerName)
				}
				// Check hostname match
				if !r.hostnameMatches(httpRoute.Spec.Hostnames, listener.Hostname) {
					return false, fmt.Sprintf("No matching hostname for listener %s", listenerName)
				}
				return true, ""
			}
		}
		return false, fmt.Sprintf("Listener %s not found on Gateway", listenerName)
	}

	// No specific listener, check if any HTTP/HTTPS listener matches
	for _, listener := range gateway.Spec.Listeners {
		if listener.Protocol == avapigwv1alpha1.ProtocolHTTP || listener.Protocol == avapigwv1alpha1.ProtocolHTTPS {
			if r.hostnameMatches(httpRoute.Spec.Hostnames, listener.Hostname) {
				return true, ""
			}
		}
	}

	return false, "No matching HTTP/HTTPS listener found on Gateway"
}

// hostnameMatches checks if route hostnames match the listener hostname
func (r *HTTPRouteReconciler) hostnameMatches(routeHostnames []avapigwv1alpha1.Hostname, listenerHostname *avapigwv1alpha1.Hostname) bool {
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
func (r *HTTPRouteReconciler) hostnameMatch(routeHost, listenerHost string) bool {
	// Exact match
	if routeHost == listenerHost {
		return true
	}

	// Wildcard matching
	if len(listenerHost) > 0 && listenerHost[0] == '*' {
		// Listener has wildcard, e.g., *.example.com
		suffix := listenerHost[1:] // .example.com
		if len(routeHost) > 0 && routeHost[0] == '*' {
			// Both have wildcards
			return routeHost[1:] == suffix
		}
		// Route is specific, check if it matches the wildcard
		if len(routeHost) > len(suffix) {
			return routeHost[len(routeHost)-len(suffix):] == suffix
		}
	}

	if len(routeHost) > 0 && routeHost[0] == '*' {
		// Route has wildcard, e.g., *.example.com
		suffix := routeHost[1:] // .example.com
		// Listener is specific, check if it matches the wildcard
		if len(listenerHost) > len(suffix) {
			return listenerHost[len(listenerHost)-len(suffix):] == suffix
		}
	}

	return false
}

// validateBackendRefs validates backend references
func (r *HTTPRouteReconciler) validateBackendRefs(ctx context.Context, httpRoute *avapigwv1alpha1.HTTPRoute) error {
	logger := log.FromContext(ctx)

	for _, rule := range httpRoute.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			namespace := httpRoute.Namespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}

			kind := "Service"
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}

			group := ""
			if backendRef.Group != nil {
				group = *backendRef.Group
			}

			// Check based on kind
			switch {
			case group == "" && kind == "Service":
				// Kubernetes Service
				svc := &corev1.Service{}
				if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: backendRef.Name}, svc); err != nil {
					if errors.IsNotFound(err) {
						logger.Info("Backend Service not found", "service", backendRef.Name, "namespace", namespace)
						r.Recorder.Event(httpRoute, corev1.EventTypeWarning, "BackendNotFound",
							fmt.Sprintf("Service %s/%s not found", namespace, backendRef.Name))
						continue
					}
					return fmt.Errorf("failed to get Service %s/%s: %w", namespace, backendRef.Name, err)
				}
			case group == avapigwv1alpha1.GroupVersion.Group && kind == "Backend":
				// Custom Backend resource
				backend := &avapigwv1alpha1.Backend{}
				if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: backendRef.Name}, backend); err != nil {
					if errors.IsNotFound(err) {
						logger.Info("Backend not found", "backend", backendRef.Name, "namespace", namespace)
						r.Recorder.Event(httpRoute, corev1.EventTypeWarning, "BackendNotFound",
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
	var requests []reconcile.Request

	// Use field index for efficient lookup
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)
	var httpRoutes avapigwv1alpha1.HTTPRouteList
	if err := r.List(ctx, &httpRoutes, client.MatchingFields{HTTPRouteGatewayIndexField: gatewayKey}); err != nil {
		return requests
	}

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
	var requests []reconcile.Request

	// Use field index for efficient lookup
	backendKey := BackendIndexKey(backend.Namespace, backend.Name)
	var httpRoutes avapigwv1alpha1.HTTPRouteList
	if err := r.List(ctx, &httpRoutes, client.MatchingFields{HTTPRouteBackendIndexField: backendKey}); err != nil {
		return requests
	}

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

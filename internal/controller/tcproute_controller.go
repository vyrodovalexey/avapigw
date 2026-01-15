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
	tcpRouteFinalizer = "avapigw.vyrodovalexey.github.com/tcproute-finalizer"

	// tcpRouteReconcileTimeout is the maximum duration for a single TCPRoute reconciliation
	tcpRouteReconcileTimeout = 30 * time.Second
)

// Prometheus metrics for TCPRoute controller
var (
	tcpRouteReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "tcproute_reconcile_duration_seconds",
			Help:      "Duration of TCPRoute reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	tcpRouteReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "tcproute_reconcile_total",
			Help:      "Total number of TCPRoute reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(tcpRouteReconcileDuration, tcpRouteReconcileTotal)
}

// TCPRouteReconciler reconciles a TCPRoute object
type TCPRouteReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy
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

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tcproutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tcproutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tcproutes/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles TCPRoute reconciliation
func (r *TCPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add timeout to prevent hanging reconciliations
	ctx, cancel := context.WithTimeout(ctx, tcpRouteReconcileTimeout)
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
		tcpRouteReconcileDuration.WithLabelValues(result).Observe(duration)
		tcpRouteReconcileTotal.WithLabelValues(result).Inc()
	}()

	logger.Info("Reconciling TCPRoute",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the TCPRoute instance
	tcpRoute := &avapigwv1alpha1.TCPRoute{}
	if err := r.Get(ctx, req.NamespacedName, tcpRoute); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("TCPRoute not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return ctrl.Result{}, nil
		}
		reconcileErr = ClassifyError("getTCPRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get TCPRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}

	// Handle deletion
	if !tcpRoute.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, tcpRoute)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(tcpRoute, tcpRouteFinalizer) {
		controllerutil.AddFinalizer(tcpRoute, tcpRouteFinalizer)
		if err := r.Update(ctx, tcpRoute); err != nil {
			reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to add finalizer",
				"errorType", reconcileErr.Type,
			)
			r.Recorder.Event(tcpRoute, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
		return strategy.ForImmediateRequeue(), nil
	}

	// Reconcile the TCPRoute
	if err := r.reconcileTCPRoute(ctx, tcpRoute); err != nil {
		reconcileErr = ClassifyError("reconcileTCPRoute", resourceKey, err)
		logger.Error(reconcileErr, "Failed to reconcile TCPRoute",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
			"userActionRequired", reconcileErr.UserActionRequired,
		)
		r.Recorder.Event(tcpRoute, corev1.EventTypeWarning, string(reconcileErr.Type)+"Error", err.Error())

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
	logger.Info("TCPRoute reconciled successfully", "name", req.Name, "namespace", req.Namespace)
	return strategy.ForSuccess(), nil
}

// handleDeletion handles TCPRoute deletion
func (r *TCPRouteReconciler) handleDeletion(ctx context.Context, tcpRoute *avapigwv1alpha1.TCPRoute) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(tcpRoute).String()

	if controllerutil.ContainsFinalizer(tcpRoute, tcpRouteFinalizer) {
		// Perform cleanup
		logger.Info("Performing cleanup for TCPRoute deletion",
			"name", tcpRoute.Name,
			"namespace", tcpRoute.Namespace,
		)

		// Record event
		r.Recorder.Event(tcpRoute, corev1.EventTypeNormal, "Deleting", "TCPRoute is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(tcpRoute, tcpRouteFinalizer)
		if err := r.Update(ctx, tcpRoute); err != nil {
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

	// Validate parent references (Gateways)
	parentStatuses, err := r.validateParentRefs(ctx, tcpRoute)
	if err != nil {
		logger.Error(err, "Failed to validate parent references")
		return err
	}

	// Validate backend references
	if err := r.validateBackendRefs(ctx, tcpRoute); err != nil {
		logger.Error(err, "Failed to validate backend references")
		// Continue with status update even if backends are invalid
	}

	// Update route status with parent statuses
	tcpRoute.Status.Parents = parentStatuses

	// Update status
	if err := r.Status().Update(ctx, tcpRoute); err != nil {
		logger.Error(err, "Failed to update TCPRoute status")
		return err
	}

	r.Recorder.Event(tcpRoute, corev1.EventTypeNormal, "Reconciled", "TCPRoute reconciled successfully")
	return nil
}

// validateParentRefs validates parent references and returns parent statuses
func (r *TCPRouteReconciler) validateParentRefs(ctx context.Context, tcpRoute *avapigwv1alpha1.TCPRoute) ([]avapigwv1alpha1.RouteParentStatus, error) {
	logger := log.FromContext(ctx)
	var parentStatuses []avapigwv1alpha1.RouteParentStatus

	for _, parentRef := range tcpRoute.Spec.ParentRefs {
		parentStatus := avapigwv1alpha1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: "avapigw.vyrodovalexey.github.com/gateway-controller",
		}

		// Determine namespace
		namespace := tcpRoute.Namespace
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
		accepted, message := r.validateListenerMatch(gateway, parentRef)
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
func (r *TCPRouteReconciler) validateListenerMatch(gateway *avapigwv1alpha1.Gateway, parentRef avapigwv1alpha1.ParentRef) (bool, string) {
	// If a specific section (listener) is specified, validate it
	if parentRef.SectionName != nil {
		listenerName := *parentRef.SectionName
		for _, listener := range gateway.Spec.Listeners {
			if listener.Name == listenerName {
				// Check protocol compatibility
				if listener.Protocol != avapigwv1alpha1.ProtocolTCP {
					return false, fmt.Sprintf("Listener %s does not support TCP protocol", listenerName)
				}
				// Check port match if specified
				if parentRef.Port != nil && int32(listener.Port) != *parentRef.Port {
					return false, fmt.Sprintf("Port %d does not match listener %s port %d", *parentRef.Port, listenerName, listener.Port)
				}
				return true, ""
			}
		}
		return false, fmt.Sprintf("Listener %s not found on Gateway", listenerName)
	}

	// No specific listener, check if any TCP listener matches
	for _, listener := range gateway.Spec.Listeners {
		if listener.Protocol == avapigwv1alpha1.ProtocolTCP {
			// Check port match if specified
			if parentRef.Port != nil && int32(listener.Port) != *parentRef.Port {
				continue
			}
			return true, ""
		}
	}

	return false, "No matching TCP listener found on Gateway"
}

// validateBackendRefs validates backend references
func (r *TCPRouteReconciler) validateBackendRefs(ctx context.Context, tcpRoute *avapigwv1alpha1.TCPRoute) error {
	logger := log.FromContext(ctx)

	for _, rule := range tcpRoute.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			namespace := tcpRoute.Namespace
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
						r.Recorder.Event(tcpRoute, corev1.EventTypeWarning, "BackendNotFound",
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
						r.Recorder.Event(tcpRoute, corev1.EventTypeWarning, "BackendNotFound",
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

// findTCPRoutesForGateway finds TCPRoutes that reference a Gateway
func (r *TCPRouteReconciler) findTCPRoutesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)
	var requests []reconcile.Request

	var tcpRoutes avapigwv1alpha1.TCPRouteList
	if err := r.List(ctx, &tcpRoutes); err != nil {
		return requests
	}

	for _, route := range tcpRoutes.Items {
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

// findTCPRoutesForBackend finds TCPRoutes that reference a Backend
func (r *TCPRouteReconciler) findTCPRoutesForBackend(ctx context.Context, obj client.Object) []reconcile.Request {
	backend := obj.(*avapigwv1alpha1.Backend)
	var requests []reconcile.Request

	var tcpRoutes avapigwv1alpha1.TCPRouteList
	if err := r.List(ctx, &tcpRoutes); err != nil {
		return requests
	}

	for _, route := range tcpRoutes.Items {
		for _, rule := range route.Spec.Rules {
			for _, backendRef := range rule.BackendRefs {
				namespace := route.Namespace
				if backendRef.Namespace != nil {
					namespace = *backendRef.Namespace
				}
				kind := "Service"
				if backendRef.Kind != nil {
					kind = *backendRef.Kind
				}
				if kind == "Backend" && namespace == backend.Namespace && backendRef.Name == backend.Name {
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

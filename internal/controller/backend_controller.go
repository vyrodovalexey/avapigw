// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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
	backendFinalizer = "avapigw.vyrodovalexey.github.com/backend-finalizer"

	// backendReconcileTimeout is the maximum duration for a single Backend reconciliation
	backendReconcileTimeout = 30 * time.Second
)

// Prometheus metrics for Backend controller
var (
	backendReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "backend_reconcile_duration_seconds",
			Help:      "Duration of Backend reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	backendReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "backend_reconcile_total",
			Help:      "Total number of Backend reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(backendReconcileDuration, backendReconcileTotal)
}

// BackendReconciler reconciles a Backend object
type BackendReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy
}

// getRequeueStrategy returns the requeue strategy, initializing with defaults if needed.
// Uses sync.Once to ensure thread-safe initialization and prevent race conditions
// when multiple goroutines access the strategy concurrently.
func (r *BackendReconciler) getRequeueStrategy() *RequeueStrategy {
	r.requeueStrategyOnce.Do(func() {
		if r.RequeueStrategy == nil {
			r.RequeueStrategy = DefaultRequeueStrategy()
		}
	})
	return r.RequeueStrategy
}

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles Backend reconciliation
func (r *BackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add timeout to prevent hanging reconciliations
	ctx, cancel := context.WithTimeout(ctx, backendReconcileTimeout)
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
		backendReconcileDuration.WithLabelValues(result).Observe(duration)
		backendReconcileTotal.WithLabelValues(result).Inc()
	}()

	logger.Info("Reconciling Backend",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the Backend instance
	backend := &avapigwv1alpha1.Backend{}
	if err := r.Get(ctx, req.NamespacedName, backend); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Backend not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return ctrl.Result{}, nil
		}
		reconcileErr = ClassifyError("getBackend", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get Backend",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}

	// Handle deletion
	if !backend.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, backend)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(backend, backendFinalizer) {
		controllerutil.AddFinalizer(backend, backendFinalizer)
		if err := r.Update(ctx, backend); err != nil {
			reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to add finalizer",
				"errorType", reconcileErr.Type,
			)
			r.Recorder.Event(backend, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
		return strategy.ForImmediateRequeue(), nil
	}

	// Reconcile the Backend
	if err := r.reconcileBackend(ctx, backend); err != nil {
		reconcileErr = ClassifyError("reconcileBackend", resourceKey, err)
		logger.Error(reconcileErr, "Failed to reconcile Backend",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
			"userActionRequired", reconcileErr.UserActionRequired,
		)
		r.Recorder.Event(backend, corev1.EventTypeWarning, string(reconcileErr.Type)+"Error", err.Error())

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

	// Success - reset failure count and use custom interval based on health check
	strategy.ResetFailureCount(resourceKey)

	// Determine requeue interval based on health check configuration
	requeueAfter := strategy.ForSuccess().RequeueAfter
	if backend.Spec.HealthCheck != nil && backend.Spec.HealthCheck.Interval != nil {
		// Parse interval and use it for requeue
		if interval, err := time.ParseDuration(string(*backend.Spec.HealthCheck.Interval)); err == nil {
			requeueAfter = interval
		}
	}

	logger.Info("Backend reconciled successfully",
		"name", req.Name,
		"namespace", req.Namespace,
		"nextCheck", requeueAfter,
	)
	return strategy.ForCustomInterval(requeueAfter), nil
}

// handleDeletion handles Backend deletion
func (r *BackendReconciler) handleDeletion(ctx context.Context, backend *avapigwv1alpha1.Backend) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(backend).String()

	if controllerutil.ContainsFinalizer(backend, backendFinalizer) {
		// Perform cleanup
		logger.Info("Performing cleanup for Backend deletion",
			"name", backend.Name,
			"namespace", backend.Namespace,
		)

		// Record event
		r.Recorder.Event(backend, corev1.EventTypeNormal, "Deleting", "Backend is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(backend, backendFinalizer)
		if err := r.Update(ctx, backend); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
}

// reconcileBackend performs the main reconciliation logic
func (r *BackendReconciler) reconcileBackend(ctx context.Context, backend *avapigwv1alpha1.Backend) error {
	logger := log.FromContext(ctx)

	// Update status
	backend.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	backend.Status.ObservedGeneration = backend.Generation
	backend.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}

	// Discover endpoints
	endpoints, err := r.discoverEndpoints(ctx, backend)
	if err != nil {
		logger.Error(err, "Failed to discover endpoints")
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeResolvedRefs, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonRefNotFound), err.Error())
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusError
		return r.updateStatus(ctx, backend)
	}

	// Update endpoint statuses
	backend.Status.Endpoints = endpoints
	backend.Status.TotalEndpoints = int32(len(endpoints))

	// Count healthy endpoints
	healthyCount := int32(0)
	for _, ep := range endpoints {
		if ep.Healthy {
			healthyCount++
		}
	}
	backend.Status.HealthyEndpoints = healthyCount

	// Set conditions based on endpoint health
	if backend.Status.TotalEndpoints == 0 {
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonNotReady), "No endpoints available")
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusError
	} else if backend.Status.HealthyEndpoints == 0 {
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonDegraded), "No healthy endpoints")
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusDegraded
	} else if backend.Status.HealthyEndpoints < backend.Status.TotalEndpoints {
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			string(avapigwv1alpha1.ReasonDegraded), fmt.Sprintf("%d/%d endpoints healthy", healthyCount, backend.Status.TotalEndpoints))
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusDegraded
	} else {
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			string(avapigwv1alpha1.ReasonReady), "All endpoints healthy")
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusReady
	}

	r.setCondition(backend, avapigwv1alpha1.ConditionTypeResolvedRefs, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonResolvedRefs), "All references resolved")

	// Update status
	if err := r.updateStatus(ctx, backend); err != nil {
		return err
	}

	r.Recorder.Event(backend, corev1.EventTypeNormal, "Reconciled",
		fmt.Sprintf("Backend reconciled: %d/%d endpoints healthy", healthyCount, backend.Status.TotalEndpoints))
	return nil
}

// discoverEndpoints discovers endpoints for the backend
func (r *BackendReconciler) discoverEndpoints(ctx context.Context, backend *avapigwv1alpha1.Backend) ([]avapigwv1alpha1.EndpointStatus, error) {
	var endpoints []avapigwv1alpha1.EndpointStatus

	// If direct endpoints are specified, use them
	if len(backend.Spec.Endpoints) > 0 {
		for _, ep := range backend.Spec.Endpoints {
			endpoints = append(endpoints, avapigwv1alpha1.EndpointStatus{
				Address:       ep.Address,
				Port:          ep.Port,
				Healthy:       true, // Assume healthy for direct endpoints until health check runs
				LastCheckTime: &metav1.Time{Time: time.Now()},
			})
		}
		return endpoints, nil
	}

	// If service reference is specified, discover endpoints from service
	if backend.Spec.Service != nil {
		return r.discoverServiceEndpoints(ctx, backend)
	}

	return nil, fmt.Errorf("no endpoints or service reference specified")
}

// discoverServiceEndpoints discovers endpoints from a Kubernetes Service
func (r *BackendReconciler) discoverServiceEndpoints(ctx context.Context, backend *avapigwv1alpha1.Backend) ([]avapigwv1alpha1.EndpointStatus, error) {
	var endpoints []avapigwv1alpha1.EndpointStatus

	serviceRef := backend.Spec.Service
	namespace := backend.Namespace
	if serviceRef.Namespace != nil {
		namespace = *serviceRef.Namespace
	}

	// First, verify the service exists
	svc := &corev1.Service{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: serviceRef.Name}, svc); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("service %s/%s not found", namespace, serviceRef.Name)
		}
		return nil, fmt.Errorf("failed to get service %s/%s: %w", namespace, serviceRef.Name, err)
	}

	// Try to get EndpointSlices first (preferred in newer Kubernetes versions)
	logger := log.FromContext(ctx)
	endpointSlices := &discoveryv1.EndpointSliceList{}
	if err := r.List(ctx, endpointSlices, client.InNamespace(namespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: serviceRef.Name}); err != nil {
		logger.V(1).Info("Failed to list EndpointSlices, falling back to Endpoints", "error", err)
	} else if len(endpointSlices.Items) > 0 {
		// Use EndpointSlices
		for _, slice := range endpointSlices.Items {
			for _, ep := range slice.Endpoints {
				if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
					for _, addr := range ep.Addresses {
						// Find the matching port
						port := serviceRef.Port
						for _, p := range slice.Ports {
							if p.Port != nil && *p.Port == serviceRef.Port {
								port = *p.Port
								break
							}
						}
						endpoints = append(endpoints, avapigwv1alpha1.EndpointStatus{
							Address:         addr,
							Port:            port,
							Healthy:         ep.Conditions.Ready == nil || *ep.Conditions.Ready,
							LastCheckTime:   &metav1.Time{Time: time.Now()},
							LastHealthyTime: &metav1.Time{Time: time.Now()},
						})
					}
				}
			}
		}
		return endpoints, nil
	}

	// Fall back to Endpoints
	eps := &corev1.Endpoints{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: serviceRef.Name}, eps); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("endpoints for service %s/%s not found", namespace, serviceRef.Name)
		}
		return nil, fmt.Errorf("failed to get endpoints for service %s/%s: %w", namespace, serviceRef.Name, err)
	}

	for _, subset := range eps.Subsets {
		// Find the matching port
		port := serviceRef.Port
		for _, p := range subset.Ports {
			if p.Port == serviceRef.Port {
				port = p.Port
				break
			}
		}

		// Add ready addresses
		for _, addr := range subset.Addresses {
			endpoints = append(endpoints, avapigwv1alpha1.EndpointStatus{
				Address:         addr.IP,
				Port:            port,
				Healthy:         true,
				LastCheckTime:   &metav1.Time{Time: time.Now()},
				LastHealthyTime: &metav1.Time{Time: time.Now()},
			})
		}

		// Add not-ready addresses as unhealthy
		for _, addr := range subset.NotReadyAddresses {
			reason := "NotReady"
			endpoints = append(endpoints, avapigwv1alpha1.EndpointStatus{
				Address:       addr.IP,
				Port:          port,
				Healthy:       false,
				LastCheckTime: &metav1.Time{Time: time.Now()},
				FailureReason: &reason,
			})
		}
	}

	return endpoints, nil
}

// setCondition sets a condition on the backend status
func (r *BackendReconciler) setCondition(backend *avapigwv1alpha1.Backend, conditionType avapigwv1alpha1.ConditionType, status metav1.ConditionStatus, reason, message string) {
	backend.Status.SetCondition(conditionType, status, reason, message)
}

// updateStatus updates the backend status
func (r *BackendReconciler) updateStatus(ctx context.Context, backend *avapigwv1alpha1.Backend) error {
	return r.Status().Update(ctx, backend)
}

// SetupWithManager sets up the controller with the Manager
func (r *BackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.Backend{}).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(r.findBackendsForService),
		).
		Watches(
			&corev1.Endpoints{},
			handler.EnqueueRequestsFromMapFunc(r.findBackendsForEndpoints),
		).
		Complete(r)
}

// findBackendsForService finds Backends that reference a Service
func (r *BackendReconciler) findBackendsForService(ctx context.Context, obj client.Object) []reconcile.Request {
	svc := obj.(*corev1.Service)
	var requests []reconcile.Request

	var backends avapigwv1alpha1.BackendList
	if err := r.List(ctx, &backends); err != nil {
		return requests
	}

	for _, backend := range backends.Items {
		if backend.Spec.Service != nil {
			namespace := backend.Namespace
			if backend.Spec.Service.Namespace != nil {
				namespace = *backend.Spec.Service.Namespace
			}
			if namespace == svc.Namespace && backend.Spec.Service.Name == svc.Name {
				requests = append(requests, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Namespace: backend.Namespace,
						Name:      backend.Name,
					},
				})
			}
		}
	}

	return requests
}

// findBackendsForEndpoints finds Backends that reference Endpoints
func (r *BackendReconciler) findBackendsForEndpoints(ctx context.Context, obj client.Object) []reconcile.Request {
	eps := obj.(*corev1.Endpoints)
	var requests []reconcile.Request

	var backends avapigwv1alpha1.BackendList
	if err := r.List(ctx, &backends); err != nil {
		return requests
	}

	for _, backend := range backends.Items {
		if backend.Spec.Service != nil {
			namespace := backend.Namespace
			if backend.Spec.Service.Namespace != nil {
				namespace = *backend.Spec.Service.Namespace
			}
			// Endpoints have the same name as the Service
			if namespace == eps.Namespace && backend.Spec.Service.Name == eps.Name {
				requests = append(requests, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Namespace: backend.Namespace,
						Name:      backend.Name,
					},
				})
			}
		}
	}

	return requests
}

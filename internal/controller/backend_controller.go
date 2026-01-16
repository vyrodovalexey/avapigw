// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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
	backendFinalizer        = BackendFinalizerName
	backendReconcileTimeout = BackendReconcileTimeout
)

// BackendReconciler reconciles a Backend object
type BackendReconciler struct {
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
func (r *BackendReconciler) getRequeueStrategy() *RequeueStrategy {
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
func (r *BackendReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("backend")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, backendFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *BackendReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=backends/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles Backend reconciliation
func (r *BackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, backendReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling Backend",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the Backend instance
	backend, result, err := r.fetchBackend(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if backend == nil {
		return result, nil
	}

	// Handle deletion
	if !backend.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, backend)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Ensure finalizer and reconcile
	return r.ensureFinalizerAndReconcileBackend(ctx, backend, strategy, resourceKey, &reconcileErr)
}

// fetchBackend fetches the Backend instance and handles not-found errors.
func (r *BackendReconciler) fetchBackend(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.Backend, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	backend := &avapigwv1alpha1.Backend{}
	if err := r.Get(ctx, req.NamespacedName, backend); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Backend not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getBackend", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get Backend",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return backend, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcileBackend ensures the finalizer is present and performs reconciliation.
func (r *BackendReconciler) ensureFinalizerAndReconcileBackend(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Add finalizer if not present
	if !r.finalizerHandler.HasFinalizer(backend) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, backend)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(backend, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	// Reconcile the Backend
	if err := r.reconcileBackend(ctx, backend); err != nil {
		*reconcileErr = ClassifyError("reconcileBackend", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile Backend",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
			"userActionRequired", (*reconcileErr).UserActionRequired,
		)
		r.Recorder.Event(backend, corev1.EventTypeWarning, string((*reconcileErr).Type)+"Error", err.Error())
		return r.handleReconcileError(*reconcileErr, strategy, resourceKey)
	}

	return r.handleReconcileSuccess(ctx, backend, strategy, resourceKey)
}

// handleReconcileError returns the appropriate result based on error type.
func (r *BackendReconciler) handleReconcileError(
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

// handleReconcileSuccess handles successful reconciliation and determines requeue interval.
func (r *BackendReconciler) handleReconcileSuccess(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
	strategy *RequeueStrategy,
	resourceKey string,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	strategy.ResetFailureCount(resourceKey)

	requeueAfter := strategy.ForSuccess().RequeueAfter
	if backend.Spec.HealthCheck != nil && backend.Spec.HealthCheck.Interval != nil {
		if interval, err := time.ParseDuration(string(*backend.Spec.HealthCheck.Interval)); err == nil {
			requeueAfter = interval
		}
	}

	logger.Info("Backend reconciled successfully",
		"name", backend.Name,
		"namespace", backend.Namespace,
		"nextCheck", requeueAfter,
	)
	return strategy.ForCustomInterval(requeueAfter), nil
}

// handleDeletion handles Backend deletion
func (r *BackendReconciler) handleDeletion(ctx context.Context, backend *avapigwv1alpha1.Backend) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(backend).String()

	if r.finalizerHandler.HasFinalizer(backend) {
		// Perform cleanup
		logger.Info("Performing cleanup for Backend deletion",
			"name", backend.Name,
			"namespace", backend.Namespace,
		)

		// Record event
		r.Recorder.Event(backend, corev1.EventTypeNormal, "Deleting", "Backend is being deleted")

		// Remove finalizer
		if _, err := r.finalizerHandler.RemoveFinalizer(ctx, backend); err != nil {
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
	resourceKey := client.ObjectKeyFromObject(backend).String()

	r.initBackendStatus(backend)

	// Discover endpoints
	endpoints, err := r.discoverEndpoints(ctx, backend)
	if err != nil {
		return r.handleEndpointDiscoveryError(ctx, backend, resourceKey, err, logger)
	}

	// Update endpoint statuses and set conditions
	healthyCount := r.updateEndpointStatus(backend, endpoints)
	r.setEndpointHealthConditions(backend, healthyCount)

	// Update status
	if err := r.updateStatus(ctx, backend); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update Backend status", "errorType", reconcileErr.Type)
		return reconcileErr
	}

	r.Recorder.Event(backend, corev1.EventTypeNormal, EventReasonReconciled,
		fmt.Sprintf("Backend reconciled: %d/%d endpoints healthy", healthyCount, backend.Status.TotalEndpoints))
	return nil
}

// initBackendStatus initializes the backend status for reconciliation.
func (r *BackendReconciler) initBackendStatus(backend *avapigwv1alpha1.Backend) {
	backend.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	backend.Status.ObservedGeneration = backend.Generation
	backend.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}
}

// handleEndpointDiscoveryError handles errors during endpoint discovery.
func (r *BackendReconciler) handleEndpointDiscoveryError(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
	resourceKey string,
	err error,
	logger logr.Logger,
) error {
	reconcileErr := ClassifyError("discoverEndpoints", resourceKey, err)
	logger.Error(reconcileErr, "Failed to discover endpoints", "errorType", reconcileErr.Type)
	r.setCondition(backend, avapigwv1alpha1.ConditionTypeResolvedRefs, metav1.ConditionFalse,
		string(avapigwv1alpha1.ReasonRefNotFound), err.Error())
	backend.Status.Phase = avapigwv1alpha1.PhaseStatusError
	return r.updateStatus(ctx, backend)
}

// updateEndpointStatus updates the backend status with endpoint information.
func (r *BackendReconciler) updateEndpointStatus(
	backend *avapigwv1alpha1.Backend,
	endpoints []avapigwv1alpha1.EndpointStatus,
) int32 {
	backend.Status.Endpoints = endpoints
	backend.Status.TotalEndpoints = safeIntToInt32(len(endpoints))

	healthyCount := int32(0)
	for _, ep := range endpoints {
		if ep.Healthy {
			healthyCount++
		}
	}
	backend.Status.HealthyEndpoints = healthyCount
	return healthyCount
}

// setEndpointHealthConditions sets conditions based on endpoint health.
func (r *BackendReconciler) setEndpointHealthConditions(
	backend *avapigwv1alpha1.Backend,
	healthyCount int32,
) {
	switch {
	case backend.Status.TotalEndpoints == 0:
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonNotReady), "No endpoints available")
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusError
	case backend.Status.HealthyEndpoints == 0:
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonDegraded), "No healthy endpoints")
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusDegraded
	case backend.Status.HealthyEndpoints < backend.Status.TotalEndpoints:
		msg := fmt.Sprintf("%d/%d endpoints healthy", healthyCount, backend.Status.TotalEndpoints)
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			string(avapigwv1alpha1.ReasonDegraded), msg)
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusDegraded
	default:
		r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			string(avapigwv1alpha1.ReasonReady), "All endpoints healthy")
		backend.Status.Phase = avapigwv1alpha1.PhaseStatusReady
	}

	r.setCondition(backend, avapigwv1alpha1.ConditionTypeResolvedRefs, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonResolvedRefs), "All references resolved")
}

// discoverEndpoints discovers endpoints for the backend
func (r *BackendReconciler) discoverEndpoints(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) ([]avapigwv1alpha1.EndpointStatus, error) {
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
func (r *BackendReconciler) discoverServiceEndpoints(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) ([]avapigwv1alpha1.EndpointStatus, error) {
	serviceRef := backend.Spec.Service
	namespace := backend.Namespace
	if serviceRef.Namespace != nil {
		namespace = *serviceRef.Namespace
	}

	// First, verify the service exists
	if err := r.verifyServiceExists(ctx, namespace, serviceRef.Name); err != nil {
		return nil, err
	}

	// Try to get EndpointSlices first (preferred in newer Kubernetes versions)
	endpoints, found := r.discoverFromEndpointSlices(ctx, namespace, serviceRef)
	if found {
		return endpoints, nil
	}

	// Fall back to Endpoints
	return r.discoverFromEndpoints(ctx, namespace, serviceRef)
}

// verifyServiceExists verifies that the service exists.
func (r *BackendReconciler) verifyServiceExists(ctx context.Context, namespace, name string) error {
	svc := &corev1.Service{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, svc); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("service %s/%s not found", namespace, name)
		}
		return fmt.Errorf("failed to get service %s/%s: %w", namespace, name, err)
	}
	return nil
}

// discoverFromEndpointSlices discovers endpoints from EndpointSlices.
func (r *BackendReconciler) discoverFromEndpointSlices(
	ctx context.Context,
	namespace string,
	serviceRef *avapigwv1alpha1.ServiceRef,
) ([]avapigwv1alpha1.EndpointStatus, bool) {
	logger := log.FromContext(ctx)
	endpointSlices := &discoveryv1.EndpointSliceList{}
	if err := r.List(ctx, endpointSlices, client.InNamespace(namespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: serviceRef.Name}); err != nil {
		logger.V(1).Info("Failed to list EndpointSlices, falling back to Endpoints", "error", err)
		return nil, false
	}

	if len(endpointSlices.Items) == 0 {
		return nil, false
	}

	var endpoints []avapigwv1alpha1.EndpointStatus
	for _, slice := range endpointSlices.Items {
		endpoints = append(endpoints, r.extractEndpointsFromSlice(&slice, serviceRef.Port)...)
	}
	return endpoints, true
}

// extractEndpointsFromSlice extracts endpoints from a single EndpointSlice.
func (r *BackendReconciler) extractEndpointsFromSlice(
	slice *discoveryv1.EndpointSlice,
	targetPort int32,
) []avapigwv1alpha1.EndpointStatus {
	var endpoints []avapigwv1alpha1.EndpointStatus
	for _, ep := range slice.Endpoints {
		if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
			continue
		}
		for _, addr := range ep.Addresses {
			port := r.findMatchingPort(slice.Ports, targetPort)
			endpoints = append(endpoints, avapigwv1alpha1.EndpointStatus{
				Address:         addr,
				Port:            port,
				Healthy:         ep.Conditions.Ready == nil || *ep.Conditions.Ready,
				LastCheckTime:   &metav1.Time{Time: time.Now()},
				LastHealthyTime: &metav1.Time{Time: time.Now()},
			})
		}
	}
	return endpoints
}

// findMatchingPort finds the matching port from EndpointSlice ports.
func (r *BackendReconciler) findMatchingPort(ports []discoveryv1.EndpointPort, targetPort int32) int32 {
	for _, p := range ports {
		if p.Port != nil && *p.Port == targetPort {
			return *p.Port
		}
	}
	return targetPort
}

// discoverFromEndpoints discovers endpoints from the legacy Endpoints resource.
func (r *BackendReconciler) discoverFromEndpoints(
	ctx context.Context,
	namespace string,
	serviceRef *avapigwv1alpha1.ServiceRef,
) ([]avapigwv1alpha1.EndpointStatus, error) {
	eps := &corev1.Endpoints{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: serviceRef.Name}, eps); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("endpoints for service %s/%s not found", namespace, serviceRef.Name)
		}
		return nil, fmt.Errorf("failed to get endpoints for service %s/%s: %w", namespace, serviceRef.Name, err)
	}

	var endpoints []avapigwv1alpha1.EndpointStatus
	for _, subset := range eps.Subsets {
		port := r.findMatchingSubsetPort(subset.Ports, serviceRef.Port)
		endpoints = append(endpoints, r.extractEndpointsFromSubset(&subset, port)...)
	}
	return endpoints, nil
}

// findMatchingSubsetPort finds the matching port from EndpointSubset ports.
func (r *BackendReconciler) findMatchingSubsetPort(ports []corev1.EndpointPort, targetPort int32) int32 {
	for _, p := range ports {
		if p.Port == targetPort {
			return p.Port
		}
	}
	return targetPort
}

// extractEndpointsFromSubset extracts endpoints from a single EndpointSubset.
func (r *BackendReconciler) extractEndpointsFromSubset(
	subset *corev1.EndpointSubset,
	port int32,
) []avapigwv1alpha1.EndpointStatus {
	// Pre-allocate slice with capacity for all addresses
	totalAddresses := len(subset.Addresses) + len(subset.NotReadyAddresses)
	endpoints := make([]avapigwv1alpha1.EndpointStatus, 0, totalAddresses)

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

	return endpoints
}

// setCondition sets a condition on the backend status
func (r *BackendReconciler) setCondition(
	backend *avapigwv1alpha1.Backend,
	conditionType avapigwv1alpha1.ConditionType,
	status metav1.ConditionStatus,
	reason, message string,
) {
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

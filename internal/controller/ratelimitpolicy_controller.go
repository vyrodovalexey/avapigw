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
	policyutil "github.com/vyrodovalexey/avapigw/internal/controller/policy"
)

// Local aliases for constants to maintain backward compatibility.
// These reference the centralized constants from constants.go.
const (
	rateLimitPolicyFinalizer        = RateLimitPolicyFinalizerName
	rateLimitPolicyReconcileTimeout = RateLimitPolicyReconcileTimeout
)

// RateLimitPolicyReconciler reconciles a RateLimitPolicy object
type RateLimitPolicyReconciler struct {
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
func (r *RateLimitPolicyReconciler) getRequeueStrategy() *RequeueStrategy {
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
func (r *RateLimitPolicyReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("ratelimitpolicy")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, rateLimitPolicyFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *RateLimitPolicyReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=ratelimitpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=ratelimitpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=ratelimitpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles RateLimitPolicy reconciliation
func (r *RateLimitPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, rateLimitPolicyReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling RateLimitPolicy", "name", req.Name, "namespace", req.Namespace)

	policy, result, err := r.fetchRateLimitPolicy(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if policy == nil {
		return result, nil
	}

	if !policy.DeletionTimestamp.IsZero() {
		result, delErr := r.handleDeletion(ctx, policy)
		if delErr == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, delErr
	}

	return r.ensureFinalizerAndReconcile(ctx, policy, strategy, resourceKey, &reconcileErr)
}

// fetchRateLimitPolicy fetches the RateLimitPolicy instance and handles not-found errors.
func (r *RateLimitPolicyReconciler) fetchRateLimitPolicy(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.RateLimitPolicy, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	policy := &avapigwv1alpha1.RateLimitPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("RateLimitPolicy not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getRateLimitPolicy", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get RateLimitPolicy",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return policy, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcile ensures the finalizer is present and performs reconciliation.
func (r *RateLimitPolicyReconciler) ensureFinalizerAndReconcile(
	ctx context.Context,
	policy *avapigwv1alpha1.RateLimitPolicy,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if !r.finalizerHandler.HasFinalizer(policy) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, policy)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(policy, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	if err := r.reconcileRateLimitPolicy(ctx, policy); err != nil {
		*reconcileErr = ClassifyError("reconcileRateLimitPolicy", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile RateLimitPolicy",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
		)
		r.Recorder.Event(policy, corev1.EventTypeWarning, "ReconcileError", err.Error())
		return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
	}

	strategy.ResetFailureCount(resourceKey)
	return strategy.ForSuccess(), nil
}

// handleDeletion handles RateLimitPolicy deletion
func (r *RateLimitPolicyReconciler) handleDeletion(
	ctx context.Context,
	policy *avapigwv1alpha1.RateLimitPolicy,
) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(policy).String()

	if r.finalizerHandler.HasFinalizer(policy) {
		// Perform cleanup
		logger.Info("Performing cleanup for RateLimitPolicy deletion")

		// Record event
		r.Recorder.Event(policy, corev1.EventTypeNormal, "Deleting", "RateLimitPolicy is being deleted")

		// Remove finalizer
		if _, err := r.finalizerHandler.RemoveFinalizer(ctx, policy); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
}

// reconcileRateLimitPolicy performs the main reconciliation logic
func (r *RateLimitPolicyReconciler) reconcileRateLimitPolicy(
	ctx context.Context,
	policy *avapigwv1alpha1.RateLimitPolicy,
) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(policy).String()

	// Update status
	policy.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}

	// Validate target reference
	if err := r.validateTargetRef(ctx, policy); err != nil {
		reconcileErr := ClassifyError("validateTargetRef", resourceKey, err)
		logger.Error(reconcileErr, "Failed to validate target reference",
			"errorType", reconcileErr.Type,
		)
		r.setCondition(policy, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonInvalidRef), err.Error())
		policy.Status.Phase = avapigwv1alpha1.PhaseStatusError
		return r.updateStatus(ctx, policy)
	}

	// Validate storage configuration if Redis is used
	if policy.Spec.Storage != nil && policy.Spec.Storage.Type == avapigwv1alpha1.RateLimitStorageRedis {
		if err := r.validateRedisConfig(ctx, policy); err != nil {
			reconcileErr := ClassifyError("validateRedisConfig", resourceKey, err)
			logger.Error(reconcileErr, "Failed to validate Redis configuration",
				"errorType", reconcileErr.Type,
			)
			r.setCondition(policy, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
				string(avapigwv1alpha1.ReasonNotReady), err.Error())
			policy.Status.Phase = avapigwv1alpha1.PhaseStatusError
			return r.updateStatus(ctx, policy)
		}
	}

	// Set conditions
	r.setCondition(policy, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonAccepted), "RateLimitPolicy configuration accepted")
	r.setCondition(policy, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonReady), "RateLimitPolicy is ready")

	policy.Status.Phase = avapigwv1alpha1.PhaseStatusReady

	// Update status
	if err := r.updateStatus(ctx, policy); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update RateLimitPolicy status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, EventReasonReconciled, "RateLimitPolicy reconciled successfully")
	return nil
}

// validateTargetRef validates the target reference using the shared policy validator.
func (r *RateLimitPolicyReconciler) validateTargetRef(ctx context.Context, p *avapigwv1alpha1.RateLimitPolicy) error {
	validator := policyutil.NewTargetRefValidator(r.Client)
	return validator.ValidateTargetRef(ctx, p)
}

// validateRedisConfig validates Redis storage configuration
func (r *RateLimitPolicyReconciler) validateRedisConfig(
	ctx context.Context,
	policy *avapigwv1alpha1.RateLimitPolicy,
) error {
	if policy.Spec.Storage == nil || policy.Spec.Storage.Redis == nil {
		return fmt.Errorf("redis configuration is required when storage type is redis")
	}

	redis := policy.Spec.Storage.Redis

	// Validate address
	if redis.Address == "" {
		return fmt.Errorf("redis address is required")
	}

	// Validate secret reference if provided
	if redis.SecretRef != nil {
		namespace := policy.Namespace
		if redis.SecretRef.Namespace != nil {
			namespace = *redis.SecretRef.Namespace
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: redis.SecretRef.Name}, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("redis secret %s/%s not found", namespace, redis.SecretRef.Name)
			}
			return fmt.Errorf("failed to get Redis secret %s/%s: %w", namespace, redis.SecretRef.Name, err)
		}
	}

	// Validate TLS CA cert reference if provided
	if redis.TLS != nil && redis.TLS.CACertRef != nil {
		namespace := policy.Namespace
		if redis.TLS.CACertRef.Namespace != nil {
			namespace = *redis.TLS.CACertRef.Namespace
		}

		secret := &corev1.Secret{}
		secretKey := client.ObjectKey{Namespace: namespace, Name: redis.TLS.CACertRef.Name}
		if err := r.Get(ctx, secretKey, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("redis TLS CA cert secret %s/%s not found", namespace, redis.TLS.CACertRef.Name)
			}
			return fmt.Errorf(
				"failed to get Redis TLS CA cert secret %s/%s: %w",
				namespace, redis.TLS.CACertRef.Name, err,
			)
		}
	}

	return nil
}

// setCondition sets a condition on the policy status
func (r *RateLimitPolicyReconciler) setCondition(
	policy *avapigwv1alpha1.RateLimitPolicy,
	conditionType avapigwv1alpha1.ConditionType,
	status metav1.ConditionStatus,
	reason, message string,
) {
	policy.Status.SetCondition(conditionType, status, reason, message)
}

// updateStatus updates the policy status
func (r *RateLimitPolicyReconciler) updateStatus(ctx context.Context, policy *avapigwv1alpha1.RateLimitPolicy) error {
	return r.Status().Update(ctx, policy)
}

// SetupWithManager sets up the controller with the Manager
func (r *RateLimitPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.RateLimitPolicy{}).
		Watches(
			&avapigwv1alpha1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(r.findPoliciesForGateway),
		).
		Watches(
			&avapigwv1alpha1.HTTPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.findPoliciesForHTTPRoute),
		).
		Watches(
			&avapigwv1alpha1.GRPCRoute{},
			handler.EnqueueRequestsFromMapFunc(r.findPoliciesForGRPCRoute),
		).
		Complete(r)
}

// findPoliciesForGateway finds RateLimitPolicies that target a Gateway
func (r *RateLimitPolicyReconciler) findPoliciesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)
	return r.findPoliciesForTarget(ctx, "Gateway", gateway.Namespace, gateway.Name)
}

// findPoliciesForHTTPRoute finds RateLimitPolicies that target an HTTPRoute
func (r *RateLimitPolicyReconciler) findPoliciesForHTTPRoute(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	route := obj.(*avapigwv1alpha1.HTTPRoute)
	return r.findPoliciesForTarget(ctx, "HTTPRoute", route.Namespace, route.Name)
}

// findPoliciesForGRPCRoute finds RateLimitPolicies that target a GRPCRoute
func (r *RateLimitPolicyReconciler) findPoliciesForGRPCRoute(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	route := obj.(*avapigwv1alpha1.GRPCRoute)
	return r.findPoliciesForTarget(ctx, "GRPCRoute", route.Namespace, route.Name)
}

// findPoliciesForTarget finds RateLimitPolicies that target a specific resource
// using the shared watch handler.
func (r *RateLimitPolicyReconciler) findPoliciesForTarget(
	ctx context.Context,
	kind, namespace, name string,
) []reconcile.Request {
	watchHandler := policyutil.NewPolicyWatchHandler[*avapigwv1alpha1.RateLimitPolicy](
		r.Client, &avapigwv1alpha1.RateLimitPolicyList{},
	)
	return watchHandler.FindPoliciesForTarget(ctx, kind, namespace, name)
}

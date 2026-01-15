// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"fmt"
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
	rateLimitPolicyFinalizer = "avapigw.vyrodovalexey.github.com/ratelimitpolicy-finalizer"

	// rateLimitPolicyReconcileTimeout is the maximum duration for a single RateLimitPolicy reconciliation
	rateLimitPolicyReconcileTimeout = 30 * time.Second
)

// Prometheus metrics for RateLimitPolicy controller
var (
	rateLimitPolicyReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "ratelimitpolicy_reconcile_duration_seconds",
			Help:      "Duration of RateLimitPolicy reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	rateLimitPolicyReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "ratelimitpolicy_reconcile_total",
			Help:      "Total number of RateLimitPolicy reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(rateLimitPolicyReconcileDuration, rateLimitPolicyReconcileTotal)
}

// RateLimitPolicyReconciler reconciles a RateLimitPolicy object
type RateLimitPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=ratelimitpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=ratelimitpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=ratelimitpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles RateLimitPolicy reconciliation
func (r *RateLimitPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add timeout to prevent hanging reconciliations
	ctx, cancel := context.WithTimeout(ctx, rateLimitPolicyReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)

	// Track reconciliation metrics
	start := time.Now()
	var reconcileResult = "success"
	defer func() {
		duration := time.Since(start).Seconds()
		rateLimitPolicyReconcileDuration.WithLabelValues(reconcileResult).Observe(duration)
		rateLimitPolicyReconcileTotal.WithLabelValues(reconcileResult).Inc()
	}()

	logger.Info("Reconciling RateLimitPolicy", "name", req.Name, "namespace", req.Namespace)

	// Fetch the RateLimitPolicy instance
	policy := &avapigwv1alpha1.RateLimitPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("RateLimitPolicy not found, ignoring")
			return ctrl.Result{}, nil
		}
		reconcileResult = MetricResultError
		logger.Error(err, "Failed to get RateLimitPolicy")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, policy)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(policy, rateLimitPolicyFinalizer) {
		controllerutil.AddFinalizer(policy, rateLimitPolicyFinalizer)
		if err := r.Update(ctx, policy); err != nil {
			reconcileResult = MetricResultError
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the RateLimitPolicy
	if err := r.reconcileRateLimitPolicy(ctx, policy); err != nil {
		reconcileResult = MetricResultError
		logger.Error(err, "Failed to reconcile RateLimitPolicy")
		r.Recorder.Event(policy, corev1.EventTypeWarning, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// handleDeletion handles RateLimitPolicy deletion
//
//nolint:unparam // result kept for API consistency with other controllers
func (r *RateLimitPolicyReconciler) handleDeletion(ctx context.Context, policy *avapigwv1alpha1.RateLimitPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(policy, rateLimitPolicyFinalizer) {
		// Perform cleanup
		logger.Info("Performing cleanup for RateLimitPolicy deletion")

		// Record event
		r.Recorder.Event(policy, corev1.EventTypeNormal, "Deleting", "RateLimitPolicy is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(policy, rateLimitPolicyFinalizer)
		if err := r.Update(ctx, policy); err != nil {
			logger.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// reconcileRateLimitPolicy performs the main reconciliation logic
func (r *RateLimitPolicyReconciler) reconcileRateLimitPolicy(ctx context.Context, policy *avapigwv1alpha1.RateLimitPolicy) error {
	logger := log.FromContext(ctx)

	// Update status
	policy.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}

	// Validate target reference
	if err := r.validateTargetRef(ctx, policy); err != nil {
		logger.Error(err, "Failed to validate target reference")
		r.setCondition(policy, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonInvalidRef), err.Error())
		policy.Status.Phase = avapigwv1alpha1.PhaseStatusError
		return r.updateStatus(ctx, policy)
	}

	// Validate storage configuration if Redis is used
	if policy.Spec.Storage != nil && policy.Spec.Storage.Type == avapigwv1alpha1.RateLimitStorageRedis {
		if err := r.validateRedisConfig(ctx, policy); err != nil {
			logger.Error(err, "Failed to validate Redis configuration")
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
		return err
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, "Reconciled", "RateLimitPolicy reconciled successfully")
	return nil
}

// validateTargetRef validates the target reference
func (r *RateLimitPolicyReconciler) validateTargetRef(ctx context.Context, policy *avapigwv1alpha1.RateLimitPolicy) error {
	targetRef := policy.Spec.TargetRef
	namespace := policy.Namespace
	if targetRef.Namespace != nil {
		namespace = *targetRef.Namespace
	}

	// Validate based on target kind
	switch targetRef.Kind {
	case "Gateway":
		gateway := &avapigwv1alpha1.Gateway{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: targetRef.Name}, gateway); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("target Gateway %s/%s not found", namespace, targetRef.Name)
			}
			return fmt.Errorf("failed to get target Gateway %s/%s: %w", namespace, targetRef.Name, err)
		}
	case "HTTPRoute":
		route := &avapigwv1alpha1.HTTPRoute{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: targetRef.Name}, route); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("target HTTPRoute %s/%s not found", namespace, targetRef.Name)
			}
			return fmt.Errorf("failed to get target HTTPRoute %s/%s: %w", namespace, targetRef.Name, err)
		}
	case "GRPCRoute":
		route := &avapigwv1alpha1.GRPCRoute{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: targetRef.Name}, route); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("target GRPCRoute %s/%s not found", namespace, targetRef.Name)
			}
			return fmt.Errorf("failed to get target GRPCRoute %s/%s: %w", namespace, targetRef.Name, err)
		}
	default:
		return fmt.Errorf("unsupported target kind: %s", targetRef.Kind)
	}

	return nil
}

// validateRedisConfig validates Redis storage configuration
func (r *RateLimitPolicyReconciler) validateRedisConfig(ctx context.Context, policy *avapigwv1alpha1.RateLimitPolicy) error {
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
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: redis.TLS.CACertRef.Name}, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("redis TLS CA cert secret %s/%s not found", namespace, redis.TLS.CACertRef.Name)
			}
			return fmt.Errorf("failed to get Redis TLS CA cert secret %s/%s: %w", namespace, redis.TLS.CACertRef.Name, err)
		}
	}

	return nil
}

// setCondition sets a condition on the policy status
func (r *RateLimitPolicyReconciler) setCondition(policy *avapigwv1alpha1.RateLimitPolicy, conditionType avapigwv1alpha1.ConditionType, status metav1.ConditionStatus, reason, message string) {
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
func (r *RateLimitPolicyReconciler) findPoliciesForHTTPRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	route := obj.(*avapigwv1alpha1.HTTPRoute)
	return r.findPoliciesForTarget(ctx, "HTTPRoute", route.Namespace, route.Name)
}

// findPoliciesForGRPCRoute finds RateLimitPolicies that target a GRPCRoute
func (r *RateLimitPolicyReconciler) findPoliciesForGRPCRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	route := obj.(*avapigwv1alpha1.GRPCRoute)
	return r.findPoliciesForTarget(ctx, "GRPCRoute", route.Namespace, route.Name)
}

// findPoliciesForTarget finds RateLimitPolicies that target a specific resource
func (r *RateLimitPolicyReconciler) findPoliciesForTarget(ctx context.Context, kind, namespace, name string) []reconcile.Request {
	var requests []reconcile.Request

	var policies avapigwv1alpha1.RateLimitPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return requests
	}

	for _, policy := range policies.Items {
		targetNamespace := policy.Namespace
		if policy.Spec.TargetRef.Namespace != nil {
			targetNamespace = *policy.Spec.TargetRef.Namespace
		}
		if policy.Spec.TargetRef.Kind == kind &&
			targetNamespace == namespace &&
			policy.Spec.TargetRef.Name == name {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKey{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				},
			})
		}
	}

	return requests
}

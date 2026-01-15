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
	authPolicyFinalizer = "avapigw.vyrodovalexey.github.com/authpolicy-finalizer"

	// authPolicyReconcileTimeout is the maximum duration for a single AuthPolicy reconciliation
	authPolicyReconcileTimeout = 30 * time.Second
)

// Prometheus metrics for AuthPolicy controller
var (
	authPolicyReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "authpolicy_reconcile_duration_seconds",
			Help:      "Duration of AuthPolicy reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	authPolicyReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "authpolicy_reconcile_total",
			Help:      "Total number of AuthPolicy reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(authPolicyReconcileDuration, authPolicyReconcileTotal)
}

// AuthPolicyReconciler reconciles an AuthPolicy object
type AuthPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=authpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=authpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=authpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles AuthPolicy reconciliation
func (r *AuthPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add timeout to prevent hanging reconciliations
	ctx, cancel := context.WithTimeout(ctx, authPolicyReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)

	// Track reconciliation metrics
	start := time.Now()
	var reconcileResult = "success"
	defer func() {
		duration := time.Since(start).Seconds()
		authPolicyReconcileDuration.WithLabelValues(reconcileResult).Observe(duration)
		authPolicyReconcileTotal.WithLabelValues(reconcileResult).Inc()
	}()

	logger.Info("Reconciling AuthPolicy", "name", req.Name, "namespace", req.Namespace)

	// Fetch the AuthPolicy instance
	policy := &avapigwv1alpha1.AuthPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("AuthPolicy not found, ignoring")
			return ctrl.Result{}, nil
		}
		reconcileResult = MetricResultError
		logger.Error(err, "Failed to get AuthPolicy")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, policy)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(policy, authPolicyFinalizer) {
		controllerutil.AddFinalizer(policy, authPolicyFinalizer)
		if err := r.Update(ctx, policy); err != nil {
			reconcileResult = MetricResultError
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the AuthPolicy
	if err := r.reconcileAuthPolicy(ctx, policy); err != nil {
		reconcileResult = MetricResultError
		logger.Error(err, "Failed to reconcile AuthPolicy")
		r.Recorder.Event(policy, corev1.EventTypeWarning, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// handleDeletion handles AuthPolicy deletion
//
//nolint:unparam // result kept for API consistency with other controllers
func (r *AuthPolicyReconciler) handleDeletion(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(policy, authPolicyFinalizer) {
		// Perform cleanup
		logger.Info("Performing cleanup for AuthPolicy deletion")

		// Record event
		r.Recorder.Event(policy, corev1.EventTypeNormal, "Deleting", "AuthPolicy is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(policy, authPolicyFinalizer)
		if err := r.Update(ctx, policy); err != nil {
			logger.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// reconcileAuthPolicy performs the main reconciliation logic
func (r *AuthPolicyReconciler) reconcileAuthPolicy(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy) error {
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

	// Validate authentication configuration
	if policy.Spec.Authentication != nil {
		if err := r.validateAuthenticationConfig(ctx, policy); err != nil {
			logger.Error(err, "Failed to validate authentication configuration")
			r.setCondition(policy, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
				string(avapigwv1alpha1.ReasonNotReady), err.Error())
			policy.Status.Phase = avapigwv1alpha1.PhaseStatusError
			return r.updateStatus(ctx, policy)
		}
	}

	// Set conditions
	r.setCondition(policy, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonAccepted), "AuthPolicy configuration accepted")
	r.setCondition(policy, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonReady), "AuthPolicy is ready")

	policy.Status.Phase = avapigwv1alpha1.PhaseStatusReady

	// Update status
	if err := r.updateStatus(ctx, policy); err != nil {
		return err
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, "Reconciled", "AuthPolicy reconciled successfully")
	return nil
}

// validateTargetRef validates the target reference
func (r *AuthPolicyReconciler) validateTargetRef(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy) error {
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

// validateAuthenticationConfig validates authentication configuration
func (r *AuthPolicyReconciler) validateAuthenticationConfig(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy) error {
	auth := policy.Spec.Authentication

	// Validate JWT configuration
	if auth.JWT != nil && auth.JWT.Enabled != nil && *auth.JWT.Enabled {
		if err := r.validateJWTConfig(ctx, policy, auth.JWT); err != nil {
			return fmt.Errorf("JWT configuration error: %w", err)
		}
	}

	// Validate API Key configuration
	if auth.APIKey != nil && auth.APIKey.Enabled != nil && *auth.APIKey.Enabled {
		if err := r.validateAPIKeyConfig(ctx, policy, auth.APIKey); err != nil {
			return fmt.Errorf("API Key configuration error: %w", err)
		}
	}

	// Validate Basic Auth configuration
	if auth.Basic != nil && auth.Basic.Enabled != nil && *auth.Basic.Enabled {
		if err := r.validateBasicAuthConfig(ctx, policy, auth.Basic); err != nil {
			return fmt.Errorf("basic auth configuration error: %w", err)
		}
	}

	// Validate OAuth2 configuration
	if auth.OAuth2 != nil && auth.OAuth2.Enabled != nil && *auth.OAuth2.Enabled {
		if err := r.validateOAuth2Config(ctx, policy, auth.OAuth2); err != nil {
			return fmt.Errorf("OAuth2 configuration error: %w", err)
		}
	}

	return nil
}

// validateJWTConfig validates JWT authentication configuration
func (r *AuthPolicyReconciler) validateJWTConfig(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy, jwt *avapigwv1alpha1.JWTAuthConfig) error {
	// Either JWKS URI or JWKS secret must be provided
	if jwt.JWKSUri == nil && jwt.JWKS == nil {
		return fmt.Errorf("either jwksUri or jwks secret reference must be provided")
	}

	// Validate JWKS secret reference if provided
	if jwt.JWKS != nil {
		namespace := policy.Namespace
		if jwt.JWKS.Namespace != nil {
			namespace = *jwt.JWKS.Namespace
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: jwt.JWKS.Name}, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("JWKS secret %s/%s not found", namespace, jwt.JWKS.Name)
			}
			return fmt.Errorf("failed to get JWKS secret %s/%s: %w", namespace, jwt.JWKS.Name, err)
		}
	}

	return nil
}

// validateAPIKeyConfig validates API Key authentication configuration
func (r *AuthPolicyReconciler) validateAPIKeyConfig(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy, apiKey *avapigwv1alpha1.APIKeyAuthConfig) error {
	if apiKey.Validation == nil {
		return fmt.Errorf("API Key validation configuration is required")
	}

	// Validate secret reference if validation type is Secret
	if apiKey.Validation.Type == avapigwv1alpha1.APIKeyValidationSecret {
		if apiKey.Validation.SecretRef == nil {
			return fmt.Errorf("secret reference is required for Secret validation type")
		}

		namespace := policy.Namespace
		if apiKey.Validation.SecretRef.Namespace != nil {
			namespace = *apiKey.Validation.SecretRef.Namespace
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: apiKey.Validation.SecretRef.Name}, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("API Key secret %s/%s not found", namespace, apiKey.Validation.SecretRef.Name)
			}
			return fmt.Errorf("failed to get API Key secret %s/%s: %w", namespace, apiKey.Validation.SecretRef.Name, err)
		}
	}

	// Validate external configuration if validation type is External
	if apiKey.Validation.Type == avapigwv1alpha1.APIKeyValidationExternal {
		if apiKey.Validation.External == nil {
			return fmt.Errorf("external configuration is required for External validation type")
		}
		if apiKey.Validation.External.URL == "" {
			return fmt.Errorf("external validation URL is required")
		}
	}

	return nil
}

// validateBasicAuthConfig validates Basic authentication configuration
func (r *AuthPolicyReconciler) validateBasicAuthConfig(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy, basic *avapigwv1alpha1.BasicAuthConfig) error {
	if basic.SecretRef == nil {
		return fmt.Errorf("secret reference is required for Basic authentication")
	}

	namespace := policy.Namespace
	if basic.SecretRef.Namespace != nil {
		namespace = *basic.SecretRef.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: basic.SecretRef.Name}, secret); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("basic auth secret %s/%s not found", namespace, basic.SecretRef.Name)
		}
		return fmt.Errorf("failed to get Basic Auth secret %s/%s: %w", namespace, basic.SecretRef.Name, err)
	}

	return nil
}

// validateOAuth2Config validates OAuth2 configuration
func (r *AuthPolicyReconciler) validateOAuth2Config(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy, oauth2 *avapigwv1alpha1.OAuth2Config) error {
	if oauth2.TokenEndpoint == nil || *oauth2.TokenEndpoint == "" {
		return fmt.Errorf("token endpoint is required for OAuth2")
	}

	if oauth2.ClientID == nil || *oauth2.ClientID == "" {
		return fmt.Errorf("client ID is required for OAuth2")
	}

	// Validate client secret reference if provided
	if oauth2.ClientSecretRef != nil {
		namespace := policy.Namespace
		if oauth2.ClientSecretRef.Namespace != nil {
			namespace = *oauth2.ClientSecretRef.Namespace
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: oauth2.ClientSecretRef.Name}, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("OAuth2 client secret %s/%s not found", namespace, oauth2.ClientSecretRef.Name)
			}
			return fmt.Errorf("failed to get OAuth2 client secret %s/%s: %w", namespace, oauth2.ClientSecretRef.Name, err)
		}
	}

	return nil
}

// setCondition sets a condition on the policy status
func (r *AuthPolicyReconciler) setCondition(policy *avapigwv1alpha1.AuthPolicy, conditionType avapigwv1alpha1.ConditionType, status metav1.ConditionStatus, reason, message string) {
	policy.Status.SetCondition(conditionType, status, reason, message)
}

// updateStatus updates the policy status
func (r *AuthPolicyReconciler) updateStatus(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy) error {
	return r.Status().Update(ctx, policy)
}

// SetupWithManager sets up the controller with the Manager
func (r *AuthPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.AuthPolicy{}).
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
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findPoliciesForSecret),
		).
		Complete(r)
}

// findPoliciesForGateway finds AuthPolicies that target a Gateway
func (r *AuthPolicyReconciler) findPoliciesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)
	return r.findPoliciesForTarget(ctx, "Gateway", gateway.Namespace, gateway.Name)
}

// findPoliciesForHTTPRoute finds AuthPolicies that target an HTTPRoute
func (r *AuthPolicyReconciler) findPoliciesForHTTPRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	route := obj.(*avapigwv1alpha1.HTTPRoute)
	return r.findPoliciesForTarget(ctx, "HTTPRoute", route.Namespace, route.Name)
}

// findPoliciesForGRPCRoute finds AuthPolicies that target a GRPCRoute
func (r *AuthPolicyReconciler) findPoliciesForGRPCRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	route := obj.(*avapigwv1alpha1.GRPCRoute)
	return r.findPoliciesForTarget(ctx, "GRPCRoute", route.Namespace, route.Name)
}

// findPoliciesForTarget finds AuthPolicies that target a specific resource
func (r *AuthPolicyReconciler) findPoliciesForTarget(ctx context.Context, kind, namespace, name string) []reconcile.Request {
	var requests []reconcile.Request

	var policies avapigwv1alpha1.AuthPolicyList
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

// findPoliciesForSecret finds AuthPolicies that reference a Secret
func (r *AuthPolicyReconciler) findPoliciesForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret := obj.(*corev1.Secret)
	var requests []reconcile.Request

	var policies avapigwv1alpha1.AuthPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return requests
	}

	for _, policy := range policies.Items {
		if r.policyReferencesSecret(&policy, secret.Namespace, secret.Name) {
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

// policyReferencesSecret checks if a policy references a specific secret
func (r *AuthPolicyReconciler) policyReferencesSecret(policy *avapigwv1alpha1.AuthPolicy, secretNamespace, secretName string) bool {
	if policy.Spec.Authentication == nil {
		return false
	}

	auth := policy.Spec.Authentication

	// Check JWT JWKS secret
	if auth.JWT != nil && auth.JWT.JWKS != nil {
		ns := policy.Namespace
		if auth.JWT.JWKS.Namespace != nil {
			ns = *auth.JWT.JWKS.Namespace
		}
		if ns == secretNamespace && auth.JWT.JWKS.Name == secretName {
			return true
		}
	}

	// Check API Key secret
	if auth.APIKey != nil && auth.APIKey.Validation != nil && auth.APIKey.Validation.SecretRef != nil {
		ns := policy.Namespace
		if auth.APIKey.Validation.SecretRef.Namespace != nil {
			ns = *auth.APIKey.Validation.SecretRef.Namespace
		}
		if ns == secretNamespace && auth.APIKey.Validation.SecretRef.Name == secretName {
			return true
		}
	}

	// Check Basic Auth secret
	if auth.Basic != nil && auth.Basic.SecretRef != nil {
		ns := policy.Namespace
		if auth.Basic.SecretRef.Namespace != nil {
			ns = *auth.Basic.SecretRef.Namespace
		}
		if ns == secretNamespace && auth.Basic.SecretRef.Name == secretName {
			return true
		}
	}

	// Check OAuth2 client secret
	if auth.OAuth2 != nil && auth.OAuth2.ClientSecretRef != nil {
		ns := policy.Namespace
		if auth.OAuth2.ClientSecretRef.Namespace != nil {
			ns = *auth.OAuth2.ClientSecretRef.Namespace
		}
		if ns == secretNamespace && auth.OAuth2.ClientSecretRef.Name == secretName {
			return true
		}
	}

	return false
}

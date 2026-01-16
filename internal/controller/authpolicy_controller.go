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
	authPolicyFinalizer        = AuthPolicyFinalizerName
	authPolicyReconcileTimeout = AuthPolicyReconcileTimeout
)

// AuthPolicyReconciler reconciles an AuthPolicy object
type AuthPolicyReconciler struct {
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
func (r *AuthPolicyReconciler) getRequeueStrategy() *RequeueStrategy {
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
func (r *AuthPolicyReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("authpolicy")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, authPolicyFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *AuthPolicyReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=authpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=authpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=authpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles AuthPolicy reconciliation
func (r *AuthPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, authPolicyReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling AuthPolicy", "name", req.Name, "namespace", req.Namespace)

	// Fetch the AuthPolicy instance
	policy, result, err := r.fetchAuthPolicy(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if policy == nil {
		return result, nil
	}

	// Handle deletion
	if !policy.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, policy)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Ensure finalizer and reconcile
	return r.ensureFinalizerAndReconcile(ctx, policy, strategy, resourceKey, &reconcileErr)
}

// fetchAuthPolicy fetches the AuthPolicy instance and handles not-found errors.
func (r *AuthPolicyReconciler) fetchAuthPolicy(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.AuthPolicy, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	policy := &avapigwv1alpha1.AuthPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("AuthPolicy not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getAuthPolicy", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get AuthPolicy",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return policy, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcile ensures the finalizer is present and performs reconciliation.
func (r *AuthPolicyReconciler) ensureFinalizerAndReconcile(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Add finalizer if not present
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

	// Reconcile the AuthPolicy
	if err := r.reconcileAuthPolicy(ctx, policy); err != nil {
		*reconcileErr = ClassifyError("reconcileAuthPolicy", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile AuthPolicy",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
		)
		r.Recorder.Event(policy, corev1.EventTypeWarning, "ReconcileError", err.Error())
		return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
	}

	strategy.ResetFailureCount(resourceKey)
	return strategy.ForSuccess(), nil
}

// handleDeletion handles AuthPolicy deletion
func (r *AuthPolicyReconciler) handleDeletion(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(policy).String()

	if r.finalizerHandler.HasFinalizer(policy) {
		// Perform cleanup
		logger.Info("Performing cleanup for AuthPolicy deletion")

		// Record event
		r.Recorder.Event(policy, corev1.EventTypeNormal, "Deleting", "AuthPolicy is being deleted")

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

// reconcileAuthPolicy performs the main reconciliation logic
func (r *AuthPolicyReconciler) reconcileAuthPolicy(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy) error {
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

	// Validate authentication configuration
	if policy.Spec.Authentication != nil {
		if err := r.validateAuthenticationConfig(ctx, policy); err != nil {
			reconcileErr := ClassifyError("validateAuthenticationConfig", resourceKey, err)
			logger.Error(reconcileErr, "Failed to validate authentication configuration",
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
		string(avapigwv1alpha1.ReasonAccepted), "AuthPolicy configuration accepted")
	r.setCondition(policy, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonReady), "AuthPolicy is ready")

	policy.Status.Phase = avapigwv1alpha1.PhaseStatusReady

	// Update status
	if err := r.updateStatus(ctx, policy); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update AuthPolicy status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, EventReasonReconciled, "AuthPolicy reconciled successfully")
	return nil
}

// validateTargetRef validates the target reference using the shared policy validator.
func (r *AuthPolicyReconciler) validateTargetRef(ctx context.Context, p *avapigwv1alpha1.AuthPolicy) error {
	validator := policyutil.NewTargetRefValidator(r.Client)
	return validator.ValidateTargetRef(ctx, p)
}

// validateAuthenticationConfig validates authentication configuration
func (r *AuthPolicyReconciler) validateAuthenticationConfig(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
) error {
	auth := policy.Spec.Authentication

	// Validate JWT configuration
	if err := r.validateJWTIfEnabled(ctx, policy, auth.JWT); err != nil {
		return err
	}

	// Validate API Key configuration
	if err := r.validateAPIKeyIfEnabled(ctx, policy, auth.APIKey); err != nil {
		return err
	}

	// Validate Basic Auth configuration
	if err := r.validateBasicAuthIfEnabled(ctx, policy, auth.Basic); err != nil {
		return err
	}

	// Validate OAuth2 configuration
	if err := r.validateOAuth2IfEnabled(ctx, policy, auth.OAuth2); err != nil {
		return err
	}

	return nil
}

// validateJWTIfEnabled validates JWT configuration if enabled.
func (r *AuthPolicyReconciler) validateJWTIfEnabled(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	jwt *avapigwv1alpha1.JWTAuthConfig,
) error {
	if jwt == nil || jwt.Enabled == nil || !*jwt.Enabled {
		return nil
	}
	if err := r.validateJWTConfig(ctx, policy, jwt); err != nil {
		return fmt.Errorf("JWT configuration error: %w", err)
	}
	return nil
}

// validateAPIKeyIfEnabled validates API Key configuration if enabled.
func (r *AuthPolicyReconciler) validateAPIKeyIfEnabled(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	apiKey *avapigwv1alpha1.APIKeyAuthConfig,
) error {
	if apiKey == nil || apiKey.Enabled == nil || !*apiKey.Enabled {
		return nil
	}
	if err := r.validateAPIKeyConfig(ctx, policy, apiKey); err != nil {
		return fmt.Errorf("API Key configuration error: %w", err)
	}
	return nil
}

// validateBasicAuthIfEnabled validates Basic Auth configuration if enabled.
func (r *AuthPolicyReconciler) validateBasicAuthIfEnabled(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	basic *avapigwv1alpha1.BasicAuthConfig,
) error {
	if basic == nil || basic.Enabled == nil || !*basic.Enabled {
		return nil
	}
	if err := r.validateBasicAuthConfig(ctx, policy, basic); err != nil {
		return fmt.Errorf("basic auth configuration error: %w", err)
	}
	return nil
}

// validateOAuth2IfEnabled validates OAuth2 configuration if enabled.
func (r *AuthPolicyReconciler) validateOAuth2IfEnabled(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	oauth2 *avapigwv1alpha1.OAuth2Config,
) error {
	if oauth2 == nil || oauth2.Enabled == nil || !*oauth2.Enabled {
		return nil
	}
	if err := r.validateOAuth2Config(ctx, policy, oauth2); err != nil {
		return fmt.Errorf("OAuth2 configuration error: %w", err)
	}
	return nil
}

// validateJWTConfig validates JWT authentication configuration
func (r *AuthPolicyReconciler) validateJWTConfig(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	jwt *avapigwv1alpha1.JWTAuthConfig,
) error {
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
func (r *AuthPolicyReconciler) validateAPIKeyConfig(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	apiKey *avapigwv1alpha1.APIKeyAuthConfig,
) error {
	if apiKey.Validation == nil {
		return fmt.Errorf("API Key validation configuration is required")
	}

	switch apiKey.Validation.Type {
	case avapigwv1alpha1.APIKeyValidationSecret:
		return r.validateAPIKeySecretRef(ctx, policy.Namespace, apiKey.Validation)
	case avapigwv1alpha1.APIKeyValidationExternal:
		return r.validateAPIKeyExternalConfig(apiKey.Validation)
	}

	return nil
}

// validateAPIKeySecretRef validates the secret reference for API Key validation
func (r *AuthPolicyReconciler) validateAPIKeySecretRef(
	ctx context.Context,
	policyNamespace string,
	validation *avapigwv1alpha1.APIKeyValidationConfig,
) error {
	if validation.SecretRef == nil {
		return fmt.Errorf("secret reference is required for Secret validation type")
	}

	namespace := policyNamespace
	if validation.SecretRef.Namespace != nil {
		namespace = *validation.SecretRef.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: validation.SecretRef.Name}, secret); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("API Key secret %s/%s not found", namespace, validation.SecretRef.Name)
		}
		return fmt.Errorf("failed to get API Key secret %s/%s: %w", namespace, validation.SecretRef.Name, err)
	}

	return nil
}

// validateAPIKeyExternalConfig validates the external configuration for API Key validation
func (r *AuthPolicyReconciler) validateAPIKeyExternalConfig(validation *avapigwv1alpha1.APIKeyValidationConfig) error {
	if validation.External == nil {
		return fmt.Errorf("external configuration is required for External validation type")
	}
	if validation.External.URL == "" {
		return fmt.Errorf("external validation URL is required")
	}
	return nil
}

// validateBasicAuthConfig validates Basic authentication configuration
func (r *AuthPolicyReconciler) validateBasicAuthConfig(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	basic *avapigwv1alpha1.BasicAuthConfig,
) error {
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
func (r *AuthPolicyReconciler) validateOAuth2Config(
	ctx context.Context,
	policy *avapigwv1alpha1.AuthPolicy,
	oauth2 *avapigwv1alpha1.OAuth2Config,
) error {
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
		secretKey := client.ObjectKey{Namespace: namespace, Name: oauth2.ClientSecretRef.Name}
		if err := r.Get(ctx, secretKey, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("OAuth2 client secret %s/%s not found", namespace, oauth2.ClientSecretRef.Name)
			}
			return fmt.Errorf(
				"failed to get OAuth2 client secret %s/%s: %w",
				namespace, oauth2.ClientSecretRef.Name, err,
			)
		}
	}

	return nil
}

// setCondition sets a condition on the policy status
func (r *AuthPolicyReconciler) setCondition(
	policy *avapigwv1alpha1.AuthPolicy,
	conditionType avapigwv1alpha1.ConditionType,
	status metav1.ConditionStatus,
	reason, message string,
) {
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
func (r *AuthPolicyReconciler) findPoliciesForGateway(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	gateway := obj.(*avapigwv1alpha1.Gateway)
	return r.findPoliciesForTarget(ctx, "Gateway", gateway.Namespace, gateway.Name)
}

// findPoliciesForHTTPRoute finds AuthPolicies that target an HTTPRoute
func (r *AuthPolicyReconciler) findPoliciesForHTTPRoute(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	route := obj.(*avapigwv1alpha1.HTTPRoute)
	return r.findPoliciesForTarget(ctx, "HTTPRoute", route.Namespace, route.Name)
}

// findPoliciesForGRPCRoute finds AuthPolicies that target a GRPCRoute
func (r *AuthPolicyReconciler) findPoliciesForGRPCRoute(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	route := obj.(*avapigwv1alpha1.GRPCRoute)
	return r.findPoliciesForTarget(ctx, "GRPCRoute", route.Namespace, route.Name)
}

// findPoliciesForTarget finds AuthPolicies that target a specific resource
// using the shared watch handler.
func (r *AuthPolicyReconciler) findPoliciesForTarget(
	ctx context.Context,
	kind, namespace, name string,
) []reconcile.Request {
	watchHandler := policyutil.NewPolicyWatchHandler[*avapigwv1alpha1.AuthPolicy](
		r.Client, &avapigwv1alpha1.AuthPolicyList{},
	)
	return watchHandler.FindPoliciesForTarget(ctx, kind, namespace, name)
}

// findPoliciesForSecret finds AuthPolicies that reference a Secret
func (r *AuthPolicyReconciler) findPoliciesForSecret(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
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
func (r *AuthPolicyReconciler) policyReferencesSecret(
	policy *avapigwv1alpha1.AuthPolicy,
	secretNamespace, secretName string,
) bool {
	if policy.Spec.Authentication == nil {
		return false
	}

	auth := policy.Spec.Authentication

	// Check JWT JWKS secret
	if r.jwtReferencesSecret(auth.JWT, policy.Namespace, secretNamespace, secretName) {
		return true
	}

	// Check API Key secret
	if r.apiKeyReferencesSecret(auth.APIKey, policy.Namespace, secretNamespace, secretName) {
		return true
	}

	// Check Basic Auth secret
	if r.basicAuthReferencesSecret(auth.Basic, policy.Namespace, secretNamespace, secretName) {
		return true
	}

	// Check OAuth2 client secret
	if r.oauth2ReferencesSecret(auth.OAuth2, policy.Namespace, secretNamespace, secretName) {
		return true
	}

	return false
}

// jwtReferencesSecret checks if JWT config references a specific secret
func (r *AuthPolicyReconciler) jwtReferencesSecret(
	jwt *avapigwv1alpha1.JWTAuthConfig,
	policyNamespace, secretNamespace, secretName string,
) bool {
	if jwt == nil || jwt.JWKS == nil {
		return false
	}
	return r.secretRefMatches(jwt.JWKS.Namespace, jwt.JWKS.Name, policyNamespace, secretNamespace, secretName)
}

// apiKeyReferencesSecret checks if API Key config references a specific secret
func (r *AuthPolicyReconciler) apiKeyReferencesSecret(
	apiKey *avapigwv1alpha1.APIKeyAuthConfig,
	policyNamespace, secretNamespace, secretName string,
) bool {
	if apiKey == nil || apiKey.Validation == nil || apiKey.Validation.SecretRef == nil {
		return false
	}
	return r.secretRefMatches(
		apiKey.Validation.SecretRef.Namespace,
		apiKey.Validation.SecretRef.Name,
		policyNamespace, secretNamespace, secretName,
	)
}

// basicAuthReferencesSecret checks if Basic Auth config references a specific secret
func (r *AuthPolicyReconciler) basicAuthReferencesSecret(
	basic *avapigwv1alpha1.BasicAuthConfig,
	policyNamespace, secretNamespace, secretName string,
) bool {
	if basic == nil || basic.SecretRef == nil {
		return false
	}
	return r.secretRefMatches(
		basic.SecretRef.Namespace,
		basic.SecretRef.Name,
		policyNamespace, secretNamespace, secretName,
	)
}

// oauth2ReferencesSecret checks if OAuth2 config references a specific secret
func (r *AuthPolicyReconciler) oauth2ReferencesSecret(
	oauth2 *avapigwv1alpha1.OAuth2Config,
	policyNamespace, secretNamespace, secretName string,
) bool {
	if oauth2 == nil || oauth2.ClientSecretRef == nil {
		return false
	}
	return r.secretRefMatches(
		oauth2.ClientSecretRef.Namespace,
		oauth2.ClientSecretRef.Name,
		policyNamespace, secretNamespace, secretName,
	)
}

// secretRefMatches checks if a secret reference matches the given namespace and name
func (r *AuthPolicyReconciler) secretRefMatches(
	refNamespace *string,
	refName string,
	policyNamespace, secretNamespace, secretName string,
) bool {
	ns := policyNamespace
	if refNamespace != nil {
		ns = *refNamespace
	}
	return ns == secretNamespace && refName == secretName
}

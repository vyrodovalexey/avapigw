// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"context"
	"fmt"
	"net/url"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/webhook/defaulter"
	"github.com/vyrodovalexey/avapigw/internal/webhook/validator"
)

var authpolicylog = logf.Log.WithName("authpolicy-webhook")

// AuthPolicyWebhook implements admission webhooks for AuthPolicy
type AuthPolicyWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.AuthPolicyDefaulter
	DuplicateChecker   *validator.DuplicateChecker
	ReferenceValidator *validator.ReferenceValidator
}

// SetupAuthPolicyWebhookWithManager sets up the webhook with the Manager
func SetupAuthPolicyWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &AuthPolicyWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewAuthPolicyDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(mgr.GetClient()),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.AuthPolicy{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

//nolint:lll // kubebuilder webhook annotation cannot be shortened
//+kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-authpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=authpolicies,verbs=create;update,versions=v1alpha1,name=mauthpolicy.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &AuthPolicyWebhook{}

// Default implements webhook.CustomDefaulter
func (w *AuthPolicyWebhook) Default(ctx context.Context, obj runtime.Object) error {
	policy, ok := obj.(*avapigwv1alpha1.AuthPolicy)
	if !ok {
		return fmt.Errorf("expected an AuthPolicy but got %T", obj)
	}

	authpolicylog.Info("defaulting AuthPolicy", "name", policy.Name, "namespace", policy.Namespace)
	w.Defaulter.Default(policy)

	return nil
}

//nolint:lll // kubebuilder webhook annotation cannot be shortened
//+kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-authpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=authpolicies,verbs=create;update;delete,versions=v1alpha1,name=vauthpolicy.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &AuthPolicyWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *AuthPolicyWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*avapigwv1alpha1.AuthPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an AuthPolicy but got %T", obj)
	}

	authpolicylog.Info("validating AuthPolicy create", "name", policy.Name, "namespace", policy.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "AuthPolicy"); err != nil {
		return nil, err
	}

	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(policy); err != nil {
		return warnings, err
	}

	// Validate target reference
	if err := w.ReferenceValidator.ValidateTargetRef(ctx, &policy.Spec.TargetRef, policy.Namespace); err != nil {
		return warnings, validator.NewValidationError("spec.targetRef", err.Error())
	}

	// Check for duplicate targetRef
	if err := w.DuplicateChecker.CheckPolicyTargetDuplicates(
		ctx, &policy.Spec.TargetRef, policy.Namespace, policy.Name, "AuthPolicy"); err != nil {
		return warnings, err
	}

	// Validate references
	if err := w.validateReferences(ctx, policy); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *AuthPolicyWebhook) ValidateUpdate(
	ctx context.Context,
	oldObj, newObj runtime.Object,
) (admission.Warnings, error) {
	policy, ok := newObj.(*avapigwv1alpha1.AuthPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an AuthPolicy but got %T", newObj)
	}

	authpolicylog.Info("validating AuthPolicy update", "name", policy.Name, "namespace", policy.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "AuthPolicy"); err != nil {
		return nil, err
	}

	return w.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator
func (w *AuthPolicyWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*avapigwv1alpha1.AuthPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an AuthPolicy but got %T", obj)
	}

	authpolicylog.Info("validating AuthPolicy delete", "name", policy.Name, "namespace", policy.Namespace)

	return nil, nil
}

// validateSyntax performs syntax validation
func (w *AuthPolicyWebhook) validateSyntax(policy *avapigwv1alpha1.AuthPolicy) error {
	errs := validator.NewValidationErrors()

	// Validate target ref kind
	validKinds := map[string]bool{
		"Gateway":   true,
		"HTTPRoute": true,
		"GRPCRoute": true,
	}
	if !validKinds[policy.Spec.TargetRef.Kind] {
		errs.Add("spec.targetRef.kind",
			fmt.Sprintf("invalid target kind: %s (must be Gateway, HTTPRoute, or GRPCRoute)",
				policy.Spec.TargetRef.Kind))
	}

	// Validate authentication configuration
	if policy.Spec.Authentication != nil {
		w.validateAuthenticationSyntax(policy.Spec.Authentication, errs)
	}

	// Validate authorization rules
	if policy.Spec.Authorization != nil {
		for i, rule := range policy.Spec.Authorization.Rules {
			if rule.Name == "" {
				errs.Add(fmt.Sprintf("spec.authorization.rules[%d].name", i), "name is required")
			}
		}
	}

	// Validate CORS configuration
	w.validateCORSSyntax(policy, errs)

	return errs.ToError()
}

// validateAuthenticationSyntax validates authentication configuration syntax
func (w *AuthPolicyWebhook) validateAuthenticationSyntax(
	auth *avapigwv1alpha1.AuthenticationConfig,
	errs *validator.ValidationErrors,
) {
	// Validate JWT configuration
	if auth.JWT != nil && auth.JWT.Enabled != nil && *auth.JWT.Enabled {
		w.validateJWTSyntax(auth.JWT, errs)
	}

	// Validate API key configuration
	if auth.APIKey != nil && auth.APIKey.Enabled != nil && *auth.APIKey.Enabled {
		w.validateAPIKeySyntax(auth.APIKey, errs)
	}

	// Validate OAuth2 configuration
	if auth.OAuth2 != nil && auth.OAuth2.Enabled != nil && *auth.OAuth2.Enabled {
		w.validateOAuth2Syntax(auth.OAuth2, errs)
	}
}

// validateJWTSyntax validates JWT configuration syntax
func (w *AuthPolicyWebhook) validateJWTSyntax(jwt *avapigwv1alpha1.JWTAuthConfig, errs *validator.ValidationErrors) {
	// Validate issuer URL format
	if jwt.Issuer != nil && *jwt.Issuer != "" {
		if _, err := url.Parse(*jwt.Issuer); err != nil {
			errs.Add("spec.authentication.jwt.issuer", fmt.Sprintf("invalid URL format: %v", err))
		}
	}

	// Validate JWKS URI format
	if jwt.JWKSUri != nil && *jwt.JWKSUri != "" {
		if _, err := url.Parse(*jwt.JWKSUri); err != nil {
			errs.Add("spec.authentication.jwt.jwksUri", fmt.Sprintf("invalid URL format: %v", err))
		}
	}

	// Either JWKS URI or JWKS secret must be specified
	if (jwt.JWKSUri == nil || *jwt.JWKSUri == "") && jwt.JWKS == nil {
		errs.Add("spec.authentication.jwt", "either jwksUri or jwks must be specified")
	}
}

// validateAPIKeySyntax validates API key configuration syntax
func (w *AuthPolicyWebhook) validateAPIKeySyntax(
	apiKey *avapigwv1alpha1.APIKeyAuthConfig,
	errs *validator.ValidationErrors,
) {
	if apiKey.Validation == nil {
		return
	}

	switch apiKey.Validation.Type {
	case avapigwv1alpha1.APIKeyValidationSecret:
		if apiKey.Validation.SecretRef == nil {
			errs.Add("spec.authentication.apiKey.validation.secretRef",
				"secretRef is required for Secret validation type")
		}
	case avapigwv1alpha1.APIKeyValidationExternal:
		w.validateAPIKeyExternalConfig(apiKey.Validation.External, errs)
	}
}

// validateAPIKeyExternalConfig validates external API key validation configuration
func (w *AuthPolicyWebhook) validateAPIKeyExternalConfig(
	external *avapigwv1alpha1.ExternalValidationConfig,
	errs *validator.ValidationErrors,
) {
	if external == nil {
		errs.Add("spec.authentication.apiKey.validation.external",
			"external configuration is required for External validation type")
		return
	}

	if external.URL == "" {
		errs.Add("spec.authentication.apiKey.validation.external.url", "URL is required")
		return
	}

	if _, err := url.Parse(external.URL); err != nil {
		errs.Add("spec.authentication.apiKey.validation.external.url",
			fmt.Sprintf("invalid URL format: %v", err))
	}
}

// validateOAuth2Syntax validates OAuth2 configuration syntax
func (w *AuthPolicyWebhook) validateOAuth2Syntax(
	oauth2 *avapigwv1alpha1.OAuth2Config,
	errs *validator.ValidationErrors,
) {
	if oauth2.TokenEndpoint == nil || *oauth2.TokenEndpoint == "" {
		return
	}

	if _, err := url.Parse(*oauth2.TokenEndpoint); err != nil {
		errs.Add("spec.authentication.oauth2.tokenEndpoint",
			fmt.Sprintf("invalid URL format: %v", err))
	}
}

// validateCORSSyntax validates CORS configuration syntax
func (w *AuthPolicyWebhook) validateCORSSyntax(policy *avapigwv1alpha1.AuthPolicy, errs *validator.ValidationErrors) {
	if policy.Spec.SecurityHeaders == nil || policy.Spec.SecurityHeaders.CORS == nil {
		return
	}

	cors := policy.Spec.SecurityHeaders.CORS
	for i, origin := range cors.AllowOrigins {
		if origin.Exact == nil || *origin.Exact == "" {
			continue
		}

		if _, err := url.Parse(*origin.Exact); err != nil {
			errs.Add(fmt.Sprintf("spec.securityHeaders.cors.allowOrigins[%d].exact", i),
				fmt.Sprintf("invalid URL format: %v", err))
		}
	}
}

// validateReferences validates cross-resource references
func (w *AuthPolicyWebhook) validateReferences(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy) error {
	if policy.Spec.Authentication == nil {
		return nil
	}

	errs := validator.NewValidationErrors()
	w.validateAuthenticationReferences(ctx, policy.Spec.Authentication, policy.Namespace, errs)
	return errs.ToError()
}

// validateAuthenticationReferences validates authentication-related secret references
func (w *AuthPolicyWebhook) validateAuthenticationReferences(
	ctx context.Context,
	auth *avapigwv1alpha1.AuthenticationConfig,
	namespace string,
	errs *validator.ValidationErrors,
) {
	// Validate JWT JWKS secret reference
	if auth.JWT != nil && auth.JWT.JWKS != nil {
		if err := w.ReferenceValidator.ValidateSecretObjectReference(ctx, auth.JWT.JWKS, namespace); err != nil {
			errs.Add("spec.authentication.jwt.jwks", err.Error())
		}
	}

	// Validate API key secret reference
	w.validateAPIKeySecretReference(ctx, auth.APIKey, namespace, errs)

	// Validate basic auth secret reference
	if auth.Basic != nil && auth.Basic.SecretRef != nil {
		if err := w.ReferenceValidator.ValidateSecretObjectReference(ctx, auth.Basic.SecretRef, namespace); err != nil {
			errs.Add("spec.authentication.basic.secretRef", err.Error())
		}
	}

	// Validate OAuth2 client secret reference
	if auth.OAuth2 != nil && auth.OAuth2.ClientSecretRef != nil {
		err := w.ReferenceValidator.ValidateSecretObjectReference(ctx, auth.OAuth2.ClientSecretRef, namespace)
		if err != nil {
			errs.Add("spec.authentication.oauth2.clientSecretRef", err.Error())
		}
	}
}

// validateAPIKeySecretReference validates API key secret reference
func (w *AuthPolicyWebhook) validateAPIKeySecretReference(
	ctx context.Context,
	apiKey *avapigwv1alpha1.APIKeyAuthConfig,
	namespace string,
	errs *validator.ValidationErrors,
) {
	if apiKey == nil || apiKey.Validation == nil || apiKey.Validation.SecretRef == nil {
		return
	}

	err := w.ReferenceValidator.ValidateSecretObjectReference(ctx, apiKey.Validation.SecretRef, namespace)
	if err != nil {
		errs.Add("spec.authentication.apiKey.validation.secretRef", err.Error())
	}
}

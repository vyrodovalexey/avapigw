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

// +kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-authpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=authpolicies,verbs=create;update,versions=v1alpha1,name=mauthpolicy.kb.io,admissionReviewVersions=v1

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

// +kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-authpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=authpolicies,verbs=create;update;delete,versions=v1alpha1,name=vauthpolicy.kb.io,admissionReviewVersions=v1

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
func (w *AuthPolicyWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
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
		auth := policy.Spec.Authentication

		// Validate JWT configuration
		if auth.JWT != nil && auth.JWT.Enabled != nil && *auth.JWT.Enabled {
			jwt := auth.JWT

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

		// Validate API key configuration
		if auth.APIKey != nil && auth.APIKey.Enabled != nil && *auth.APIKey.Enabled {
			apiKey := auth.APIKey

			if apiKey.Validation != nil {
				switch apiKey.Validation.Type {
				case avapigwv1alpha1.APIKeyValidationSecret:
					if apiKey.Validation.SecretRef == nil {
						errs.Add("spec.authentication.apiKey.validation.secretRef",
							"secretRef is required for Secret validation type")
					}
				case avapigwv1alpha1.APIKeyValidationExternal:
					if apiKey.Validation.External == nil {
						errs.Add("spec.authentication.apiKey.validation.external",
							"external configuration is required for External validation type")
					} else if apiKey.Validation.External.URL == "" {
						errs.Add("spec.authentication.apiKey.validation.external.url", "URL is required")
					} else {
						if _, err := url.Parse(apiKey.Validation.External.URL); err != nil {
							errs.Add("spec.authentication.apiKey.validation.external.url",
								fmt.Sprintf("invalid URL format: %v", err))
						}
					}
				}
			}
		}

		// Validate OAuth2 configuration
		if auth.OAuth2 != nil && auth.OAuth2.Enabled != nil && *auth.OAuth2.Enabled {
			oauth2 := auth.OAuth2

			if oauth2.TokenEndpoint != nil && *oauth2.TokenEndpoint != "" {
				if _, err := url.Parse(*oauth2.TokenEndpoint); err != nil {
					errs.Add("spec.authentication.oauth2.tokenEndpoint",
						fmt.Sprintf("invalid URL format: %v", err))
				}
			}
		}
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
	if policy.Spec.SecurityHeaders != nil && policy.Spec.SecurityHeaders.CORS != nil {
		cors := policy.Spec.SecurityHeaders.CORS

		for i, origin := range cors.AllowOrigins {
			if origin.Exact != nil && *origin.Exact != "" {
				if _, err := url.Parse(*origin.Exact); err != nil {
					errs.Add(fmt.Sprintf("spec.securityHeaders.cors.allowOrigins[%d].exact", i),
						fmt.Sprintf("invalid URL format: %v", err))
				}
			}
		}
	}

	return errs.ToError()
}

// validateReferences validates cross-resource references
func (w *AuthPolicyWebhook) validateReferences(ctx context.Context, policy *avapigwv1alpha1.AuthPolicy) error {
	errs := validator.NewValidationErrors()

	if policy.Spec.Authentication != nil {
		auth := policy.Spec.Authentication

		// Validate JWT JWKS secret reference
		if auth.JWT != nil && auth.JWT.JWKS != nil {
			if err := w.ReferenceValidator.ValidateSecretObjectReference(
				ctx, auth.JWT.JWKS, policy.Namespace); err != nil {
				errs.Add("spec.authentication.jwt.jwks", err.Error())
			}
		}

		// Validate API key secret reference
		if auth.APIKey != nil && auth.APIKey.Validation != nil && auth.APIKey.Validation.SecretRef != nil {
			if err := w.ReferenceValidator.ValidateSecretObjectReference(
				ctx, auth.APIKey.Validation.SecretRef, policy.Namespace); err != nil {
				errs.Add("spec.authentication.apiKey.validation.secretRef", err.Error())
			}
		}

		// Validate basic auth secret reference
		if auth.Basic != nil && auth.Basic.SecretRef != nil {
			if err := w.ReferenceValidator.ValidateSecretObjectReference(
				ctx, auth.Basic.SecretRef, policy.Namespace); err != nil {
				errs.Add("spec.authentication.basic.secretRef", err.Error())
			}
		}

		// Validate OAuth2 client secret reference
		if auth.OAuth2 != nil && auth.OAuth2.ClientSecretRef != nil {
			if err := w.ReferenceValidator.ValidateSecretObjectReference(
				ctx, auth.OAuth2.ClientSecretRef, policy.Namespace); err != nil {
				errs.Add("spec.authentication.oauth2.clientSecretRef", err.Error())
			}
		}
	}

	return errs.ToError()
}

// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"context"
	"fmt"

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

var ratelimitpolicylog = logf.Log.WithName("ratelimitpolicy-webhook")

// RateLimitPolicyWebhook implements admission webhooks for RateLimitPolicy
type RateLimitPolicyWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.RateLimitPolicyDefaulter
	DuplicateChecker   *validator.DuplicateChecker
	ReferenceValidator *validator.ReferenceValidator
}

// SetupRateLimitPolicyWebhookWithManager sets up the webhook with the Manager
func SetupRateLimitPolicyWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &RateLimitPolicyWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(mgr.GetClient()),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.RateLimitPolicy{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-ratelimitpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=ratelimitpolicies,verbs=create;update,versions=v1alpha1,name=mratelimitpolicy.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &RateLimitPolicyWebhook{}

// Default implements webhook.CustomDefaulter
func (w *RateLimitPolicyWebhook) Default(ctx context.Context, obj runtime.Object) error {
	policy, ok := obj.(*avapigwv1alpha1.RateLimitPolicy)
	if !ok {
		return fmt.Errorf("expected a RateLimitPolicy but got %T", obj)
	}

	ratelimitpolicylog.Info("defaulting RateLimitPolicy", "name", policy.Name, "namespace", policy.Namespace)
	w.Defaulter.Default(policy)

	return nil
}

// +kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-ratelimitpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=ratelimitpolicies,verbs=create;update;delete,versions=v1alpha1,name=vratelimitpolicy.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &RateLimitPolicyWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *RateLimitPolicyWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*avapigwv1alpha1.RateLimitPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a RateLimitPolicy but got %T", obj)
	}

	ratelimitpolicylog.Info("validating RateLimitPolicy create", "name", policy.Name, "namespace", policy.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "RateLimitPolicy"); err != nil {
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
		ctx, &policy.Spec.TargetRef, policy.Namespace, policy.Name, "RateLimitPolicy"); err != nil {
		return warnings, err
	}

	// Validate references
	if err := w.validateReferences(ctx, policy); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *RateLimitPolicyWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	policy, ok := newObj.(*avapigwv1alpha1.RateLimitPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a RateLimitPolicy but got %T", newObj)
	}

	ratelimitpolicylog.Info("validating RateLimitPolicy update", "name", policy.Name, "namespace", policy.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "RateLimitPolicy"); err != nil {
		return nil, err
	}

	return w.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator
func (w *RateLimitPolicyWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*avapigwv1alpha1.RateLimitPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a RateLimitPolicy but got %T", obj)
	}

	ratelimitpolicylog.Info("validating RateLimitPolicy delete", "name", policy.Name, "namespace", policy.Namespace)

	return nil, nil
}

// validateSyntax performs syntax validation
func (w *RateLimitPolicyWebhook) validateSyntax(policy *avapigwv1alpha1.RateLimitPolicy) error {
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

	// Validate rules
	if len(policy.Spec.Rules) == 0 {
		errs.Add("spec.rules", "at least one rule is required")
	}

	for i, rule := range policy.Spec.Rules {
		// Validate limit values
		if rule.Limit.Requests < 1 {
			errs.Add(fmt.Sprintf("spec.rules[%d].limit.requests", i), "requests must be at least 1")
		}

		// Validate algorithm-specific configuration
		if rule.Algorithm != nil && *rule.Algorithm == avapigwv1alpha1.RateLimitAlgorithmTokenBucket {
			if rule.TokenBucket != nil {
				if rule.TokenBucket.Tokens < 1 {
					errs.Add(fmt.Sprintf("spec.rules[%d].tokenBucket.tokens", i), "tokens must be at least 1")
				}
			}
		}

		// Validate client identifier
		if rule.ClientIdentifier != nil {
			ci := rule.ClientIdentifier
			switch ci.Type {
			case avapigwv1alpha1.ClientIdentifierHeader:
				if ci.Header == nil || *ci.Header == "" {
					errs.Add(fmt.Sprintf("spec.rules[%d].clientIdentifier.header", i),
						"header is required for Header client identifier type")
				}
			case avapigwv1alpha1.ClientIdentifierJWTClaim:
				if ci.Claim == nil || *ci.Claim == "" {
					errs.Add(fmt.Sprintf("spec.rules[%d].clientIdentifier.claim", i),
						"claim is required for JWTClaim client identifier type")
				}
			case avapigwv1alpha1.ClientIdentifierCookie:
				if ci.Cookie == nil || *ci.Cookie == "" {
					errs.Add(fmt.Sprintf("spec.rules[%d].clientIdentifier.cookie", i),
						"cookie is required for Cookie client identifier type")
				}
			}
		}

		// Validate tiers
		for j, tier := range rule.Tiers {
			if tier.Limit.Requests < 1 {
				errs.Add(fmt.Sprintf("spec.rules[%d].tiers[%d].limit.requests", i, j),
					"requests must be at least 1")
			}
		}
	}

	// Validate storage configuration
	if policy.Spec.Storage != nil {
		if policy.Spec.Storage.Type == avapigwv1alpha1.RateLimitStorageRedis {
			if policy.Spec.Storage.Redis == nil {
				errs.Add("spec.storage.redis", "redis configuration is required for Redis storage type")
			} else if policy.Spec.Storage.Redis.Address == "" {
				errs.Add("spec.storage.redis.address", "address is required")
			}
		}
	}

	return errs.ToError()
}

// validateReferences validates cross-resource references
func (w *RateLimitPolicyWebhook) validateReferences(ctx context.Context, policy *avapigwv1alpha1.RateLimitPolicy) error {
	errs := validator.NewValidationErrors()

	// Validate Redis secret reference
	if policy.Spec.Storage != nil && policy.Spec.Storage.Redis != nil {
		if policy.Spec.Storage.Redis.SecretRef != nil {
			if err := w.ReferenceValidator.ValidateSecretObjectReference(
				ctx, policy.Spec.Storage.Redis.SecretRef, policy.Namespace); err != nil {
				errs.Add("spec.storage.redis.secretRef", err.Error())
			}
		}
	}

	return errs.ToError()
}

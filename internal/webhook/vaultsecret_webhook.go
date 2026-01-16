// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"context"
	"fmt"
	"net/url"
	"strings"

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

var vaultsecretlog = logf.Log.WithName("vaultsecret-webhook")

// VaultSecretWebhook implements admission webhooks for VaultSecret
type VaultSecretWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.VaultSecretDefaulter
	ReferenceValidator *validator.ReferenceValidator
}

// SetupVaultSecretWebhookWithManager sets up the webhook with the Manager
func SetupVaultSecretWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &VaultSecretWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewVaultSecretDefaulter(),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.VaultSecret{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

//nolint:lll // kubebuilder webhook annotation cannot be shortened
//+kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-vaultsecret,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=vaultsecrets,verbs=create;update,versions=v1alpha1,name=mvaultsecret.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &VaultSecretWebhook{}

// Default implements webhook.CustomDefaulter
func (w *VaultSecretWebhook) Default(ctx context.Context, obj runtime.Object) error {
	secret, ok := obj.(*avapigwv1alpha1.VaultSecret)
	if !ok {
		return fmt.Errorf("expected a VaultSecret but got %T", obj)
	}

	vaultsecretlog.Info("defaulting VaultSecret", "name", secret.Name, "namespace", secret.Namespace)
	w.Defaulter.Default(secret)

	return nil
}

//nolint:lll // kubebuilder webhook annotation cannot be shortened
//+kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-vaultsecret,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=vaultsecrets,verbs=create;update;delete,versions=v1alpha1,name=vvaultsecret.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &VaultSecretWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *VaultSecretWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	secret, ok := obj.(*avapigwv1alpha1.VaultSecret)
	if !ok {
		return nil, fmt.Errorf("expected a VaultSecret but got %T", obj)
	}

	vaultsecretlog.Info("validating VaultSecret create", "name", secret.Name, "namespace", secret.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "VaultSecret"); err != nil {
		return nil, err
	}

	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(secret); err != nil {
		return warnings, err
	}

	// Validate references
	if err := w.validateReferences(ctx, secret); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *VaultSecretWebhook) ValidateUpdate(
	ctx context.Context,
	oldObj, newObj runtime.Object,
) (admission.Warnings, error) {
	secret, ok := newObj.(*avapigwv1alpha1.VaultSecret)
	if !ok {
		return nil, fmt.Errorf("expected a VaultSecret but got %T", newObj)
	}

	vaultsecretlog.Info("validating VaultSecret update", "name", secret.Name, "namespace", secret.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "VaultSecret"); err != nil {
		return nil, err
	}

	return w.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator
func (w *VaultSecretWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	secret, ok := obj.(*avapigwv1alpha1.VaultSecret)
	if !ok {
		return nil, fmt.Errorf("expected a VaultSecret but got %T", obj)
	}

	vaultsecretlog.Info("validating VaultSecret delete", "name", secret.Name, "namespace", secret.Namespace)

	return nil, nil
}

// validSecretTypes contains the list of valid Kubernetes secret types
var validSecretTypes = map[string]bool{
	"Opaque":                         true,
	"kubernetes.io/tls":              true,
	"kubernetes.io/dockerconfigjson": true,
}

// validateVaultAuth validates Vault authentication configuration
func (w *VaultSecretWebhook) validateVaultAuth(
	auth *avapigwv1alpha1.VaultAuthConfig,
	errs *validator.ValidationErrors,
) {
	hasKubernetes := auth.Kubernetes != nil
	hasToken := auth.Token != nil
	hasAppRole := auth.AppRole != nil

	if !hasKubernetes && !hasToken && !hasAppRole {
		errs.Add("spec.vaultConnection.auth",
			"at least one authentication method must be specified (kubernetes, token, or appRole)")
	}

	authCount := 0
	if hasKubernetes {
		authCount++
	}
	if hasToken {
		authCount++
	}
	if hasAppRole {
		authCount++
	}

	if authCount > 1 {
		errs.Add("spec.vaultConnection.auth",
			"only one authentication method should be specified")
	}

	if auth.Kubernetes != nil && auth.Kubernetes.Role == "" {
		errs.Add("spec.vaultConnection.auth.kubernetes.role", "role is required")
	}

	if auth.AppRole != nil && auth.AppRole.RoleID == "" {
		errs.Add("spec.vaultConnection.auth.appRole.roleId", "roleId is required")
	}
}

// validateVaultKeyMappings validates key mappings configuration
func (w *VaultSecretWebhook) validateVaultKeyMappings(
	keys []avapigwv1alpha1.VaultKeyMapping,
	errs *validator.ValidationErrors,
) {
	keyNames := make(map[string]bool)
	for i, mapping := range keys {
		if mapping.VaultKey == "" {
			errs.Add(fmt.Sprintf("spec.keys[%d].vaultKey", i), "vaultKey is required")
		}
		if mapping.TargetKey == "" {
			errs.Add(fmt.Sprintf("spec.keys[%d].targetKey", i), "targetKey is required")
		}

		if keyNames[mapping.TargetKey] {
			errs.Add(fmt.Sprintf("spec.keys[%d].targetKey", i),
				fmt.Sprintf("duplicate target key: %s", mapping.TargetKey))
		}
		keyNames[mapping.TargetKey] = true
	}
}

// validateVaultTarget validates target configuration
func (w *VaultSecretWebhook) validateVaultTarget(
	target *avapigwv1alpha1.VaultTargetConfig,
	errs *validator.ValidationErrors,
) {
	if target == nil {
		return
	}

	if target.Name == "" {
		errs.Add("spec.target.name", "name is required")
	}

	if target.Type != nil && !validSecretTypes[*target.Type] {
		errs.Add("spec.target.type",
			fmt.Sprintf("invalid secret type: %s", *target.Type))
	}
}

// validateSyntax performs syntax validation
func (w *VaultSecretWebhook) validateSyntax(secret *avapigwv1alpha1.VaultSecret) error {
	errs := validator.NewValidationErrors()

	if _, err := url.Parse(secret.Spec.VaultConnection.Address); err != nil {
		errs.Add("spec.vaultConnection.address", fmt.Sprintf("invalid URL format: %v", err))
	}

	w.validateVaultAuth(&secret.Spec.VaultConnection.Auth, errs)

	if secret.Spec.Path == "" {
		errs.Add("spec.path", "path is required")
	} else if strings.HasPrefix(secret.Spec.Path, "/") {
		errs.Add("spec.path", "path should not start with /")
	}

	w.validateVaultKeyMappings(secret.Spec.Keys, errs)

	if secret.Spec.Refresh != nil && secret.Spec.Refresh.Interval != nil {
		if err := validateDuration(string(*secret.Spec.Refresh.Interval)); err != nil {
			errs.Add("spec.refresh.interval", err.Error())
		}
	}

	w.validateVaultTarget(secret.Spec.Target, errs)

	return errs.ToError()
}

// validateReferences validates cross-resource references
func (w *VaultSecretWebhook) validateReferences(ctx context.Context, secret *avapigwv1alpha1.VaultSecret) error {
	errs := validator.NewValidationErrors()

	auth := secret.Spec.VaultConnection.Auth

	// Validate Kubernetes auth service account reference
	if auth.Kubernetes != nil && auth.Kubernetes.ServiceAccountRef != nil {
		if err := w.ReferenceValidator.ValidateServiceAccountExists(
			ctx, secret.Namespace, auth.Kubernetes.ServiceAccountRef.Name); err != nil {
			errs.Add("spec.vaultConnection.auth.kubernetes.serviceAccountRef", err.Error())
		}
	}

	// Validate token auth secret reference
	if auth.Token != nil {
		if err := w.ReferenceValidator.ValidateSecretObjectReference(
			ctx, &auth.Token.SecretRef, secret.Namespace); err != nil {
			errs.Add("spec.vaultConnection.auth.token.secretRef", err.Error())
		}
	}

	// Validate AppRole auth secret reference
	if auth.AppRole != nil {
		if err := w.ReferenceValidator.ValidateSecretObjectReference(
			ctx, &auth.AppRole.SecretIDRef, secret.Namespace); err != nil {
			errs.Add("spec.vaultConnection.auth.appRole.secretIdRef", err.Error())
		}
	}

	// Validate TLS configuration references
	w.validateTLSReferences(ctx, secret, errs)

	return errs.ToError()
}

// validateTLSReferences validates TLS-related secret references
func (w *VaultSecretWebhook) validateTLSReferences(
	ctx context.Context,
	secret *avapigwv1alpha1.VaultSecret,
	errs *validator.ValidationErrors,
) {
	tls := secret.Spec.VaultConnection.TLS
	if tls == nil {
		return
	}

	if tls.CACertRef != nil {
		if err := w.ReferenceValidator.ValidateSecretObjectReference(ctx, tls.CACertRef, secret.Namespace); err != nil {
			errs.Add("spec.vaultConnection.tls.caCertRef", err.Error())
		}
	}

	if tls.ClientCertRef != nil {
		err := w.ReferenceValidator.ValidateSecretObjectReference(ctx, tls.ClientCertRef, secret.Namespace)
		if err != nil {
			errs.Add("spec.vaultConnection.tls.clientCertRef", err.Error())
		}
	}

	if tls.ClientKeyRef != nil {
		err := w.ReferenceValidator.ValidateSecretObjectReference(ctx, tls.ClientKeyRef, secret.Namespace)
		if err != nil {
			errs.Add("spec.vaultConnection.tls.clientKeyRef", err.Error())
		}
	}
}

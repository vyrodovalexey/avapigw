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

var tlsconfiglog = logf.Log.WithName("tlsconfig-webhook")

// TLSConfigWebhook implements admission webhooks for TLSConfig
type TLSConfigWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.TLSConfigDefaulter
	ReferenceValidator *validator.ReferenceValidator
}

// SetupTLSConfigWebhookWithManager sets up the webhook with the Manager
func SetupTLSConfigWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &TLSConfigWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewTLSConfigDefaulter(),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.TLSConfig{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-tlsconfig,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs,verbs=create;update,versions=v1alpha1,name=mtlsconfig.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &TLSConfigWebhook{}

// Default implements webhook.CustomDefaulter
func (w *TLSConfigWebhook) Default(ctx context.Context, obj runtime.Object) error {
	config, ok := obj.(*avapigwv1alpha1.TLSConfig)
	if !ok {
		return fmt.Errorf("expected a TLSConfig but got %T", obj)
	}

	tlsconfiglog.Info("defaulting TLSConfig", "name", config.Name, "namespace", config.Namespace)
	w.Defaulter.Default(config)

	return nil
}

// +kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-tlsconfig,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs,verbs=create;update;delete,versions=v1alpha1,name=vtlsconfig.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &TLSConfigWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *TLSConfigWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	config, ok := obj.(*avapigwv1alpha1.TLSConfig)
	if !ok {
		return nil, fmt.Errorf("expected a TLSConfig but got %T", obj)
	}

	tlsconfiglog.Info("validating TLSConfig create", "name", config.Name, "namespace", config.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "TLSConfig"); err != nil {
		return nil, err
	}

	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(config); err != nil {
		return warnings, err
	}

	// Validate references
	if err := w.validateReferences(ctx, config); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *TLSConfigWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	config, ok := newObj.(*avapigwv1alpha1.TLSConfig)
	if !ok {
		return nil, fmt.Errorf("expected a TLSConfig but got %T", newObj)
	}

	tlsconfiglog.Info("validating TLSConfig update", "name", config.Name, "namespace", config.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "TLSConfig"); err != nil {
		return nil, err
	}

	return w.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator
func (w *TLSConfigWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	config, ok := obj.(*avapigwv1alpha1.TLSConfig)
	if !ok {
		return nil, fmt.Errorf("expected a TLSConfig but got %T", obj)
	}

	tlsconfiglog.Info("validating TLSConfig delete", "name", config.Name, "namespace", config.Namespace)

	// Check for gateways referencing this TLSConfig
	hasRefs, err := w.ReferenceValidator.CheckTLSConfigHasReferences(ctx, config.Namespace, config.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check for TLSConfig references: %w", err)
	}

	if hasRefs {
		return nil, validator.NewValidationError("",
			"TLSConfig is referenced by one or more Gateways and cannot be deleted")
	}

	return nil, nil
}

// validateSyntax performs syntax validation
func (w *TLSConfigWebhook) validateSyntax(config *avapigwv1alpha1.TLSConfig) error {
	errs := validator.NewValidationErrors()

	// Validate certificate source - either Secret or Vault must be specified
	hasSecret := config.Spec.CertificateSource.Secret != nil
	hasVault := config.Spec.CertificateSource.Vault != nil

	if !hasSecret && !hasVault {
		errs.Add("spec.certificateSource", "either secret or vault must be specified")
	}

	if hasSecret && hasVault {
		errs.Add("spec.certificateSource", "secret and vault are mutually exclusive")
	}

	// Validate TLS version compatibility
	if config.Spec.MinVersion != nil && config.Spec.MaxVersion != nil {
		minVersion := tlsVersionToInt(*config.Spec.MinVersion)
		maxVersion := tlsVersionToInt(*config.Spec.MaxVersion)

		if minVersion > maxVersion {
			errs.Add("spec.minVersion", "minVersion cannot be greater than maxVersion")
		}
	}

	// Validate cipher suites
	validCipherSuites := map[string]bool{
		"TLS_RSA_WITH_AES_128_CBC_SHA":                true,
		"TLS_RSA_WITH_AES_256_CBC_SHA":                true,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":             true,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":             true,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":        true,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":        true,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":          true,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":          true,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":     true,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":     true,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":       true,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":       true,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":        true,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":      true,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": true,
	}

	for i, suite := range config.Spec.CipherSuites {
		if !validCipherSuites[suite] {
			errs.Add(fmt.Sprintf("spec.cipherSuites[%d]", i),
				fmt.Sprintf("unknown cipher suite: %s", suite))
		}
	}

	// Validate ALPN protocols
	validALPNProtocols := map[string]bool{
		"h2":       true,
		"http/1.1": true,
		"http/1.0": true,
		"spdy/3.1": true,
		"grpc-exp": true,
		"h2c":      true,
	}

	for i, protocol := range config.Spec.ALPNProtocols {
		if !validALPNProtocols[protocol] {
			errs.Add(fmt.Sprintf("spec.alpnProtocols[%d]", i),
				fmt.Sprintf("unknown ALPN protocol: %s", protocol))
		}
	}

	// Validate client validation configuration
	if config.Spec.ClientValidation != nil {
		cv := config.Spec.ClientValidation

		if cv.Enabled != nil && *cv.Enabled {
			if cv.CACertificateRef == nil && len(cv.TrustedCAs) == 0 {
				errs.Add("spec.clientValidation",
					"caCertificateRef or trustedCAs is required when client validation is enabled")
			}
		}
	}

	// Validate rotation configuration
	if config.Spec.Rotation != nil {
		if config.Spec.Rotation.CheckInterval != nil {
			if err := validateDuration(string(*config.Spec.Rotation.CheckInterval)); err != nil {
				errs.Add("spec.rotation.checkInterval", err.Error())
			}
		}
	}

	return errs.ToError()
}

// validateReferences validates cross-resource references
func (w *TLSConfigWebhook) validateReferences(ctx context.Context, config *avapigwv1alpha1.TLSConfig) error {
	errs := validator.NewValidationErrors()

	// Validate secret certificate source
	if config.Spec.CertificateSource.Secret != nil {
		secret := config.Spec.CertificateSource.Secret
		namespace := config.Namespace
		if secret.Namespace != nil {
			namespace = *secret.Namespace
		}

		if err := w.ReferenceValidator.ValidateSecretExists(ctx, namespace, secret.Name); err != nil {
			errs.Add("spec.certificateSource.secret", err.Error())
		}
	}

	// Validate client validation CA certificate reference
	if config.Spec.ClientValidation != nil && config.Spec.ClientValidation.CACertificateRef != nil {
		if err := w.ReferenceValidator.ValidateSecretObjectReference(
			ctx, config.Spec.ClientValidation.CACertificateRef, config.Namespace); err != nil {
			errs.Add("spec.clientValidation.caCertificateRef", err.Error())
		}
	}

	// Validate trusted CAs
	if config.Spec.ClientValidation != nil {
		for i, caRef := range config.Spec.ClientValidation.TrustedCAs {
			if err := w.ReferenceValidator.ValidateSecretObjectReference(ctx, &caRef, config.Namespace); err != nil {
				errs.Add(fmt.Sprintf("spec.clientValidation.trustedCAs[%d]", i), err.Error())
			}
		}
	}

	return errs.ToError()
}

// tlsVersionToInt converts TLS version to integer for comparison
func tlsVersionToInt(version avapigwv1alpha1.TLSVersion) int {
	switch version {
	case avapigwv1alpha1.TLSVersion10:
		return 10
	case avapigwv1alpha1.TLSVersion11:
		return 11
	case avapigwv1alpha1.TLSVersion12:
		return 12
	case avapigwv1alpha1.TLSVersion13:
		return 13
	default:
		return 0
	}
}

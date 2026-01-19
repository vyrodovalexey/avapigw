// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"context"
	"fmt"
	"net"

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

var backendlog = logf.Log.WithName("backend-webhook")

// BackendWebhook implements admission webhooks for Backend
type BackendWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.BackendDefaulter
	ReferenceValidator *validator.ReferenceValidator
}

// SetupBackendWebhookWithManager sets up the webhook with the Manager
func SetupBackendWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &BackendWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewBackendDefaulter(),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.Backend{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

//nolint:lll // kubebuilder webhook annotation cannot be shortened
//+kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-backend,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=create;update,versions=v1alpha1,name=mbackend.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &BackendWebhook{}

// Default implements webhook.CustomDefaulter
func (w *BackendWebhook) Default(ctx context.Context, obj runtime.Object) error {
	backend, ok := obj.(*avapigwv1alpha1.Backend)
	if !ok {
		return fmt.Errorf("expected a Backend but got %T", obj)
	}

	backendlog.Info("defaulting Backend", "name", backend.Name, "namespace", backend.Namespace)
	w.Defaulter.Default(backend)

	return nil
}

//nolint:lll // kubebuilder webhook annotation cannot be shortened
//+kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-backend,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=backends,verbs=create;update;delete,versions=v1alpha1,name=vbackend.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &BackendWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *BackendWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	backend, ok := obj.(*avapigwv1alpha1.Backend)
	if !ok {
		return nil, fmt.Errorf("expected a Backend but got %T", obj)
	}

	backendlog.Info("validating Backend create", "name", backend.Name, "namespace", backend.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "Backend"); err != nil {
		return nil, err
	}

	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(backend); err != nil {
		return warnings, err
	}

	// Validate references
	if err := w.validateReferences(ctx, backend); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *BackendWebhook) ValidateUpdate(
	ctx context.Context,
	oldObj, newObj runtime.Object,
) (admission.Warnings, error) {
	backend, ok := newObj.(*avapigwv1alpha1.Backend)
	if !ok {
		return nil, fmt.Errorf("expected a Backend but got %T", newObj)
	}

	backendlog.Info("validating Backend update", "name", backend.Name, "namespace", backend.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "Backend"); err != nil {
		return nil, err
	}

	return w.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator
func (w *BackendWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	backend, ok := obj.(*avapigwv1alpha1.Backend)
	if !ok {
		return nil, fmt.Errorf("expected a Backend but got %T", obj)
	}

	backendlog.Info("validating Backend delete", "name", backend.Name, "namespace", backend.Namespace)

	// Check for routes referencing this backend
	hasRefs, err := w.ReferenceValidator.CheckBackendHasReferences(ctx, backend.Namespace, backend.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check for backend references: %w", err)
	}

	if hasRefs {
		return admission.Warnings{"Backend is referenced by routes that will be affected"}, nil
	}

	return nil, nil
}

// validateBackendSource validates that either Service or Endpoints is specified
func (w *BackendWebhook) validateBackendSource(backend *avapigwv1alpha1.Backend, errs *validator.ValidationErrors) {
	hasService := backend.Spec.Service != nil
	hasEndpoints := len(backend.Spec.Endpoints) > 0

	if !hasService && !hasEndpoints {
		errs.Add("spec", "either service or endpoints must be specified")
	}

	if hasService && hasEndpoints {
		errs.Add("spec", "service and endpoints are mutually exclusive")
	}

	if backend.Spec.Service != nil {
		if backend.Spec.Service.Port < 1 || backend.Spec.Service.Port > 65535 {
			errs.Add("spec.service.port", "port must be between 1 and 65535")
		}
	}

	for i, endpoint := range backend.Spec.Endpoints {
		if net.ParseIP(endpoint.Address) == nil {
			if err := validateHostname(endpoint.Address); err != nil {
				errs.Add(fmt.Sprintf("spec.endpoints[%d].address", i),
					"address must be a valid IP address or hostname")
			}
		}

		if endpoint.Port < 1 || endpoint.Port > 65535 {
			errs.Add(fmt.Sprintf("spec.endpoints[%d].port", i), "port must be between 1 and 65535")
		}
	}
}

// validateLoadBalancingConfig validates load balancing configuration
func (w *BackendWebhook) validateLoadBalancingConfig(
	lb *avapigwv1alpha1.LoadBalancingConfig,
	errs *validator.ValidationErrors,
) {
	if lb.Algorithm == nil || *lb.Algorithm != avapigwv1alpha1.LoadBalancingConsistentHash {
		return
	}

	if lb.ConsistentHash == nil {
		errs.Add("spec.loadBalancing.consistentHash",
			"consistentHash configuration is required when algorithm is ConsistentHash")
		return
	}

	ch := lb.ConsistentHash
	switch ch.Type {
	case avapigwv1alpha1.ConsistentHashHeader:
		if ch.Header == nil || *ch.Header == "" {
			errs.Add("spec.loadBalancing.consistentHash.header",
				"header is required for Header consistent hash type")
		}
	case avapigwv1alpha1.ConsistentHashCookie:
		if ch.Cookie == nil || *ch.Cookie == "" {
			errs.Add("spec.loadBalancing.consistentHash.cookie",
				"cookie is required for Cookie consistent hash type")
		}
	}
}

// validateHealthCheckConfig validates health check configuration
func (w *BackendWebhook) validateHealthCheckConfig(
	hc *avapigwv1alpha1.HealthCheckConfig,
	errs *validator.ValidationErrors,
) {
	if hc.Interval != nil {
		if err := validateDuration(string(*hc.Interval)); err != nil {
			errs.Add("spec.healthCheck.interval", err.Error())
		}
	}

	if hc.Timeout != nil {
		if err := validateDuration(string(*hc.Timeout)); err != nil {
			errs.Add("spec.healthCheck.timeout", err.Error())
		}
	}

	if hc.HTTP != nil {
		if hc.HTTP.Path == "" {
			errs.Add("spec.healthCheck.http.path", "path is required for HTTP health check")
		}
		for i, status := range hc.HTTP.ExpectedStatuses {
			if status < 100 || status > 599 {
				errs.Add(fmt.Sprintf("spec.healthCheck.http.expectedStatuses[%d]", i),
					"status code must be between 100 and 599")
			}
		}
	}
}

// validateCircuitBreakerConfig validates circuit breaker configuration
func (w *BackendWebhook) validateCircuitBreakerConfig(
	cb *avapigwv1alpha1.CircuitBreakerConfig,
	errs *validator.ValidationErrors,
) {
	if cb.Interval != nil {
		if err := validateDuration(string(*cb.Interval)); err != nil {
			errs.Add("spec.circuitBreaker.interval", err.Error())
		}
	}

	if cb.BaseEjectionTime != nil {
		if err := validateDuration(string(*cb.BaseEjectionTime)); err != nil {
			errs.Add("spec.circuitBreaker.baseEjectionTime", err.Error())
		}
	}
}

// validateSyntax performs syntax validation
func (w *BackendWebhook) validateSyntax(backend *avapigwv1alpha1.Backend) error {
	errs := validator.NewValidationErrors()

	w.validateBackendSource(backend, errs)

	if backend.Spec.LoadBalancing != nil {
		w.validateLoadBalancingConfig(backend.Spec.LoadBalancing, errs)
	}

	if backend.Spec.HealthCheck != nil {
		w.validateHealthCheckConfig(backend.Spec.HealthCheck, errs)
	}

	if backend.Spec.CircuitBreaker != nil {
		w.validateCircuitBreakerConfig(backend.Spec.CircuitBreaker, errs)
	}

	if backend.Spec.TLS != nil {
		tls := backend.Spec.TLS
		if tls.Mode != nil && *tls.Mode == avapigwv1alpha1.BackendTLSModeMutual {
			if tls.CertificateRef == nil {
				errs.Add("spec.tls.certificateRef",
					"certificateRef is required for Mutual TLS mode")
			}
		}
	}

	return errs.ToError()
}

// validateReferences validates cross-resource references
func (w *BackendWebhook) validateReferences(ctx context.Context, backend *avapigwv1alpha1.Backend) error {
	errs := validator.NewValidationErrors()

	// Validate service reference
	if backend.Spec.Service != nil {
		namespace := backend.Namespace
		if backend.Spec.Service.Namespace != nil {
			namespace = *backend.Spec.Service.Namespace
		}

		if err := w.ReferenceValidator.ValidateServiceExists(ctx, namespace, backend.Spec.Service.Name); err != nil {
			errs.Add("spec.service", err.Error())
		}
	}

	// Validate TLS certificate references
	if backend.Spec.TLS != nil {
		w.validateTLSReferences(ctx, backend, errs)
	}

	return errs.ToError()
}

// validateTLSReferences validates TLS certificate references for a backend
func (w *BackendWebhook) validateTLSReferences(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
	errs *validator.ValidationErrors,
) {
	tls := backend.Spec.TLS

	if tls.CertificateRef != nil {
		if err := w.ReferenceValidator.ValidateSecretObjectReference(
			ctx, tls.CertificateRef, backend.Namespace); err != nil {
			errs.Add("spec.tls.certificateRef", err.Error())
		}
	}

	if tls.CACertificateRef != nil {
		if err := w.ReferenceValidator.ValidateSecretObjectReference(
			ctx, tls.CACertificateRef, backend.Namespace); err != nil {
			errs.Add("spec.tls.caCertificateRef", err.Error())
		}
	}
}

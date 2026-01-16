// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"context"
	"fmt"
	"net"
	"regexp"

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

var gatewaylog = logf.Log.WithName("gateway-webhook")

// hostnameRegex is a pre-compiled regex for RFC 1123 hostname validation.
// Pre-compiling at package level avoids repeated compilation on each validation call,
// improving performance for high-frequency webhook operations.
var hostnameRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// GatewayWebhook implements admission webhooks for Gateway
type GatewayWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.GatewayDefaulter
	DuplicateChecker   *validator.DuplicateChecker
	ReferenceValidator *validator.ReferenceValidator
}

// SetupGatewayWebhookWithManager sets up the webhook with the Manager
func SetupGatewayWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &GatewayWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewGatewayDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(mgr.GetClient()),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.Gateway{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

//nolint:lll // kubebuilder webhook annotation cannot be shortened
//+kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-gateway,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=create;update,versions=v1alpha1,name=mgateway.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &GatewayWebhook{}

// Default implements webhook.CustomDefaulter
func (w *GatewayWebhook) Default(ctx context.Context, obj runtime.Object) error {
	gateway, ok := obj.(*avapigwv1alpha1.Gateway)
	if !ok {
		return fmt.Errorf("expected a Gateway but got %T", obj)
	}

	gatewaylog.Info("defaulting Gateway", "name", gateway.Name, "namespace", gateway.Namespace)
	w.Defaulter.Default(gateway)

	return nil
}

//nolint:lll // kubebuilder webhook annotation cannot be shortened
//+kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-gateway,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=gateways,verbs=create;update;delete,versions=v1alpha1,name=vgateway.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &GatewayWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *GatewayWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	gateway, ok := obj.(*avapigwv1alpha1.Gateway)
	if !ok {
		return nil, fmt.Errorf("expected a Gateway but got %T", obj)
	}

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "Gateway"); err != nil {
		return nil, err
	}

	gatewaylog.Info("validating Gateway create", "name", gateway.Name, "namespace", gateway.Namespace)

	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(gateway); err != nil {
		return warnings, err
	}

	// Validate semantics
	if err := w.validateSemantics(gateway); err != nil {
		return warnings, err
	}

	// Check for duplicates
	if err := w.DuplicateChecker.CheckGatewayListenerDuplicates(ctx, gateway); err != nil {
		return warnings, err
	}

	// Validate references
	if err := w.validateReferences(ctx, gateway); err != nil {
		return warnings, err
	}

	// Check for wildcard hostname overlaps (warning only)
	if wildcardWarnings := w.checkWildcardOverlaps(gateway); len(wildcardWarnings) > 0 {
		warnings = append(warnings, wildcardWarnings...)
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *GatewayWebhook) ValidateUpdate(
	ctx context.Context,
	oldObj, newObj runtime.Object,
) (admission.Warnings, error) {
	gateway, ok := newObj.(*avapigwv1alpha1.Gateway)
	if !ok {
		return nil, fmt.Errorf("expected a Gateway but got %T", newObj)
	}

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "Gateway"); err != nil {
		return nil, err
	}

	gatewaylog.Info("validating Gateway update", "name", gateway.Name, "namespace", gateway.Namespace)

	// Perform same validations as create (skip rate limit check since we already did it)
	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(gateway); err != nil {
		return warnings, err
	}

	// Validate semantics
	if err := w.validateSemantics(gateway); err != nil {
		return warnings, err
	}

	// Check for duplicates
	if err := w.DuplicateChecker.CheckGatewayListenerDuplicates(ctx, gateway); err != nil {
		return warnings, err
	}

	// Validate references
	if err := w.validateReferences(ctx, gateway); err != nil {
		return warnings, err
	}

	// Check for wildcard hostname overlaps (warning only)
	if wildcardWarnings := w.checkWildcardOverlaps(gateway); len(wildcardWarnings) > 0 {
		warnings = append(warnings, wildcardWarnings...)
	}

	return warnings, nil
}

// ValidateDelete implements webhook.CustomValidator
func (w *GatewayWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	gateway, ok := obj.(*avapigwv1alpha1.Gateway)
	if !ok {
		return nil, fmt.Errorf("expected a Gateway but got %T", obj)
	}

	gatewaylog.Info("validating Gateway delete", "name", gateway.Name, "namespace", gateway.Namespace)

	// Check for attached routes
	hasRoutes, err := w.ReferenceValidator.CheckGatewayHasAttachedRoutes(ctx, gateway.Namespace, gateway.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check for attached routes: %w", err)
	}

	if hasRoutes {
		return admission.Warnings{"Gateway has attached routes that will be orphaned"}, nil
	}

	return nil, nil
}

// validateSyntax performs syntax validation
func (w *GatewayWebhook) validateSyntax(gateway *avapigwv1alpha1.Gateway) error {
	errs := validator.NewValidationErrors()

	if len(gateway.Spec.Listeners) == 0 {
		errs.Add("spec.listeners", "at least one listener is required")
	}

	w.validateListenersSyntax(gateway.Spec.Listeners, errs)
	w.validateAddressesSyntax(gateway.Spec.Addresses, errs)

	return errs.ToError()
}

// validateListenersSyntax validates the syntax of all listeners
func (w *GatewayWebhook) validateListenersSyntax(
	listeners []avapigwv1alpha1.Listener,
	errs *validator.ValidationErrors,
) {
	listenerNames := make(map[string]bool)
	for i, listener := range listeners {
		w.validateListenerSyntax(i, listener, listenerNames, errs)
	}
}

// validateListenerSyntax validates the syntax of a single listener
func (w *GatewayWebhook) validateListenerSyntax(
	index int,
	listener avapigwv1alpha1.Listener,
	listenerNames map[string]bool,
	errs *validator.ValidationErrors,
) {
	if listenerNames[listener.Name] {
		errs.Add(
			fmt.Sprintf("spec.listeners[%d].name", index), fmt.Sprintf("duplicate listener name: %s", listener.Name))
	}
	listenerNames[listener.Name] = true

	if listener.Port < 1 || listener.Port > 65535 {
		errs.Add(fmt.Sprintf("spec.listeners[%d].port", index), "port must be between 1 and 65535")
	}

	if listener.Hostname != nil {
		if err := validateHostname(string(*listener.Hostname)); err != nil {
			errs.Add(fmt.Sprintf("spec.listeners[%d].hostname", index), err.Error())
		}
	}

	if w.requiresTLS(listener.Protocol) && listener.TLS == nil {
		errs.Add(fmt.Sprintf("spec.listeners[%d].tls", index),
			fmt.Sprintf("TLS configuration is required for protocol %s", listener.Protocol))
	}
}

// requiresTLS returns true if the protocol requires TLS configuration
func (w *GatewayWebhook) requiresTLS(protocol avapigwv1alpha1.ProtocolType) bool {
	return protocol == avapigwv1alpha1.ProtocolHTTPS ||
		protocol == avapigwv1alpha1.ProtocolGRPCS ||
		protocol == avapigwv1alpha1.ProtocolTLS
}

// validateAddressesSyntax validates the syntax of all addresses
func (w *GatewayWebhook) validateAddressesSyntax(
	addresses []avapigwv1alpha1.GatewayAddress,
	errs *validator.ValidationErrors,
) {
	for i, addr := range addresses {
		if addr.Type != nil && *addr.Type == avapigwv1alpha1.AddressTypeIPAddress {
			if net.ParseIP(addr.Value) == nil {
				errs.Add(fmt.Sprintf("spec.addresses[%d].value", i), "invalid IP address")
			}
		}
	}
}

// validateSemantics performs semantic validation
func (w *GatewayWebhook) validateSemantics(gateway *avapigwv1alpha1.Gateway) error {
	errs := validator.NewValidationErrors()

	// Check for port conflicts within the same gateway
	portHostnameMap := make(map[string]int) // "port:hostname" -> listener index
	for i, listener := range gateway.Spec.Listeners {
		hostname := ""
		if listener.Hostname != nil {
			hostname = string(*listener.Hostname)
		}
		key := fmt.Sprintf("%d:%s", listener.Port, hostname)

		if existingIdx, exists := portHostnameMap[key]; exists {
			errs.Add(fmt.Sprintf("spec.listeners[%d]", i),
				fmt.Sprintf("port %d with hostname %q conflicts with listener at index %d",
					listener.Port, hostname, existingIdx))
		}
		portHostnameMap[key] = i
	}

	return errs.ToError()
}

// validateReferences validates cross-resource references
func (w *GatewayWebhook) validateReferences(ctx context.Context, gateway *avapigwv1alpha1.Gateway) error {
	errs := validator.NewValidationErrors()

	for i, listener := range gateway.Spec.Listeners {
		if listener.TLS != nil {
			for j, certRef := range listener.TLS.CertificateRefs {
				namespace := gateway.Namespace
				if certRef.Namespace != nil {
					namespace = *certRef.Namespace
				}

				// Try to find as TLSConfig first, then as Secret
				if err := w.ReferenceValidator.ValidateTLSConfigExists(ctx, namespace, certRef.Name); err != nil {
					// Try as Secret
					if err := w.ReferenceValidator.ValidateSecretExists(ctx, namespace, certRef.Name); err != nil {
						fieldPath := fmt.Sprintf("spec.listeners[%d].tls.certificateRefs[%d]", i, j)
						msg := fmt.Sprintf(
							"certificate reference %s/%s not found as TLSConfig or Secret", namespace, certRef.Name)
						errs.Add(fieldPath, msg)
					}
				}
			}
		}
	}

	return errs.ToError()
}

// checkWildcardOverlaps checks for potential wildcard hostname overlaps
func (w *GatewayWebhook) checkWildcardOverlaps(gateway *avapigwv1alpha1.Gateway) admission.Warnings {
	var warnings admission.Warnings

	wildcardListeners := make(map[string]string) // domain -> listener name
	for _, listener := range gateway.Spec.Listeners {
		if listener.Hostname == nil {
			continue
		}
		hostname := string(*listener.Hostname)
		if len(hostname) > 2 && hostname[:2] == "*." {
			domain := hostname[2:]
			if existing, exists := wildcardListeners[domain]; exists {
				warnings = append(warnings,
					fmt.Sprintf("listener %q has wildcard hostname %q that overlaps with listener %q",
						listener.Name, hostname, existing))
			}
			wildcardListeners[domain] = listener.Name
		}
	}

	return warnings
}

// validateHostname validates a hostname format
func validateHostname(hostname string) error {
	if hostname == "" {
		return nil
	}

	// Allow wildcard hostnames
	if len(hostname) > 2 && hostname[:2] == "*." {
		hostname = hostname[2:]
	}

	// RFC 1123 hostname validation using pre-compiled regex for better performance
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("invalid hostname format: %s", hostname)
	}

	if len(hostname) > 253 {
		return fmt.Errorf("hostname exceeds maximum length of 253 characters")
	}

	return nil
}

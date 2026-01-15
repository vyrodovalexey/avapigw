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

// Backend reference kind constants for TLSRoute webhook
const (
	tlsRouteBackendKindService = "Service"
	tlsRouteBackendKindBackend = "Backend"
)

var tlsroutelog = logf.Log.WithName("tlsroute-webhook")

// TLSRouteWebhook implements admission webhooks for TLSRoute
type TLSRouteWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.TLSRouteDefaulter
	DuplicateChecker   *validator.DuplicateChecker
	ReferenceValidator *validator.ReferenceValidator
}

// SetupTLSRouteWebhookWithManager sets up the webhook with the Manager
func SetupTLSRouteWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &TLSRouteWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewTLSRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(mgr.GetClient()),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.TLSRoute{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-tlsroute,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes,verbs=create;update,versions=v1alpha1,name=mtlsroute.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &TLSRouteWebhook{}

// Default implements webhook.CustomDefaulter
func (w *TLSRouteWebhook) Default(ctx context.Context, obj runtime.Object) error {
	route, ok := obj.(*avapigwv1alpha1.TLSRoute)
	if !ok {
		return fmt.Errorf("expected a TLSRoute but got %T", obj)
	}

	tlsroutelog.Info("defaulting TLSRoute", "name", route.Name, "namespace", route.Namespace)
	w.Defaulter.Default(route)

	return nil
}

// +kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-tlsroute,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=tlsroutes,verbs=create;update;delete,versions=v1alpha1,name=vtlsroute.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &TLSRouteWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *TLSRouteWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	route, ok := obj.(*avapigwv1alpha1.TLSRoute)
	if !ok {
		return nil, fmt.Errorf("expected a TLSRoute but got %T", obj)
	}

	tlsroutelog.Info("validating TLSRoute create", "name", route.Name, "namespace", route.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "TLSRoute"); err != nil {
		return nil, err
	}

	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(route); err != nil {
		return warnings, err
	}

	// Validate parent references
	if err := w.ReferenceValidator.ValidateParentRefs(ctx, route.Spec.ParentRefs, route.Namespace); err != nil {
		return warnings, err
	}

	// Validate parent gateway has TLS passthrough
	if err := w.validateParentProtocols(ctx, route); err != nil {
		return warnings, err
	}

	// Validate backend references
	if err := w.validateBackendRefs(ctx, route); err != nil {
		return warnings, err
	}

	// Check for duplicate hostnames
	if err := w.DuplicateChecker.CheckTLSRouteHostnameDuplicates(ctx, route); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *TLSRouteWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	route, ok := newObj.(*avapigwv1alpha1.TLSRoute)
	if !ok {
		return nil, fmt.Errorf("expected a TLSRoute but got %T", newObj)
	}

	tlsroutelog.Info("validating TLSRoute update", "name", route.Name, "namespace", route.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "TLSRoute"); err != nil {
		return nil, err
	}

	return w.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator
func (w *TLSRouteWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	route, ok := obj.(*avapigwv1alpha1.TLSRoute)
	if !ok {
		return nil, fmt.Errorf("expected a TLSRoute but got %T", obj)
	}

	tlsroutelog.Info("validating TLSRoute delete", "name", route.Name, "namespace", route.Namespace)

	return nil, nil
}

// validateSyntax performs syntax validation
func (w *TLSRouteWebhook) validateSyntax(route *avapigwv1alpha1.TLSRoute) error {
	errs := validator.NewValidationErrors()

	// Validate hostnames (required for SNI matching)
	if len(route.Spec.Hostnames) == 0 {
		errs.Add("spec.hostnames", "at least one hostname is required for TLS passthrough (SNI matching)")
	}

	for i, hostname := range route.Spec.Hostnames {
		if err := validateHostname(string(hostname)); err != nil {
			errs.Add(fmt.Sprintf("spec.hostnames[%d]", i), err.Error())
		}
	}

	// Validate rules
	if len(route.Spec.Rules) == 0 {
		errs.Add("spec.rules", "at least one rule is required")
	}

	for i, rule := range route.Spec.Rules {
		// Validate backend refs
		if len(rule.BackendRefs) == 0 {
			errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs", i), "at least one backend reference is required")
		}
	}

	return errs.ToError()
}

// validateParentProtocols validates that parent gateways have TLS passthrough listeners
func (w *TLSRouteWebhook) validateParentProtocols(ctx context.Context, route *avapigwv1alpha1.TLSRoute) error {
	errs := validator.NewValidationErrors()

	for i, parentRef := range route.Spec.ParentRefs {
		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}

		if parentRef.SectionName != nil {
			// Validate specific listener has TLS passthrough
			err := w.ReferenceValidator.ValidateGatewayListenerHasTLSPassthrough(
				ctx, namespace, parentRef.Name, *parentRef.SectionName,
			)
			if err != nil {
				errs.Add(fmt.Sprintf("spec.parentRefs[%d]", i), err.Error())
			}
		}
	}

	return errs.ToError()
}

// validateBackendRefs validates backend references
func (w *TLSRouteWebhook) validateBackendRefs(ctx context.Context, route *avapigwv1alpha1.TLSRoute) error {
	errs := validator.NewValidationErrors()

	for i, rule := range route.Spec.Rules {
		for j, backendRef := range rule.BackendRefs {
			namespace := route.Namespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}

			kind := tlsRouteBackendKindService
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}

			group := ""
			if backendRef.Group != nil {
				group = *backendRef.Group
			}

			switch {
			case group == "" && kind == tlsRouteBackendKindService:
				if err := w.ReferenceValidator.ValidateServiceExists(ctx, namespace, backendRef.Name); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), err.Error())
				}
			case group == avapigwv1alpha1.GroupVersion.Group && kind == tlsRouteBackendKindBackend:
				if err := w.ReferenceValidator.ValidateBackendExists(ctx, namespace, backendRef.Name); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), err.Error())
				}
			}
		}
	}

	return errs.ToError()
}

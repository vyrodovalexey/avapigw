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

var tcproutelog = logf.Log.WithName("tcproute-webhook")

// Backend reference kinds for TCPRoute validation.
const (
	tcpRouteBackendKindService = "Service"
	tcpRouteBackendKindBackend = "Backend"
)

// TCPRouteWebhook implements admission webhooks for TCPRoute
type TCPRouteWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.TCPRouteDefaulter
	DuplicateChecker   *validator.DuplicateChecker
	ReferenceValidator *validator.ReferenceValidator
}

// SetupTCPRouteWebhookWithManager sets up the webhook with the Manager
func SetupTCPRouteWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &TCPRouteWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewTCPRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(mgr.GetClient()),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.TCPRoute{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-tcproute,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=tcproutes,verbs=create;update,versions=v1alpha1,name=mtcproute.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &TCPRouteWebhook{}

// Default implements webhook.CustomDefaulter
func (w *TCPRouteWebhook) Default(ctx context.Context, obj runtime.Object) error {
	route, ok := obj.(*avapigwv1alpha1.TCPRoute)
	if !ok {
		return fmt.Errorf("expected a TCPRoute but got %T", obj)
	}

	tcproutelog.Info("defaulting TCPRoute", "name", route.Name, "namespace", route.Namespace)
	w.Defaulter.Default(route)

	return nil
}

// +kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-tcproute,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=tcproutes,verbs=create;update;delete,versions=v1alpha1,name=vtcproute.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &TCPRouteWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *TCPRouteWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	route, ok := obj.(*avapigwv1alpha1.TCPRoute)
	if !ok {
		return nil, fmt.Errorf("expected a TCPRoute but got %T", obj)
	}

	tcproutelog.Info("validating TCPRoute create", "name", route.Name, "namespace", route.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "TCPRoute"); err != nil {
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

	// Validate parent gateway has TCP protocol
	if err := w.validateParentProtocols(ctx, route); err != nil {
		return warnings, err
	}

	// Validate backend references
	if err := w.validateBackendRefs(ctx, route); err != nil {
		return warnings, err
	}

	// Check for port conflicts
	if err := w.DuplicateChecker.CheckTCPRoutePortConflicts(ctx, route); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *TCPRouteWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	route, ok := newObj.(*avapigwv1alpha1.TCPRoute)
	if !ok {
		return nil, fmt.Errorf("expected a TCPRoute but got %T", newObj)
	}

	tcproutelog.Info("validating TCPRoute update", "name", route.Name, "namespace", route.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "TCPRoute"); err != nil {
		return nil, err
	}

	return w.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator
func (w *TCPRouteWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	route, ok := obj.(*avapigwv1alpha1.TCPRoute)
	if !ok {
		return nil, fmt.Errorf("expected a TCPRoute but got %T", obj)
	}

	tcproutelog.Info("validating TCPRoute delete", "name", route.Name, "namespace", route.Namespace)

	return nil, nil
}

// validateSyntax performs syntax validation
func (w *TCPRouteWebhook) validateSyntax(route *avapigwv1alpha1.TCPRoute) error {
	errs := validator.NewValidationErrors()

	// Validate rules
	if len(route.Spec.Rules) == 0 {
		errs.Add("spec.rules", "at least one rule is required")
	}

	for i, rule := range route.Spec.Rules {
		// Validate backend refs
		if len(rule.BackendRefs) == 0 {
			errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs", i), "at least one backend reference is required")
		}

		// Validate timeouts
		if rule.IdleTimeout != nil {
			if err := validateDuration(string(*rule.IdleTimeout)); err != nil {
				errs.Add(fmt.Sprintf("spec.rules[%d].idleTimeout", i), err.Error())
			}
		}
		if rule.ConnectTimeout != nil {
			if err := validateDuration(string(*rule.ConnectTimeout)); err != nil {
				errs.Add(fmt.Sprintf("spec.rules[%d].connectTimeout", i), err.Error())
			}
		}
	}

	return errs.ToError()
}

// validateParentProtocols validates that parent gateways have TCP listeners
func (w *TCPRouteWebhook) validateParentProtocols(ctx context.Context, route *avapigwv1alpha1.TCPRoute) error {
	errs := validator.NewValidationErrors()

	for i, parentRef := range route.Spec.ParentRefs {
		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}

		if parentRef.SectionName != nil {
			// Validate specific listener has TCP protocol
			err := w.ReferenceValidator.ValidateGatewayListenerHasProtocol(
				ctx, namespace, parentRef.Name, *parentRef.SectionName,
				avapigwv1alpha1.ProtocolTCP,
			)
			if err != nil {
				errs.Add(fmt.Sprintf("spec.parentRefs[%d]", i), err.Error())
			}
		}
	}

	return errs.ToError()
}

// validateBackendRefs validates backend references
func (w *TCPRouteWebhook) validateBackendRefs(ctx context.Context, route *avapigwv1alpha1.TCPRoute) error {
	errs := validator.NewValidationErrors()

	for i, rule := range route.Spec.Rules {
		for j, backendRef := range rule.BackendRefs {
			namespace := route.Namespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}

			kind := tcpRouteBackendKindService
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}

			group := ""
			if backendRef.Group != nil {
				group = *backendRef.Group
			}

			switch {
			case group == "" && kind == tcpRouteBackendKindService:
				if err := w.ReferenceValidator.ValidateServiceExists(ctx, namespace, backendRef.Name); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), err.Error())
				}
			case group == avapigwv1alpha1.GroupVersion.Group && kind == tcpRouteBackendKindBackend:
				if err := w.ReferenceValidator.ValidateBackendExists(ctx, namespace, backendRef.Name); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), err.Error())
				}
			}
		}
	}

	return errs.ToError()
}

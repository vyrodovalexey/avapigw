// Package webhook provides admission webhooks for CRD validation and defaulting.
package webhook

import (
	"context"
	"fmt"
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

var grpcroutelog = logf.Log.WithName("grpcroute-webhook")

// GRPCRouteWebhook implements admission webhooks for GRPCRoute
type GRPCRouteWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.GRPCRouteDefaulter
	DuplicateChecker   *validator.DuplicateChecker
	ReferenceValidator *validator.ReferenceValidator
}

// SetupGRPCRouteWebhookWithManager sets up the webhook with the Manager
func SetupGRPCRouteWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &GRPCRouteWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewGRPCRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(mgr.GetClient()),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.GRPCRoute{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-grpcroute,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes,verbs=create;update,versions=v1alpha1,name=mgrpcroute.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &GRPCRouteWebhook{}

// Default implements webhook.CustomDefaulter
func (w *GRPCRouteWebhook) Default(ctx context.Context, obj runtime.Object) error {
	route, ok := obj.(*avapigwv1alpha1.GRPCRoute)
	if !ok {
		return fmt.Errorf("expected a GRPCRoute but got %T", obj)
	}

	grpcroutelog.Info("defaulting GRPCRoute", "name", route.Name, "namespace", route.Namespace)
	w.Defaulter.Default(route)

	return nil
}

// +kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-grpcroute,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=grpcroutes,verbs=create;update;delete,versions=v1alpha1,name=vgrpcroute.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &GRPCRouteWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *GRPCRouteWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	route, ok := obj.(*avapigwv1alpha1.GRPCRoute)
	if !ok {
		return nil, fmt.Errorf("expected a GRPCRoute but got %T", obj)
	}

	grpcroutelog.Info("validating GRPCRoute create", "name", route.Name, "namespace", route.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "GRPCRoute"); err != nil {
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

	// Validate parent gateway has GRPC/GRPCS protocol
	if err := w.validateParentProtocols(ctx, route); err != nil {
		return warnings, err
	}

	// Validate backend references
	if err := w.validateBackendRefs(ctx, route); err != nil {
		return warnings, err
	}

	// Check for duplicates
	if err := w.DuplicateChecker.CheckGRPCRouteDuplicates(ctx, route); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *GRPCRouteWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	route, ok := newObj.(*avapigwv1alpha1.GRPCRoute)
	if !ok {
		return nil, fmt.Errorf("expected a GRPCRoute but got %T", newObj)
	}

	grpcroutelog.Info("validating GRPCRoute update", "name", route.Name, "namespace", route.Namespace)

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "GRPCRoute"); err != nil {
		return nil, err
	}

	return w.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator
func (w *GRPCRouteWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	route, ok := obj.(*avapigwv1alpha1.GRPCRoute)
	if !ok {
		return nil, fmt.Errorf("expected a GRPCRoute but got %T", obj)
	}

	grpcroutelog.Info("validating GRPCRoute delete", "name", route.Name, "namespace", route.Namespace)

	return nil, nil
}

// validateSyntax performs syntax validation
func (w *GRPCRouteWebhook) validateSyntax(route *avapigwv1alpha1.GRPCRoute) error {
	errs := validator.NewValidationErrors()

	// Validate hostnames
	for i, hostname := range route.Spec.Hostnames {
		if err := validateHostname(string(hostname)); err != nil {
			errs.Add(fmt.Sprintf("spec.hostnames[%d]", i), err.Error())
		}
	}

	// Validate rules
	for i, rule := range route.Spec.Rules {
		// Validate matches
		for j, match := range rule.Matches {
			// Validate method match
			if match.Method != nil {
				if match.Method.Type != nil && *match.Method.Type == avapigwv1alpha1.GRPCMethodMatchRegularExpression {
					if match.Method.Service != nil {
						if _, err := regexp.Compile(*match.Method.Service); err != nil {
							errs.Add(fmt.Sprintf("spec.rules[%d].matches[%d].method.service", i, j),
								fmt.Sprintf("invalid regex pattern: %v", err))
						}
					}
					if match.Method.Method != nil {
						if _, err := regexp.Compile(*match.Method.Method); err != nil {
							errs.Add(fmt.Sprintf("spec.rules[%d].matches[%d].method.method", i, j),
								fmt.Sprintf("invalid regex pattern: %v", err))
						}
					}
				}
			}

			// Validate headers
			for k, header := range match.Headers {
				if header.Type != nil && *header.Type == avapigwv1alpha1.HeaderMatchRegularExpression {
					if _, err := regexp.Compile(header.Value); err != nil {
						errs.Add(fmt.Sprintf("spec.rules[%d].matches[%d].headers[%d].value", i, j, k),
							fmt.Sprintf("invalid regex pattern: %v", err))
					}
				}
			}
		}

		// Validate retry policy
		if rule.RetryPolicy != nil {
			if rule.RetryPolicy.NumRetries != nil && *rule.RetryPolicy.NumRetries < 0 {
				errs.Add(fmt.Sprintf("spec.rules[%d].retryPolicy.numRetries", i), "numRetries must be non-negative")
			}
			if rule.RetryPolicy.PerTryTimeout != nil {
				if err := validateDuration(string(*rule.RetryPolicy.PerTryTimeout)); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].retryPolicy.perTryTimeout", i), err.Error())
				}
			}
		}

		// Validate session affinity
		if rule.SessionAffinity != nil {
			switch rule.SessionAffinity.Type {
			case avapigwv1alpha1.GRPCSessionAffinityTypeHeader:
				if rule.SessionAffinity.Header == nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].sessionAffinity.header", i),
						"header configuration is required for Header session affinity type")
				}
			case avapigwv1alpha1.GRPCSessionAffinityTypeCookie:
				if rule.SessionAffinity.Cookie == nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].sessionAffinity.cookie", i),
						"cookie configuration is required for Cookie session affinity type")
				}
			}
		}
	}

	return errs.ToError()
}

// validateParentProtocols validates that parent gateways have GRPC/GRPCS listeners
func (w *GRPCRouteWebhook) validateParentProtocols(ctx context.Context, route *avapigwv1alpha1.GRPCRoute) error {
	errs := validator.NewValidationErrors()

	for i, parentRef := range route.Spec.ParentRefs {
		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}

		if parentRef.SectionName != nil {
			// Validate specific listener has GRPC/GRPCS protocol
			err := w.ReferenceValidator.ValidateGatewayListenerHasProtocol(
				ctx, namespace, parentRef.Name, *parentRef.SectionName,
				avapigwv1alpha1.ProtocolGRPC, avapigwv1alpha1.ProtocolGRPCS,
			)
			if err != nil {
				errs.Add(fmt.Sprintf("spec.parentRefs[%d]", i), err.Error())
			}
		}
	}

	return errs.ToError()
}

// validateBackendRefs validates backend references
func (w *GRPCRouteWebhook) validateBackendRefs(ctx context.Context, route *avapigwv1alpha1.GRPCRoute) error {
	errs := validator.NewValidationErrors()

	for i, rule := range route.Spec.Rules {
		for j, backendRef := range rule.BackendRefs {
			namespace := route.Namespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}

			kind := "Service"
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}

			group := ""
			if backendRef.Group != nil {
				group = *backendRef.Group
			}

			switch {
			case group == "" && kind == "Service":
				if err := w.ReferenceValidator.ValidateServiceExists(ctx, namespace, backendRef.Name); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), err.Error())
				}
			case group == avapigwv1alpha1.GroupVersion.Group && kind == "Backend":
				if err := w.ReferenceValidator.ValidateBackendExists(ctx, namespace, backendRef.Name); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), err.Error())
				}
			}
		}
	}

	return errs.ToError()
}

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

var httproutelog = logf.Log.WithName("httproute-webhook")

// Backend reference kinds for HTTPRoute validation.
const (
	httpRouteBackendKindService = "Service"
	httpRouteBackendKindBackend = "Backend"
)

// HTTPRouteWebhook implements admission webhooks for HTTPRoute
type HTTPRouteWebhook struct {
	Client             client.Client
	Defaulter          *defaulter.HTTPRouteDefaulter
	DuplicateChecker   *validator.DuplicateChecker
	ReferenceValidator *validator.ReferenceValidator
}

// SetupHTTPRouteWebhookWithManager sets up the webhook with the Manager
func SetupHTTPRouteWebhookWithManager(mgr ctrl.Manager) error {
	webhookHandler := &HTTPRouteWebhook{
		Client:             mgr.GetClient(),
		Defaulter:          defaulter.NewHTTPRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(mgr.GetClient()),
		ReferenceValidator: validator.NewReferenceValidator(mgr.GetClient()),
	}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&avapigwv1alpha1.HTTPRoute{}).
		WithDefaulter(webhookHandler).
		WithValidator(webhookHandler).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-avapigw-vyrodovalexey-github-com-v1alpha1-httproute,mutating=true,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=create;update,versions=v1alpha1,name=mhttproute.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &HTTPRouteWebhook{}

// Default implements webhook.CustomDefaulter
func (w *HTTPRouteWebhook) Default(ctx context.Context, obj runtime.Object) error {
	route, ok := obj.(*avapigwv1alpha1.HTTPRoute)
	if !ok {
		return fmt.Errorf("expected an HTTPRoute but got %T", obj)
	}

	httproutelog.Info("defaulting HTTPRoute", "name", route.Name, "namespace", route.Namespace)
	w.Defaulter.Default(route)

	return nil
}

// +kubebuilder:webhook:path=/validate-avapigw-vyrodovalexey-github-com-v1alpha1-httproute,mutating=false,failurePolicy=fail,sideEffects=None,groups=avapigw.vyrodovalexey.github.com,resources=httproutes,verbs=create;update;delete,versions=v1alpha1,name=vhttproute.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &HTTPRouteWebhook{}

// ValidateCreate implements webhook.CustomValidator
func (w *HTTPRouteWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	route, ok := obj.(*avapigwv1alpha1.HTTPRoute)
	if !ok {
		return nil, fmt.Errorf("expected an HTTPRoute but got %T", obj)
	}

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "HTTPRoute"); err != nil {
		return nil, err
	}

	httproutelog.Info("validating HTTPRoute create", "name", route.Name, "namespace", route.Namespace)

	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(route); err != nil {
		return warnings, err
	}

	// Validate parent references
	if err := w.ReferenceValidator.ValidateParentRefs(ctx, route.Spec.ParentRefs, route.Namespace); err != nil {
		return warnings, err
	}

	// Validate parent gateway has HTTP/HTTPS protocol
	if err := w.validateParentProtocols(ctx, route); err != nil {
		return warnings, err
	}

	// Validate backend references
	if err := w.validateBackendRefs(ctx, route); err != nil {
		return warnings, err
	}

	// Check for duplicates
	if err := w.DuplicateChecker.CheckHTTPRouteDuplicates(ctx, route); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator
func (w *HTTPRouteWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	route, ok := newObj.(*avapigwv1alpha1.HTTPRoute)
	if !ok {
		return nil, fmt.Errorf("expected an HTTPRoute but got %T", newObj)
	}

	// Check rate limit
	if err := GetGlobalWebhookRateLimiter().CheckRateLimit(ctx, "HTTPRoute"); err != nil {
		return nil, err
	}

	httproutelog.Info("validating HTTPRoute update", "name", route.Name, "namespace", route.Namespace)

	var warnings admission.Warnings

	// Validate syntax
	if err := w.validateSyntax(route); err != nil {
		return warnings, err
	}

	// Validate parent references
	if err := w.ReferenceValidator.ValidateParentRefs(ctx, route.Spec.ParentRefs, route.Namespace); err != nil {
		return warnings, err
	}

	// Validate parent gateway has HTTP/HTTPS protocol
	if err := w.validateParentProtocols(ctx, route); err != nil {
		return warnings, err
	}

	// Validate backend references
	if err := w.validateBackendRefs(ctx, route); err != nil {
		return warnings, err
	}

	// Check for duplicates
	if err := w.DuplicateChecker.CheckHTTPRouteDuplicates(ctx, route); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateDelete implements webhook.CustomValidator
func (w *HTTPRouteWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	route, ok := obj.(*avapigwv1alpha1.HTTPRoute)
	if !ok {
		return nil, fmt.Errorf("expected an HTTPRoute but got %T", obj)
	}

	httproutelog.Info("validating HTTPRoute delete", "name", route.Name, "namespace", route.Namespace)

	// No special handling for delete
	return nil, nil
}

// validateSyntax performs syntax validation
func (w *HTTPRouteWebhook) validateSyntax(route *avapigwv1alpha1.HTTPRoute) error {
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
			// Validate path
			if match.Path != nil {
				if match.Path.Type != nil && *match.Path.Type == avapigwv1alpha1.PathMatchRegularExpression {
					if match.Path.Value != nil {
						if _, err := regexp.Compile(*match.Path.Value); err != nil {
							errs.Add(fmt.Sprintf("spec.rules[%d].matches[%d].path.value", i, j),
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

			// Validate query params
			for k, param := range match.QueryParams {
				if param.Type != nil && *param.Type == avapigwv1alpha1.QueryParamMatchRegularExpression {
					if _, err := regexp.Compile(param.Value); err != nil {
						errs.Add(fmt.Sprintf("spec.rules[%d].matches[%d].queryParams[%d].value", i, j, k),
							fmt.Sprintf("invalid regex pattern: %v", err))
					}
				}
			}
		}

		// Validate filters
		for j, filter := range rule.Filters {
			if err := w.validateFilter(filter, fmt.Sprintf("spec.rules[%d].filters[%d]", i, j)); err != nil {
				errs.AddError(err.(*validator.ValidationError))
			}
		}

		// Validate timeouts
		if rule.Timeouts != nil {
			if rule.Timeouts.Request != nil {
				if err := validateDuration(string(*rule.Timeouts.Request)); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].timeouts.request", i), err.Error())
				}
			}
			if rule.Timeouts.BackendRequest != nil {
				if err := validateDuration(string(*rule.Timeouts.BackendRequest)); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].timeouts.backendRequest", i), err.Error())
				}
			}
		}
	}

	return errs.ToError()
}

// validateDuration validates a duration string
func validateDuration(duration string) error {
	if duration == "" {
		return nil
	}

	// Simple validation for duration format (e.g., "30s", "5m", "1h")
	durationRegex := regexp.MustCompile(`^(\d+)(ms|s|m|h)$`)
	if !durationRegex.MatchString(duration) {
		return fmt.Errorf("invalid duration format: %s (expected format like '30s', '5m', '1h')", duration)
	}

	return nil
}

// validateFilter validates a single filter
func (w *HTTPRouteWebhook) validateFilter(filter avapigwv1alpha1.HTTPRouteFilter, fieldPath string) error {
	switch filter.Type {
	case avapigwv1alpha1.HTTPRouteFilterRequestHeaderModifier:
		if filter.RequestHeaderModifier == nil {
			return validator.NewValidationError(fieldPath, "requestHeaderModifier is required for type RequestHeaderModifier")
		}
	case avapigwv1alpha1.HTTPRouteFilterResponseHeaderModifier:
		if filter.ResponseHeaderModifier == nil {
			return validator.NewValidationError(fieldPath, "responseHeaderModifier is required for type ResponseHeaderModifier")
		}
	case avapigwv1alpha1.HTTPRouteFilterRequestMirror:
		if filter.RequestMirror == nil {
			return validator.NewValidationError(fieldPath, "requestMirror is required for type RequestMirror")
		}
	case avapigwv1alpha1.HTTPRouteFilterRequestRedirect:
		if filter.RequestRedirect == nil {
			return validator.NewValidationError(fieldPath, "requestRedirect is required for type RequestRedirect")
		}
	case avapigwv1alpha1.HTTPRouteFilterURLRewrite:
		if filter.URLRewrite == nil {
			return validator.NewValidationError(fieldPath, "urlRewrite is required for type URLRewrite")
		}
	case avapigwv1alpha1.HTTPRouteFilterDirectResponse:
		if filter.DirectResponse == nil {
			return validator.NewValidationError(fieldPath, "directResponse is required for type DirectResponse")
		}
	}
	return nil
}

// validateParentProtocols validates that parent gateways have HTTP/HTTPS listeners
func (w *HTTPRouteWebhook) validateParentProtocols(ctx context.Context, route *avapigwv1alpha1.HTTPRoute) error {
	errs := validator.NewValidationErrors()

	for i, parentRef := range route.Spec.ParentRefs {
		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}

		if parentRef.SectionName != nil {
			// Validate specific listener has HTTP/HTTPS protocol
			err := w.ReferenceValidator.ValidateGatewayListenerHasProtocol(
				ctx, namespace, parentRef.Name, *parentRef.SectionName,
				avapigwv1alpha1.ProtocolHTTP, avapigwv1alpha1.ProtocolHTTPS,
			)
			if err != nil {
				errs.Add(fmt.Sprintf("spec.parentRefs[%d]", i), err.Error())
			}
		}
	}

	return errs.ToError()
}

// validateBackendRefs validates backend references
func (w *HTTPRouteWebhook) validateBackendRefs(ctx context.Context, route *avapigwv1alpha1.HTTPRoute) error {
	errs := validator.NewValidationErrors()

	for i, rule := range route.Spec.Rules {
		for j, backendRef := range rule.BackendRefs {
			namespace := route.Namespace
			if backendRef.Namespace != nil {
				namespace = *backendRef.Namespace
			}

			kind := httpRouteBackendKindService
			if backendRef.Kind != nil {
				kind = *backendRef.Kind
			}

			group := ""
			if backendRef.Group != nil {
				group = *backendRef.Group
			}

			switch {
			case group == "" && kind == httpRouteBackendKindService:
				if err := w.ReferenceValidator.ValidateServiceExists(ctx, namespace, backendRef.Name); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), err.Error())
				}
			case group == avapigwv1alpha1.GroupVersion.Group && kind == httpRouteBackendKindBackend:
				if err := w.ReferenceValidator.ValidateBackendExists(ctx, namespace, backendRef.Name); err != nil {
					errs.Add(fmt.Sprintf("spec.rules[%d].backendRefs[%d]", i, j), err.Error())
				}
			}
		}
	}

	return errs.ToError()
}

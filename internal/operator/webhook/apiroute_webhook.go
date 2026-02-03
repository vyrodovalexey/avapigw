// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// APIRouteValidator validates APIRoute resources.
type APIRouteValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
}

// SetupAPIRouteWebhook sets up the APIRoute webhook with the manager.
func SetupAPIRouteWebhook(mgr ctrl.Manager) error {
	validator := &APIRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateChecker(mgr.GetClient()),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.APIRoute{}).
		WithValidator(validator).
		Complete()
}

// ValidateCreate implements admission.CustomValidator.
func (v *APIRouteValidator) ValidateCreate(
	ctx context.Context,
	obj *avapigwv1alpha1.APIRoute,
) (admission.Warnings, error) {
	warnings, err := v.validate(obj)
	if err != nil {
		return warnings, err
	}

	// Check for duplicates
	if v.DuplicateChecker != nil {
		if dupErr := v.DuplicateChecker.CheckAPIRouteDuplicate(ctx, obj); dupErr != nil {
			return warnings, dupErr
		}
	}

	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (v *APIRouteValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj *avapigwv1alpha1.APIRoute,
) (admission.Warnings, error) {
	warnings, err := v.validate(newObj)
	if err != nil {
		return warnings, err
	}

	// Check for duplicates (excluding self)
	if v.DuplicateChecker != nil {
		if dupErr := v.DuplicateChecker.CheckAPIRouteDuplicate(ctx, newObj); dupErr != nil {
			return warnings, dupErr
		}
	}

	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
func (v *APIRouteValidator) ValidateDelete(_ context.Context, _ *avapigwv1alpha1.APIRoute) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs validation on the APIRoute spec.
//
//nolint:gocognit,gocyclo // Validation requires checking multiple fields: matches, routes, redirects, policies
func (v *APIRouteValidator) validate(apiRoute *avapigwv1alpha1.APIRoute) (admission.Warnings, error) {
	var warnings admission.Warnings
	var errs []string

	spec := &apiRoute.Spec

	// Validate match conditions
	if err := v.validateMatches(spec.Match); err != nil {
		errs = append(errs, err.Error())
	}

	// Validate route destinations
	if err := v.validateRouteDestinations(spec.Route); err != nil {
		errs = append(errs, err.Error())
	}

	// Validate timeout
	if spec.Timeout != "" {
		if err := validateDuration(string(spec.Timeout)); err != nil {
			errs = append(errs, fmt.Sprintf("invalid timeout: %v", err))
		}
	}

	// Validate retry policy
	if spec.Retries != nil {
		if err := v.validateRetryPolicy(spec.Retries); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate redirect configuration
	if spec.Redirect != nil {
		if err := v.validateRedirect(spec.Redirect); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate direct response
	if spec.DirectResponse != nil {
		if err := v.validateDirectResponse(spec.DirectResponse); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate fault injection
	if spec.Fault != nil {
		if err := v.validateFaultInjection(spec.Fault); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate rate limit
	if spec.RateLimit != nil {
		if err := validateRateLimit(spec.RateLimit); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate cache configuration
	if spec.Cache != nil {
		if err := v.validateCache(spec.Cache); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate CORS configuration
	if spec.CORS != nil {
		if err := validateCORS(spec.CORS); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate max sessions
	if spec.MaxSessions != nil {
		if err := validateMaxSessions(spec.MaxSessions); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate TLS configuration
	if spec.TLS != nil {
		if err := validateRouteTLS(spec.TLS); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate authentication configuration
	if spec.Authentication != nil {
		if err := validateAuthentication(spec.Authentication); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate authorization configuration
	if spec.Authorization != nil {
		if err := validateAuthorization(spec.Authorization); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Check for conflicting configurations
	if spec.Redirect != nil && len(spec.Route) > 0 {
		warnings = append(warnings, "redirect and route are both specified; redirect will take precedence")
	}
	if spec.DirectResponse != nil && len(spec.Route) > 0 {
		warnings = append(warnings, "directResponse and route are both specified; directResponse will take precedence")
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

// validateMatches validates route match conditions.
//
//nolint:gocognit,gocyclo // Match validation requires checking URI, methods, headers, and query params
func (v *APIRouteValidator) validateMatches(matches []avapigwv1alpha1.RouteMatch) error {
	for i, match := range matches {
		// Validate URI match
		if match.URI != nil {
			matchCount := 0
			if match.URI.Exact != "" {
				matchCount++
			}
			if match.URI.Prefix != "" {
				matchCount++
			}
			if match.URI.Regex != "" {
				matchCount++
				if _, err := regexp.Compile(match.URI.Regex); err != nil {
					return fmt.Errorf("match[%d].uri.regex is invalid: %w", i, err)
				}
			}
			if matchCount > 1 {
				return fmt.Errorf("match[%d].uri: only one of exact, prefix, or regex can be specified", i)
			}
		}

		// Validate HTTP methods
		validMethods := map[string]bool{
			"GET": true, "POST": true, "PUT": true, "DELETE": true,
			"PATCH": true, "HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
		}
		for _, method := range match.Methods {
			if !validMethods[strings.ToUpper(method)] {
				return fmt.Errorf("match[%d].methods: invalid HTTP method %q", i, method)
			}
		}

		// Validate header matches
		for j, header := range match.Headers {
			if header.Name == "" {
				return fmt.Errorf("match[%d].headers[%d].name is required", i, j)
			}
			if header.Regex != "" {
				if _, err := regexp.Compile(header.Regex); err != nil {
					return fmt.Errorf("match[%d].headers[%d].regex is invalid: %w", i, j, err)
				}
			}
		}

		// Validate query param matches
		for j, qp := range match.QueryParams {
			if qp.Name == "" {
				return fmt.Errorf("match[%d].queryParams[%d].name is required", i, j)
			}
			if qp.Regex != "" {
				if _, err := regexp.Compile(qp.Regex); err != nil {
					return fmt.Errorf("match[%d].queryParams[%d].regex is invalid: %w", i, j, err)
				}
			}
		}
	}

	return nil
}

// validateRouteDestinations validates route destinations.
func (v *APIRouteValidator) validateRouteDestinations(routes []avapigwv1alpha1.RouteDestination) error {
	totalWeight := 0
	for i, route := range routes {
		if route.Destination.Host == "" {
			return fmt.Errorf("route[%d].destination.host is required", i)
		}
		if route.Destination.Port < 1 || route.Destination.Port > 65535 {
			return fmt.Errorf("route[%d].destination.port must be between 1 and 65535", i)
		}
		if route.Weight < 0 || route.Weight > 100 {
			return fmt.Errorf("route[%d].weight must be between 0 and 100", i)
		}
		totalWeight += route.Weight
	}

	if len(routes) > 1 && totalWeight != 100 && totalWeight != 0 {
		return fmt.Errorf("total weight of all routes must equal 100 (got %d)", totalWeight)
	}

	return nil
}

// validateRetryPolicy validates retry policy configuration.
func (v *APIRouteValidator) validateRetryPolicy(policy *avapigwv1alpha1.RetryPolicy) error {
	if policy.Attempts < 1 || policy.Attempts > 10 {
		return fmt.Errorf("retries.attempts must be between 1 and 10")
	}

	if policy.PerTryTimeout != "" {
		if err := validateDuration(string(policy.PerTryTimeout)); err != nil {
			return fmt.Errorf("retries.perTryTimeout is invalid: %w", err)
		}
	}

	if policy.RetryOn != "" {
		validConditions := map[string]bool{
			"5xx": true, "reset": true, "connect-failure": true,
			"retriable-4xx": true, "refused-stream": true, "retriable-status-codes": true,
			"retriable-headers": true, "gateway-error": true,
		}
		for _, cond := range strings.Split(policy.RetryOn, ",") {
			cond = strings.TrimSpace(cond)
			if !validConditions[cond] {
				return fmt.Errorf("retries.retryOn contains invalid condition: %q", cond)
			}
		}
	}

	return nil
}

// validateRedirect validates redirect configuration.
func (v *APIRouteValidator) validateRedirect(redirect *avapigwv1alpha1.RedirectConfig) error {
	if redirect.URI != "" {
		if _, err := url.Parse(redirect.URI); err != nil {
			return fmt.Errorf("redirect.uri is invalid: %w", err)
		}
	}

	validCodes := map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}
	if redirect.Code != 0 && !validCodes[redirect.Code] {
		return fmt.Errorf("redirect.code must be one of 301, 302, 303, 307, 308")
	}

	if redirect.Scheme != "" && redirect.Scheme != "http" && redirect.Scheme != "https" {
		return fmt.Errorf("redirect.scheme must be 'http' or 'https'")
	}

	if redirect.Port != 0 && (redirect.Port < 1 || redirect.Port > 65535) {
		return fmt.Errorf("redirect.port must be between 1 and 65535")
	}

	return nil
}

// validateDirectResponse validates direct response configuration.
func (v *APIRouteValidator) validateDirectResponse(dr *avapigwv1alpha1.DirectResponseConfig) error {
	if dr.Status < 100 || dr.Status > 599 {
		return fmt.Errorf("directResponse.status must be between 100 and 599")
	}

	return nil
}

// validateFaultInjection validates fault injection configuration.
func (v *APIRouteValidator) validateFaultInjection(fault *avapigwv1alpha1.FaultInjection) error {
	if fault.Delay != nil {
		if fault.Delay.FixedDelay == "" {
			return fmt.Errorf("fault.delay.fixedDelay is required")
		}
		if err := validateDuration(string(fault.Delay.FixedDelay)); err != nil {
			return fmt.Errorf("fault.delay.fixedDelay is invalid: %w", err)
		}
		if fault.Delay.Percentage < 0 || fault.Delay.Percentage > 100 {
			return fmt.Errorf("fault.delay.percentage must be between 0 and 100")
		}
	}

	if fault.Abort != nil {
		if fault.Abort.HTTPStatus < 100 || fault.Abort.HTTPStatus > 599 {
			return fmt.Errorf("fault.abort.httpStatus must be between 100 and 599")
		}
		if fault.Abort.Percentage < 0 || fault.Abort.Percentage > 100 {
			return fmt.Errorf("fault.abort.percentage must be between 0 and 100")
		}
	}

	return nil
}

// validateCache validates cache configuration.
func (v *APIRouteValidator) validateCache(cache *avapigwv1alpha1.CacheConfig) error {
	if cache.TTL != "" {
		if err := validateDuration(string(cache.TTL)); err != nil {
			return fmt.Errorf("cache.ttl is invalid: %w", err)
		}
	}

	if cache.StaleWhileRevalidate != "" {
		if err := validateDuration(string(cache.StaleWhileRevalidate)); err != nil {
			return fmt.Errorf("cache.staleWhileRevalidate is invalid: %w", err)
		}
	}

	return nil
}

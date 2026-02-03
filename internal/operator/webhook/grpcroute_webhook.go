// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// GRPCRouteValidator validates GRPCRoute resources.
type GRPCRouteValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
}

// SetupGRPCRouteWebhook sets up the GRPCRoute webhook with the manager.
func SetupGRPCRouteWebhook(mgr ctrl.Manager) error {
	validator := &GRPCRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateChecker(mgr.GetClient()),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GRPCRoute{}).
		WithValidator(validator).
		Complete()
}

// ValidateCreate implements admission.CustomValidator.
func (v *GRPCRouteValidator) ValidateCreate(
	ctx context.Context,
	obj *avapigwv1alpha1.GRPCRoute,
) (admission.Warnings, error) {
	warnings, err := v.validate(obj)
	if err != nil {
		return warnings, err
	}

	// Check for duplicates
	if v.DuplicateChecker != nil {
		if dupErr := v.DuplicateChecker.CheckGRPCRouteDuplicate(ctx, obj); dupErr != nil {
			return warnings, dupErr
		}
	}

	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (v *GRPCRouteValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj *avapigwv1alpha1.GRPCRoute,
) (admission.Warnings, error) {
	warnings, err := v.validate(newObj)
	if err != nil {
		return warnings, err
	}

	// Check for duplicates (excluding self)
	if v.DuplicateChecker != nil {
		if dupErr := v.DuplicateChecker.CheckGRPCRouteDuplicate(ctx, newObj); dupErr != nil {
			return warnings, dupErr
		}
	}

	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
func (v *GRPCRouteValidator) ValidateDelete(
	_ context.Context,
	_ *avapigwv1alpha1.GRPCRoute,
) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs validation on the GRPCRoute spec.
//
//nolint:gocognit,gocyclo,unparam // Validation requires multiple field checks; warnings for interface
func (v *GRPCRouteValidator) validate(grpcRoute *avapigwv1alpha1.GRPCRoute) (admission.Warnings, error) {
	var warnings admission.Warnings
	var errs []string

	spec := &grpcRoute.Spec

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
		if err := v.validateGRPCRetryPolicy(spec.Retries); err != nil {
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

	// Validate max sessions configuration
	if spec.MaxSessions != nil {
		if err := validateMaxSessions(spec.MaxSessions); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate request limits configuration
	if spec.RequestLimits != nil {
		if err := validateRequestLimits(spec.RequestLimits); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

// validateMatches validates gRPC route match conditions.
//
//nolint:gocognit // Match validation requires checking multiple nested conditions
func (v *GRPCRouteValidator) validateMatches(matches []avapigwv1alpha1.GRPCRouteMatch) error {
	for i, match := range matches {
		// Validate service match
		if match.Service != nil {
			if err := v.validateStringMatch(match.Service, fmt.Sprintf("match[%d].service", i)); err != nil {
				return err
			}
		}

		// Validate method match
		if match.Method != nil {
			if err := v.validateStringMatch(match.Method, fmt.Sprintf("match[%d].method", i)); err != nil {
				return err
			}
		}

		// Validate authority match
		if match.Authority != nil {
			if err := v.validateStringMatch(match.Authority, fmt.Sprintf("match[%d].authority", i)); err != nil {
				return err
			}
		}

		// Validate metadata matches
		for j, meta := range match.Metadata {
			if meta.Name == "" {
				return fmt.Errorf("match[%d].metadata[%d].name is required", i, j)
			}
			if meta.Regex != "" {
				if _, err := regexp.Compile(meta.Regex); err != nil {
					return fmt.Errorf("match[%d].metadata[%d].regex is invalid: %w", i, j, err)
				}
			}
		}
	}

	return nil
}

// validateStringMatch validates a StringMatch configuration.
func (v *GRPCRouteValidator) validateStringMatch(sm *avapigwv1alpha1.StringMatch, fieldPath string) error {
	matchCount := 0
	if sm.Exact != "" {
		matchCount++
	}
	if sm.Prefix != "" {
		matchCount++
	}
	if sm.Regex != "" {
		matchCount++
		if _, err := regexp.Compile(sm.Regex); err != nil {
			return fmt.Errorf("%s.regex is invalid: %w", fieldPath, err)
		}
	}

	if matchCount > 1 {
		return fmt.Errorf("%s: only one of exact, prefix, or regex can be specified", fieldPath)
	}

	return nil
}

// validateRouteDestinations validates route destinations.
func (v *GRPCRouteValidator) validateRouteDestinations(routes []avapigwv1alpha1.RouteDestination) error {
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

// validateGRPCRetryPolicy validates gRPC retry policy configuration.
func (v *GRPCRouteValidator) validateGRPCRetryPolicy(policy *avapigwv1alpha1.GRPCRetryPolicy) error {
	if policy.Attempts < 1 || policy.Attempts > 10 {
		return fmt.Errorf("retries.attempts must be between 1 and 10")
	}

	if policy.PerTryTimeout != "" {
		if err := validateDuration(string(policy.PerTryTimeout)); err != nil {
			return fmt.Errorf("retries.perTryTimeout is invalid: %w", err)
		}
	}

	if policy.BackoffBaseInterval != "" {
		if err := validateDuration(string(policy.BackoffBaseInterval)); err != nil {
			return fmt.Errorf("retries.backoffBaseInterval is invalid: %w", err)
		}
	}

	if policy.BackoffMaxInterval != "" {
		if err := validateDuration(string(policy.BackoffMaxInterval)); err != nil {
			return fmt.Errorf("retries.backoffMaxInterval is invalid: %w", err)
		}
	}

	if policy.RetryOn != "" {
		//nolint:misspell // "cancelled" is the correct gRPC status code spelling
		validConditions := map[string]bool{
			"cancelled": true, "deadline-exceeded": true, "internal": true,
			"resource-exhausted": true, "unavailable": true,
		}
		for _, cond := range strings.Split(policy.RetryOn, ",") {
			cond = strings.TrimSpace(cond)
			if !validConditions[cond] {
				return fmt.Errorf("retries.retryOn contains invalid gRPC status: %q", cond)
			}
		}
	}

	return nil
}

// validateCache validates cache configuration.
func (v *GRPCRouteValidator) validateCache(cache *avapigwv1alpha1.CacheConfig) error {
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

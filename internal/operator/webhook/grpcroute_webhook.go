// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Compile-time assertion: GRPCRouteValidator must implement admission.Validator
// for the typed *avapigwv1alpha1.GRPCRoute parameter.
var _ admission.Validator[*avapigwv1alpha1.GRPCRoute] = (*GRPCRouteValidator)(nil)

// GRPCRouteValidator validates GRPCRoute resources.
type GRPCRouteValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
}

// SetupGRPCRouteWebhook sets up the GRPCRoute webhook with the manager using default configuration.
func SetupGRPCRouteWebhook(mgr ctrl.Manager) error {
	return SetupGRPCRouteWebhookWithConfig(mgr, DefaultDuplicateCheckerConfig())
}

// SetupGRPCRouteWebhookWithConfig sets up the GRPCRoute webhook with the manager using the provided configuration.
func SetupGRPCRouteWebhookWithConfig(mgr ctrl.Manager, cfg DuplicateCheckerConfig) error {
	validator := &GRPCRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfig(mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GRPCRoute{}).
		WithValidator(validator).
		Complete()
}

// SetupGRPCRouteWebhookWithConfigAndContext sets up the GRPCRoute webhook with context-based
// lifecycle management for the DuplicateChecker cleanup goroutine.
func SetupGRPCRouteWebhookWithConfigAndContext(
	ctx context.Context, mgr ctrl.Manager, cfg DuplicateCheckerConfig,
) error {
	validator := &GRPCRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfigWithContext(ctx, mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GRPCRoute{}).
		WithValidator(validator).
		Complete()
}

// SetupGRPCRouteWebhookWithChecker sets up the GRPCRoute webhook with a shared DuplicateChecker.
// This avoids creating multiple DuplicateChecker instances (and cleanup goroutines) across webhooks.
func SetupGRPCRouteWebhookWithChecker(mgr ctrl.Manager, dc *DuplicateChecker) error {
	validator := &GRPCRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: dc,
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
	start := time.Now()
	warnings, err := v.validate(obj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("GRPCRoute", "create", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	// Check for duplicates
	if v.DuplicateChecker != nil {
		if dupErr := v.DuplicateChecker.CheckGRPCRouteDuplicate(ctx, obj); dupErr != nil {
			GetWebhookMetrics().RecordValidation("GRPCRoute", "create", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
	}

	GetWebhookMetrics().RecordValidation("GRPCRoute", "create", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (v *GRPCRouteValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj *avapigwv1alpha1.GRPCRoute,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(newObj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("GRPCRoute", "update", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	// Check for duplicates (excluding self)
	if v.DuplicateChecker != nil {
		if dupErr := v.DuplicateChecker.CheckGRPCRouteDuplicate(ctx, newObj); dupErr != nil {
			GetWebhookMetrics().RecordValidation("GRPCRoute", "update", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
	}

	GetWebhookMetrics().RecordValidation("GRPCRoute", "update", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
// No-op: GRPCRoute deletion does not require validation because the gateway
// controller handles cleanup of derived configuration via finalizers.
func (v *GRPCRouteValidator) ValidateDelete(
	_ context.Context,
	_ *avapigwv1alpha1.GRPCRoute,
) (admission.Warnings, error) {
	return nil, nil
}

// validate performs validation on the GRPCRoute spec.
//
//nolint:gocognit,gocyclo,unparam // Validation requires checking matches, routes, policies; warnings for interface
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

	// Security warnings for plaintext secrets in authentication config
	if spec.Authentication != nil {
		warnings = append(warnings, warnPlaintextAuthSecrets(spec.Authentication)...)
	}

	// Security warnings for plaintext secrets in authorization cache sentinel config
	if spec.Authorization != nil && spec.Authorization.Cache != nil && spec.Authorization.Cache.Sentinel != nil {
		warnings = append(warnings, warnPlaintextSentinelSecrets(spec.Authorization.Cache.Sentinel)...)
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

// validateMatches validates gRPC route match conditions.
//
//nolint:gocognit // Match validation requires checking service, method, authority, and metadata
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
		if route.Destination.Port < MinPort || route.Destination.Port > MaxPort {
			return fmt.Errorf("route[%d].destination.port must be between %d and %d", i, MinPort, MaxPort)
		}
		if route.Weight < MinWeight || route.Weight > MaxWeight {
			return fmt.Errorf("route[%d].weight must be between %d and %d", i, MinWeight, MaxWeight)
		}
		totalWeight += route.Weight
	}

	if len(routes) > 1 && totalWeight != TotalWeightExpected && totalWeight != 0 {
		return fmt.Errorf("total weight of all routes must equal %d (got %d)", TotalWeightExpected, totalWeight)
	}

	return nil
}

// validateGRPCRetryPolicy validates gRPC retry policy configuration.
func (v *GRPCRouteValidator) validateGRPCRetryPolicy(policy *avapigwv1alpha1.GRPCRetryPolicy) error {
	if policy.Attempts < MinRetryAttempts || policy.Attempts > MaxRetryAttempts {
		return fmt.Errorf("retries.attempts must be between %d and %d", MinRetryAttempts, MaxRetryAttempts)
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
		//nolint:misspell // "cancelled" is the correct gRPC status code spelling per gRPC specification
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

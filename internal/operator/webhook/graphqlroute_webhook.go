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

// Compile-time assertion: GraphQLRouteValidator must implement admission.Validator
// for the typed *avapigwv1alpha1.GraphQLRoute parameter.
var _ admission.Validator[*avapigwv1alpha1.GraphQLRoute] = (*GraphQLRouteValidator)(nil)

// GraphQLRouteValidator validates GraphQLRoute resources.
type GraphQLRouteValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
}

// SetupGraphQLRouteWebhook sets up the GraphQLRoute webhook with the manager using default configuration.
func SetupGraphQLRouteWebhook(mgr ctrl.Manager) error {
	return SetupGraphQLRouteWebhookWithConfig(mgr, DefaultDuplicateCheckerConfig())
}

// SetupGraphQLRouteWebhookWithConfig sets up the GraphQLRoute webhook with the manager
// using the provided configuration.
func SetupGraphQLRouteWebhookWithConfig(mgr ctrl.Manager, cfg DuplicateCheckerConfig) error {
	validator := &GraphQLRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfig(mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GraphQLRoute{}).
		WithValidator(validator).
		Complete()
}

// SetupGraphQLRouteWebhookWithConfigAndContext sets up the GraphQLRoute webhook with context-based
// lifecycle management for the DuplicateChecker cleanup goroutine.
func SetupGraphQLRouteWebhookWithConfigAndContext(
	ctx context.Context, mgr ctrl.Manager, cfg DuplicateCheckerConfig,
) error {
	validator := &GraphQLRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfigWithContext(ctx, mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GraphQLRoute{}).
		WithValidator(validator).
		Complete()
}

// SetupGraphQLRouteWebhookWithChecker sets up the GraphQLRoute webhook with a shared DuplicateChecker.
// This avoids creating multiple DuplicateChecker instances (and cleanup goroutines) across webhooks.
func SetupGraphQLRouteWebhookWithChecker(mgr ctrl.Manager, dc *DuplicateChecker) error {
	validator := &GraphQLRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: dc,
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GraphQLRoute{}).
		WithValidator(validator).
		Complete()
}

// ValidateCreate implements admission.CustomValidator.
func (v *GraphQLRouteValidator) ValidateCreate(
	ctx context.Context,
	obj *avapigwv1alpha1.GraphQLRoute,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(obj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("GraphQLRoute", "create", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	// Check for duplicates
	if v.DuplicateChecker != nil {
		if dupErr := v.DuplicateChecker.CheckGraphQLRouteDuplicate(ctx, obj); dupErr != nil {
			GetWebhookMetrics().RecordValidation("GraphQLRoute", "create", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
	}

	// Check for cross-CRD path conflicts with APIRoutes
	if v.DuplicateChecker != nil {
		if crossErr := v.DuplicateChecker.CheckGraphQLRouteCrossConflictsWithAPIRoute(ctx, obj); crossErr != nil {
			GetWebhookMetrics().RecordValidation("GraphQLRoute", "create", "rejected", time.Since(start), len(warnings))
			return warnings, crossErr
		}
	}

	GetWebhookMetrics().RecordValidation("GraphQLRoute", "create", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (v *GraphQLRouteValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj *avapigwv1alpha1.GraphQLRoute,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(newObj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("GraphQLRoute", "update", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	// Check for duplicates (excluding self)
	if v.DuplicateChecker != nil {
		if dupErr := v.DuplicateChecker.CheckGraphQLRouteDuplicate(ctx, newObj); dupErr != nil {
			GetWebhookMetrics().RecordValidation("GraphQLRoute", "update", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
	}

	// Check for cross-CRD path conflicts with APIRoutes
	if v.DuplicateChecker != nil {
		if crossErr := v.DuplicateChecker.CheckGraphQLRouteCrossConflictsWithAPIRoute(ctx, newObj); crossErr != nil {
			GetWebhookMetrics().RecordValidation("GraphQLRoute", "update", "rejected", time.Since(start), len(warnings))
			return warnings, crossErr
		}
	}

	GetWebhookMetrics().RecordValidation("GraphQLRoute", "update", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
// No-op: GraphQLRoute deletion does not require validation because the gateway
// controller handles cleanup of derived configuration via finalizers.
func (v *GraphQLRouteValidator) ValidateDelete(
	_ context.Context,
	_ *avapigwv1alpha1.GraphQLRoute,
) (admission.Warnings, error) {
	return nil, nil
}

// validGraphQLOperations defines the valid GraphQL operation types.
var validGraphQLOperations = map[string]bool{
	"query":        true,
	"mutation":     true,
	"subscription": true,
}

// validate performs validation on the GraphQLRoute spec.
//
//nolint:gocognit,gocyclo,unparam // Validation requires checking matches, routes, policies; warnings for interface
func (v *GraphQLRouteValidator) validate(graphqlRoute *avapigwv1alpha1.GraphQLRoute) (admission.Warnings, error) {
	var warnings admission.Warnings
	var errs []string

	spec := &graphqlRoute.Spec

	// Validate match conditions
	if err := v.validateGraphQLMatches(spec.Match); err != nil {
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

	// Validate GraphQL-specific fields
	if spec.DepthLimit < 0 {
		errs = append(errs, "depthLimit must be non-negative")
	}

	if spec.ComplexityLimit < 0 {
		errs = append(errs, "complexityLimit must be non-negative")
	}

	// Validate allowed operations
	if err := v.validateAllowedOperations(spec.AllowedOperations); err != nil {
		errs = append(errs, err.Error())
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

// validateGraphQLMatches validates GraphQL route match conditions.
//
//nolint:gocognit // Match validation requires checking path, operation type, operation name, and headers
func (v *GraphQLRouteValidator) validateGraphQLMatches(matches []avapigwv1alpha1.GraphQLRouteMatch) error {
	for i, match := range matches {
		// Validate path match
		if match.Path != nil {
			if err := v.validateStringMatch(match.Path, fmt.Sprintf("match[%d].path", i)); err != nil {
				return err
			}
		}

		// Validate operation type
		if match.OperationType != "" {
			if !validGraphQLOperations[match.OperationType] {
				return fmt.Errorf("match[%d].operationType must be one of: query, mutation, subscription", i)
			}
		}

		// Validate operation name match
		if match.OperationName != nil {
			opNamePath := fmt.Sprintf("match[%d].operationName", i)
			if err := v.validateStringMatch(match.OperationName, opNamePath); err != nil {
				return err
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
	}

	return nil
}

// validateStringMatch validates a StringMatch configuration.
func (v *GraphQLRouteValidator) validateStringMatch(sm *avapigwv1alpha1.StringMatch, fieldPath string) error {
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
func (v *GraphQLRouteValidator) validateRouteDestinations(routes []avapigwv1alpha1.RouteDestination) error {
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

// validateRetryPolicy validates retry policy configuration.
func (v *GraphQLRouteValidator) validateRetryPolicy(policy *avapigwv1alpha1.RetryPolicy) error {
	if policy.Attempts < MinRetryAttempts || policy.Attempts > MaxRetryAttempts {
		return fmt.Errorf("retries.attempts must be between %d and %d", MinRetryAttempts, MaxRetryAttempts)
	}

	if policy.PerTryTimeout != "" {
		if err := validateDuration(string(policy.PerTryTimeout)); err != nil {
			return fmt.Errorf("retries.perTryTimeout is invalid: %w", err)
		}
	}

	return nil
}

// validateCache validates cache configuration.
func (v *GraphQLRouteValidator) validateCache(cache *avapigwv1alpha1.CacheConfig) error {
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

// validateAllowedOperations validates the allowed operations list.
func (v *GraphQLRouteValidator) validateAllowedOperations(ops []string) error {
	for i, op := range ops {
		if !validGraphQLOperations[op] {
			return fmt.Errorf(
				"allowedOperations[%d] %q is invalid; must be one of: query, mutation, subscription",
				i, op)
		}
	}
	return nil
}

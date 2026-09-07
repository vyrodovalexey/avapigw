// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Compile-time assertion: MCPRouteValidator must implement admission.Validator
// for the typed *avapigwv1alpha1.MCPRoute parameter.
var _ admission.Validator[*avapigwv1alpha1.MCPRoute] = (*MCPRouteValidator)(nil)

// MCPRouteValidator validates MCPRoute resources.
type MCPRouteValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
}

// SetupMCPRouteWebhook sets up the MCPRoute webhook with the manager using default configuration.
func SetupMCPRouteWebhook(mgr ctrl.Manager) error {
	return SetupMCPRouteWebhookWithConfig(mgr, DefaultDuplicateCheckerConfig())
}

// SetupMCPRouteWebhookWithConfig sets up the MCPRoute webhook with the manager
// using the provided configuration.
func SetupMCPRouteWebhookWithConfig(mgr ctrl.Manager, cfg DuplicateCheckerConfig) error {
	validator := &MCPRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfig(mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.MCPRoute{}).
		WithValidator(validator).
		Complete()
}

// SetupMCPRouteWebhookWithConfigAndContext sets up the MCPRoute webhook with context-based
// lifecycle management for the DuplicateChecker cleanup goroutine.
func SetupMCPRouteWebhookWithConfigAndContext(
	ctx context.Context, mgr ctrl.Manager, cfg DuplicateCheckerConfig,
) error {
	validator := &MCPRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfigWithContext(ctx, mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.MCPRoute{}).
		WithValidator(validator).
		Complete()
}

// SetupMCPRouteWebhookWithChecker sets up the MCPRoute webhook with a shared DuplicateChecker.
// This avoids creating multiple DuplicateChecker instances (and cleanup goroutines) across webhooks.
func SetupMCPRouteWebhookWithChecker(mgr ctrl.Manager, dc *DuplicateChecker) error {
	validator := &MCPRouteValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: dc,
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.MCPRoute{}).
		WithValidator(validator).
		Complete()
}

// runMCPCrossChecks runs the duplicate and cross-kind conflict checks for an
// MCPRoute in the established order (same-kind duplicate → APIRoute
// cross-check → GraphQLRoute cross-check) and returns the first conflict
// error, if any. Extracted so ValidateCreate and ValidateUpdate share one
// implementation instead of duplicating the check sequence.
func (v *MCPRouteValidator) runMCPCrossChecks(
	ctx context.Context,
	obj *avapigwv1alpha1.MCPRoute,
) error {
	if v.DuplicateChecker == nil {
		return nil
	}
	if err := v.DuplicateChecker.CheckMCPRouteDuplicate(ctx, obj); err != nil {
		return err
	}
	if err := v.DuplicateChecker.CheckMCPRouteCrossConflictsWithAPIRoute(ctx, obj); err != nil {
		return err
	}
	return v.DuplicateChecker.CheckMCPRouteCrossConflictsWithGraphQL(ctx, obj)
}

// ValidateCreate implements admission.CustomValidator.
func (v *MCPRouteValidator) ValidateCreate(
	ctx context.Context,
	obj *avapigwv1alpha1.MCPRoute,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(obj)
	if err != nil {
		GetWebhookMetrics().RecordValidation(kindMCPRoute, "create", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	if crossErr := v.runMCPCrossChecks(ctx, obj); crossErr != nil {
		GetWebhookMetrics().RecordValidation(kindMCPRoute, "create", "rejected", time.Since(start), len(warnings))
		return warnings, crossErr
	}

	GetWebhookMetrics().RecordValidation(kindMCPRoute, "create", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
//
// Two lifecycle short-circuits prevent the webhook/finalizer deadlock:
// deleting objects are admitted unconditionally, and metadata-only updates
// (semantically unchanged spec) run local spec validation only, skipping
// duplicate and cross-kind conflict checks.
func (v *MCPRouteValidator) ValidateUpdate(
	ctx context.Context,
	oldObj, newObj *avapigwv1alpha1.MCPRoute,
) (admission.Warnings, error) {
	// The object is being deleted; admit so metadata updates (for example
	// finalizer removal) always proceed.
	if newObj.GetDeletionTimestamp() != nil {
		return nil, nil
	}

	start := time.Now()
	warnings, err := v.validate(newObj)
	if err != nil {
		GetWebhookMetrics().RecordValidation(kindMCPRoute, "update", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	// Metadata-only update: the spec is unchanged, so this update cannot
	// introduce new duplicate or cross-kind conflicts. Local spec
	// validation (above) still applies.
	if apiequality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		GetWebhookMetrics().RecordValidation(kindMCPRoute, "update", "allowed", time.Since(start), len(warnings))
		return warnings, nil
	}

	if crossErr := v.runMCPCrossChecks(ctx, newObj); crossErr != nil {
		GetWebhookMetrics().RecordValidation(kindMCPRoute, "update", "rejected", time.Since(start), len(warnings))
		return warnings, crossErr
	}

	GetWebhookMetrics().RecordValidation(kindMCPRoute, "update", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
// No-op: MCPRoute deletion does not require validation because the gateway
// controller handles cleanup of derived configuration via finalizers.
func (v *MCPRouteValidator) ValidateDelete(
	_ context.Context,
	_ *avapigwv1alpha1.MCPRoute,
) (admission.Warnings, error) {
	return nil, nil
}

// validate performs validation on the MCPRoute spec.
//
//nolint:gocognit,gocyclo,unparam // Validation requires checking matches, upstreams, policies; warnings for interface
func (v *MCPRouteValidator) validate(mcpRoute *avapigwv1alpha1.MCPRoute) (admission.Warnings, error) {
	var errs []string

	spec := &mcpRoute.Spec

	// Validate match conditions
	if err := v.validateMCPMatches(spec.Match); err != nil {
		errs = append(errs, err.Error())
	}

	// Validate upstreams (legacy list and/or weighted refs)
	if err := v.validateUpstreamRefs(spec); err != nil {
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
		if err := validateRouteCacheConfig(spec.Cache); err != nil {
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

	warnings := admission.Warnings(collectMCPRouteWarnings(spec))

	if len(errs) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

// collectMCPRouteWarnings assembles the non-blocking admission warnings for
// an MCPRoute spec: plaintext-secret warnings in authentication,
// authorization cache and route cache / rate limiter Redis Sentinel
// configurations.
func collectMCPRouteWarnings(spec *avapigwv1alpha1.MCPRouteSpec) []string {
	var warnings []string

	// Security warnings for plaintext secrets in authentication config,
	// plus a warning when mTLS is enabled without an explicit caFile.
	if spec.Authentication != nil {
		warnings = append(warnings, warnPlaintextAuthSecrets(spec.Authentication)...)
		warnings = append(warnings, warnMTLSMissingCAFile(spec.Authentication)...)
	}

	// Security warnings for plaintext secrets in authorization cache
	// (both redis.sentinel and the deprecated sentinel block), plus
	// transparency warnings for deprecated/unusable authz cache config.
	warnings = append(warnings, warnAuthzCacheSecrets(spec.Authorization)...)
	warnings = append(warnings, warnAuthzCacheSentinelDeprecated(spec.Authorization)...)
	warnings = append(warnings, warnAuthzCacheRedisWithoutConnection(spec.Authorization, kindMCPRoute)...)

	// Security warnings for plaintext secrets in route cache and rate limiter
	// Redis Sentinel configurations.
	warnings = append(warnings, warnRouteCacheSentinelSecrets(spec.Cache)...)
	warnings = append(warnings, warnRateLimitSentinelSecrets(spec.RateLimit)...)

	// Transparency warning: mixed zero/positive weighted upstreams (0% canary).
	warnings = append(warnings, warnMixedWeightedUpstreams(spec.WeightedUpstreams)...)

	return warnings
}

// warnMixedWeightedUpstreams returns an admission warning when a route mixes
// zero-weight and positive-weight upstreams: the zero-weight upstreams receive
// no traffic (an intentional 0% canary) which is worth surfacing because an
// all-zero configuration instead spreads traffic uniformly.
func warnMixedWeightedUpstreams(refs []avapigwv1alpha1.MCPUpstreamRef) []string {
	totalWeight := 0
	zeroWeightCount := 0
	for i := range refs {
		if refs[i].Weight > 0 {
			totalWeight += refs[i].Weight
		} else {
			zeroWeightCount++
		}
	}
	if totalWeight > 0 && zeroWeightCount > 0 {
		return []string{fmt.Sprintf(
			"%d weightedUpstream(s) with weight 0 will receive no traffic while other "+
				"upstreams carry positive weights; remove them or assign a positive weight",
			zeroWeightCount)}
	}
	return nil
}

// validateMCPMatches validates MCPRoute match conditions: path/name
// StringMatch one-of exclusivity (with regex compilation) and header
// name/regex constraints.
func (v *MCPRouteValidator) validateMCPMatches(matches []avapigwv1alpha1.MCPRouteMatch) error {
	for i := range matches {
		match := &matches[i]

		// Validate path match
		if match.Path != nil {
			if err := v.validateStringMatch(match.Path, fmt.Sprintf("match[%d].path", i)); err != nil {
				return err
			}
		}

		// Validate name match
		if match.Name != nil {
			if err := v.validateStringMatch(match.Name, fmt.Sprintf("match[%d].name", i)); err != nil {
				return err
			}
		}

		// Validate header matches
		if err := v.validateMCPHeaderMatches(i, match.Headers); err != nil {
			return err
		}
	}

	return nil
}

// validateMCPHeaderMatches validates the header match conditions of a single
// MCPRoute match block: each header must carry a name and, when set, a
// compilable regex.
func (v *MCPRouteValidator) validateMCPHeaderMatches(
	matchIdx int,
	headers []avapigwv1alpha1.HeaderMatch,
) error {
	for j := range headers {
		header := &headers[j]
		if header.Name == "" {
			return fmt.Errorf("match[%d].headers[%d].name is required", matchIdx, j)
		}
		if header.Regex != "" {
			if _, err := regexp.Compile(header.Regex); err != nil {
				return fmt.Errorf("match[%d].headers[%d].regex is invalid: %w", matchIdx, j, err)
			}
		}
	}
	return nil
}

// validateStringMatch validates a StringMatch configuration: at most one of
// exact/prefix/regex, and a compilable regex when set.
func (v *MCPRouteValidator) validateStringMatch(sm *avapigwv1alpha1.StringMatch, fieldPath string) error {
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

// validateUpstreamRefs validates the route's upstream configuration: exactly
// one of upstreams / weightedUpstreams, at least one upstream, and (for
// weighted upstreams) the range/sum rules. It mirrors
// apiroute_webhook.validateRouteDestinations, reusing the shared MinWeight /
// MaxWeight / TotalWeightExpected constants.
func (v *MCPRouteValidator) validateUpstreamRefs(spec *avapigwv1alpha1.MCPRouteSpec) error {
	hasLegacy := len(spec.Upstreams) > 0
	hasWeighted := len(spec.WeightedUpstreams) > 0

	if hasLegacy && hasWeighted {
		return fmt.Errorf("only one of upstreams or weightedUpstreams may be set")
	}

	if hasWeighted {
		return v.validateWeightedUpstreams(spec.WeightedUpstreams)
	}

	return v.validateUpstreams(spec.Upstreams)
}

// validateUpstreams validates that an MCPRoute references at least one
// non-empty MCPBackend upstream.
func (v *MCPRouteValidator) validateUpstreams(upstreams []string) error {
	if len(upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	for i, up := range upstreams {
		if strings.TrimSpace(up) == "" {
			return fmt.Errorf("upstreams[%d] must not be empty", i)
		}
	}
	return nil
}

// validateWeightedUpstreams validates weighted upstream refs: each ref carries
// a non-empty trimmed name and a weight in [MinWeight,MaxWeight]; when more
// than one ref carries positive weight the total must equal
// TotalWeightExpected (or be 0 for all-unset). Mirrors
// apiroute_webhook.validateRouteDestinations.
func (v *MCPRouteValidator) validateWeightedUpstreams(refs []avapigwv1alpha1.MCPUpstreamRef) error {
	if len(refs) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	totalWeight := 0
	for i := range refs {
		ref := &refs[i]
		if strings.TrimSpace(ref.Name) == "" {
			return fmt.Errorf("weightedUpstreams[%d].name must not be empty", i)
		}
		if ref.Weight < MinWeight || ref.Weight > MaxWeight {
			return fmt.Errorf("weightedUpstreams[%d].weight must be between %d and %d",
				i, MinWeight, MaxWeight)
		}
		totalWeight += ref.Weight
	}

	if len(refs) > 1 && totalWeight != TotalWeightExpected && totalWeight != 0 {
		return fmt.Errorf("total weight of all weightedUpstreams must equal %d (got %d)",
			TotalWeightExpected, totalWeight)
	}

	return nil
}

// validateRetryPolicy validates retry policy configuration.
func (v *MCPRouteValidator) validateRetryPolicy(policy *avapigwv1alpha1.RetryPolicy) error {
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

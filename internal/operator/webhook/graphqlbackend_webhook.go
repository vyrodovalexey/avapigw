// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"fmt"
	"strings"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Compile-time assertion: GraphQLBackendValidator must implement admission.Validator
// for the typed *avapigwv1alpha1.GraphQLBackend parameter.
var _ admission.Validator[*avapigwv1alpha1.GraphQLBackend] = (*GraphQLBackendValidator)(nil)

// GraphQLBackendValidator validates GraphQLBackend resources.
type GraphQLBackendValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
}

// SetupGraphQLBackendWebhook sets up the GraphQLBackend webhook with the manager using default configuration.
func SetupGraphQLBackendWebhook(mgr ctrl.Manager) error {
	return SetupGraphQLBackendWebhookWithConfig(mgr, DefaultDuplicateCheckerConfig())
}

// SetupGraphQLBackendWebhookWithConfig sets up the GraphQLBackend webhook with the manager
// using the provided configuration.
func SetupGraphQLBackendWebhookWithConfig(mgr ctrl.Manager, cfg DuplicateCheckerConfig) error {
	validator := &GraphQLBackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfig(mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GraphQLBackend{}).
		WithValidator(validator).
		Complete()
}

// SetupGraphQLBackendWebhookWithConfigAndContext sets up the GraphQLBackend webhook with context-based
// lifecycle management for the DuplicateChecker cleanup goroutine.
func SetupGraphQLBackendWebhookWithConfigAndContext(
	ctx context.Context, mgr ctrl.Manager, cfg DuplicateCheckerConfig,
) error {
	validator := &GraphQLBackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfigWithContext(ctx, mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GraphQLBackend{}).
		WithValidator(validator).
		Complete()
}

// SetupGraphQLBackendWebhookWithChecker sets up the GraphQLBackend webhook with a shared DuplicateChecker.
// This avoids creating multiple DuplicateChecker instances (and cleanup goroutines) across webhooks.
func SetupGraphQLBackendWebhookWithChecker(mgr ctrl.Manager, dc *DuplicateChecker) error {
	validator := &GraphQLBackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: dc,
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GraphQLBackend{}).
		WithValidator(validator).
		Complete()
}

// ValidateCreate implements admission.CustomValidator.
func (v *GraphQLBackendValidator) ValidateCreate(
	ctx context.Context,
	obj *avapigwv1alpha1.GraphQLBackend,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(obj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("GraphQLBackend", "create", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	if v.DuplicateChecker != nil {
		// Check for duplicates within the same CRD type
		if dupErr := v.DuplicateChecker.CheckGraphQLBackendDuplicate(ctx, obj); dupErr != nil {
			GetWebhookMetrics().RecordValidation(
				"GraphQLBackend", "create", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
		// Check for cross-CRD host:port conflicts with Backends and GRPCBackends
		if crossErr := v.DuplicateChecker.CheckGraphQLBackendCrossConflicts(ctx, obj); crossErr != nil {
			GetWebhookMetrics().RecordValidation(
				"GraphQLBackend", "create", "rejected", time.Since(start), len(warnings))
			return warnings, crossErr
		}
	}

	GetWebhookMetrics().RecordValidation("GraphQLBackend", "create", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (v *GraphQLBackendValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj *avapigwv1alpha1.GraphQLBackend,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(newObj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("GraphQLBackend", "update", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	if v.DuplicateChecker != nil {
		// Check for duplicates within the same CRD type (excluding self)
		if dupErr := v.DuplicateChecker.CheckGraphQLBackendDuplicate(ctx, newObj); dupErr != nil {
			GetWebhookMetrics().RecordValidation(
				"GraphQLBackend", "update", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
		// Check for cross-CRD host:port conflicts with Backends and GRPCBackends
		if crossErr := v.DuplicateChecker.CheckGraphQLBackendCrossConflicts(ctx, newObj); crossErr != nil {
			GetWebhookMetrics().RecordValidation(
				"GraphQLBackend", "update", "rejected", time.Since(start), len(warnings))
			return warnings, crossErr
		}
	}

	GetWebhookMetrics().RecordValidation(
		"GraphQLBackend", "update", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
// No-op: GraphQLBackend deletion does not require validation because the gateway
// controller handles cleanup of derived configuration via finalizers.
func (v *GraphQLBackendValidator) ValidateDelete(
	_ context.Context,
	_ *avapigwv1alpha1.GraphQLBackend,
) (admission.Warnings, error) {
	return nil, nil
}

// validate performs validation on the GraphQLBackend spec.
//
//nolint:gocognit,gocyclo // Validation requires checking hosts, TLS, circuit breaker, and auth
func (v *GraphQLBackendValidator) validate(graphqlBackend *avapigwv1alpha1.GraphQLBackend) (admission.Warnings, error) {
	var warnings admission.Warnings
	var errs []string

	spec := &graphqlBackend.Spec

	// Validate hosts
	if err := validateBackendHosts(spec.Hosts); err != nil {
		errs = append(errs, err.Error())
	}

	// Validate health check
	if spec.HealthCheck != nil {
		if err := validateHealthCheck(spec.HealthCheck); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate load balancer
	if spec.LoadBalancer != nil {
		if err := validateLoadBalancer(spec.LoadBalancer); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate TLS
	if spec.TLS != nil {
		if err := validateBackendTLS(spec.TLS); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate circuit breaker
	if spec.CircuitBreaker != nil {
		if err := validateCircuitBreaker(spec.CircuitBreaker); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate authentication
	if spec.Authentication != nil {
		if err := validateBackendAuth(spec.Authentication); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate max sessions configuration
	if spec.MaxSessions != nil {
		if err := validateMaxSessions(spec.MaxSessions); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate rate limit configuration
	if spec.RateLimit != nil {
		if err := validateRateLimit(spec.RateLimit); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate cache configuration
	if spec.Cache != nil {
		if err := validateBackendCache(spec.Cache); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate encoding configuration
	if spec.Encoding != nil {
		if err := validateBackendEncoding(spec.Encoding); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Add warnings for potentially insecure configurations
	if spec.TLS != nil && spec.TLS.InsecureSkipVerify {
		warnings = append(warnings, "tls.insecureSkipVerify is enabled; this should only be used in development")
	}

	if spec.TLS != nil && spec.TLS.Mode == TLSModeInsecure {
		warnings = append(warnings, "tls.mode is INSECURE; this should only be used in development")
	}

	// Security warnings for plaintext secrets in backend authentication
	if spec.Authentication != nil {
		warnings = append(warnings, warnPlaintextBackendAuthSecrets(spec.Authentication)...)
	}

	// Security warnings for plaintext secrets in cache sentinel config
	if spec.Cache != nil && spec.Cache.Sentinel != nil {
		warnings = append(warnings, warnPlaintextSentinelSecrets(spec.Cache.Sentinel)...)
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

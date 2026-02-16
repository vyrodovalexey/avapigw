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

// BackendValidator validates Backend resources.
type BackendValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
}

// SetupBackendWebhook sets up the Backend webhook with the manager using default configuration.
func SetupBackendWebhook(mgr ctrl.Manager) error {
	return SetupBackendWebhookWithConfig(mgr, DefaultDuplicateCheckerConfig())
}

// SetupBackendWebhookWithConfig sets up the Backend webhook with the manager using the provided configuration.
func SetupBackendWebhookWithConfig(mgr ctrl.Manager, cfg DuplicateCheckerConfig) error {
	validator := &BackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfig(mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.Backend{}).
		WithValidator(validator).
		Complete()
}

// SetupBackendWebhookWithConfigAndContext sets up the Backend webhook with context-based
// lifecycle management for the DuplicateChecker cleanup goroutine.
func SetupBackendWebhookWithConfigAndContext(ctx context.Context, mgr ctrl.Manager, cfg DuplicateCheckerConfig) error {
	validator := &BackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfigWithContext(ctx, mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.Backend{}).
		WithValidator(validator).
		Complete()
}

// SetupBackendWebhookWithChecker sets up the Backend webhook with a shared DuplicateChecker.
// This avoids creating multiple DuplicateChecker instances (and cleanup goroutines) across webhooks.
func SetupBackendWebhookWithChecker(mgr ctrl.Manager, dc *DuplicateChecker) error {
	validator := &BackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: dc,
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.Backend{}).
		WithValidator(validator).
		Complete()
}

// ValidateCreate implements admission.CustomValidator.
func (v *BackendValidator) ValidateCreate(
	ctx context.Context,
	obj *avapigwv1alpha1.Backend,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(obj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("Backend", "create", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	if v.DuplicateChecker != nil {
		// Check for duplicates within the same CRD type
		if dupErr := v.DuplicateChecker.CheckBackendDuplicate(ctx, obj); dupErr != nil {
			GetWebhookMetrics().RecordValidation("Backend", "create", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
		// Check for cross-CRD host:port conflicts with GRPCBackends
		if crossErr := v.DuplicateChecker.CheckBackendCrossConflicts(ctx, obj); crossErr != nil {
			GetWebhookMetrics().RecordValidation("Backend", "create", "rejected", time.Since(start), len(warnings))
			return warnings, crossErr
		}
	}

	GetWebhookMetrics().RecordValidation("Backend", "create", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (v *BackendValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj *avapigwv1alpha1.Backend,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(newObj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("Backend", "update", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	if v.DuplicateChecker != nil {
		// Check for duplicates within the same CRD type (excluding self)
		if dupErr := v.DuplicateChecker.CheckBackendDuplicate(ctx, newObj); dupErr != nil {
			GetWebhookMetrics().RecordValidation("Backend", "update", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
		// Check for cross-CRD host:port conflicts with GRPCBackends
		if crossErr := v.DuplicateChecker.CheckBackendCrossConflicts(ctx, newObj); crossErr != nil {
			GetWebhookMetrics().RecordValidation("Backend", "update", "rejected", time.Since(start), len(warnings))
			return warnings, crossErr
		}
	}

	GetWebhookMetrics().RecordValidation("Backend", "update", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
// No-op: Backend deletion does not require validation because the gateway
// controller handles cleanup of derived configuration via finalizers.
func (v *BackendValidator) ValidateDelete(_ context.Context, _ *avapigwv1alpha1.Backend) (admission.Warnings, error) {
	return nil, nil
}

// validate performs validation on the Backend spec.
//
//nolint:gocognit,gocyclo // Validation requires checking hosts, TLS, auth, and rate limiting
func (v *BackendValidator) validate(backend *avapigwv1alpha1.Backend) (admission.Warnings, error) {
	var warnings admission.Warnings
	var errs []string

	spec := &backend.Spec

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

	// Validate max sessions
	if spec.MaxSessions != nil {
		if err := validateMaxSessions(spec.MaxSessions); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate rate limit
	if spec.RateLimit != nil {
		if err := validateRateLimit(spec.RateLimit); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate request limits
	if spec.RequestLimits != nil {
		if err := validateRequestLimits(spec.RequestLimits); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Validate transform configuration
	if spec.Transform != nil {
		if err := validateBackendTransform(spec.Transform); err != nil {
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

	if spec.TLS != nil && spec.TLS.Mode == "INSECURE" {
		warnings = append(warnings, "tls.mode is INSECURE; this should only be used in development")
	}

	// Security warning for static JWT tokens
	if spec.Authentication != nil && spec.Authentication.JWT != nil &&
		spec.Authentication.JWT.Enabled && spec.Authentication.JWT.TokenSource == "static" {
		warnings = append(warnings,
			"SECURITY WARNING: Static JWT tokens are configured. "+
				"Static tokens pose security risks as they cannot be rotated easily "+
				"and may be exposed in configuration. "+
				"Consider using Vault or OIDC token sources for production environments.")
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

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

// GRPCBackendValidator validates GRPCBackend resources.
type GRPCBackendValidator struct {
	Client           client.Client
	DuplicateChecker *DuplicateChecker
}

// SetupGRPCBackendWebhook sets up the GRPCBackend webhook with the manager using default configuration.
func SetupGRPCBackendWebhook(mgr ctrl.Manager) error {
	return SetupGRPCBackendWebhookWithConfig(mgr, DefaultDuplicateCheckerConfig())
}

// SetupGRPCBackendWebhookWithConfig sets up the GRPCBackend webhook with the manager using the provided configuration.
func SetupGRPCBackendWebhookWithConfig(mgr ctrl.Manager, cfg DuplicateCheckerConfig) error {
	validator := &GRPCBackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfig(mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GRPCBackend{}).
		WithValidator(validator).
		Complete()
}

// SetupGRPCBackendWebhookWithConfigAndContext sets up the GRPCBackend webhook with context-based
// lifecycle management for the DuplicateChecker cleanup goroutine.
func SetupGRPCBackendWebhookWithConfigAndContext(
	ctx context.Context, mgr ctrl.Manager, cfg DuplicateCheckerConfig,
) error {
	validator := &GRPCBackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: NewDuplicateCheckerFromConfigWithContext(ctx, mgr.GetClient(), cfg),
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GRPCBackend{}).
		WithValidator(validator).
		Complete()
}

// SetupGRPCBackendWebhookWithChecker sets up the GRPCBackend webhook with a shared DuplicateChecker.
// This avoids creating multiple DuplicateChecker instances (and cleanup goroutines) across webhooks.
func SetupGRPCBackendWebhookWithChecker(mgr ctrl.Manager, dc *DuplicateChecker) error {
	validator := &GRPCBackendValidator{
		Client:           mgr.GetClient(),
		DuplicateChecker: dc,
	}
	return ctrl.NewWebhookManagedBy(mgr, &avapigwv1alpha1.GRPCBackend{}).
		WithValidator(validator).
		Complete()
}

// ValidateCreate implements admission.CustomValidator.
func (v *GRPCBackendValidator) ValidateCreate(
	ctx context.Context,
	obj *avapigwv1alpha1.GRPCBackend,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(obj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("GRPCBackend", "create", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	if v.DuplicateChecker != nil {
		// Check for duplicates within the same CRD type
		if dupErr := v.DuplicateChecker.CheckGRPCBackendDuplicate(ctx, obj); dupErr != nil {
			GetWebhookMetrics().RecordValidation("GRPCBackend", "create", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
		// Check for cross-CRD host:port conflicts with Backends
		if crossErr := v.DuplicateChecker.CheckGRPCBackendCrossConflicts(ctx, obj); crossErr != nil {
			GetWebhookMetrics().RecordValidation("GRPCBackend", "create", "rejected", time.Since(start), len(warnings))
			return warnings, crossErr
		}
	}

	GetWebhookMetrics().RecordValidation("GRPCBackend", "create", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (v *GRPCBackendValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj *avapigwv1alpha1.GRPCBackend,
) (admission.Warnings, error) {
	start := time.Now()
	warnings, err := v.validate(newObj)
	if err != nil {
		GetWebhookMetrics().RecordValidation("GRPCBackend", "update", "rejected", time.Since(start), len(warnings))
		return warnings, err
	}

	if v.DuplicateChecker != nil {
		// Check for duplicates within the same CRD type (excluding self)
		if dupErr := v.DuplicateChecker.CheckGRPCBackendDuplicate(ctx, newObj); dupErr != nil {
			GetWebhookMetrics().RecordValidation("GRPCBackend", "update", "rejected", time.Since(start), len(warnings))
			return warnings, dupErr
		}
		// Check for cross-CRD host:port conflicts with Backends
		if crossErr := v.DuplicateChecker.CheckGRPCBackendCrossConflicts(ctx, newObj); crossErr != nil {
			GetWebhookMetrics().RecordValidation("GRPCBackend", "update", "rejected", time.Since(start), len(warnings))
			return warnings, crossErr
		}
	}

	GetWebhookMetrics().RecordValidation("GRPCBackend", "update", "allowed", time.Since(start), len(warnings))
	return warnings, nil
}

// ValidateDelete implements admission.CustomValidator.
// No-op: GRPCBackend deletion does not require validation because the gateway
// controller handles cleanup of derived configuration via finalizers.
func (v *GRPCBackendValidator) ValidateDelete(
	_ context.Context,
	_ *avapigwv1alpha1.GRPCBackend,
) (admission.Warnings, error) {
	return nil, nil
}

// validate performs validation on the GRPCBackend spec.
//
//nolint:gocognit,gocyclo // Validation requires checking hosts, TLS, connection pool, and auth
func (v *GRPCBackendValidator) validate(grpcBackend *avapigwv1alpha1.GRPCBackend) (admission.Warnings, error) {
	var warnings admission.Warnings
	var errs []string

	spec := &grpcBackend.Spec

	// Validate hosts
	if err := validateBackendHosts(spec.Hosts); err != nil {
		errs = append(errs, err.Error())
	}

	// Validate health check
	if spec.HealthCheck != nil {
		if err := validateGRPCHealthCheck(spec.HealthCheck); err != nil {
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

	// Validate connection pool
	if spec.ConnectionPool != nil {
		if err := v.validateConnectionPool(spec.ConnectionPool); err != nil {
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

	// Validate transform configuration
	if spec.Transform != nil {
		if err := validateGRPCBackendTransform(spec.Transform); err != nil {
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

// validateConnectionPool validates gRPC connection pool configuration.
func (v *GRPCBackendValidator) validateConnectionPool(cp *avapigwv1alpha1.GRPCConnectionPoolConfig) error {
	if cp.MaxIdleConns < 0 {
		return fmt.Errorf("connectionPool.maxIdleConns must be non-negative")
	}

	if cp.MaxConnsPerHost < 0 {
		return fmt.Errorf("connectionPool.maxConnsPerHost must be non-negative")
	}

	if cp.IdleConnTimeout != "" {
		if err := validateDuration(string(cp.IdleConnTimeout)); err != nil {
			return fmt.Errorf("connectionPool.idleConnTimeout is invalid: %w", err)
		}
	}

	return nil
}

// Package secrets provides a unified interface for secrets management
// with support for multiple backends including Kubernetes Secrets, Vault,
// local files, and environment variables.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ProviderType represents the type of secrets provider
type ProviderType string

const (
	// ProviderTypeKubernetes uses Kubernetes Secrets as the backend
	ProviderTypeKubernetes ProviderType = "kubernetes"
	// ProviderTypeVault uses HashiCorp Vault as the backend
	ProviderTypeVault ProviderType = "vault"
	// ProviderTypeLocal uses local files as the backend
	ProviderTypeLocal ProviderType = "local"
	// ProviderTypeEnv uses environment variables as the backend
	ProviderTypeEnv ProviderType = "env"
)

// Common errors for secrets providers
var (
	// ErrSecretNotFound is returned when a secret is not found
	ErrSecretNotFound = errors.New("secret not found")
	// ErrProviderNotConfigured is returned when the provider is not properly configured
	ErrProviderNotConfigured = errors.New("provider not configured")
	// ErrReadOnly is returned when attempting to write to a read-only provider
	ErrReadOnly = errors.New("provider is read-only")
	// ErrInvalidPath is returned when the secret path is invalid
	ErrInvalidPath = errors.New("invalid secret path")
	// ErrProviderUnavailable is returned when the provider is temporarily unavailable
	ErrProviderUnavailable = errors.New("provider unavailable")
	// ErrInvalidProviderType is returned when an unknown provider type is specified
	ErrInvalidProviderType = errors.New("invalid provider type")
)

// Secret represents a secret with key-value data
type Secret struct {
	// Name is the name of the secret
	Name string
	// Namespace is the namespace of the secret (if applicable)
	Namespace string
	// Data contains the secret key-value pairs
	Data map[string][]byte
	// Metadata contains additional metadata about the secret
	Metadata map[string]string
	// Version is the version of the secret (if supported by the provider)
	Version string
	// CreatedAt is when the secret was created
	CreatedAt *time.Time
	// UpdatedAt is when the secret was last updated
	UpdatedAt *time.Time
}

// GetString returns a string value from the secret data
func (s *Secret) GetString(key string) (string, bool) {
	if s == nil || s.Data == nil {
		return "", false
	}
	v, ok := s.Data[key]
	if !ok {
		return "", false
	}
	return string(v), true
}

// GetBytes returns a byte slice value from the secret data
func (s *Secret) GetBytes(key string) ([]byte, bool) {
	if s == nil || s.Data == nil {
		return nil, false
	}
	v, ok := s.Data[key]
	return v, ok
}

// Provider is the interface for secrets providers
type Provider interface {
	// Type returns the provider type
	Type() ProviderType

	// GetSecret retrieves a secret by path/name
	// Path format depends on the provider:
	// - kubernetes: "namespace/secret-name" or "secret-name" (uses default namespace)
	// - vault: "mount/path/to/secret"
	// - local: "secret-name" (maps to base-path/secret-name/)
	// - env: "SECRET_NAME" (maps to env var with configured prefix)
	GetSecret(ctx context.Context, path string) (*Secret, error)

	// ListSecrets lists secrets at a path
	// Returns a list of secret names/paths
	ListSecrets(ctx context.Context, path string) ([]string, error)

	// WriteSecret writes a secret (if supported)
	// Returns ErrReadOnly if the provider doesn't support writes
	WriteSecret(ctx context.Context, path string, data map[string][]byte) error

	// DeleteSecret deletes a secret (if supported)
	// Returns ErrReadOnly if the provider doesn't support deletes
	DeleteSecret(ctx context.Context, path string) error

	// IsReadOnly returns true if provider doesn't support writes
	IsReadOnly() bool

	// HealthCheck checks provider connectivity
	// Returns nil if the provider is healthy
	HealthCheck(ctx context.Context) error

	// Close cleans up provider resources
	Close() error
}

// Prometheus metrics for secrets provider operations
var (
	secretsOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "secrets",
			Name:      "operation_duration_seconds",
			Help:      "Duration of secrets provider operations in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"provider", "operation", "result"},
	)

	secretsOperationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "secrets",
			Name:      "operation_total",
			Help:      "Total number of secrets provider operations",
		},
		[]string{"provider", "operation", "result"},
	)

	secretsProviderHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "avapigw",
			Subsystem: "secrets",
			Name:      "provider_healthy",
			Help:      "Whether the secrets provider is healthy (1) or not (0)",
		},
		[]string{"provider"},
	)
)

func init() {
	prometheus.MustRegister(
		secretsOperationDuration,
		secretsOperationTotal,
		secretsProviderHealth,
	)
}

// RecordOperation records metrics for a secrets provider operation
func RecordOperation(provider ProviderType, operation string, duration time.Duration, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	providerStr := string(provider)
	secretsOperationDuration.WithLabelValues(providerStr, operation, result).Observe(duration.Seconds())
	secretsOperationTotal.WithLabelValues(providerStr, operation, result).Inc()
}

// RecordHealthStatus records the health status of a provider
func RecordHealthStatus(provider ProviderType, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	secretsProviderHealth.WithLabelValues(string(provider)).Set(value)
}

// ValidateProviderType validates that the given string is a valid provider type
func ValidateProviderType(providerType string) (ProviderType, error) {
	switch ProviderType(providerType) {
	case ProviderTypeKubernetes, ProviderTypeVault, ProviderTypeLocal, ProviderTypeEnv:
		return ProviderType(providerType), nil
	default:
		return "", fmt.Errorf("%w: %s, must be one of: kubernetes, vault, local, env", ErrInvalidProviderType, providerType)
	}
}

// IsValidProviderType checks if the given string is a valid provider type
func IsValidProviderType(providerType string) bool {
	_, err := ValidateProviderType(providerType)
	return err == nil
}

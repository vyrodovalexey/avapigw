//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
package operator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// TestFunctional_GraphQLBackend_Validation tests GraphQLBackend CRD validation.
func TestFunctional_GraphQLBackend_Validation(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLBackendValidator{}

	t.Run("valid basic backend", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		warnings, err := validator.ValidateCreate(context.Background(), backend)
		require.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("valid full backend with all fields", func(t *testing.T) {
		t.Parallel()

		backend := createFullGraphQLBackend()
		warnings, err := validator.ValidateCreate(context.Background(), backend)
		require.NoError(t, err)
		_ = warnings
	})

	t.Run("invalid - empty hosts", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		backend.Spec.Hosts = nil
		_, err := validator.ValidateCreate(context.Background(), backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one host is required")
	})

	t.Run("invalid - port out of range zero", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		backend.Spec.Hosts[0].Port = 0
		_, err := validator.ValidateCreate(context.Background(), backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid - port out of range 65536", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		backend.Spec.Hosts[0].Port = 65536
		_, err := validator.ValidateCreate(context.Background(), backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid - negative weight", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		backend.Spec.Hosts[0].Weight = -1
		_, err := validator.ValidateCreate(context.Background(), backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})

	t.Run("invalid - invalid health check interval", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
			Path:     "/health",
			Interval: "invalid",
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "interval is invalid")
	})

	t.Run("invalid - invalid health check timeout", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
			Path:    "/health",
			Timeout: "invalid",
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timeout is invalid")
	})

	t.Run("invalid - invalid load balancer algorithm", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
			Algorithm: "invalidAlgorithm",
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "loadBalancer.algorithm must be one of")
	})

	t.Run("invalid - invalid TLS mode", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
			Enabled: true,
			Mode:    "INVALID_MODE",
		}
		_, err := validator.ValidateCreate(context.Background(), backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tls.mode must be")
	})
}

// TestFunctional_GraphQLBackend_UpdateValidation tests GraphQLBackend update validation.
func TestFunctional_GraphQLBackend_UpdateValidation(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLBackendValidator{}

	t.Run("valid update", func(t *testing.T) {
		t.Parallel()

		oldBackend := createBasicGraphQLBackend()
		newBackend := createBasicGraphQLBackend()
		newBackend.Spec.Hosts[0].Weight = 50
		warnings, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
		require.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("invalid update - invalid new config", func(t *testing.T) {
		t.Parallel()

		oldBackend := createBasicGraphQLBackend()
		newBackend := createBasicGraphQLBackend()
		newBackend.Spec.Hosts[0].Port = 0
		_, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})
}

// TestFunctional_GraphQLBackend_DeleteValidation tests GraphQLBackend delete validation.
func TestFunctional_GraphQLBackend_DeleteValidation(t *testing.T) {
	t.Parallel()

	validator := &webhook.GraphQLBackendValidator{}

	t.Run("delete always succeeds", func(t *testing.T) {
		t.Parallel()

		backend := createBasicGraphQLBackend()
		warnings, err := validator.ValidateDelete(context.Background(), backend)
		require.NoError(t, err)
		assert.Empty(t, warnings)
	})
}

// Helper functions

func createBasicGraphQLBackend() *avapigwv1alpha1.GraphQLBackend {
	return &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-backend",
			Namespace: "avapigw-test",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "graphql-service.default.svc.cluster.local",
					Port:    8080,
					Weight:  1,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:               "/health",
				Interval:           "10s",
				Timeout:            "5s",
				HealthyThreshold:   2,
				UnhealthyThreshold: 3,
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
			},
		},
	}
}

func createFullGraphQLBackend() *avapigwv1alpha1.GraphQLBackend {
	backend := createBasicGraphQLBackend()
	backend.Name = "full-graphql-backend"

	backend.Spec.Hosts = []avapigwv1alpha1.BackendHost{
		{Address: "graphql-service-1.default.svc.cluster.local", Port: 8080, Weight: 60},
		{Address: "graphql-service-2.default.svc.cluster.local", Port: 8080, Weight: 40},
	}

	backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
		Path:               "/health",
		Interval:           "10s",
		Timeout:            "5s",
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
	}

	backend.Spec.LoadBalancer = &avapigwv1alpha1.LoadBalancerConfig{
		Algorithm: avapigwv1alpha1.LoadBalancerWeighted,
	}

	backend.Spec.TLS = &avapigwv1alpha1.BackendTLSConfig{
		Enabled:    true,
		Mode:       "MUTUAL",
		ServerName: "graphql-backend.internal",
		MinVersion: "TLS12",
		Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "graphql-client",
			CommonName: "gateway-graphql-client",
			TTL:        "24h",
		},
	}

	backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
		Enabled:          true,
		Threshold:        5,
		Timeout:          "30s",
		HalfOpenRequests: 3,
	}

	backend.Spec.Authentication = &avapigwv1alpha1.BackendAuthConfig{
		Type: "jwt",
		JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: "oidc",
			OIDC: &avapigwv1alpha1.BackendOIDCConfig{
				IssuerURL:     "https://keycloak.example.com/realms/myrealm",
				ClientID:      "graphql-client",
				ClientSecret:  "secret",
				Scopes:        []string{"openid"},
				TokenCacheTTL: "5m",
			},
			HeaderName:   "authorization",
			HeaderPrefix: "Bearer",
		},
	}

	backend.Spec.MaxSessions = &avapigwv1alpha1.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 1000,
		QueueSize:     100,
		QueueTimeout:  "15s",
	}

	backend.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 500,
		Burst:             1000,
	}

	backend.Spec.Cache = &avapigwv1alpha1.BackendCacheConfig{
		Enabled: true,
		TTL:     "5m",
		Type:    "memory",
	}

	backend.Spec.Encoding = &avapigwv1alpha1.BackendEncodingConfig{
		Request: &avapigwv1alpha1.BackendEncodingSettings{
			ContentType: "application/json",
		},
		Response: &avapigwv1alpha1.BackendEncodingSettings{
			ContentType: "application/json",
		},
	}

	return backend
}

// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"testing"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGRPCBackendValidator_ValidateCreate_ValidBackend(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_NoHosts(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for no hosts")
	}
}

func TestGRPCBackendValidator_ValidateCreate_MissingHostAddress(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "",
					Port:    50051,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing host address")
	}
}

func TestGRPCBackendValidator_ValidateCreate_InvalidHostPort(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    0,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid host port")
	}
}

func TestGRPCBackendValidator_ValidateCreate_PortTooHigh(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    70000,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for port > 65535")
	}
}

func TestGRPCBackendValidator_ValidateCreate_InvalidHostWeight(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  150,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for weight > 100")
	}
}

func TestGRPCBackendValidator_ValidateCreate_NegativeHostWeight(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  -10,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative weight")
	}
}

func TestGRPCBackendValidator_ValidateCreate_WeightSumNot100(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service-1",
					Port:    50051,
					Weight:  30,
				},
				{
					Address: "grpc-service-2",
					Port:    50051,
					Weight:  30,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for weight sum not 100")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ValidWeightSum100(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service-1",
					Port:    50051,
					Weight:  70,
				},
				{
					Address: "grpc-service-2",
					Port:    50051,
					Weight:  30,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_WeightSumZero(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service-1",
					Port:    50051,
					Weight:  0,
				},
				{
					Address: "grpc-service-2",
					Port:    50051,
					Weight:  0,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil (weight sum 0 is allowed)", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_InvalidHealthCheckInterval(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Interval: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid health check interval")
	}
}

func TestGRPCBackendValidator_ValidateCreate_InvalidHealthCheckTimeout(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Timeout: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid health check timeout")
	}
}

func TestGRPCBackendValidator_ValidateCreate_NegativeHealthyThreshold(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				HealthyThreshold: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative healthy threshold")
	}
}

func TestGRPCBackendValidator_ValidateCreate_NegativeUnhealthyThreshold(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				UnhealthyThreshold: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative unhealthy threshold")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ValidHealthCheck(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Service:            "grpc.health.v1.Health",
				Interval:           avapigwv1alpha1.Duration("10s"),
				Timeout:            avapigwv1alpha1.Duration("5s"),
				HealthyThreshold:   3,
				UnhealthyThreshold: 3,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_InvalidLoadBalancerAlgorithm(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: "invalid",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid load balancer algorithm")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ValidLoadBalancer(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm avapigwv1alpha1.LoadBalancerAlgorithm
	}{
		{"roundRobin", avapigwv1alpha1.LoadBalancerRoundRobin},
		{"weighted", avapigwv1alpha1.LoadBalancerWeighted},
		{"leastConn", avapigwv1alpha1.LoadBalancerLeastConn},
		{"random", avapigwv1alpha1.LoadBalancerRandom},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &GRPCBackendValidator{}
			backend := &avapigwv1alpha1.GRPCBackend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-grpc-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{
							Address: "grpc-service",
							Port:    50051,
							Weight:  100,
						},
					},
					LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
						Algorithm: tc.algorithm,
					},
				},
			}

			warnings, err := validator.ValidateCreate(context.Background(), backend)
			if err != nil {
				t.Errorf("ValidateCreate() error = %v, want nil", err)
			}
			if len(warnings) > 0 {
				t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
			}
		})
	}
}

func TestGRPCBackendValidator_ValidateCreate_TLSDisabled(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: false,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_InvalidTLSMode(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "INVALID",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid TLS mode")
	}
}

func TestGRPCBackendValidator_ValidateCreate_TLSVersionMismatch(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:    true,
				MinVersion: "TLS13",
				MaxVersion: "TLS12",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for TLS version mismatch")
	}
}

func TestGRPCBackendValidator_ValidateCreate_MutualTLSWithVault(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "MUTUAL",
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "grpc-backend",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_VaultTLSMissingPKIMount(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "",
					Role:     "grpc-backend",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing Vault PKI mount")
	}
}

func TestGRPCBackendValidator_ValidateCreate_VaultTLSMissingRole(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing Vault role")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ConnectionPoolNegativeMaxIdleConns(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			ConnectionPool: &avapigwv1alpha1.GRPCConnectionPoolConfig{
				MaxIdleConns: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative max idle conns")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ConnectionPoolNegativeMaxConnsPerHost(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			ConnectionPool: &avapigwv1alpha1.GRPCConnectionPoolConfig{
				MaxConnsPerHost: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative max conns per host")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ConnectionPoolInvalidIdleConnTimeout(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			ConnectionPool: &avapigwv1alpha1.GRPCConnectionPoolConfig{
				IdleConnTimeout: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid idle conn timeout")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ValidConnectionPool(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			ConnectionPool: &avapigwv1alpha1.GRPCConnectionPoolConfig{
				MaxIdleConns:    100,
				MaxConnsPerHost: 50,
				IdleConnTimeout: avapigwv1alpha1.Duration("5m"),
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_CircuitBreakerDisabled(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled: false,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_CircuitBreakerInvalidThreshold(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 0,
				Timeout:   avapigwv1alpha1.Duration("30s"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid circuit breaker threshold")
	}
}

func TestGRPCBackendValidator_ValidateCreate_CircuitBreakerMissingTimeout(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   avapigwv1alpha1.Duration(""),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing circuit breaker timeout")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ValidCircuitBreaker(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          avapigwv1alpha1.Duration("30s"),
				HalfOpenRequests: 3,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_InvalidAuthType(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "invalid",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid auth type")
	}
}

func TestGRPCBackendValidator_ValidateCreate_ValidJWTAuth(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "static",
					StaticToken: "my-jwt-token",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_ValidMTLSAuth(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
					Enabled:  true,
					CertFile: "/certs/client.crt",
					KeyFile:  "/certs/client.key",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateCreate_WarningInsecureSkipVerify(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() should return warning for insecureSkipVerify")
	}
}

func TestGRPCBackendValidator_ValidateCreate_WarningInsecureMode(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "INSECURE",
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() should return warning for INSECURE mode")
	}
}

func TestGRPCBackendValidator_ValidateUpdate(t *testing.T) {
	validator := &GRPCBackendValidator{}
	oldBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}
	newBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
		},
	}

	warnings, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
	if err != nil {
		t.Errorf("ValidateUpdate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateUpdate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCBackendValidator_ValidateUpdate_Invalid(t *testing.T) {
	validator := &GRPCBackendValidator{}
	oldBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    50051,
					Weight:  100,
				},
			},
		},
	}
	newBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{}, // No hosts - invalid
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
	if err == nil {
		t.Error("ValidateUpdate() should return error for invalid new backend (no hosts)")
	}
}

func TestGRPCBackendValidator_ValidateUpdate_InvalidPort(t *testing.T) {
	validator := &GRPCBackendValidator{}
	oldBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}
	newBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service",
					Port:    70000, // Port too high - invalid
					Weight:  100,
				},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
	if err == nil {
		t.Error("ValidateUpdate() should return error for invalid port")
	}
}

func TestGRPCBackendValidator_ValidateDelete(t *testing.T) {
	validator := &GRPCBackendValidator{}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}

	warnings, err := validator.ValidateDelete(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateDelete() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() warnings = %v, want empty", warnings)
	}
}

// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"strings"
	"testing"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBackendValidator_ValidateCreate_ValidBackend(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_NoHosts(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for no hosts")
	}
}

func TestBackendValidator_ValidateCreate_MissingHostAddress(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "",
					Port:    8080,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing host address")
	}
}

func TestBackendValidator_ValidateCreate_InvalidHostPort(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
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

func TestBackendValidator_ValidateCreate_PortTooHigh(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
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

func TestBackendValidator_ValidateCreate_InvalidHostWeight(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_NegativeHostWeight(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_WeightSumNot100(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-1",
					Port:    8080,
					Weight:  30,
				},
				{
					Address: "backend-2",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_ValidWeightSum100(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-1",
					Port:    8080,
					Weight:  70,
				},
				{
					Address: "backend-2",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_WeightSumZero(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-1",
					Port:    8080,
					Weight:  0,
				},
				{
					Address: "backend-2",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_MissingHealthCheckPath(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path: "",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing health check path")
	}
}

func TestBackendValidator_ValidateCreate_InvalidHealthCheckInterval(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:     "/health",
				Interval: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid health check interval")
	}
}

func TestBackendValidator_ValidateCreate_InvalidHealthCheckTimeout(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:    "/health",
				Timeout: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid health check timeout")
	}
}

func TestBackendValidator_ValidateCreate_NegativeHealthyThreshold(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:             "/health",
				HealthyThreshold: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative healthy threshold")
	}
}

func TestBackendValidator_ValidateCreate_NegativeUnhealthyThreshold(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:               "/health",
				UnhealthyThreshold: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative unhealthy threshold")
	}
}

func TestBackendValidator_ValidateCreate_ValidHealthCheck(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:               "/health",
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

func TestBackendValidator_ValidateCreate_InvalidLoadBalancerAlgorithm(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_ValidLoadBalancer(t *testing.T) {
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
			validator := &BackendValidator{}
			backend := &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{
							Address: "backend-service",
							Port:    8080,
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

func TestBackendValidator_ValidateCreate_TLSDisabled(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_InvalidTLSMode(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_ValidTLSModes(t *testing.T) {
	testCases := []struct {
		name string
		mode string
	}{
		{"SIMPLE", "SIMPLE"},
		{"MUTUAL", "MUTUAL"},
		{"INSECURE", "INSECURE"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &BackendValidator{}
			backend := &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{
							Address: "backend-service",
							Port:    8080,
							Weight:  100,
						},
					},
					TLS: &avapigwv1alpha1.BackendTLSConfig{
						Enabled:  true,
						Mode:     tc.mode,
						CertFile: "/certs/tls.crt",
						KeyFile:  "/certs/tls.key",
					},
				},
			}

			_, err := validator.ValidateCreate(context.Background(), backend)
			// INSECURE mode should generate warning but not error
			if err != nil && tc.mode != "MUTUAL" {
				t.Errorf("ValidateCreate() error = %v, want nil for mode %s", err, tc.mode)
			}
		})
	}
}

func TestBackendValidator_ValidateCreate_InvalidTLSMinVersion(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:    true,
				MinVersion: "TLS10",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid TLS min version")
	}
}

func TestBackendValidator_ValidateCreate_InvalidTLSMaxVersion(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:    true,
				MaxVersion: "TLS10",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid TLS max version")
	}
}

func TestBackendValidator_ValidateCreate_TLSVersionMismatch(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_MutualTLSWithoutCert(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:  true,
				Mode:     "MUTUAL",
				CertFile: "",
				KeyFile:  "",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for MUTUAL TLS without cert")
	}
}

func TestBackendValidator_ValidateCreate_MutualTLSWithoutKey(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:  true,
				Mode:     "MUTUAL",
				CertFile: "/certs/tls.crt",
				KeyFile:  "",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for MUTUAL TLS without key")
	}
}

func TestBackendValidator_ValidateCreate_MutualTLSWithVault(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "MUTUAL",
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "backend",
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

func TestBackendValidator_ValidateCreate_VaultTLSMissingPKIMount(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "",
					Role:     "backend",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing Vault PKI mount")
	}
}

func TestBackendValidator_ValidateCreate_VaultTLSMissingRole(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_CircuitBreakerDisabled(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_CircuitBreakerInvalidThreshold(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_CircuitBreakerMissingTimeout(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_CircuitBreakerInvalidTimeout(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid circuit breaker timeout")
	}
}

func TestBackendValidator_ValidateCreate_CircuitBreakerNegativeHalfOpenRequests(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          avapigwv1alpha1.Duration("30s"),
				HalfOpenRequests: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative half open requests")
	}
}

func TestBackendValidator_ValidateCreate_ValidCircuitBreaker(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_InvalidAuthType(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_JWTAuthMissingConfig(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT:  nil,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for JWT auth without config")
	}
}

func TestBackendValidator_ValidateCreate_JWTAuthInvalidTokenSource(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "invalid",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid JWT token source")
	}
}

func TestBackendValidator_ValidateCreate_JWTAuthStaticMissingToken(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "static",
					StaticToken: "",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for static JWT without token")
	}
}

func TestBackendValidator_ValidateCreate_JWTAuthVaultMissingPath(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "vault",
					VaultPath:   "",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for vault JWT without path")
	}
}

func TestBackendValidator_ValidateCreate_JWTAuthOIDCMissingConfig(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "oidc",
					OIDC:        nil,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for OIDC JWT without config")
	}
}

func TestBackendValidator_ValidateCreate_JWTAuthOIDCMissingIssuerURL(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "oidc",
					OIDC: &avapigwv1alpha1.BackendOIDCConfig{
						IssuerURL: "",
						ClientID:  "client-id",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for OIDC without issuer URL")
	}
}

func TestBackendValidator_ValidateCreate_JWTAuthOIDCMissingClientID(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "oidc",
					OIDC: &avapigwv1alpha1.BackendOIDCConfig{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for OIDC without client ID")
	}
}

func TestBackendValidator_ValidateCreate_ValidJWTAuthStatic(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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
	// Static JWT tokens should generate a security warning
	if len(warnings) != 1 {
		t.Errorf("ValidateCreate() warnings count = %d, want 1", len(warnings))
	}
	if len(warnings) > 0 && !strings.Contains(string(warnings[0]), "SECURITY WARNING") {
		t.Errorf("ValidateCreate() warning should contain 'SECURITY WARNING', got %v", warnings)
	}
}

func TestBackendValidator_ValidateCreate_ValidJWTAuthVault(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "vault",
					VaultPath:   "secret/data/jwt",
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

func TestBackendValidator_ValidateCreate_ValidJWTAuthOIDC(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "oidc",
					OIDC: &avapigwv1alpha1.BackendOIDCConfig{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "client-id",
					},
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

func TestBackendValidator_ValidateCreate_BasicAuthMissingConfig(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type:  "basic",
				Basic: nil,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for basic auth without config")
	}
}

func TestBackendValidator_ValidateCreate_BasicAuthMissingCredentials(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled:   true,
					Username:  "",
					Password:  "",
					VaultPath: "",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for basic auth without credentials")
	}
}

func TestBackendValidator_ValidateCreate_ValidBasicAuthStatic(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled:  true,
					Username: "user",
					Password: "pass",
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

func TestBackendValidator_ValidateCreate_ValidBasicAuthVault(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled:   true,
					VaultPath: "secret/data/basic-auth",
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

func TestBackendValidator_ValidateCreate_MTLSAuthMissingConfig(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: nil,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for mTLS auth without config")
	}
}

func TestBackendValidator_ValidateCreate_MTLSAuthMissingCerts(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
					Enabled:  true,
					CertFile: "",
					KeyFile:  "",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for mTLS auth without certs")
	}
}

func TestBackendValidator_ValidateCreate_ValidMTLSAuthFiles(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_ValidMTLSAuthVault(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
					Enabled: true,
					Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
						Enabled:  true,
						PKIMount: "pki",
						Role:     "client",
					},
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

func TestBackendValidator_ValidateCreate_MTLSAuthVaultMissingPKIMount(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
					Enabled: true,
					Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
						Enabled:  true,
						PKIMount: "",
						Role:     "client",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for mTLS Vault without PKI mount")
	}
}

func TestBackendValidator_ValidateCreate_MTLSAuthVaultMissingRole(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
					Enabled: true,
					Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
						Enabled:  true,
						PKIMount: "pki",
						Role:     "",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for mTLS Vault without role")
	}
}

func TestBackendValidator_ValidateCreate_MaxSessionsDisabled(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
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

func TestBackendValidator_ValidateCreate_MaxSessionsInvalidMaxConcurrent(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 0,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid max concurrent")
	}
}

func TestBackendValidator_ValidateCreate_MaxSessionsNegativeQueueSize(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
				QueueSize:     -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative queue size")
	}
}

func TestBackendValidator_ValidateCreate_MaxSessionsInvalidQueueTimeout(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
				QueueTimeout:  avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid queue timeout")
	}
}

func TestBackendValidator_ValidateCreate_ValidMaxSessions(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
				QueueSize:     50,
				QueueTimeout:  avapigwv1alpha1.Duration("30s"),
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

func TestBackendValidator_ValidateCreate_RateLimitDisabled(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
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

func TestBackendValidator_ValidateCreate_RateLimitInvalidRequestsPerSecond(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 0,
				Burst:             100,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid requests per second")
	}
}

func TestBackendValidator_ValidateCreate_RateLimitInvalidBurst(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             0,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid burst")
	}
}

func TestBackendValidator_ValidateCreate_ValidRateLimit(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
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

func TestBackendValidator_ValidateCreate_WarningInsecureSkipVerify(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateCreate_WarningInsecureMode(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateUpdate(t *testing.T) {
	validator := &BackendValidator{}
	oldBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}
	newBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
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

func TestBackendValidator_ValidateDelete(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
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

func TestBackendValidator_ValidateCreate_JWTAuthDisabled(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled: false,
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

func TestBackendValidator_ValidateCreate_BasicAuthDisabled(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled: false,
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

func TestBackendValidator_ValidateUpdate_Invalid(t *testing.T) {
	validator := &BackendValidator{}
	oldBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
		},
	}
	newBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{}, // No hosts - invalid
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
	if err == nil {
		t.Error("ValidateUpdate() should return error for invalid new backend (no hosts)")
	}
}

func TestBackendValidator_ValidateUpdate_InvalidPort(t *testing.T) {
	validator := &BackendValidator{}
	oldBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}
	newBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    0, // Invalid port
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

func TestBackendValidator_ValidateCreate_MTLSAuthDisabled(t *testing.T) {
	validator := &BackendValidator{}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-service",
					Port:    8080,
					Weight:  100,
				},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
					Enabled: false,
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

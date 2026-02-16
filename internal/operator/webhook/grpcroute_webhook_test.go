// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"testing"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGRPCRouteValidator_ValidateCreate_ValidRoute(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Exact: "myservice.MyService",
					},
					Method: &avapigwv1alpha1.StringMatch{
						Exact: "GetUser",
					},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidServiceRegex(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Regex: "[invalid(regex",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid service regex")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidMethodRegex(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Method: &avapigwv1alpha1.StringMatch{
						Regex: "[invalid(regex",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid method regex")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidAuthorityRegex(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Authority: &avapigwv1alpha1.StringMatch{
						Regex: "[invalid(regex",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid authority regex")
	}
}

func TestGRPCRouteValidator_ValidateCreate_MultipleStringMatchTypes(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Exact:  "myservice.MyService",
						Prefix: "myservice",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for multiple string match types")
	}
}

func TestGRPCRouteValidator_ValidateCreate_MissingMetadataName(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Metadata: []avapigwv1alpha1.MetadataMatch{
						{
							Name:  "",
							Exact: "value",
						},
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing metadata name")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidMetadataRegex(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Metadata: []avapigwv1alpha1.MetadataMatch{
						{
							Name:  "x-custom-header",
							Regex: "[invalid(regex",
						},
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid metadata regex")
	}
}

func TestGRPCRouteValidator_ValidateCreate_MissingDestinationHost(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "",
						Port: 50051,
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing destination host")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidDestinationPort(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 0,
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid destination port")
	}
}

func TestGRPCRouteValidator_ValidateCreate_PortTooHigh(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 70000,
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for port > 65535")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidWeight(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 50051,
					},
					Weight: 150,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for weight > 100")
	}
}

func TestGRPCRouteValidator_ValidateCreate_NegativeWeight(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 50051,
					},
					Weight: -10,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative weight")
	}
}

func TestGRPCRouteValidator_ValidateCreate_WeightSumNot100(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend-1",
						Port: 50051,
					},
					Weight: 30,
				},
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend-2",
						Port: 50051,
					},
					Weight: 30,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for weight sum not 100")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidTimeout(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Timeout: avapigwv1alpha1.Duration("invalid"),
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid timeout")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidRetryAttempts(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Retries: &avapigwv1alpha1.GRPCRetryPolicy{
				Attempts: 0,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid retry attempts")
	}
}

func TestGRPCRouteValidator_ValidateCreate_RetryAttemptsTooHigh(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Retries: &avapigwv1alpha1.GRPCRetryPolicy{
				Attempts: 15,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for retry attempts > 10")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidPerTryTimeout(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Retries: &avapigwv1alpha1.GRPCRetryPolicy{
				Attempts:      3,
				PerTryTimeout: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid perTryTimeout")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidBackoffBaseInterval(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Retries: &avapigwv1alpha1.GRPCRetryPolicy{
				Attempts:            3,
				BackoffBaseInterval: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid backoffBaseInterval")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidBackoffMaxInterval(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Retries: &avapigwv1alpha1.GRPCRetryPolicy{
				Attempts:           3,
				BackoffMaxInterval: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid backoffMaxInterval")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidRetryOn(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Retries: &avapigwv1alpha1.GRPCRetryPolicy{
				Attempts: 3,
				RetryOn:  "invalid-status",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid retryOn")
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidRetryOn(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Retries: &avapigwv1alpha1.GRPCRetryPolicy{
				Attempts: 3,
				RetryOn:  "cancelled,deadline-exceeded,unavailable",
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidRateLimit(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 0,
				Burst:             100,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid rate limit")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidCacheTTL(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid cache TTL")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidCacheStaleWhileRevalidate(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled:              true,
				TTL:                  avapigwv1alpha1.Duration("5m"),
				StaleWhileRevalidate: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid staleWhileRevalidate")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidCORSMethod(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			CORS: &avapigwv1alpha1.CORSConfig{
				AllowMethods: []string{"INVALID"},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid CORS method")
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidTLSVersion(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				MinVersion: "TLS10",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid TLS version")
	}
}

func TestGRPCRouteValidator_ValidateCreate_TLSVersionMismatch(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				MinVersion: "TLS13",
				MaxVersion: "TLS12",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for TLS version mismatch")
	}
}

func TestGRPCRouteValidator_ValidateUpdate(t *testing.T) {
	validator := &GRPCRouteValidator{}
	oldRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}
	newRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	warnings, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err != nil {
		t.Errorf("ValidateUpdate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateUpdate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateDelete(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}

	warnings, err := validator.ValidateDelete(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateDelete() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidRetryPolicy(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Retries: &avapigwv1alpha1.GRPCRetryPolicy{
				Attempts:            3,
				PerTryTimeout:       avapigwv1alpha1.Duration("10s"),
				BackoffBaseInterval: avapigwv1alpha1.Duration("100ms"),
				BackoffMaxInterval:  avapigwv1alpha1.Duration("1s"),
				RetryOn:             "unavailable,internal,resource-exhausted",
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidTLS(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				CertFile:   "/certs/tls.crt",
				KeyFile:    "/certs/tls.key",
				MinVersion: "TLS12",
				MaxVersion: "TLS13",
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidVaultTLS(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "grpc-route",
					CommonName: "grpc.example.com",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_MissingVaultPKIMount(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:  true,
					PKIMount: "",
					Role:     "grpc-route",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing Vault PKI mount")
	}
}

func TestGRPCRouteValidator_ValidateCreate_MissingVaultRole(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing Vault role")
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidCache(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled:              true,
				TTL:                  avapigwv1alpha1.Duration("5m"),
				StaleWhileRevalidate: avapigwv1alpha1.Duration("1m"),
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidRateLimit(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidCORS(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			CORS: &avapigwv1alpha1.CORSConfig{
				AllowOrigins: []string{"https://example.com"},
				AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
				AllowHeaders: []string{"Content-Type", "Authorization"},
				MaxAge:       3600,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidTimeout(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Timeout: avapigwv1alpha1.Duration("30s"),
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_WeightSumZero(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend-1",
						Port: 50051,
					},
					Weight: 0,
				},
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend-2",
						Port: 50051,
					},
					Weight: 0,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil (weight sum 0 is allowed)", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidWeightSum100(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend-1",
						Port: 50051,
					},
					Weight: 70,
				},
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend-2",
						Port: 50051,
					},
					Weight: 30,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_PrefixMatch(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Prefix: "myservice.",
					},
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidRegexMatch(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Regex: "^myservice\\..*$",
					},
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidMetadata(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Metadata: []avapigwv1alpha1.MetadataMatch{
						{
							Name:  "x-custom-header",
							Exact: "value",
						},
						{
							Name:   "x-another-header",
							Prefix: "prefix-",
						},
						{
							Name:  "x-regex-header",
							Regex: "^[a-z]+$",
						},
					},
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_ClientValidationWithoutCA(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				ClientValidation: &avapigwv1alpha1.ClientValidationConfig{
					Enabled: true,
					CAFile:  "",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for client validation without CA file")
	}
}

func TestGRPCRouteValidator_ValidateCreate_ValidClientValidation(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				ClientValidation: &avapigwv1alpha1.ClientValidationConfig{
					Enabled: true,
					CAFile:  "/certs/ca.crt",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_DisabledRateLimit(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           false,
				RequestsPerSecond: 0,
				Burst:             0,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil (disabled rate limit should pass)", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGRPCRouteValidator_ValidateCreate_InvalidRateLimitBurst(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             0,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid rate limit burst")
	}
}

func TestGRPCRouteValidator_ValidateUpdate_Invalid(t *testing.T) {
	validator := &GRPCRouteValidator{}
	oldRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}
	newRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "", // Missing host - invalid
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err == nil {
		t.Error("ValidateUpdate() should return error for invalid new route (missing host)")
	}
}

func TestGRPCRouteValidator_ValidateUpdate_InvalidTimeout(t *testing.T) {
	validator := &GRPCRouteValidator{}
	oldRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}
	newRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Timeout: avapigwv1alpha1.Duration("invalid"),
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err == nil {
		t.Error("ValidateUpdate() should return error for invalid timeout")
	}
}

func TestGRPCRouteValidator_ValidateCreate_NegativeCORSMaxAge(t *testing.T) {
	validator := &GRPCRouteValidator{}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			CORS: &avapigwv1alpha1.CORSConfig{
				MaxAge: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative CORS maxAge")
	}
}

// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"strings"
	"testing"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ============================================================================
// GraphQLBackendValidator ValidateCreate Tests
// ============================================================================

func TestGraphQLBackendValidator_ValidateCreate_ValidMinimalBackend(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
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

func TestGraphQLBackendValidator_ValidateCreate_ValidFullBackend(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service-1", Port: 8080, Weight: 60},
				{Address: "graphql-service-2", Port: 8080, Weight: 40},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:     "/health",
				Interval: avapigwv1alpha1.Duration("10s"),
				Timeout:  avapigwv1alpha1.Duration("5s"),
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "SIMPLE",
			},
			CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   avapigwv1alpha1.Duration("30s"),
			},
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
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
	// TLS warnings are expected for SIMPLE mode (no insecure warnings)
	_ = warnings
}

func TestGraphQLBackendValidator_ValidateCreate_NoHosts(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for no hosts")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_MissingHostAddress(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "", Port: 8080},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing host address")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidHostPort(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 0},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid host port")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidHealthCheck(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path: "", // Required field
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid health check")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidLoadBalancer(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: "invalid_algorithm",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid load balancer algorithm")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidTLSMode(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "INVALID_MODE",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid TLS mode")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InsecureSkipVerifyWarning(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			TLS: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:            true,
				Mode:               "SIMPLE",
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
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "insecureSkipVerify") {
			found = true
			break
		}
	}
	if !found {
		t.Error("ValidateCreate() warning should mention insecureSkipVerify")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InsecureTLSModeWarning(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
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
		t.Error("ValidateCreate() should return warning for INSECURE TLS mode")
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "INSECURE") {
			found = true
			break
		}
	}
	if !found {
		t.Error("ValidateCreate() warning should mention INSECURE mode")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidCircuitBreaker(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 0, // Invalid: must be at least 1
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid circuit breaker")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidAuthentication(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "invalid_type",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid authentication type")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidMaxSessions(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 0, // Invalid
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid max sessions")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidRateLimit(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 0, // Invalid
				Burst:             100,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid rate limit")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidCache(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			Cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid cache TTL")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_InvalidEncoding(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			Encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					Compression: "invalid_compression",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid encoding")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_PlaintextBasicAuthWarning(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			Authentication: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled:  true,
					Username: "user",
					Password: "plaintext-password",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() should return warning for plaintext password")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_CacheSentinelWarning(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
			Cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				Type:    "redis",
				TTL:     avapigwv1alpha1.Duration("5m"),
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"sentinel:26379"},
					Password:      "plaintext-password",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), backend)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() should return warning for plaintext sentinel password")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_WithDuplicateChecker_NoDuplicate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &GraphQLBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
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

func TestGraphQLBackendValidator_ValidateCreate_WithDuplicateChecker_Duplicate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	validator := &GraphQLBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	newBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), newBackend)
	if err == nil {
		t.Error("ValidateCreate() should return error for duplicate backend")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_WithDuplicateChecker_CrossConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	// Create an HTTP Backend with same host:port
	existingHTTPBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-http-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "shared-service", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingHTTPBackend).
		Build()

	validator := &GraphQLBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	newBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-graphql-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "shared-service", Port: 8080},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), newBackend)
	if err == nil {
		t.Error("ValidateCreate() should return error for cross-CRD conflict")
	}
}

func TestGraphQLBackendValidator_ValidateCreate_ValidationError_SkipsDuplicateCheck(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &GraphQLBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{}, // Invalid: no hosts
		},
	}

	_, err := validator.ValidateCreate(context.Background(), backend)
	if err == nil {
		t.Error("ValidateCreate() should return validation error")
	}
}

// ============================================================================
// GraphQLBackendValidator ValidateUpdate Tests
// ============================================================================

func TestGraphQLBackendValidator_ValidateUpdate_Valid(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	oldBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}
	newBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
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

func TestGraphQLBackendValidator_ValidateUpdate_Invalid(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	oldBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}
	newBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{}, // Invalid
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
	if err == nil {
		t.Error("ValidateUpdate() should return error for invalid backend")
	}
}

func TestGraphQLBackendValidator_ValidateUpdate_WithDuplicateChecker_Duplicate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	validator := &GraphQLBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	oldBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "updated-backend",
			Namespace: "default",
		},
	}
	newBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "updated-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
	if err == nil {
		t.Error("ValidateUpdate() should return error for duplicate backend")
	}
}

func TestGraphQLBackendValidator_ValidateUpdate_WithDuplicateChecker_CrossConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingGRPCBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "shared-service", Port: 50051},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingGRPCBackend).
		Build()

	validator := &GraphQLBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	oldBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "updated-backend",
			Namespace: "default",
		},
	}
	newBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "updated-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "shared-service", Port: 50051},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldBackend, newBackend)
	if err == nil {
		t.Error("ValidateUpdate() should return error for cross-CRD conflict")
	}
}

// ============================================================================
// GraphQLBackendValidator ValidateDelete Tests
// ============================================================================

func TestGraphQLBackendValidator_ValidateDelete(t *testing.T) {
	validator := &GraphQLBackendValidator{}
	backend := &avapigwv1alpha1.GraphQLBackend{
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

// ============================================================================
// GraphQLBackendValidator NilDuplicateChecker Tests
// ============================================================================

func TestGraphQLBackendValidator_ValidateCreate_NilDuplicateChecker(t *testing.T) {
	validator := &GraphQLBackendValidator{
		DuplicateChecker: nil,
	}
	backend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
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

func TestGraphQLBackendValidator_ValidateUpdate_NilDuplicateChecker(t *testing.T) {
	validator := &GraphQLBackendValidator{
		DuplicateChecker: nil,
	}
	oldBackend := &avapigwv1alpha1.GraphQLBackend{}
	newBackend := &avapigwv1alpha1.GraphQLBackend{
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-service", Port: 8080},
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

// ============================================================================
// GraphQLBackendValidator validate - Table-Driven Tests
// ============================================================================

func TestGraphQLBackendValidator_Validate_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		backend   *avapigwv1alpha1.GraphQLBackend
		wantErr   bool
		errSubstr string
		wantWarn  bool
	}{
		{
			name: "valid single host",
			backend: &avapigwv1alpha1.GraphQLBackend{
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-service", Port: 8080},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid multiple hosts with weights",
			backend: &avapigwv1alpha1.GraphQLBackend{
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-1", Port: 8080, Weight: 70},
						{Address: "graphql-2", Port: 8080, Weight: 30},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "no hosts",
			backend: &avapigwv1alpha1.GraphQLBackend{
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{},
				},
			},
			wantErr:   true,
			errSubstr: "host",
		},
		{
			name: "port too high",
			backend: &avapigwv1alpha1.GraphQLBackend{
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-service", Port: 70000},
					},
				},
			},
			wantErr:   true,
			errSubstr: "port",
		},
		{
			name: "insecure skip verify warning",
			backend: &avapigwv1alpha1.GraphQLBackend{
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-service", Port: 8080},
					},
					TLS: &avapigwv1alpha1.BackendTLSConfig{
						Enabled:            true,
						Mode:               "SIMPLE",
						InsecureSkipVerify: true,
					},
				},
			},
			wantErr:  false,
			wantWarn: true,
		},
		{
			name: "insecure TLS mode warning",
			backend: &avapigwv1alpha1.GraphQLBackend{
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-service", Port: 8080},
					},
					TLS: &avapigwv1alpha1.BackendTLSConfig{
						Enabled: true,
						Mode:    "INSECURE",
					},
				},
			},
			wantErr:  false,
			wantWarn: true,
		},
	}

	validator := &GraphQLBackendValidator{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := validator.ValidateCreate(context.Background(), tt.backend)
			if tt.wantErr {
				if err == nil {
					t.Error("validate() should return error")
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("validate() error = %v, want substring %q", err, tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("validate() error = %v, want nil", err)
				}
			}
			if tt.wantWarn && len(warnings) == 0 {
				t.Error("validate() should return warnings")
			}
		})
	}
}

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
// GraphQLRouteValidator ValidateCreate Tests
// ============================================================================

func TestGraphQLRouteValidator_ValidateCreate_ValidMinimalRoute(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "graphql-backend",
						Port: 8080,
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

func TestGraphQLRouteValidator_ValidateCreate_ValidFullRoute(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path:          &avapigwv1alpha1.StringMatch{Prefix: "/graphql"},
					OperationType: "query",
					OperationName: &avapigwv1alpha1.StringMatch{Exact: "GetUser"},
					Headers: []avapigwv1alpha1.GraphQLHeaderMatch{
						{Name: "X-Custom", Exact: "value"},
					},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "graphql-backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
			Timeout: avapigwv1alpha1.Duration("30s"),
			Retries: &avapigwv1alpha1.RetryPolicy{
				Attempts:      3,
				PerTryTimeout: avapigwv1alpha1.Duration("5s"),
			},
			DepthLimit:        10,
			ComplexityLimit:   100,
			AllowedOperations: []string{"query", "mutation"},
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

func TestGraphQLRouteValidator_ValidateCreate_InvalidPathRegex(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Regex: "[invalid(regex"},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid path regex")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_MultiplePathMatchTypes(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact:  "/graphql",
						Prefix: "/gql",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for multiple path match types")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidOperationType(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					OperationType: "invalid_type",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid operation type")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidOperationNameRegex(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					OperationName: &avapigwv1alpha1.StringMatch{Regex: "[bad(regex"},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid operation name regex")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_MultipleOperationNameMatchTypes(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					OperationName: &avapigwv1alpha1.StringMatch{
						Exact:  "GetUser",
						Prefix: "Get",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for multiple operation name match types")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_MissingHeaderName(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Headers: []avapigwv1alpha1.GraphQLHeaderMatch{
						{Name: "", Exact: "value"},
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing header name")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidHeaderRegex(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Headers: []avapigwv1alpha1.GraphQLHeaderMatch{
						{Name: "X-Custom", Regex: "[invalid(regex"},
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid header regex")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_MissingDestinationHost(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "",
						Port: 8080,
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

func TestGraphQLRouteValidator_ValidateCreate_InvalidDestinationPort(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 0,
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid port")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidWeight(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 150,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid weight")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_WeightSumNot100(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend1",
						Port: 8080,
					},
					Weight: 30,
				},
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend2",
						Port: 8080,
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

func TestGraphQLRouteValidator_ValidateCreate_InvalidTimeout(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Timeout: avapigwv1alpha1.Duration("invalid"),
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid timeout")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidRetryAttempts(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Retries: &avapigwv1alpha1.RetryPolicy{
				Attempts: 0,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid retry attempts")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidRetryPerTryTimeout(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Retries: &avapigwv1alpha1.RetryPolicy{
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

func TestGraphQLRouteValidator_ValidateCreate_InvalidRateLimit(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
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

func TestGraphQLRouteValidator_ValidateCreate_InvalidCacheTTL(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				TTL: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid cache TTL")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidCacheStaleWhileRevalidate(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				StaleWhileRevalidate: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid staleWhileRevalidate")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_ValidCache(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
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

func TestGraphQLRouteValidator_ValidateCreate_InvalidCORSMethod(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
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

func TestGraphQLRouteValidator_ValidateCreate_InvalidTLSVersion(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
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

func TestGraphQLRouteValidator_ValidateCreate_InvalidMaxSessions(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 0,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid max sessions")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidRequestLimits(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			RequestLimits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize: -1,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid request limits")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_NegativeDepthLimit(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			DepthLimit: -1,
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative depth limit")
	}
	if err != nil && !strings.Contains(err.Error(), "depthLimit") {
		t.Errorf("ValidateCreate() error should mention depthLimit, got %v", err)
	}
}

func TestGraphQLRouteValidator_ValidateCreate_NegativeComplexityLimit(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			ComplexityLimit: -5,
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for negative complexity limit")
	}
	if err != nil && !strings.Contains(err.Error(), "complexityLimit") {
		t.Errorf("ValidateCreate() error should mention complexityLimit, got %v", err)
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidAllowedOperations(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			AllowedOperations: []string{"query", "invalid_op"},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid allowed operations")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_ValidAllowedOperations(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			AllowedOperations: []string{"query", "mutation", "subscription"},
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

func TestGraphQLRouteValidator_ValidateCreate_EmptyAllowedOperations(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			AllowedOperations: []string{},
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

func TestGraphQLRouteValidator_ValidateCreate_WithDuplicateChecker_NoDuplicate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &GraphQLRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Prefix: "/graphql"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
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

func TestGraphQLRouteValidator_ValidateCreate_WithDuplicateChecker_Duplicate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Prefix: "/graphql"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	validator := &GraphQLRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	newRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Prefix: "/graphql"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), newRoute)
	if err == nil {
		t.Error("ValidateCreate() should return error for duplicate route")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_ValidationError_SkipsDuplicateCheck(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &GraphQLRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			DepthLimit: -1, // Invalid
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return validation error")
	}
}

// ============================================================================
// GraphQLRouteValidator ValidateUpdate Tests
// ============================================================================

func TestGraphQLRouteValidator_ValidateUpdate_Valid(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	oldRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}
	newRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
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

func TestGraphQLRouteValidator_ValidateUpdate_Invalid(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	oldRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}
	newRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			DepthLimit: -1,
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err == nil {
		t.Error("ValidateUpdate() should return error for invalid route")
	}
}

func TestGraphQLRouteValidator_ValidateUpdate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Prefix: "/graphql"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	validator := &GraphQLRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	oldRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "updated-route",
			Namespace: "default",
		},
	}
	newRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "updated-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Prefix: "/graphql"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err == nil {
		t.Error("ValidateUpdate() should return error for duplicate route")
	}
}

// ============================================================================
// GraphQLRouteValidator ValidateDelete Tests
// ============================================================================

func TestGraphQLRouteValidator_ValidateDelete(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
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

// ============================================================================
// GraphQLRouteValidator validate - Table-Driven Tests
// ============================================================================

func TestGraphQLRouteValidator_Validate_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		route     *avapigwv1alpha1.GraphQLRoute
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid empty spec",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{},
			},
			wantErr: false,
		},
		{
			name: "valid query operation type",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{OperationType: "query"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid mutation operation type",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{OperationType: "mutation"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid subscription operation type",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{OperationType: "subscription"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid operation type",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{OperationType: "invalid"},
					},
				},
			},
			wantErr:   true,
			errSubstr: "operationType",
		},
		{
			name: "valid path exact match",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid path prefix match",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Prefix: "/gql"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid path regex match",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Regex: "^/graphql/.*"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "negative depth and complexity limits",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					DepthLimit:      -1,
					ComplexityLimit: -1,
				},
			},
			wantErr:   true,
			errSubstr: "depthLimit",
		},
		{
			name: "zero depth and complexity limits are valid",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					DepthLimit:      0,
					ComplexityLimit: 0,
				},
			},
			wantErr: false,
		},
		{
			name: "valid retry policy with max attempts",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Retries: &avapigwv1alpha1.RetryPolicy{
						Attempts: 10,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "retry attempts too high",
			route: &avapigwv1alpha1.GraphQLRoute{
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Retries: &avapigwv1alpha1.RetryPolicy{
						Attempts: 11,
					},
				},
			},
			wantErr:   true,
			errSubstr: "retries.attempts",
		},
	}

	validator := &GraphQLRouteValidator{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := validator.ValidateCreate(context.Background(), tt.route)
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
			_ = warnings
		})
	}
}

// ============================================================================
// GraphQLRouteValidator Authentication/Authorization Warnings Tests
// ============================================================================

func TestGraphQLRouteValidator_ValidateCreate_AuthenticationWarnings(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Authentication: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					Secret:  "plaintext-secret",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() should return warnings for plaintext secret")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidAuthentication(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Authentication: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				// No auth method configured
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for enabled auth without method")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_InvalidAuthorization(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Authorization: &avapigwv1alpha1.AuthorizationConfig{
				Enabled: true,
				// No authz method configured
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for enabled authz without method")
	}
}

func TestGraphQLRouteValidator_ValidateCreate_AuthorizationSentinelWarnings(t *testing.T) {
	validator := &GraphQLRouteValidator{}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Authorization: &avapigwv1alpha1.AuthorizationConfig{
				Enabled: true,
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
				},
				Cache: &avapigwv1alpha1.AuthzCacheConfig{
					Enabled: true,
					Type:    "redis",
					Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
						MasterName:    "mymaster",
						SentinelAddrs: []string{"sentinel:26379"},
						Password:      "plaintext-password",
					},
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() should return warnings for plaintext sentinel password")
	}
}

// ============================================================================
// GraphQLRouteValidator NilDuplicateChecker Tests
// ============================================================================

func TestGraphQLRouteValidator_ValidateCreate_NilDuplicateChecker(t *testing.T) {
	validator := &GraphQLRouteValidator{
		DuplicateChecker: nil,
	}
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestGraphQLRouteValidator_ValidateUpdate_NilDuplicateChecker(t *testing.T) {
	validator := &GraphQLRouteValidator{
		DuplicateChecker: nil,
	}
	oldRoute := &avapigwv1alpha1.GraphQLRoute{}
	newRoute := &avapigwv1alpha1.GraphQLRoute{
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	warnings, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err != nil {
		t.Errorf("ValidateUpdate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateUpdate() warnings = %v, want empty", warnings)
	}
}

// ============================================================================
// GraphQLRouteValidator Cross-CRD Conflict Tests
// ============================================================================

func TestGraphQLRouteValidator_ValidateCreate_CrossConflictWithAPIRoute(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingAPIRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-api-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingAPIRoute).
		Build()

	validator := &GraphQLRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Exact: "/api/graphql"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "graphql-backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for cross-CRD conflict with APIRoute")
	}
	if err != nil && !strings.Contains(err.Error(), "path conflict") {
		t.Errorf("ValidateCreate() error should mention path conflict, got %v", err)
	}
}

func TestGraphQLRouteValidator_ValidateUpdate_CrossConflictWithAPIRoute(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingAPIRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-api-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingAPIRoute).
		Build()

	validator := &GraphQLRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	oldRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}
	newRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Exact: "/api/graphql"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "graphql-backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err == nil {
		t.Error("ValidateUpdate() should return error for cross-CRD conflict with APIRoute")
	}
	if err != nil && !strings.Contains(err.Error(), "path conflict") {
		t.Errorf("ValidateUpdate() error should mention path conflict, got %v", err)
	}
}

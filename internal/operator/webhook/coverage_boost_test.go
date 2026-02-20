// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"testing"
	"time"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ============================================================================
// DuplicateChecker Options and Cache Tests
// ============================================================================

func TestDuplicateChecker_WithNamespaceScoped(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Test with namespace scoped = true
	checker := NewDuplicateChecker(client, WithNamespaceScoped(true))
	if checker.GetScope() != ScopeNamespace {
		t.Errorf("GetScope() = %v, want %v", checker.GetScope(), ScopeNamespace)
	}

	// Test with namespace scoped = false
	checker2 := NewDuplicateChecker(client, WithNamespaceScoped(false))
	if checker2.GetScope() != ScopeCluster {
		t.Errorf("GetScope() = %v, want %v", checker2.GetScope(), ScopeCluster)
	}
}

func TestDuplicateChecker_WithCacheEnabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	checker := NewDuplicateChecker(client, WithCacheEnabled(true))
	if !checker.cacheEnabled {
		t.Error("cacheEnabled should be true")
	}

	checker2 := NewDuplicateChecker(client, WithCacheEnabled(false))
	if checker2.cacheEnabled {
		t.Error("cacheEnabled should be false")
	}
}

func TestDuplicateChecker_WithCacheTTL(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	customTTL := 60 * time.Second
	checker := NewDuplicateChecker(client, WithCacheTTL(customTTL))
	if checker.cacheTTL != customTTL {
		t.Errorf("cacheTTL = %v, want %v", checker.cacheTTL, customTTL)
	}
}

func TestDuplicateChecker_SetScope(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	checker := NewDuplicateChecker(client)

	// Set to cluster scope
	checker.SetScope(ScopeCluster)
	if checker.GetScope() != ScopeCluster {
		t.Errorf("GetScope() = %v, want %v", checker.GetScope(), ScopeCluster)
	}

	// Set back to namespace scope
	checker.SetScope(ScopeNamespace)
	if checker.GetScope() != ScopeNamespace {
		t.Errorf("GetScope() = %v, want %v", checker.GetScope(), ScopeNamespace)
	}
}

func TestDuplicateChecker_IsCacheValidLocked(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Test with cache enabled but no entry
	checker2 := NewDuplicateChecker(client, WithCacheEnabled(true))
	checker2.cache.mu.RLock()
	valid := checker2.isCacheValidLocked("nonexistent-key")
	checker2.cache.mu.RUnlock()
	if valid {
		t.Error("isCacheValidLocked() should return false for nonexistent key")
	}

	// Test with cache enabled and valid entry
	checker3 := NewDuplicateChecker(client, WithCacheEnabled(true), WithCacheTTL(1*time.Hour))
	checker3.updateCacheTimestamp("valid-key")
	checker3.cache.mu.RLock()
	valid = checker3.isCacheValidLocked("valid-key")
	checker3.cache.mu.RUnlock()
	if !valid {
		t.Error("isCacheValidLocked() should return true for valid cache entry")
	}

	// Test with expired cache entry
	checker4 := NewDuplicateChecker(client, WithCacheEnabled(true), WithCacheTTL(1*time.Nanosecond))
	checker4.updateCacheTimestamp("expired-key")
	time.Sleep(10 * time.Millisecond) // Wait for cache to expire
	checker4.cache.mu.RLock()
	valid = checker4.isCacheValidLocked("expired-key")
	checker4.cache.mu.RUnlock()
	if valid {
		t.Error("isCacheValidLocked() should return false for expired cache entry")
	}
}

func TestDuplicateChecker_UpdateCacheTimestamp(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	checker := NewDuplicateChecker(client, WithCacheEnabled(true))

	// Update timestamp
	checker.updateCacheTimestamp("test-key")

	// Verify timestamp was set
	checker.cache.mu.RLock()
	_, ok := checker.cache.lastRefresh["test-key"]
	checker.cache.mu.RUnlock()

	if !ok {
		t.Error("updateCacheTimestamp() should set the timestamp")
	}
}

func TestDuplicateChecker_InvalidateCache(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	checker := NewDuplicateChecker(client, WithCacheEnabled(true))

	// Add some cache entries
	checker.updateCacheTimestamp("key1")
	checker.updateCacheTimestamp("key2")

	// Invalidate cache
	checker.InvalidateCache()

	// Verify cache is empty
	checker.cache.mu.RLock()
	apiRoutesLen := len(checker.cache.apiRoutes)
	grpcRoutesLen := len(checker.cache.grpcRoutes)
	backendsLen := len(checker.cache.backends)
	grpcBackendsLen := len(checker.cache.grpcBackends)
	lastRefreshLen := len(checker.cache.lastRefresh)
	checker.cache.mu.RUnlock()

	if apiRoutesLen != 0 || grpcRoutesLen != 0 || backendsLen != 0 || grpcBackendsLen != 0 || lastRefreshLen != 0 {
		t.Error("InvalidateCache() should clear all cache entries")
	}
}

// ============================================================================
// APIRoute Validator Tests with DuplicateChecker
// ============================================================================

func TestAPIRouteValidator_ValidateCreate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1",
					},
					Methods: []string{"GET"},
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

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	validator := &APIRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	// Test creating a duplicate route
	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1/users",
					},
					Methods: []string{"GET"},
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

func TestAPIRouteValidator_ValidateUpdate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1",
					},
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

	anotherRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "another-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v2",
					},
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

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute, anotherRoute).
		Build()

	validator := &APIRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	// Test updating to a conflicting route
	updatedRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "another-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1/users",
					},
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

	_, err := validator.ValidateUpdate(context.Background(), anotherRoute, updatedRoute)
	if err == nil {
		t.Error("ValidateUpdate() should return error for conflicting route")
	}
}

func TestAPIRouteValidator_ValidateCreate_NilDuplicateChecker(t *testing.T) {
	validator := &APIRouteValidator{
		Client:           nil,
		DuplicateChecker: nil,
	}

	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
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

	_, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() with nil DuplicateChecker should not error, got %v", err)
	}
}

// ============================================================================
// APIRoute validateCache Tests
// ============================================================================

func TestAPIRouteValidator_ValidateCache_ValidTTL(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("1h"),
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

func TestAPIRouteValidator_ValidateCache_ValidStaleWhileRevalidate(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled:              true,
				TTL:                  avapigwv1alpha1.Duration("1h"),
				StaleWhileRevalidate: avapigwv1alpha1.Duration("5m"),
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

func TestAPIRouteValidator_ValidateCache_InvalidStaleWhileRevalidate(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled:              true,
				TTL:                  avapigwv1alpha1.Duration("1h"),
				StaleWhileRevalidate: avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid staleWhileRevalidate")
	}
}

func TestAPIRouteValidator_ValidateCache_EmptyTTL(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration(""),
			},
		},
	}

	// Empty TTL should be valid (uses default)
	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

// ============================================================================
// GRPCRoute Validator Tests with DuplicateChecker
// ============================================================================

func TestGRPCRouteValidator_ValidateCreate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.UserService"},
					Method:  &avapigwv1alpha1.StringMatch{Exact: "GetUser"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	validator := &GRPCRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	// Test creating a duplicate route
	newRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.UserService"},
					Method:  &avapigwv1alpha1.StringMatch{Exact: "GetUser"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), newRoute)
	if err == nil {
		t.Error("ValidateCreate() should return error for duplicate gRPC route")
	}
}

func TestGRPCRouteValidator_ValidateUpdate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.UserService"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	anotherRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "another-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.OrderService"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute, anotherRoute).
		Build()

	validator := &GRPCRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	// Test updating to a conflicting route
	updatedRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "another-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.UserService"},
					Method:  &avapigwv1alpha1.StringMatch{Exact: "GetUser"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), anotherRoute, updatedRoute)
	if err == nil {
		t.Error("ValidateUpdate() should return error for conflicting gRPC route")
	}
}

// ============================================================================
// Backend Validator Tests with DuplicateChecker
// ============================================================================

func TestBackendValidator_ValidateCreate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend.example.com", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	validator := &BackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	// Test creating a duplicate backend
	newBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend.example.com", Port: 8080},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), newBackend)
	if err == nil {
		t.Error("ValidateCreate() should return error for duplicate backend")
	}
}

func TestBackendValidator_ValidateUpdate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend1.example.com", Port: 8080},
			},
		},
	}

	anotherBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "another-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend2.example.com", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend, anotherBackend).
		Build()

	validator := &BackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	// Test updating to a conflicting backend
	updatedBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "another-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend1.example.com", Port: 8080},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), anotherBackend, updatedBackend)
	if err == nil {
		t.Error("ValidateUpdate() should return error for conflicting backend")
	}
}

// ============================================================================
// GRPCBackend Validator Tests with DuplicateChecker
// ============================================================================

func TestGRPCBackendValidator_ValidateCreate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend.example.com", Port: 50051},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	validator := &GRPCBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	// Test creating a duplicate backend
	newBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend.example.com", Port: 50051},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), newBackend)
	if err == nil {
		t.Error("ValidateCreate() should return error for duplicate gRPC backend")
	}
}

func TestGRPCBackendValidator_ValidateUpdate_WithDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend1.example.com", Port: 50051},
			},
		},
	}

	anotherBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "another-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend2.example.com", Port: 50051},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend, anotherBackend).
		Build()

	validator := &GRPCBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	// Test updating to a conflicting backend
	updatedBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "another-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend1.example.com", Port: 50051},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), anotherBackend, updatedBackend)
	if err == nil {
		t.Error("ValidateUpdate() should return error for conflicting gRPC backend")
	}
}

// ============================================================================
// Additional DuplicateChecker Edge Cases
// ============================================================================

func TestDuplicateChecker_GRPCMethodsOverlap(t *testing.T) {
	checker := &DuplicateChecker{}

	tests := []struct {
		name     string
		a        *avapigwv1alpha1.GRPCRouteMatch
		b        *avapigwv1alpha1.GRPCRouteMatch
		expected bool
	}{
		{
			name:     "both nil method",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: nil},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: nil},
			expected: true,
		},
		{
			name:     "a nil method",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: nil},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			expected: true,
		},
		{
			name:     "b nil method",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: nil},
			expected: true,
		},
		{
			name:     "same exact",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			expected: true,
		},
		{
			name:     "different exact",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "CreateUser"}},
			expected: false,
		},
		{
			name:     "prefix overlap",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Prefix: "Get"}},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Prefix: "GetUser"}},
			expected: true,
		},
		{
			name:     "prefix no overlap",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Prefix: "Create"}},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Prefix: "Get"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.grpcMethodsOverlap(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("grpcMethodsOverlap() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDuplicateChecker_GRPCMethodsOverlapForPrefix(t *testing.T) {
	checker := &DuplicateChecker{}

	tests := []struct {
		name     string
		a        *avapigwv1alpha1.GRPCRouteMatch
		b        *avapigwv1alpha1.GRPCRouteMatch
		expected bool
	}{
		{
			name:     "both nil method",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: nil},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: nil},
			expected: true,
		},
		{
			name:     "a nil method",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: nil},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			expected: true,
		},
		{
			name:     "same exact method",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			expected: true,
		},
		{
			name:     "different exact method",
			a:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "GetUser"}},
			b:        &avapigwv1alpha1.GRPCRouteMatch{Method: &avapigwv1alpha1.StringMatch{Exact: "CreateUser"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.grpcMethodsOverlapForPrefix(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("grpcMethodsOverlapForPrefix() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDuplicateChecker_GRPCBackendsConflict(t *testing.T) {
	checker := &DuplicateChecker{}

	tests := []struct {
		name     string
		a        *avapigwv1alpha1.GRPCBackend
		b        *avapigwv1alpha1.GRPCBackend
		expected bool
	}{
		{
			name: "same host and port",
			a: &avapigwv1alpha1.GRPCBackend{
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "backend.example.com", Port: 50051},
					},
				},
			},
			b: &avapigwv1alpha1.GRPCBackend{
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "backend.example.com", Port: 50051},
					},
				},
			},
			expected: true,
		},
		{
			name: "different host",
			a: &avapigwv1alpha1.GRPCBackend{
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "backend1.example.com", Port: 50051},
					},
				},
			},
			b: &avapigwv1alpha1.GRPCBackend{
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "backend2.example.com", Port: 50051},
					},
				},
			},
			expected: false,
		},
		{
			name: "different port",
			a: &avapigwv1alpha1.GRPCBackend{
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "backend.example.com", Port: 50051},
					},
				},
			},
			b: &avapigwv1alpha1.GRPCBackend{
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "backend.example.com", Port: 50052},
					},
				},
			},
			expected: false,
		},
		{
			name: "empty hosts",
			a: &avapigwv1alpha1.GRPCBackend{
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{},
				},
			},
			b: &avapigwv1alpha1.GRPCBackend{
				Spec: avapigwv1alpha1.GRPCBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.grpcBackendsConflict(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("grpcBackendsConflict() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDuplicateChecker_ExactAndPrefixOverlap(t *testing.T) {
	checker := &DuplicateChecker{}

	tests := []struct {
		name     string
		a        *avapigwv1alpha1.RouteMatch
		b        *avapigwv1alpha1.RouteMatch
		expected bool
	}{
		{
			name: "exact within prefix",
			a: &avapigwv1alpha1.RouteMatch{
				URI: &avapigwv1alpha1.URIMatch{Exact: "/api/v1/users"},
			},
			b: &avapigwv1alpha1.RouteMatch{
				URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"},
			},
			expected: true,
		},
		{
			name: "exact not within prefix",
			a: &avapigwv1alpha1.RouteMatch{
				URI: &avapigwv1alpha1.URIMatch{Exact: "/api/v2/users"},
			},
			b: &avapigwv1alpha1.RouteMatch{
				URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"},
			},
			expected: false,
		},
		{
			name: "prefix within exact (reversed)",
			a: &avapigwv1alpha1.RouteMatch{
				URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"},
			},
			b: &avapigwv1alpha1.RouteMatch{
				URI: &avapigwv1alpha1.URIMatch{Exact: "/api/v1/users"},
			},
			expected: true,
		},
		{
			name: "no exact or prefix",
			a: &avapigwv1alpha1.RouteMatch{
				URI: &avapigwv1alpha1.URIMatch{},
			},
			b: &avapigwv1alpha1.RouteMatch{
				URI: &avapigwv1alpha1.URIMatch{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.exactAndPrefixOverlap(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("exactAndPrefixOverlap() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// ============================================================================
// Redirect Validation Edge Cases
// ============================================================================

func TestAPIRouteValidator_ValidateRedirect_ValidConfig(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Redirect: &avapigwv1alpha1.RedirectConfig{
				Code: 301,
				URI:  "/new-path",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
}

func TestAPIRouteValidator_ValidateRedirect_InvalidPort(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Redirect: &avapigwv1alpha1.RedirectConfig{
				URI:  "/new-path",
				Code: 301,
				Port: 70000, // Invalid port
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid redirect port")
	}
}

// ============================================================================
// Fault Injection Edge Cases
// ============================================================================

func TestAPIRouteValidator_ValidateFaultInjection_InvalidAbortPercentage(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Fault: &avapigwv1alpha1.FaultInjection{
				Abort: &avapigwv1alpha1.FaultAbort{
					HTTPStatus: 503,
					Percentage: 150, // Invalid percentage
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid abort percentage")
	}
}

func TestAPIRouteValidator_ValidateFaultInjection_InvalidDelayDuration(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Fault: &avapigwv1alpha1.FaultInjection{
				Delay: &avapigwv1alpha1.FaultDelay{
					FixedDelay: avapigwv1alpha1.Duration("invalid"),
					Percentage: 10,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid delay duration")
	}
}

// ============================================================================
// Retry Policy Edge Cases
// ============================================================================

func TestAPIRouteValidator_ValidateRetryPolicy_InvalidPerTryTimeout(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
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

func TestAPIRouteValidator_ValidateRetryPolicy_TooManyAttempts(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Retries: &avapigwv1alpha1.RetryPolicy{
				Attempts: 100, // Too many attempts
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for too many retry attempts")
	}
}

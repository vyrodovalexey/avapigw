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

func TestNewDuplicateChecker(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	checker := NewDuplicateChecker(client)
	if checker == nil {
		t.Error("NewDuplicateChecker() returned nil")
	}
	if checker.client == nil {
		t.Error("NewDuplicateChecker() client is nil")
	}
	if checker.logger == nil {
		t.Error("NewDuplicateChecker() logger is nil")
	}
}

func TestDuplicateChecker_CheckAPIRouteDuplicate_NilClient(t *testing.T) {
	checker := &DuplicateChecker{client: nil}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	err := checker.CheckAPIRouteDuplicate(context.Background(), route)
	if err != nil {
		t.Errorf("CheckAPIRouteDuplicate() with nil client should return nil, got %v", err)
	}
}

func TestDuplicateChecker_CheckAPIRouteDuplicate_NoDuplicates(t *testing.T) {
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
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v2",
					},
					Methods: []string{"GET"},
				},
			},
		},
	}

	err := checker.CheckAPIRouteDuplicate(context.Background(), newRoute)
	if err != nil {
		t.Errorf("CheckAPIRouteDuplicate() should not return error for non-overlapping routes, got %v", err)
	}
}

func TestDuplicateChecker_CheckAPIRouteDuplicate_OverlappingPrefix(t *testing.T) {
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
						Prefix: "/api",
					},
					Methods: []string{"GET"},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
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
		},
	}

	err := checker.CheckAPIRouteDuplicate(context.Background(), newRoute)
	if err == nil {
		t.Error("CheckAPIRouteDuplicate() should return error for overlapping prefix routes")
	}
}

func TestDuplicateChecker_CheckAPIRouteDuplicate_ExactMatch(t *testing.T) {
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
						Exact: "/api/v1/users",
					},
					Methods: []string{"GET"},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Exact: "/api/v1/users",
					},
					Methods: []string{"GET"},
				},
			},
		},
	}

	err := checker.CheckAPIRouteDuplicate(context.Background(), newRoute)
	if err == nil {
		t.Error("CheckAPIRouteDuplicate() should return error for exact match duplicates")
	}
}

func TestDuplicateChecker_CheckAPIRouteDuplicate_DifferentMethods(t *testing.T) {
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
						Exact: "/api/v1/users",
					},
					Methods: []string{"GET"},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Exact: "/api/v1/users",
					},
					Methods: []string{"POST"},
				},
			},
		},
	}

	err := checker.CheckAPIRouteDuplicate(context.Background(), newRoute)
	if err != nil {
		t.Errorf("CheckAPIRouteDuplicate() should not return error for different methods, got %v", err)
	}
}

func TestDuplicateChecker_CheckAPIRouteDuplicate_SameRoute(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

	// Same route (update scenario)
	err := checker.CheckAPIRouteDuplicate(context.Background(), existingRoute)
	if err != nil {
		t.Errorf("CheckAPIRouteDuplicate() should skip self, got %v", err)
	}
}

func TestDuplicateChecker_CheckAPIRouteDuplicate_EmptyMatch(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api",
					},
				},
			},
		},
	}

	err := checker.CheckAPIRouteDuplicate(context.Background(), newRoute)
	if err != nil {
		t.Errorf("CheckAPIRouteDuplicate() should not return error when existing has empty match, got %v", err)
	}
}

func TestDuplicateChecker_CheckBackendDuplicate_NilClient(t *testing.T) {
	checker := &DuplicateChecker{client: nil}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	err := checker.CheckBackendDuplicate(context.Background(), backend)
	if err != nil {
		t.Errorf("CheckBackendDuplicate() with nil client should return nil, got %v", err)
	}
}

func TestDuplicateChecker_CheckBackendDuplicate_NoDuplicates(t *testing.T) {
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

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	checker := NewDuplicateChecker(client)

	newBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend2.example.com", Port: 8080},
			},
		},
	}

	err := checker.CheckBackendDuplicate(context.Background(), newBackend)
	if err != nil {
		t.Errorf("CheckBackendDuplicate() should not return error for different hosts, got %v", err)
	}
}

func TestDuplicateChecker_CheckBackendDuplicate_SameHostPort(t *testing.T) {
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

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	checker := NewDuplicateChecker(client)

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

	err := checker.CheckBackendDuplicate(context.Background(), newBackend)
	if err == nil {
		t.Error("CheckBackendDuplicate() should return error for same host:port")
	}
}

func TestDuplicateChecker_CheckBackendDuplicate_SameHostDifferentPort(t *testing.T) {
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

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	checker := NewDuplicateChecker(client)

	newBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend.example.com", Port: 9090},
			},
		},
	}

	err := checker.CheckBackendDuplicate(context.Background(), newBackend)
	if err != nil {
		t.Errorf("CheckBackendDuplicate() should not return error for different ports, got %v", err)
	}
}

func TestDuplicateChecker_CheckGRPCRouteDuplicate_NilClient(t *testing.T) {
	checker := &DuplicateChecker{client: nil}
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	err := checker.CheckGRPCRouteDuplicate(context.Background(), route)
	if err != nil {
		t.Errorf("CheckGRPCRouteDuplicate() with nil client should return nil, got %v", err)
	}
}

func TestDuplicateChecker_CheckGRPCRouteDuplicate_NoDuplicates(t *testing.T) {
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
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

	newRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.OrderService"},
					Method:  &avapigwv1alpha1.StringMatch{Exact: "GetOrder"},
				},
			},
		},
	}

	err := checker.CheckGRPCRouteDuplicate(context.Background(), newRoute)
	if err != nil {
		t.Errorf("CheckGRPCRouteDuplicate() should not return error for different services, got %v", err)
	}
}

func TestDuplicateChecker_CheckGRPCRouteDuplicate_SameServiceMethod(t *testing.T) {
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
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

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
		},
	}

	err := checker.CheckGRPCRouteDuplicate(context.Background(), newRoute)
	if err == nil {
		t.Error("CheckGRPCRouteDuplicate() should return error for same service/method")
	}
}

func TestDuplicateChecker_CheckGRPCRouteDuplicate_SameServiceNoMethod(t *testing.T) {
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
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client)

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
		},
	}

	err := checker.CheckGRPCRouteDuplicate(context.Background(), newRoute)
	if err == nil {
		t.Error("CheckGRPCRouteDuplicate() should return error when existing has no method (catch-all)")
	}
}

func TestDuplicateChecker_CheckGRPCBackendDuplicate_NilClient(t *testing.T) {
	checker := &DuplicateChecker{client: nil}
	backend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	err := checker.CheckGRPCBackendDuplicate(context.Background(), backend)
	if err != nil {
		t.Errorf("CheckGRPCBackendDuplicate() with nil client should return nil, got %v", err)
	}
}

func TestDuplicateChecker_CheckGRPCBackendDuplicate_SameHostPort(t *testing.T) {
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

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	checker := NewDuplicateChecker(client)

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

	err := checker.CheckGRPCBackendDuplicate(context.Background(), newBackend)
	if err == nil {
		t.Error("CheckGRPCBackendDuplicate() should return error for same host:port")
	}
}

func TestDuplicateChecker_MethodsOverlap(t *testing.T) {
	checker := &DuplicateChecker{}

	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{"both empty", []string{}, []string{}, true},
		{"a empty", []string{}, []string{"GET"}, true},
		{"b empty", []string{"GET"}, []string{}, true},
		{"same method", []string{"GET"}, []string{"GET"}, true},
		{"different methods", []string{"GET"}, []string{"POST"}, false},
		{"case insensitive", []string{"get"}, []string{"GET"}, true},
		{"multiple overlap", []string{"GET", "POST"}, []string{"POST", "PUT"}, true},
		{"multiple no overlap", []string{"GET", "DELETE"}, []string{"POST", "PUT"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.methodsOverlap(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("methodsOverlap(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestDuplicateChecker_MatchConditionsOverlap_ExactAndPrefix(t *testing.T) {
	checker := &DuplicateChecker{}

	// Test exact match with prefix
	a := &avapigwv1alpha1.RouteMatch{
		URI: &avapigwv1alpha1.URIMatch{
			Exact: "/api/v1/users",
		},
	}
	b := &avapigwv1alpha1.RouteMatch{
		URI: &avapigwv1alpha1.URIMatch{
			Prefix: "/api/v1",
		},
	}

	if !checker.matchConditionsOverlap(a, b) {
		t.Error("matchConditionsOverlap() should return true for exact within prefix")
	}
}

func TestDuplicateChecker_GRPCMatchConditionsOverlap_PrefixService(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.GRPCRouteMatch{
		Service: &avapigwv1alpha1.StringMatch{Prefix: "service.v1"},
	}
	b := &avapigwv1alpha1.GRPCRouteMatch{
		Service: &avapigwv1alpha1.StringMatch{Prefix: "service.v1.User"},
	}

	if !checker.grpcMatchConditionsOverlap(a, b) {
		t.Error("grpcMatchConditionsOverlap() should return true for overlapping service prefixes")
	}
}

// ============================================================================
// DuplicateChecker Stop and Cleanup Tests
// ============================================================================

func TestDuplicateChecker_Stop_CacheDisabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create checker with cache disabled
	checker := NewDuplicateChecker(client, WithCacheEnabled(false))

	// Stop should return immediately without blocking
	checker.Stop()
}

func TestDuplicateChecker_Stop_CacheEnabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create checker with cache enabled
	checker := NewDuplicateChecker(client, WithCacheEnabled(true))

	// Stop should gracefully shutdown the cleanup goroutine
	checker.Stop()
}

func TestDuplicateChecker_WithCleanupInterval(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	customInterval := 5 * time.Minute
	checker := NewDuplicateChecker(client, WithCleanupInterval(customInterval))

	if checker.cleanupInterval != customInterval {
		t.Errorf("cleanupInterval = %v, want %v", checker.cleanupInterval, customInterval)
	}
}

func TestDuplicateChecker_CleanupExpiredEntries(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create checker with very short TTL
	checker := NewDuplicateChecker(client,
		WithCacheEnabled(true),
		WithCacheTTL(1*time.Nanosecond),
	)

	// Add some cache entries
	checker.cache.mu.Lock()
	checker.cache.lastRefresh["expired-key-1"] = time.Now().Add(-1 * time.Hour)
	checker.cache.lastRefresh["expired-key-2"] = time.Now().Add(-2 * time.Hour)
	checker.cache.apiRoutes["expired-key-1"] = &avapigwv1alpha1.APIRouteList{}
	checker.cache.backends["expired-key-2"] = &avapigwv1alpha1.BackendList{}
	checker.cache.mu.Unlock()

	// Run cleanup
	checker.cleanupExpiredEntries()

	// Verify expired entries were removed
	checker.cache.mu.RLock()
	_, ok1 := checker.cache.lastRefresh["expired-key-1"]
	_, ok2 := checker.cache.lastRefresh["expired-key-2"]
	_, ok3 := checker.cache.apiRoutes["expired-key-1"]
	_, ok4 := checker.cache.backends["expired-key-2"]
	checker.cache.mu.RUnlock()

	if ok1 || ok2 || ok3 || ok4 {
		t.Error("cleanupExpiredEntries() should remove expired entries")
	}

	// Stop the checker
	checker.Stop()
}

func TestDuplicateChecker_CleanupExpiredEntries_NoExpired(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create checker with long TTL
	checker := NewDuplicateChecker(client,
		WithCacheEnabled(true),
		WithCacheTTL(1*time.Hour),
	)

	// Add fresh cache entries
	checker.cache.mu.Lock()
	checker.cache.lastRefresh["fresh-key"] = time.Now()
	checker.cache.apiRoutes["fresh-key"] = &avapigwv1alpha1.APIRouteList{}
	checker.cache.mu.Unlock()

	// Run cleanup
	checker.cleanupExpiredEntries()

	// Verify fresh entries were NOT removed
	checker.cache.mu.RLock()
	_, ok := checker.cache.lastRefresh["fresh-key"]
	checker.cache.mu.RUnlock()

	if !ok {
		t.Error("cleanupExpiredEntries() should not remove fresh entries")
	}

	// Stop the checker
	checker.Stop()
}

func TestDuplicateChecker_AutomaticCleanup(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create checker with very short cleanup interval and TTL
	checker := NewDuplicateChecker(client,
		WithCacheEnabled(true),
		WithCacheTTL(1*time.Millisecond),
		WithCleanupInterval(10*time.Millisecond),
	)

	// Add an expired entry
	checker.cache.mu.Lock()
	checker.cache.lastRefresh["auto-cleanup-key"] = time.Now().Add(-1 * time.Hour)
	checker.cache.apiRoutes["auto-cleanup-key"] = &avapigwv1alpha1.APIRouteList{}
	checker.cache.mu.Unlock()

	// Wait for automatic cleanup to run
	time.Sleep(50 * time.Millisecond)

	// Verify entry was cleaned up
	checker.cache.mu.RLock()
	_, ok := checker.cache.lastRefresh["auto-cleanup-key"]
	checker.cache.mu.RUnlock()

	if ok {
		t.Error("Automatic cleanup should remove expired entries")
	}

	// Stop the checker
	checker.Stop()
}

func TestDuplicateChecker_CleanupAllCacheTypes(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create checker with very short TTL
	checker := NewDuplicateChecker(client,
		WithCacheEnabled(true),
		WithCacheTTL(1*time.Nanosecond),
	)

	// Add expired entries for all cache types
	expiredTime := time.Now().Add(-1 * time.Hour)
	checker.cache.mu.Lock()
	checker.cache.lastRefresh["key1"] = expiredTime
	checker.cache.apiRoutes["key1"] = &avapigwv1alpha1.APIRouteList{}
	checker.cache.grpcRoutes["key1"] = &avapigwv1alpha1.GRPCRouteList{}
	checker.cache.backends["key1"] = &avapigwv1alpha1.BackendList{}
	checker.cache.grpcBackends["key1"] = &avapigwv1alpha1.GRPCBackendList{}
	checker.cache.mu.Unlock()

	// Run cleanup
	checker.cleanupExpiredEntries()

	// Verify all entries were removed
	checker.cache.mu.RLock()
	apiRoutesLen := len(checker.cache.apiRoutes)
	grpcRoutesLen := len(checker.cache.grpcRoutes)
	backendsLen := len(checker.cache.backends)
	grpcBackendsLen := len(checker.cache.grpcBackends)
	lastRefreshLen := len(checker.cache.lastRefresh)
	checker.cache.mu.RUnlock()

	if apiRoutesLen != 0 || grpcRoutesLen != 0 || backendsLen != 0 || grpcBackendsLen != 0 || lastRefreshLen != 0 {
		t.Error("cleanupExpiredEntries() should remove all expired entries from all cache types")
	}

	// Stop the checker
	checker.Stop()
}

// ============================================================================
// DuplicateChecker Cluster-Scoped Tests
// ============================================================================

func TestDuplicateChecker_ClusterScoped_APIRoute(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	// Create routes in different namespaces
	route1 := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route1",
			Namespace: "ns1",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		Build()

	// Create cluster-scoped checker
	checker := NewDuplicateChecker(client, WithNamespaceScoped(false))

	// Try to create conflicting route in different namespace
	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route2",
			Namespace: "ns2",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1/users",
					},
				},
			},
		},
	}

	err := checker.CheckAPIRouteDuplicate(context.Background(), newRoute)
	if err == nil {
		t.Error("Cluster-scoped checker should detect conflicts across namespaces")
	}
}

func TestDuplicateChecker_ClusterScoped_Backend(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	backend1 := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend1",
			Namespace: "ns1",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend.example.com", Port: 8080},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend1).
		Build()

	// Create cluster-scoped checker
	checker := NewDuplicateChecker(client, WithNamespaceScoped(false))

	// Try to create conflicting backend in different namespace
	newBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend2",
			Namespace: "ns2",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend.example.com", Port: 8080},
			},
		},
	}

	err := checker.CheckBackendDuplicate(context.Background(), newBackend)
	if err == nil {
		t.Error("Cluster-scoped checker should detect conflicts across namespaces")
	}
}

func TestDuplicateChecker_ClusterScoped_GRPCRoute(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	route1 := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route1",
			Namespace: "ns1",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.UserService"},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		Build()

	// Create cluster-scoped checker
	checker := NewDuplicateChecker(client, WithNamespaceScoped(false))

	// Try to create conflicting route in different namespace
	newRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route2",
			Namespace: "ns2",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.UserService"},
					Method:  &avapigwv1alpha1.StringMatch{Exact: "GetUser"},
				},
			},
		},
	}

	err := checker.CheckGRPCRouteDuplicate(context.Background(), newRoute)
	if err == nil {
		t.Error("Cluster-scoped checker should detect conflicts across namespaces")
	}
}

func TestDuplicateChecker_ClusterScoped_GRPCBackend(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	backend1 := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend1",
			Namespace: "ns1",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend.example.com", Port: 50051},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend1).
		Build()

	// Create cluster-scoped checker
	checker := NewDuplicateChecker(client, WithNamespaceScoped(false))

	// Try to create conflicting backend in different namespace
	newBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend2",
			Namespace: "ns2",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend.example.com", Port: 50051},
			},
		},
	}

	err := checker.CheckGRPCBackendDuplicate(context.Background(), newBackend)
	if err == nil {
		t.Error("Cluster-scoped checker should detect conflicts across namespaces")
	}
}

// ============================================================================
// DuplicateChecker Cache Key Tests
// ============================================================================

func TestDuplicateChecker_BuildCacheKey_NamespaceScoped(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	checker := NewDuplicateChecker(client, WithNamespaceScoped(true))

	key := checker.buildCacheKey("apiroute", "default")
	expected := "apiroute/default"
	if key != expected {
		t.Errorf("buildCacheKey() = %q, want %q", key, expected)
	}
}

func TestDuplicateChecker_BuildCacheKey_ClusterScoped(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	checker := NewDuplicateChecker(client, WithNamespaceScoped(false))

	key := checker.buildCacheKey("apiroute", "default")
	expected := "apiroute/cluster"
	if key != expected {
		t.Errorf("buildCacheKey() = %q, want %q", key, expected)
	}
}

// ============================================================================
// DuplicateChecker Cache with API Operations Tests
// ============================================================================

func TestDuplicateChecker_CacheHit_APIRoute(t *testing.T) {
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
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client,
		WithCacheEnabled(true),
		WithCacheTTL(1*time.Hour),
	)

	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
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
		},
	}

	// First call - cache miss
	err := checker.CheckAPIRouteDuplicate(context.Background(), newRoute)
	if err != nil {
		t.Errorf("First call should not return error, got %v", err)
	}

	// Second call - should use cache
	err = checker.CheckAPIRouteDuplicate(context.Background(), newRoute)
	if err != nil {
		t.Errorf("Second call should not return error, got %v", err)
	}

	// Stop the checker
	checker.Stop()
}

func TestDuplicateChecker_CacheHit_Backend(t *testing.T) {
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

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	checker := NewDuplicateChecker(client,
		WithCacheEnabled(true),
		WithCacheTTL(1*time.Hour),
	)

	newBackend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend2.example.com", Port: 8080},
			},
		},
	}

	// First call - cache miss
	err := checker.CheckBackendDuplicate(context.Background(), newBackend)
	if err != nil {
		t.Errorf("First call should not return error, got %v", err)
	}

	// Second call - should use cache
	err = checker.CheckBackendDuplicate(context.Background(), newBackend)
	if err != nil {
		t.Errorf("Second call should not return error, got %v", err)
	}

	// Stop the checker
	checker.Stop()
}

func TestDuplicateChecker_CacheHit_GRPCRoute(t *testing.T) {
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
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingRoute).
		Build()

	checker := NewDuplicateChecker(client,
		WithCacheEnabled(true),
		WithCacheTTL(1*time.Hour),
	)

	newRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{Exact: "service.v1.OrderService"},
				},
			},
		},
	}

	// First call - cache miss
	err := checker.CheckGRPCRouteDuplicate(context.Background(), newRoute)
	if err != nil {
		t.Errorf("First call should not return error, got %v", err)
	}

	// Second call - should use cache
	err = checker.CheckGRPCRouteDuplicate(context.Background(), newRoute)
	if err != nil {
		t.Errorf("Second call should not return error, got %v", err)
	}

	// Stop the checker
	checker.Stop()
}

func TestDuplicateChecker_CacheHit_GRPCBackend(t *testing.T) {
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

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackend).
		Build()

	checker := NewDuplicateChecker(client,
		WithCacheEnabled(true),
		WithCacheTTL(1*time.Hour),
	)

	newBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend2.example.com", Port: 50051},
			},
		},
	}

	// First call - cache miss
	err := checker.CheckGRPCBackendDuplicate(context.Background(), newBackend)
	if err != nil {
		t.Errorf("First call should not return error, got %v", err)
	}

	// Second call - should use cache
	err = checker.CheckGRPCBackendDuplicate(context.Background(), newBackend)
	if err != nil {
		t.Errorf("Second call should not return error, got %v", err)
	}

	// Stop the checker
	checker.Stop()
}

// ============================================================================
// DuplicateChecker Edge Cases
// ============================================================================

func TestDuplicateChecker_MatchConditionsOverlap_NilURI(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.RouteMatch{URI: nil}
	b := &avapigwv1alpha1.RouteMatch{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}}

	result := checker.matchConditionsOverlap(a, b)
	if result {
		t.Error("matchConditionsOverlap() should return false when URI is nil")
	}
}

func TestDuplicateChecker_GRPCMatchConditionsOverlap_NilService(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.GRPCRouteMatch{Service: nil}
	b := &avapigwv1alpha1.GRPCRouteMatch{Service: &avapigwv1alpha1.StringMatch{Exact: "service"}}

	result := checker.grpcMatchConditionsOverlap(a, b)
	if result {
		t.Error("grpcMatchConditionsOverlap() should return false when Service is nil")
	}
}

func TestDuplicateChecker_ExactURIsOverlap_DifferentExact(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.RouteMatch{URI: &avapigwv1alpha1.URIMatch{Exact: "/api/v1"}}
	b := &avapigwv1alpha1.RouteMatch{URI: &avapigwv1alpha1.URIMatch{Exact: "/api/v2"}}

	result := checker.exactURIsOverlap(a, b)
	if result {
		t.Error("exactURIsOverlap() should return false for different exact URIs")
	}
}

func TestDuplicateChecker_PrefixURIsOverlap_EmptyPrefix(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.RouteMatch{URI: &avapigwv1alpha1.URIMatch{Prefix: ""}}
	b := &avapigwv1alpha1.RouteMatch{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}}

	result := checker.prefixURIsOverlap(a, b)
	if result {
		t.Error("prefixURIsOverlap() should return false when prefix is empty")
	}
}

func TestDuplicateChecker_ExactServicesMatch_DifferentExact(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.GRPCRouteMatch{Service: &avapigwv1alpha1.StringMatch{Exact: "service1"}}
	b := &avapigwv1alpha1.GRPCRouteMatch{Service: &avapigwv1alpha1.StringMatch{Exact: "service2"}}

	result := checker.exactServicesMatch(a, b)
	if result {
		t.Error("exactServicesMatch() should return false for different exact services")
	}
}

func TestDuplicateChecker_PrefixServicesOverlap_EmptyPrefix(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.GRPCRouteMatch{Service: &avapigwv1alpha1.StringMatch{Prefix: ""}}
	b := &avapigwv1alpha1.GRPCRouteMatch{Service: &avapigwv1alpha1.StringMatch{Prefix: "service"}}

	result := checker.prefixServicesOverlap(a, b)
	if result {
		t.Error("prefixServicesOverlap() should return false when prefix is empty")
	}
}

func TestDuplicateChecker_BackendsConflict_EmptyHosts(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.Backend{
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{},
		},
	}
	b := &avapigwv1alpha1.Backend{
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend.example.com", Port: 8080},
			},
		},
	}

	result := checker.backendsConflict(a, b)
	if result {
		t.Error("backendsConflict() should return false when hosts are empty")
	}
}

func TestDuplicateChecker_RoutesOverlap_EmptyMatch(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.APIRoute{
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{},
		},
	}
	b := &avapigwv1alpha1.APIRoute{
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
			},
		},
	}

	result := checker.routesOverlap(a, b)
	if result {
		t.Error("routesOverlap() should return false when match is empty")
	}
}

func TestDuplicateChecker_GRPCRoutesOverlap_EmptyMatch(t *testing.T) {
	checker := &DuplicateChecker{}

	a := &avapigwv1alpha1.GRPCRoute{
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{},
		},
	}
	b := &avapigwv1alpha1.GRPCRoute{
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{Service: &avapigwv1alpha1.StringMatch{Exact: "service"}},
			},
		},
	}

	result := checker.grpcRoutesOverlap(a, b)
	if result {
		t.Error("grpcRoutesOverlap() should return false when match is empty")
	}
}

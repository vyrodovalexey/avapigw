// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"testing"

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

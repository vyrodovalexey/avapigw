package route

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// createTestScheme creates a scheme with avapigw types for testing
func createTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	return scheme
}

func TestNewWatchHandler(t *testing.T) {
	scheme := createTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	require.NotNil(t, handler)
	assert.Equal(t, fakeClient, handler.Client)
	assert.Equal(t, "spec.gatewayRef", handler.GatewayIndexField)
	assert.Equal(t, "spec.backendRef", handler.BackendIndexField)
}

func TestGatewayIndexKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		gwName    string
		expected  string
	}{
		{
			name:      "default namespace",
			namespace: "default",
			gwName:    "my-gateway",
			expected:  "default/my-gateway",
		},
		{
			name:      "custom namespace",
			namespace: "production",
			gwName:    "prod-gateway",
			expected:  "production/prod-gateway",
		},
		{
			name:      "empty namespace",
			namespace: "",
			gwName:    "gateway",
			expected:  "/gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GatewayIndexKey(tt.namespace, tt.gwName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBackendIndexKey(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		backendName string
		expected    string
	}{
		{
			name:        "default namespace",
			namespace:   "default",
			backendName: "my-backend",
			expected:    "default/my-backend",
		},
		{
			name:        "custom namespace",
			namespace:   "production",
			backendName: "prod-backend",
			expected:    "production/prod-backend",
		},
		{
			name:        "empty namespace",
			namespace:   "",
			backendName: "backend",
			expected:    "/backend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BackendIndexKey(tt.namespace, tt.backendName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildReconcileRequests(t *testing.T) {
	tests := []struct {
		name     string
		items    []avapigwv1alpha1.HTTPRoute
		expected []reconcile.Request
	}{
		{
			name:     "empty items",
			items:    []avapigwv1alpha1.HTTPRoute{},
			expected: []reconcile.Request{},
		},
		{
			name: "single item",
			items: []avapigwv1alpha1.HTTPRoute{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route1",
						Namespace: "default",
					},
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      "route1",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "multiple items",
			items: []avapigwv1alpha1.HTTPRoute{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route1",
						Namespace: "default",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route2",
						Namespace: "production",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route3",
						Namespace: "staging",
					},
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      "route1",
						Namespace: "default",
					},
				},
				{
					NamespacedName: client.ObjectKey{
						Name:      "route2",
						Namespace: "production",
					},
				},
				{
					NamespacedName: client.ObjectKey{
						Name:      "route3",
						Namespace: "staging",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildReconcileRequests(tt.items)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildGRPCReconcileRequests(t *testing.T) {
	tests := []struct {
		name     string
		items    []avapigwv1alpha1.GRPCRoute
		expected []reconcile.Request
	}{
		{
			name:     "empty items",
			items:    []avapigwv1alpha1.GRPCRoute{},
			expected: []reconcile.Request{},
		},
		{
			name: "single item",
			items: []avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "grpc-route1",
						Namespace: "default",
					},
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      "grpc-route1",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "multiple items",
			items: []avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "grpc-route1",
						Namespace: "default",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "grpc-route2",
						Namespace: "production",
					},
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      "grpc-route1",
						Namespace: "default",
					},
				},
				{
					NamespacedName: client.ObjectKey{
						Name:      "grpc-route2",
						Namespace: "production",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGRPCReconcileRequests(tt.items)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildTCPReconcileRequests(t *testing.T) {
	tests := []struct {
		name     string
		items    []avapigwv1alpha1.TCPRoute
		expected []reconcile.Request
	}{
		{
			name:     "empty items",
			items:    []avapigwv1alpha1.TCPRoute{},
			expected: []reconcile.Request{},
		},
		{
			name: "single item",
			items: []avapigwv1alpha1.TCPRoute{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tcp-route1",
						Namespace: "default",
					},
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      "tcp-route1",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "multiple items",
			items: []avapigwv1alpha1.TCPRoute{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tcp-route1",
						Namespace: "default",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tcp-route2",
						Namespace: "production",
					},
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      "tcp-route1",
						Namespace: "default",
					},
				},
				{
					NamespacedName: client.ObjectKey{
						Name:      "tcp-route2",
						Namespace: "production",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildTCPReconcileRequests(tt.items)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildTLSReconcileRequests(t *testing.T) {
	tests := []struct {
		name     string
		items    []avapigwv1alpha1.TLSRoute
		expected []reconcile.Request
	}{
		{
			name:     "empty items",
			items:    []avapigwv1alpha1.TLSRoute{},
			expected: []reconcile.Request{},
		},
		{
			name: "single item",
			items: []avapigwv1alpha1.TLSRoute{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-route1",
						Namespace: "default",
					},
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      "tls-route1",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "multiple items",
			items: []avapigwv1alpha1.TLSRoute{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-route1",
						Namespace: "default",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-route2",
						Namespace: "production",
					},
				},
			},
			expected: []reconcile.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      "tls-route1",
						Namespace: "default",
					},
				},
				{
					NamespacedName: client.ObjectKey{
						Name:      "tls-route2",
						Namespace: "production",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildTLSReconcileRequests(tt.items)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindHTTPRoutesForGateway(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create HTTPRoutes that reference the gateway
	route1 := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{
					Name:      "test-gateway",
					Namespace: stringPtr("default"),
				},
			},
		},
	}

	route2 := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route2",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{
					Name:      "other-gateway",
					Namespace: stringPtr("default"),
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1, route2).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, "spec.gatewayRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.HTTPRoute)
			var keys []string
			for _, ref := range route.Spec.ParentRefs {
				ns := route.Namespace
				if ref.Namespace != nil {
					ns = *ref.Namespace
				}
				keys = append(keys, GatewayIndexKey(ns, string(ref.Name)))
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindHTTPRoutesForGateway(context.Background(), gateway)

	assert.Len(t, requests, 1)
	assert.Equal(t, "route1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

func TestFindHTTPRoutesForGateway_NoRoutes(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create fake client with index but no routes
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, "spec.gatewayRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.HTTPRoute)
			var keys []string
			for _, ref := range route.Spec.ParentRefs {
				ns := route.Namespace
				if ref.Namespace != nil {
					ns = *ref.Namespace
				}
				keys = append(keys, GatewayIndexKey(ns, string(ref.Name)))
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindHTTPRoutesForGateway(context.Background(), gateway)

	assert.Empty(t, requests)
}

func TestFindHTTPRoutesForBackend(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create HTTPRoutes that reference the backend
	route1 := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			Rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name:      "test-backend",
								Namespace: stringPtr("default"),
							},
						},
					},
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, "spec.backendRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.HTTPRoute)
			var keys []string
			for _, rule := range route.Spec.Rules {
				for _, ref := range rule.BackendRefs {
					ns := route.Namespace
					if ref.Namespace != nil {
						ns = *ref.Namespace
					}
					keys = append(keys, BackendIndexKey(ns, string(ref.Name)))
				}
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindHTTPRoutesForBackend(context.Background(), backend)

	assert.Len(t, requests, 1)
	assert.Equal(t, "route1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

func TestFindGRPCRoutesForGateway(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create GRPCRoutes that reference the gateway
	route1 := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{
					Name:      "test-gateway",
					Namespace: stringPtr("default"),
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, "spec.gatewayRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.GRPCRoute)
			var keys []string
			for _, ref := range route.Spec.ParentRefs {
				ns := route.Namespace
				if ref.Namespace != nil {
					ns = *ref.Namespace
				}
				keys = append(keys, GatewayIndexKey(ns, string(ref.Name)))
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindGRPCRoutesForGateway(context.Background(), gateway)

	assert.Len(t, requests, 1)
	assert.Equal(t, "grpc-route1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

func TestFindGRPCRoutesForBackend(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create GRPCRoutes that reference the backend
	route1 := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Rules: []avapigwv1alpha1.GRPCRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
						{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name:      "test-backend",
								Namespace: stringPtr("default"),
							},
						},
					},
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, "spec.backendRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.GRPCRoute)
			var keys []string
			for _, rule := range route.Spec.Rules {
				for _, ref := range rule.BackendRefs {
					ns := route.Namespace
					if ref.Namespace != nil {
						ns = *ref.Namespace
					}
					keys = append(keys, BackendIndexKey(ns, string(ref.Name)))
				}
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindGRPCRoutesForBackend(context.Background(), backend)

	assert.Len(t, requests, 1)
	assert.Equal(t, "grpc-route1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

func TestFindTCPRoutesForGateway(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create TCPRoutes that reference the gateway
	route1 := &avapigwv1alpha1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tcp-route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.TCPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{
					Name:      "test-gateway",
					Namespace: stringPtr("default"),
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, "spec.gatewayRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.TCPRoute)
			var keys []string
			for _, ref := range route.Spec.ParentRefs {
				ns := route.Namespace
				if ref.Namespace != nil {
					ns = *ref.Namespace
				}
				keys = append(keys, GatewayIndexKey(ns, string(ref.Name)))
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindTCPRoutesForGateway(context.Background(), gateway)

	assert.Len(t, requests, 1)
	assert.Equal(t, "tcp-route1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

func TestFindTCPRoutesForBackend(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create TCPRoutes that reference the backend
	route1 := &avapigwv1alpha1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tcp-route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.TCPRouteSpec{
			Rules: []avapigwv1alpha1.TCPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{
						{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name:      "test-backend",
								Namespace: stringPtr("default"),
							},
						},
					},
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, "spec.backendRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.TCPRoute)
			var keys []string
			for _, rule := range route.Spec.Rules {
				for _, ref := range rule.BackendRefs {
					ns := route.Namespace
					if ref.Namespace != nil {
						ns = *ref.Namespace
					}
					keys = append(keys, BackendIndexKey(ns, string(ref.Name)))
				}
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindTCPRoutesForBackend(context.Background(), backend)

	assert.Len(t, requests, 1)
	assert.Equal(t, "tcp-route1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

func TestFindTLSRoutesForGateway(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create TLSRoutes that reference the gateway
	route1 := &avapigwv1alpha1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.TLSRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{
					Name:      "test-gateway",
					Namespace: stringPtr("default"),
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, "spec.gatewayRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.TLSRoute)
			var keys []string
			for _, ref := range route.Spec.ParentRefs {
				ns := route.Namespace
				if ref.Namespace != nil {
					ns = *ref.Namespace
				}
				keys = append(keys, GatewayIndexKey(ns, string(ref.Name)))
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindTLSRoutesForGateway(context.Background(), gateway)

	assert.Len(t, requests, 1)
	assert.Equal(t, "tls-route1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

func TestFindTLSRoutesForBackend(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create TLSRoutes that reference the backend
	route1 := &avapigwv1alpha1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.TLSRouteSpec{
			Rules: []avapigwv1alpha1.TLSRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TLSBackendRef{
						{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name:      "test-backend",
								Namespace: stringPtr("default"),
							},
						},
					},
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, "spec.backendRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.TLSRoute)
			var keys []string
			for _, rule := range route.Spec.Rules {
				for _, ref := range rule.BackendRefs {
					ns := route.Namespace
					if ref.Namespace != nil {
						ns = *ref.Namespace
					}
					keys = append(keys, BackendIndexKey(ns, string(ref.Name)))
				}
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindTLSRoutesForBackend(context.Background(), backend)

	assert.Len(t, requests, 1)
	assert.Equal(t, "tls-route1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}

// ============================================================================
// Error Path Tests - Test List errors for all Find* methods
// ============================================================================

func TestFindHTTPRoutesForGateway_ListError(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create fake client without the required index - this will cause List to fail
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	// This should return nil because the index doesn't exist
	requests := handler.FindHTTPRoutesForGateway(context.Background(), gateway)

	assert.Nil(t, requests)
}

func TestFindHTTPRoutesForBackend_ListError(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create fake client without the required index - this will cause List to fail
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	// This should return nil because the index doesn't exist
	requests := handler.FindHTTPRoutesForBackend(context.Background(), backend)

	assert.Nil(t, requests)
}

func TestFindGRPCRoutesForGateway_ListError(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create fake client without the required index - this will cause List to fail
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	// This should return nil because the index doesn't exist
	requests := handler.FindGRPCRoutesForGateway(context.Background(), gateway)

	assert.Nil(t, requests)
}

func TestFindGRPCRoutesForBackend_ListError(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create fake client without the required index - this will cause List to fail
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	// This should return nil because the index doesn't exist
	requests := handler.FindGRPCRoutesForBackend(context.Background(), backend)

	assert.Nil(t, requests)
}

func TestFindTCPRoutesForGateway_ListError(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create fake client without the required index - this will cause List to fail
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	// This should return nil because the index doesn't exist
	requests := handler.FindTCPRoutesForGateway(context.Background(), gateway)

	assert.Nil(t, requests)
}

func TestFindTCPRoutesForBackend_ListError(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create fake client without the required index - this will cause List to fail
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	// This should return nil because the index doesn't exist
	requests := handler.FindTCPRoutesForBackend(context.Background(), backend)

	assert.Nil(t, requests)
}

func TestFindTLSRoutesForGateway_ListError(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create fake client without the required index - this will cause List to fail
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	// This should return nil because the index doesn't exist
	requests := handler.FindTLSRoutesForGateway(context.Background(), gateway)

	assert.Nil(t, requests)
}

func TestFindTLSRoutesForBackend_ListError(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create fake client without the required index - this will cause List to fail
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	// This should return nil because the index doesn't exist
	requests := handler.FindTLSRoutesForBackend(context.Background(), backend)

	assert.Nil(t, requests)
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

func TestFindHTTPRoutesForGateway_MultipleRoutes(t *testing.T) {
	scheme := createTestScheme()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	// Create multiple HTTPRoutes that reference the gateway
	route1 := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway"},
			},
		},
	}

	route2 := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route2",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway"},
			},
		},
	}

	route3 := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route3",
			Namespace: "other-namespace",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway", Namespace: stringPtr("default")},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1, route2, route3).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, "spec.gatewayRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.HTTPRoute)
			var keys []string
			for _, ref := range route.Spec.ParentRefs {
				ns := route.Namespace
				if ref.Namespace != nil {
					ns = *ref.Namespace
				}
				keys = append(keys, GatewayIndexKey(ns, string(ref.Name)))
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindHTTPRoutesForGateway(context.Background(), gateway)

	// Should find all 3 routes
	assert.Len(t, requests, 3)
}

func TestFindHTTPRoutesForBackend_MultipleRules(t *testing.T) {
	scheme := createTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	// Create HTTPRoute with multiple rules referencing the same backend
	route1 := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			Rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "test-backend"}},
					},
				},
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "test-backend"}},
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "other-backend"}},
					},
				},
			},
		},
	}

	// Create fake client with index
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route1).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, "spec.backendRef", func(obj client.Object) []string {
			route := obj.(*avapigwv1alpha1.HTTPRoute)
			var keys []string
			for _, rule := range route.Spec.Rules {
				for _, ref := range rule.BackendRefs {
					ns := route.Namespace
					if ref.Namespace != nil {
						ns = *ref.Namespace
					}
					keys = append(keys, BackendIndexKey(ns, string(ref.Name)))
				}
			}
			return keys
		}).
		Build()

	handler := NewWatchHandler(fakeClient, "spec.gatewayRef", "spec.backendRef")

	requests := handler.FindHTTPRoutesForBackend(context.Background(), backend)

	// Should find the route once (even though it references the backend multiple times)
	assert.Len(t, requests, 1)
	assert.Equal(t, "route1", requests[0].Name)
}

package controller

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// Test Helpers
// ============================================================================

func newGRPCRouteReconciler(cl client.Client, scheme *runtime.Scheme) *GRPCRouteReconciler {
	return &GRPCRouteReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
}

// ============================================================================
// GRPCRouteReconciler.Reconcile Tests
// ============================================================================

func TestGRPCRouteReconciler_Reconcile(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name       string
		objects    []client.Object
		request    ctrl.Request
		wantResult ctrl.Result
		wantErr    bool
		validate   func(t *testing.T, cl client.Client)
	}{
		{
			name:    "resource not found returns nil",
			objects: []client.Object{},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent",
					Namespace: "default",
				},
			},
			wantResult: ctrl.Result{},
			wantErr:    false,
		},
		{
			name: "adds finalizer when not present",
			objects: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GRPCRouteSpec{},
				},
			},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-route",
					Namespace: "default",
				},
			},
			wantResult: ctrl.Result{Requeue: true},
			wantErr:    false,
			validate: func(t *testing.T, cl client.Client) {
				route := &avapigwv1alpha1.GRPCRoute{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, route)
				require.NoError(t, err)
				assert.Contains(t, route.Finalizers, grpcRouteFinalizer)
			},
		},
		{
			name: "successful reconciliation with gateway",
			objects: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-route",
						Namespace:  "default",
						Finalizers: []string{grpcRouteFinalizer},
					},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway"},
						},
					},
				},
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
						},
					},
				},
			},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-route",
					Namespace: "default",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				route := &avapigwv1alpha1.GRPCRoute{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, route)
				require.NoError(t, err)
				assert.Len(t, route.Status.Parents, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				WithStatusSubresource(&avapigwv1alpha1.GRPCRoute{}).
				Build()

			r := newGRPCRouteReconciler(cl, scheme)

			result, err := r.Reconcile(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.wantResult.Requeue {
				assert.True(t, result.Requeue)
			}

			if tt.validate != nil {
				tt.validate(t, cl)
			}
		})
	}
}

// ============================================================================
// GRPCRouteReconciler.handleDeletion Tests
// ============================================================================

func TestGRPCRouteReconciler_handleDeletion(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("removes finalizer on deletion", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-route",
				Namespace:  "default",
				Finalizers: []string{grpcRouteFinalizer},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			Build()

		r := newGRPCRouteReconciler(cl, scheme)

		// Re-fetch the route to get the version from the fake client
		fetchedRoute := &avapigwv1alpha1.GRPCRoute{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, fetchedRoute)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedRoute)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify finalizer was removed
		updatedRoute := &avapigwv1alpha1.GRPCRoute{}
		err = cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, updatedRoute)
		require.NoError(t, err)
		assert.NotContains(t, updatedRoute.Finalizers, grpcRouteFinalizer)
	})

	t.Run("no-op when finalizer not present", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-route",
				Namespace:  "default",
				Finalizers: []string{},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			Build()

		r := newGRPCRouteReconciler(cl, scheme)

		// Re-fetch the route
		fetchedRoute := &avapigwv1alpha1.GRPCRoute{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, fetchedRoute)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedRoute)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})
}

// ============================================================================
// GRPCRouteReconciler.validateParentRefs Tests
// ============================================================================

func TestGRPCRouteReconciler_validateParentRefs(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name           string
		objects        []client.Object
		grpcRoute      *avapigwv1alpha1.GRPCRoute
		wantErr        bool
		wantStatuses   int
		validateStatus func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus)
	}{
		{
			name:    "gateway not found",
			objects: []client.Object{},
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "missing-gateway"},
					},
				},
			},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionFalse, statuses[0].Conditions[0].Status)
				assert.Equal(t, string(avapigwv1alpha1.ReasonNoMatchingParent), statuses[0].Conditions[0].Reason)
			},
		},
		{
			name: "gateway found with matching GRPC listener",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
						},
					},
				},
			},
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "test-gateway"},
					},
				},
			},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionTrue, statuses[0].Conditions[0].Status)
				assert.Equal(t, string(avapigwv1alpha1.ReasonAccepted), statuses[0].Conditions[0].Reason)
			},
		},
		{
			name: "gateway found with GRPCS listener",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "grpcs", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPCS},
						},
					},
				},
			},
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "test-gateway"},
					},
				},
			},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionTrue, statuses[0].Conditions[0].Status)
			},
		},
		{
			name: "gateway with non-matching protocol (HTTP)",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						},
					},
				},
			},
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "test-gateway"},
					},
				},
			},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionFalse, statuses[0].Conditions[0].Status)
				assert.Equal(t, string(avapigwv1alpha1.ReasonNotAllowedByListeners), statuses[0].Conditions[0].Reason)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newGRPCRouteReconciler(cl, scheme)

			statuses, err := r.validateParentRefs(context.Background(), tt.grpcRoute)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, statuses, tt.wantStatuses)

			if tt.validateStatus != nil {
				tt.validateStatus(t, statuses)
			}
		})
	}
}

// ============================================================================
// GRPCRouteReconciler.validateListenerMatch Tests
// ============================================================================

func TestGRPCRouteReconciler_validateListenerMatch(t *testing.T) {
	tests := []struct {
		name       string
		grpcRoute  *avapigwv1alpha1.GRPCRoute
		gateway    *avapigwv1alpha1.Gateway
		parentRef  avapigwv1alpha1.ParentRef
		wantAccept bool
		wantMsg    string
	}{
		{
			name: "specific section name - listener found with GRPC protocol",
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.GRPCRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway", SectionName: ptrString("grpc")},
			wantAccept: true,
		},
		{
			name: "specific section name - listener not found",
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.GRPCRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway", SectionName: ptrString("missing")},
			wantAccept: false,
			wantMsg:    "Listener missing not found on Gateway",
		},
		{
			name: "specific section name - wrong protocol (HTTP)",
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.GRPCRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway", SectionName: ptrString("http")},
			wantAccept: false,
			wantMsg:    "Listener http does not support gRPC protocol",
		},
		{
			name: "no section name - finds GRPC listener",
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.GRPCRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway"},
			wantAccept: true,
		},
		{
			name: "no section name - no GRPC/GRPCS listener",
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.GRPCRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway"},
			wantAccept: false,
			wantMsg:    "No matching GRPC/GRPCS listener found on Gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GRPCRouteReconciler{}

			accepted, msg := r.validateListenerMatch(tt.grpcRoute, tt.gateway, tt.parentRef)

			assert.Equal(t, tt.wantAccept, accepted)
			if !tt.wantAccept {
				assert.Equal(t, tt.wantMsg, msg)
			}
		})
	}
}

// ============================================================================
// GRPCRouteReconciler.hostnameMatches Tests
// ============================================================================

func TestGRPCRouteReconciler_hostnameMatches(t *testing.T) {
	tests := []struct {
		name             string
		routeHostnames   []avapigwv1alpha1.Hostname
		listenerHostname *avapigwv1alpha1.Hostname
		wantMatch        bool
	}{
		{
			name:             "nil listener hostname matches all",
			routeHostnames:   []avapigwv1alpha1.Hostname{"example.com"},
			listenerHostname: nil,
			wantMatch:        true,
		},
		{
			name:             "empty route hostnames matches all",
			routeHostnames:   []avapigwv1alpha1.Hostname{},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com")),
			wantMatch:        true,
		},
		{
			name:             "exact match",
			routeHostnames:   []avapigwv1alpha1.Hostname{"example.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com")),
			wantMatch:        true,
		},
		{
			name:             "no match",
			routeHostnames:   []avapigwv1alpha1.Hostname{"example.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("other.com")),
			wantMatch:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GRPCRouteReconciler{}

			result := r.hostnameMatches(tt.routeHostnames, tt.listenerHostname)

			assert.Equal(t, tt.wantMatch, result)
		})
	}
}

// ============================================================================
// GRPCRouteReconciler.hostnameMatch Tests
// ============================================================================

func TestGRPCRouteReconciler_hostnameMatch(t *testing.T) {
	tests := []struct {
		name         string
		routeHost    string
		listenerHost string
		wantMatch    bool
	}{
		{
			name:         "exact match",
			routeHost:    "example.com",
			listenerHost: "example.com",
			wantMatch:    true,
		},
		{
			name:         "no match",
			routeHost:    "example.com",
			listenerHost: "other.com",
			wantMatch:    false,
		},
		{
			name:         "listener wildcard matches route subdomain",
			routeHost:    "api.example.com",
			listenerHost: "*.example.com",
			wantMatch:    true,
		},
		{
			name:         "route wildcard matches listener subdomain",
			routeHost:    "*.example.com",
			listenerHost: "api.example.com",
			wantMatch:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GRPCRouteReconciler{}

			result := r.hostnameMatch(tt.routeHost, tt.listenerHost)

			assert.Equal(t, tt.wantMatch, result)
		})
	}
}

// ============================================================================
// GRPCRouteReconciler.validateBackendRefs Tests
// ============================================================================

func TestGRPCRouteReconciler_validateBackendRefs(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name      string
		objects   []client.Object
		grpcRoute *avapigwv1alpha1.GRPCRoute
		wantErr   bool
	}{
		{
			name: "Service backend found",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
				},
			},
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "test-service"}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "Service backend not found - continues without error",
			objects: []client.Object{},
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "missing-service"}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Backend CRD found",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-backend",
						Namespace: "default",
					},
				},
			},
			grpcRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{
									Name:  "test-backend",
									Kind:  ptrString("Backend"),
									Group: ptrString(avapigwv1alpha1.GroupVersion.Group),
								}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newGRPCRouteReconciler(cl, scheme)

			err := r.validateBackendRefs(context.Background(), tt.grpcRoute)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// GRPCRouteReconciler.findGRPCRoutesForGateway Tests
// ============================================================================

func TestGRPCRouteReconciler_findGRPCRoutesForGateway(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name         string
		objects      []client.Object
		gateway      *avapigwv1alpha1.Gateway
		wantRequests int
	}{
		{
			name: "finds routes referencing gateway",
			objects: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway"},
						},
					},
				},
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway"},
						},
					},
				},
			},
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
			},
			wantRequests: 2,
		},
		{
			name: "returns empty for no matches",
			objects: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "other-gateway"},
						},
					},
				},
			},
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
			},
			wantRequests: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newGRPCRouteReconciler(cl, scheme)

			requests := r.findGRPCRoutesForGateway(context.Background(), tt.gateway)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// GRPCRouteReconciler.findGRPCRoutesForBackend Tests
// ============================================================================

func TestGRPCRouteReconciler_findGRPCRoutesForBackend(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name         string
		objects      []client.Object
		backend      *avapigwv1alpha1.Backend
		wantRequests int
	}{
		{
			name: "finds routes referencing backend",
			objects: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Rules: []avapigwv1alpha1.GRPCRouteRule{
							{
								BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
									{BackendRef: avapigwv1alpha1.BackendRef{
										Name: "test-backend",
										Kind: ptrString("Backend"),
									}},
								},
							},
						},
					},
				},
			},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
			},
			wantRequests: 1,
		},
		{
			name: "returns empty for no matches",
			objects: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Rules: []avapigwv1alpha1.GRPCRouteRule{
							{
								BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
									{BackendRef: avapigwv1alpha1.BackendRef{
										Name: "other-backend",
										Kind: ptrString("Backend"),
									}},
								},
							},
						},
					},
				},
			},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
			},
			wantRequests: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newGRPCRouteReconciler(cl, scheme)

			requests := r.findGRPCRoutesForBackend(context.Background(), tt.backend)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// GRPCRouteReconciler.getRequeueStrategy Tests
// ============================================================================

func TestGRPCRouteReconciler_getRequeueStrategy_Concurrent(t *testing.T) {
	r := &GRPCRouteReconciler{}

	var wg sync.WaitGroup
	const numGoroutines = 100
	strategies := make([]*RequeueStrategy, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			strategies[idx] = r.getRequeueStrategy()
		}(i)
	}

	wg.Wait()

	first := strategies[0]
	require.NotNil(t, first)

	for i, s := range strategies {
		if s != first {
			t.Errorf("goroutine %d got different strategy instance", i)
		}
	}
}

func TestGRPCRouteReconciler_getRequeueStrategy_InitializesDefault(t *testing.T) {
	r := &GRPCRouteReconciler{}

	strategy := r.getRequeueStrategy()

	require.NotNil(t, strategy)
	assert.NotNil(t, strategy.config)
}

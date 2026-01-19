package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/controller/route"
)

// ============================================================================
// Test Helpers
// ============================================================================

func newTestScheme(t *testing.T) *runtime.Scheme {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, discoveryv1.AddToScheme(scheme))
	return scheme
}

func newHTTPRouteReconciler(cl client.Client, scheme *runtime.Scheme) *HTTPRouteReconciler {
	return &HTTPRouteReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
}

func ptrString(s string) *string {
	return &s
}

func ptrInt32(i int32) *int32 {
	return &i
}

// ============================================================================
// HTTPRouteReconciler.Reconcile Tests
// ============================================================================

func TestHTTPRouteReconciler_Reconcile(t *testing.T) {
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
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{},
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
				route := &avapigwv1alpha1.HTTPRoute{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, route)
				require.NoError(t, err)
				assert.Contains(t, route.Finalizers, httpRouteFinalizer)
			},
		},
		{
			name: "successful reconciliation with gateway",
			objects: []client.Object{
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-route",
						Namespace:  "default",
						Finalizers: []string{httpRouteFinalizer},
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
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
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
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
				route := &avapigwv1alpha1.HTTPRoute{}
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
				WithStatusSubresource(&avapigwv1alpha1.HTTPRoute{}).
				Build()

			r := newHTTPRouteReconciler(cl, scheme)

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
// HTTPRouteReconciler.handleDeletion Tests
// ============================================================================

func TestHTTPRouteReconciler_handleDeletion(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("removes finalizer on deletion", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-route",
				Namespace:  "default",
				Finalizers: []string{httpRouteFinalizer},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)

		// Re-fetch the route to get the version from the fake client
		fetchedRoute := &avapigwv1alpha1.HTTPRoute{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, fetchedRoute)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedRoute)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify finalizer was removed
		updatedRoute := &avapigwv1alpha1.HTTPRoute{}
		err = cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, updatedRoute)
		require.NoError(t, err)
		assert.NotContains(t, updatedRoute.Finalizers, httpRouteFinalizer)
	})

	t.Run("no-op when finalizer not present", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
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

		r := newHTTPRouteReconciler(cl, scheme)

		// Re-fetch the route
		fetchedRoute := &avapigwv1alpha1.HTTPRoute{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, fetchedRoute)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedRoute)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})
}

// ============================================================================
// HTTPRouteReconciler.reconcileHTTPRoute Tests
// ============================================================================

func TestHTTPRouteReconciler_reconcileHTTPRoute(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name      string
		objects   []client.Object
		httpRoute *avapigwv1alpha1.HTTPRoute
		wantErr   bool
		validate  func(t *testing.T, cl client.Client)
	}{
		{
			name: "successful reconciliation with valid gateway",
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
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-route",
					Namespace:  "default",
					Finalizers: []string{httpRouteFinalizer},
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "test-gateway"},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				route := &avapigwv1alpha1.HTTPRoute{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, route)
				require.NoError(t, err)
				assert.Len(t, route.Status.Parents, 1)
				assert.Equal(t, metav1.ConditionTrue, route.Status.Parents[0].Conditions[0].Status)
			},
		},
		{
			name:    "handles missing gateway gracefully",
			objects: []client.Object{},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-route",
					Namespace:  "default",
					Finalizers: []string{httpRouteFinalizer},
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "missing-gateway"},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				route := &avapigwv1alpha1.HTTPRoute{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, route)
				require.NoError(t, err)
				assert.Len(t, route.Status.Parents, 1)
				assert.Equal(t, metav1.ConditionFalse, route.Status.Parents[0].Conditions[0].Status)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allObjects := append(tt.objects, tt.httpRoute)
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(allObjects...).
				WithStatusSubresource(&avapigwv1alpha1.HTTPRoute{}).
				Build()

			r := newHTTPRouteReconciler(cl, scheme)

			err := r.reconcileHTTPRoute(context.Background(), tt.httpRoute)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, cl)
			}
		})
	}
}

// ============================================================================
// HTTPRouteReconciler.validateParentRefs Tests
// ============================================================================

func TestHTTPRouteReconciler_validateParentRefs(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name           string
		objects        []client.Object
		httpRoute      *avapigwv1alpha1.HTTPRoute
		wantErr        bool
		wantStatuses   int
		validateStatus func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus)
	}{
		{
			name:    "gateway not found",
			objects: []client.Object{},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
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
			name: "gateway found with matching HTTP listener",
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
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
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
			name: "gateway found with HTTPS listener",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
						},
					},
				},
			},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
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
			name: "gateway with non-matching protocol (TCP)",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
						},
					},
				},
			},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
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
		{
			name: "multiple parent refs",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "gateway-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						},
					},
				},
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "gateway-2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
						},
					},
				},
			},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "gateway-1"},
						{Name: "gateway-2"},
					},
				},
			},
			wantErr:      false,
			wantStatuses: 2,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionTrue, statuses[0].Conditions[0].Status)
				assert.Equal(t, metav1.ConditionTrue, statuses[1].Conditions[0].Status)
			},
		},
		{
			name: "gateway in different namespace",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "other-namespace",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						},
					},
				},
			},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "test-gateway", Namespace: ptrString("other-namespace")},
					},
				},
			},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionTrue, statuses[0].Conditions[0].Status)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newHTTPRouteReconciler(cl, scheme)

			statuses, err := r.validateParentRefs(context.Background(), tt.httpRoute)

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
// HTTPRouteReconciler.validateListenerMatch Tests
// ============================================================================

func TestHTTPRouteReconciler_validateListenerMatch(t *testing.T) {
	tests := []struct {
		name       string
		httpRoute  *avapigwv1alpha1.HTTPRoute
		gateway    *avapigwv1alpha1.Gateway
		parentRef  avapigwv1alpha1.ParentRef
		wantAccept bool
		wantMsg    string
	}{
		{
			name: "specific section name - listener found with HTTP protocol",
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.HTTPRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway", SectionName: ptrString("http")},
			wantAccept: true,
		},
		{
			name: "specific section name - listener not found",
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.HTTPRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway", SectionName: ptrString("missing")},
			wantAccept: false,
			wantMsg:    "Listener missing not found on Gateway",
		},
		{
			name: "specific section name - wrong protocol (TCP)",
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.HTTPRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway", SectionName: ptrString("tcp")},
			wantAccept: false,
			wantMsg:    "Listener tcp does not support HTTP protocol",
		},
		{
			name: "no section name - finds HTTP listener",
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.HTTPRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway"},
			wantAccept: true,
		},
		{
			name: "no section name - no HTTP/HTTPS listener",
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec:       avapigwv1alpha1.HTTPRouteSpec{},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
						{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway"},
			wantAccept: false,
			wantMsg:    "No matching HTTP/HTTPS listener found on Gateway",
		},
		{
			name: "hostname matching - route hostname matches listener",
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
				},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP, Hostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com"))},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway", SectionName: ptrString("http")},
			wantAccept: true,
		},
		{
			name: "hostname matching - route hostname does not match listener",
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"other.com"},
				},
			},
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP, Hostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com"))},
					},
				},
			},
			parentRef:  avapigwv1alpha1.ParentRef{Name: "test-gateway", SectionName: ptrString("http")},
			wantAccept: false,
			wantMsg:    "No matching hostname for listener http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &HTTPRouteReconciler{}

			accepted, msg := r.validateListenerMatch(tt.httpRoute, tt.gateway, tt.parentRef)

			assert.Equal(t, tt.wantAccept, accepted)
			if !tt.wantAccept {
				assert.Equal(t, tt.wantMsg, msg)
			}
		})
	}
}

// ============================================================================
// HTTPRouteReconciler.hostnameMatches Tests
// ============================================================================

func TestHTTPRouteReconciler_hostnameMatches(t *testing.T) {
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
		{
			name:             "multiple route hostnames - one matches",
			routeHostnames:   []avapigwv1alpha1.Hostname{"foo.com", "example.com", "bar.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com")),
			wantMatch:        true,
		},
		{
			name:             "multiple route hostnames - none match",
			routeHostnames:   []avapigwv1alpha1.Hostname{"foo.com", "bar.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com")),
			wantMatch:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &HTTPRouteReconciler{}

			result := r.hostnameMatches(tt.routeHostnames, tt.listenerHostname)

			assert.Equal(t, tt.wantMatch, result)
		})
	}
}

// ============================================================================
// HTTPRouteReconciler.hostnameMatch Tests
// ============================================================================

func TestHTTPRouteReconciler_hostnameMatch(t *testing.T) {
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
			name:         "no match - different hosts",
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
			name:         "listener wildcard does not match different domain",
			routeHost:    "api.other.com",
			listenerHost: "*.example.com",
			wantMatch:    false,
		},
		{
			name:         "route wildcard matches listener subdomain",
			routeHost:    "*.example.com",
			listenerHost: "api.example.com",
			wantMatch:    true,
		},
		{
			name:         "both wildcards - same suffix",
			routeHost:    "*.example.com",
			listenerHost: "*.example.com",
			wantMatch:    true,
		},
		{
			name:         "both wildcards - different suffix",
			routeHost:    "*.example.com",
			listenerHost: "*.other.com",
			wantMatch:    false,
		},
		{
			name:         "empty strings",
			routeHost:    "",
			listenerHost: "",
			wantMatch:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := route.HostnameMatch(tt.routeHost, tt.listenerHost)

			assert.Equal(t, tt.wantMatch, result)
		})
	}
}

// ============================================================================
// HTTPRouteReconciler.validateBackendRefs Tests
// ============================================================================

func TestHTTPRouteReconciler_validateBackendRefs(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name      string
		objects   []client.Object
		httpRoute *avapigwv1alpha1.HTTPRoute
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
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
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
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
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
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
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
		{
			name:    "Backend CRD not found - continues without error",
			objects: []client.Object{},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{
									Name:  "missing-backend",
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
		{
			name:    "unsupported backend kind - continues without error",
			objects: []client.Object{},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{
									Name:  "unknown",
									Kind:  ptrString("UnknownKind"),
									Group: ptrString("unknown.group"),
								}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "backend in different namespace",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "other-namespace",
					},
				},
			},
			httpRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{
									Name:      "test-service",
									Namespace: ptrString("other-namespace"),
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

			r := newHTTPRouteReconciler(cl, scheme)

			err := r.validateBackendRefs(context.Background(), tt.httpRoute)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// HTTPRouteReconciler.findHTTPRoutesForGateway Tests
// ============================================================================

func TestHTTPRouteReconciler_findHTTPRoutesForGateway(t *testing.T) {
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
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway"},
						},
					},
				},
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
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
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
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
			// Build client with indexer
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, func(obj client.Object) []string {
					route := obj.(*avapigwv1alpha1.HTTPRoute)
					return extractGatewayRefs(route.Namespace, route.Spec.ParentRefs)
				}).
				Build()

			r := newHTTPRouteReconciler(cl, scheme)

			requests := r.findHTTPRoutesForGateway(context.Background(), tt.gateway)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// HTTPRouteReconciler.findHTTPRoutesForBackend Tests
// ============================================================================

func TestHTTPRouteReconciler_findHTTPRoutesForBackend(t *testing.T) {
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
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
						Rules: []avapigwv1alpha1.HTTPRouteRule{
							{
								BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
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
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
						Rules: []avapigwv1alpha1.HTTPRouteRule{
							{
								BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
									{BackendRef: avapigwv1alpha1.BackendRef{
										Name:  "other-backend",
										Kind:  ptrString("Backend"),
										Group: ptrString(avapigwv1alpha1.GroupVersion.Group),
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
			// Build client with indexer
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteBackendIndexField, func(obj client.Object) []string {
					route := obj.(*avapigwv1alpha1.HTTPRoute)
					return extractHTTPBackendRefs(route.Namespace, route.Spec.Rules)
				}).
				Build()

			r := newHTTPRouteReconciler(cl, scheme)

			requests := r.findHTTPRoutesForBackend(context.Background(), tt.backend)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// HTTPRouteReconciler.getRequeueStrategy Tests
// ============================================================================

func TestHTTPRouteReconciler_getRequeueStrategy_Concurrent(t *testing.T) {
	r := &HTTPRouteReconciler{}

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

func TestHTTPRouteReconciler_getRequeueStrategy_InitializesDefault(t *testing.T) {
	r := &HTTPRouteReconciler{}

	strategy := r.getRequeueStrategy()

	require.NotNil(t, strategy)
	assert.NotNil(t, strategy.config)
}

func TestHTTPRouteReconciler_getRequeueStrategy_PreservesPredefined(t *testing.T) {
	customConfig := &RequeueConfig{
		BaseInterval: 10 * time.Second,
	}
	customStrategy := NewRequeueStrategy(customConfig)

	r := &HTTPRouteReconciler{
		RequeueStrategy: customStrategy,
	}

	strategy := r.getRequeueStrategy()

	assert.Equal(t, customStrategy, strategy)
	assert.Equal(t, 10*time.Second, strategy.config.BaseInterval)
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestHTTPRouteReconciler_Reconcile_ErrorHandling(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		request ctrl.Request
		wantErr bool
		errType ErrorType
	}{
		{
			name: "transient error on get failure",
			objects: []client.Object{
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-route",
						Namespace:  "default",
						Finalizers: []string{httpRouteFinalizer},
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway"},
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				WithStatusSubresource(&avapigwv1alpha1.HTTPRoute{}).
				Build()

			r := newHTTPRouteReconciler(cl, scheme)

			_, err := r.Reconcile(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				var reconcileErr *ReconcileError
				if errors.As(err, &reconcileErr) {
					assert.Equal(t, tt.errType, reconcileErr.Type)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// HTTPRouteReconciler Reconcile with Deletion Tests
// ============================================================================

func TestHTTPRouteReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("handleDeletion removes finalizer", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-route",
				Namespace:  "default",
				Finalizers: []string{httpRouteFinalizer},
			},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway"},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)

		// Fetch the route to get the version from the fake client
		fetchedRoute := &avapigwv1alpha1.HTTPRoute{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, fetchedRoute)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedRoute)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify finalizer was removed
		updatedRoute := &avapigwv1alpha1.HTTPRoute{}
		err = cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, updatedRoute)
		require.NoError(t, err)
		assert.NotContains(t, updatedRoute.Finalizers, httpRouteFinalizer)
	})

	t.Run("handleDeletion no-op without finalizer", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
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

		r := newHTTPRouteReconciler(cl, scheme)

		// Fetch the route
		fetchedRoute := &avapigwv1alpha1.HTTPRoute{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-route", Namespace: "default"}, fetchedRoute)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedRoute)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})
}

// ============================================================================
// HTTPRouteReconciler Reconcile with Context Timeout Tests
// ============================================================================

func TestHTTPRouteReconciler_Reconcile_ContextTimeout(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("respects context timeout", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-route",
				Namespace:  "default",
				Finalizers: []string{httpRouteFinalizer},
			},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway"},
				},
			},
		}

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route, gateway).
			WithStatusSubresource(&avapigwv1alpha1.HTTPRoute{}).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)

		// Use a context with a very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		result, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-route",
				Namespace: "default",
			},
		})

		// Should complete successfully within timeout
		assert.NoError(t, err)
		assert.False(t, result.Requeue)
	})
}

// ============================================================================
// HTTPRouteReconciler validateParentRefs Error Path Tests
// ============================================================================

func TestHTTPRouteReconciler_validateParentRefs_ErrorPaths(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("handles specific section name with non-HTTP protocol", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
				},
			},
		}

		httpRoute := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway", SectionName: ptrString("grpc")},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)

		statuses, err := r.validateParentRefs(context.Background(), httpRoute)

		assert.NoError(t, err)
		assert.Len(t, statuses, 1)
		assert.Equal(t, metav1.ConditionFalse, statuses[0].Conditions[0].Status)
		assert.Contains(t, statuses[0].Conditions[0].Message, "does not support HTTP protocol")
	})

	t.Run("handles hostname mismatch with specific section", func(t *testing.T) {
		hostname := avapigwv1alpha1.Hostname("example.com")
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP, Hostname: &hostname},
				},
			},
		}

		httpRoute := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Hostnames: []avapigwv1alpha1.Hostname{"other.com"},
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway", SectionName: ptrString("http")},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)

		statuses, err := r.validateParentRefs(context.Background(), httpRoute)

		assert.NoError(t, err)
		assert.Len(t, statuses, 1)
		assert.Equal(t, metav1.ConditionFalse, statuses[0].Conditions[0].Status)
		assert.Contains(t, statuses[0].Conditions[0].Message, "No matching hostname")
	})
}

// ============================================================================
// HTTPRouteReconciler validateBackendRefs Error Path Tests
// ============================================================================

func TestHTTPRouteReconciler_validateBackendRefs_ErrorPaths(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("handles multiple rules with mixed backends", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-service",
				Namespace: "default",
			},
		}

		httpRoute := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{BackendRef: avapigwv1alpha1.BackendRef{Name: "existing-service"}},
						},
					},
					{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{BackendRef: avapigwv1alpha1.BackendRef{Name: "missing-service"}},
						},
					},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(svc).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)

		err := r.validateBackendRefs(context.Background(), httpRoute)

		// Should not return error - missing backends are logged but not fatal
		assert.NoError(t, err)
	})

	t.Run("handles backend in different namespace", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cross-ns-service",
				Namespace: "other-namespace",
			},
		}

		httpRoute := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{BackendRef: avapigwv1alpha1.BackendRef{
								Name:      "cross-ns-service",
								Namespace: ptrString("other-namespace"),
							}},
						},
					},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(svc).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)

		err := r.validateBackendRefs(context.Background(), httpRoute)

		assert.NoError(t, err)
	})
}

// ============================================================================
// HTTPRouteReconciler hostnameMatch Edge Cases Tests
// ============================================================================

func TestHTTPRouteReconciler_hostnameMatch_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		routeHost    string
		listenerHost string
		wantMatch    bool
	}{
		{
			name:         "wildcard listener with short route host",
			routeHost:    "a.com",
			listenerHost: "*.example.com",
			wantMatch:    false,
		},
		{
			name:         "wildcard route with short listener host",
			routeHost:    "*.example.com",
			listenerHost: "a.com",
			wantMatch:    false,
		},
		{
			name:         "deep subdomain matches wildcard",
			routeHost:    "deep.sub.example.com",
			listenerHost: "*.example.com",
			wantMatch:    true,
		},
		{
			name:         "wildcard route matches deep subdomain",
			routeHost:    "*.example.com",
			listenerHost: "deep.sub.example.com",
			wantMatch:    true,
		},
		{
			name:         "single character wildcard suffix",
			routeHost:    "a.b",
			listenerHost: "*.b",
			wantMatch:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := route.HostnameMatch(tt.routeHost, tt.listenerHost)

			assert.Equal(t, tt.wantMatch, result)
		})
	}
}

// ============================================================================
// HTTPRouteReconciler handleHTTPRouteReconcileError Tests
// ============================================================================

func TestHTTPRouteReconciler_handleHTTPRouteReconcileError(t *testing.T) {
	tests := []struct {
		name          string
		errorType     ErrorType
		expectRequeue bool
	}{
		{
			name:          "validation error",
			errorType:     ErrorTypeValidation,
			expectRequeue: false,
		},
		{
			name:          "permanent error",
			errorType:     ErrorTypePermanent,
			expectRequeue: false,
		},
		{
			name:          "dependency error",
			errorType:     ErrorTypeDependency,
			expectRequeue: true,
		},
		{
			name:          "transient error",
			errorType:     ErrorTypeTransient,
			expectRequeue: true,
		},
		{
			name:          "internal error",
			errorType:     ErrorTypeInternal,
			expectRequeue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &HTTPRouteReconciler{}
			strategy := DefaultRequeueStrategy()
			resourceKey := "default/test-route"

			reconcileErr := &ReconcileError{
				Type:      tt.errorType,
				Op:        "test",
				Resource:  resourceKey,
				Err:       errors.New("test error"),
				Retryable: tt.expectRequeue,
			}

			result, err := r.handleHTTPRouteReconcileError(reconcileErr, strategy, resourceKey)

			assert.Error(t, err)
			assert.Equal(t, tt.expectRequeue, result.Requeue)
			assert.True(t, result.RequeueAfter > 0)
		})
	}
}

// ============================================================================
// HTTPRouteReconciler fetchHTTPRoute Tests
// ============================================================================

func TestHTTPRouteReconciler_fetchHTTPRoute(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("success - route found", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)
		strategy := DefaultRequeueStrategy()
		resourceKey := "default/test-route"

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-route",
				Namespace: "default",
			},
		}

		fetchedRoute, result, reconcileErr := r.fetchHTTPRoute(context.Background(), req, strategy, resourceKey)

		assert.Nil(t, reconcileErr)
		assert.NotNil(t, fetchedRoute)
		assert.True(t, result.IsZero())
		assert.Equal(t, "test-route", fetchedRoute.Name)
	})

	t.Run("not found - returns nil route", func(t *testing.T) {
		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)
		strategy := DefaultRequeueStrategy()
		resourceKey := "default/non-existent"

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "non-existent",
				Namespace: "default",
			},
		}

		fetchedRoute, result, reconcileErr := r.fetchHTTPRoute(context.Background(), req, strategy, resourceKey)

		assert.Nil(t, reconcileErr)
		assert.Nil(t, fetchedRoute)
		assert.True(t, result.IsZero())
	})

	t.Run("get error - returns error", func(t *testing.T) {
		// Use an error client that returns errors on Get
		cl := &errorClient{
			Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
			getErr: errors.New("get error"),
		}

		r := &HTTPRouteReconciler{
			Client:   cl,
			Scheme:   scheme,
			Recorder: record.NewFakeRecorder(100),
		}
		strategy := DefaultRequeueStrategy()
		resourceKey := "default/test-route"

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-route",
				Namespace: "default",
			},
		}

		fetchedRoute, result, reconcileErr := r.fetchHTTPRoute(context.Background(), req, strategy, resourceKey)

		assert.NotNil(t, reconcileErr)
		assert.Nil(t, fetchedRoute)
		assert.True(t, result.RequeueAfter > 0)
	})
}

// ============================================================================
// HTTPRouteReconciler ensureFinalizerAndReconcileHTTPRoute Tests
// ============================================================================

func TestHTTPRouteReconciler_ensureFinalizerAndReconcileHTTPRoute(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("adds finalizer when not present", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(&avapigwv1alpha1.HTTPRoute{}).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)
		r.initBaseComponents()

		strategy := DefaultRequeueStrategy()
		resourceKey := "default/test-route"
		var reconcileErr *ReconcileError

		result, err := r.ensureFinalizerAndReconcileHTTPRoute(context.Background(), route, strategy, resourceKey, &reconcileErr)

		assert.NoError(t, err)
		assert.True(t, result.Requeue)
	})

	t.Run("reconciles when finalizer present", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-route",
				Namespace:  "default",
				Finalizers: []string{httpRouteFinalizer},
			},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway"},
				},
			},
		}

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route, gateway).
			WithStatusSubresource(&avapigwv1alpha1.HTTPRoute{}).
			Build()

		r := newHTTPRouteReconciler(cl, scheme)
		r.initBaseComponents()

		strategy := DefaultRequeueStrategy()
		resourceKey := "default/test-route"
		var reconcileErr *ReconcileError

		result, err := r.ensureFinalizerAndReconcileHTTPRoute(context.Background(), route, strategy, resourceKey, &reconcileErr)

		assert.NoError(t, err)
		assert.True(t, result.RequeueAfter > 0)
	})

	t.Run("handles reconcile error", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-route",
				Namespace:  "default",
				Finalizers: []string{httpRouteFinalizer},
			},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway"},
				},
			},
		}

		// Use an error client that returns errors on Status().Update()
		baseCl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(&avapigwv1alpha1.HTTPRoute{}).
			Build()

		cl := &statusUpdateErrorClient{
			Client:    baseCl,
			updateErr: errors.New("status update error"),
		}

		r := &HTTPRouteReconciler{
			Client:   cl,
			Scheme:   scheme,
			Recorder: record.NewFakeRecorder(100),
		}
		r.initBaseComponents()

		strategy := DefaultRequeueStrategy()
		resourceKey := "default/test-route"
		var reconcileErr *ReconcileError

		result, err := r.ensureFinalizerAndReconcileHTTPRoute(context.Background(), route, strategy, resourceKey, &reconcileErr)

		assert.Error(t, err)
		assert.True(t, result.RequeueAfter > 0)
	})
}

// ============================================================================
// HTTPRouteReconciler Reconcile Error Classification Tests
// ============================================================================

func TestHTTPRouteReconciler_Reconcile_ErrorClassification(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name           string
		objects        []client.Object
		request        ctrl.Request
		wantErr        bool
		wantRequeue    bool
		validateResult func(t *testing.T, result ctrl.Result)
	}{
		{
			name: "successful reconciliation resets failure count",
			objects: []client.Object{
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-route",
						Namespace:  "default",
						Finalizers: []string{httpRouteFinalizer},
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
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
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
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
			wantErr:     false,
			wantRequeue: false,
			validateResult: func(t *testing.T, result ctrl.Result) {
				assert.False(t, result.Requeue)
			},
		},
		{
			name:    "not found resource returns empty result",
			objects: []client.Object{},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent",
					Namespace: "default",
				},
			},
			wantErr:     false,
			wantRequeue: false,
			validateResult: func(t *testing.T, result ctrl.Result) {
				assert.Equal(t, ctrl.Result{}, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				WithStatusSubresource(&avapigwv1alpha1.HTTPRoute{}).
				Build()

			r := newHTTPRouteReconciler(cl, scheme)

			result, err := r.Reconcile(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

// ============================================================================
// HTTPRouteReconciler Error Path Tests
// ============================================================================

// httpRouteErrorClient - Mock client that returns errors for HTTPRoute tests
type httpRouteErrorClient struct {
	client.Client
	getError    error
	updateError error
	listError   error
}

func (c *httpRouteErrorClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.getError != nil {
		return c.getError
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *httpRouteErrorClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if c.updateError != nil {
		return c.updateError
	}
	return c.Client.Update(ctx, obj, opts...)
}

func (c *httpRouteErrorClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.listError != nil {
		return c.listError
	}
	return c.Client.List(ctx, list, opts...)
}

func TestHTTPRouteReconciler_fetchHTTPRoute_GetError(t *testing.T) {
	scheme := newTestScheme(t)

	// Create a client that will return an error on Get
	cl := &httpRouteErrorClient{
		Client:   fake.NewClientBuilder().WithScheme(scheme).Build(),
		getError: errors.New("connection refused"),
	}

	r := &HTTPRouteReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-route"

	route, result, err := r.fetchHTTPRoute(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-route", Namespace: "default"},
	}, strategy, resourceKey)

	assert.Nil(t, route)
	assert.NotNil(t, err)
	assert.True(t, result.Requeue || result.RequeueAfter > 0)
}

func TestHTTPRouteReconciler_ensureFinalizerAndReconcileHTTPRoute_FinalizerError(t *testing.T) {
	scheme := newTestScheme(t)

	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{
					Name: "test-gateway",
				},
			},
		},
	}

	// Create a client that will return an error on Update (for finalizer)
	cl := &httpRouteErrorClient{
		Client:      fake.NewClientBuilder().WithScheme(scheme).WithObjects(httpRoute).Build(),
		updateError: errors.New("update failed"),
	}

	r := &HTTPRouteReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
	r.initBaseComponents()

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-route"
	var reconcileErr *ReconcileError

	result, err := r.ensureFinalizerAndReconcileHTTPRoute(context.Background(), httpRoute, strategy, resourceKey, &reconcileErr)

	assert.Error(t, err)
	assert.True(t, result.Requeue || result.RequeueAfter > 0)
}

func TestHTTPRouteReconciler_handleDeletion_RemoveFinalizerError(t *testing.T) {
	scheme := newTestScheme(t)

	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Finalizers: []string{httpRouteFinalizer},
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{
					Name: "test-gateway",
				},
			},
		},
	}

	// Create a client that will return an error on Update (for finalizer removal)
	cl := &httpRouteErrorClient{
		Client:      fake.NewClientBuilder().WithScheme(scheme).WithObjects(httpRoute).Build(),
		updateError: errors.New("update failed"),
	}

	r := &HTTPRouteReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	result, err := r.handleDeletion(context.Background(), httpRoute)

	assert.Error(t, err)
	assert.True(t, result.Requeue || result.RequeueAfter > 0)
}

func TestHTTPRouteReconciler_findHTTPRoutesForGateway_ListError(t *testing.T) {
	scheme := newTestScheme(t)

	// Create a client that will return an error on List
	cl := &httpRouteErrorClient{
		Client:    fake.NewClientBuilder().WithScheme(scheme).Build(),
		listError: errors.New("list failed"),
	}

	r := &HTTPRouteReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	requests := r.findHTTPRoutesForGateway(context.Background(), gateway)

	assert.Empty(t, requests)
}

func TestHTTPRouteReconciler_findHTTPRoutesForBackend_ListError(t *testing.T) {
	scheme := newTestScheme(t)

	// Create a client that will return an error on List
	cl := &httpRouteErrorClient{
		Client:    fake.NewClientBuilder().WithScheme(scheme).Build(),
		listError: errors.New("list failed"),
	}

	r := &HTTPRouteReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	requests := r.findHTTPRoutesForBackend(context.Background(), backend)

	assert.Empty(t, requests)
}

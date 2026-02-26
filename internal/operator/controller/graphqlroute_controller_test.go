// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// Helper Functions for GraphQLRoute Tests
// ============================================================================

// newGraphQLRouteReconciler creates a GraphQLRouteReconciler with all required fields initialized.
func newGraphQLRouteReconciler(t *testing.T, fakeClient client.Client, recorder *fakeRecorder) *GraphQLRouteReconciler {
	scheme := newTestScheme()
	return &GraphQLRouteReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newGraphQLRouteReconcilerWithNilServer creates a GraphQLRouteReconciler with nil GRPCServer.
func newGraphQLRouteReconcilerWithNilServer(fakeClient client.Client, recorder *fakeRecorder) *GraphQLRouteReconciler {
	scheme := newTestScheme()
	return &GraphQLRouteReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    nil,
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// Ensure interface is satisfied.
var _ reconcile.Reconciler = &GraphQLRouteReconciler{}

// ============================================================================
// GraphQLRoute Controller - Reconcile Tests
// ============================================================================

func TestGraphQLRouteReconciler_Reconcile_NotFound(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "non-existent",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue for not found")
	}
}

func TestGraphQLRouteReconciler_Reconcile_AddFinalizer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact: "/graphql",
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue after adding finalizer (Patch triggers watch event)")
	}

	// Verify finalizer was added
	var updated avapigwv1alpha1.GraphQLRoute
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLRoute: %v", err)
	}

	hasFinalizer := false
	for _, f := range updated.Finalizers {
		if f == GraphQLRouteFinalizerName {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		t.Error("Reconcile() should add finalizer")
	}
}

func TestGraphQLRouteReconciler_Reconcile_Success(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact: "/graphql",
					},
					OperationType: "query",
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

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue on success")
	}

	events := recorder.getEvents()
	if len(events) == 0 {
		t.Error("Reconcile() should record an event")
	}
}

func TestGraphQLRouteReconciler_Reconcile_Deletion(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	now := metav1.Now()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-graphql-route",
			Namespace:         "default",
			Finalizers:        []string{GraphQLRouteFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact: "/graphql",
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue after deletion")
	}

	// Verify the object was deleted (finalizer removed allows deletion to complete)
	var updated avapigwv1alpha1.GraphQLRoute
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err == nil {
		for _, f := range updated.Finalizers {
			if f == GraphQLRouteFinalizerName {
				t.Error("Reconcile() should remove finalizer on deletion")
			}
		}
	}
	// If err is NotFound, that's expected - the object was deleted
}

func TestGraphQLRouteReconciler_Reconcile_NilGRPCServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact: "/graphql",
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconcilerWithNilServer(fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue with nil gRPC server")
	}
}

func TestGraphQLRouteReconciler_Deletion_NilGRPCServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	now := metav1.Now()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-graphql-route",
			Namespace:         "default",
			Finalizers:        []string{GraphQLRouteFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconcilerWithNilServer(fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue after deletion with nil gRPC server")
	}
}

// ============================================================================
// GraphQLRoute Controller - Table-Driven Reconcile Tests
// ============================================================================

func TestGraphQLRouteReconciler_Reconcile_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		graphqlRoute     *avapigwv1alpha1.GraphQLRoute
		wantRequeue      bool
		wantRequeueAfter time.Duration
		wantErr          bool
	}{
		{
			name: "route with timeout",
			graphqlRoute: &avapigwv1alpha1.GraphQLRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-route-timeout",
					Namespace:  "default",
					Finalizers: []string{GraphQLRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
					},
					Timeout: "30s",
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "route with retries",
			graphqlRoute: &avapigwv1alpha1.GraphQLRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-route-retries",
					Namespace:  "default",
					Finalizers: []string{GraphQLRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
					},
					Retries: &avapigwv1alpha1.RetryPolicy{
						Attempts:      3,
						PerTryTimeout: "5s",
						RetryOn:       "5xx,reset",
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "route with rate limit",
			graphqlRoute: &avapigwv1alpha1.GraphQLRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-route-ratelimit",
					Namespace:  "default",
					Finalizers: []string{GraphQLRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
					},
					RateLimit: &avapigwv1alpha1.RateLimitConfig{
						Enabled:           true,
						RequestsPerSecond: 100,
						Burst:             10,
						PerClient:         true,
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "route with CORS",
			graphqlRoute: &avapigwv1alpha1.GraphQLRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-route-cors",
					Namespace:  "default",
					Finalizers: []string{GraphQLRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
					},
					CORS: &avapigwv1alpha1.CORSConfig{
						AllowOrigins:     []string{"https://example.com"},
						AllowMethods:     []string{"GET", "POST"},
						AllowHeaders:     []string{"Content-Type"},
						AllowCredentials: true,
						MaxAge:           3600,
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "route with cache",
			graphqlRoute: &avapigwv1alpha1.GraphQLRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-route-cache",
					Namespace:  "default",
					Finalizers: []string{GraphQLRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
					},
					Cache: &avapigwv1alpha1.CacheConfig{
						Enabled:       true,
						TTL:           "5m",
						KeyComponents: []string{"uri", "headers.accept"},
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "route with depth limit",
			graphqlRoute: &avapigwv1alpha1.GraphQLRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-route-depth",
					Namespace:  "default",
					Finalizers: []string{GraphQLRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
					},
					DepthLimit:      10,
					ComplexityLimit: 100,
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "route with allowed operations",
			graphqlRoute: &avapigwv1alpha1.GraphQLRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-route-ops",
					Namespace:  "default",
					Finalizers: []string{GraphQLRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLRouteSpec{
					Match: []avapigwv1alpha1.GraphQLRouteMatch{
						{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
					},
					AllowedOperations: []string{"query", "mutation"},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			scheme := newTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.graphqlRoute).
				WithStatusSubresource(tt.graphqlRoute).
				Build()
			reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.graphqlRoute.Name,
					Namespace: tt.graphqlRoute.Namespace,
				},
			}

			// Act
			result, err := reconciler.Reconcile(context.Background(), req)

			// Assert
			if (err != nil) != tt.wantErr {
				t.Errorf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if result.Requeue != tt.wantRequeue {
				t.Errorf("Reconcile() Requeue = %v, want %v", result.Requeue, tt.wantRequeue)
			}
			if result.RequeueAfter != tt.wantRequeueAfter {
				t.Errorf("Reconcile() RequeueAfter = %v, want %v", result.RequeueAfter, tt.wantRequeueAfter)
			}
		})
	}
}

// ============================================================================
// GraphQLRoute Controller - reconcileGraphQLRoute Tests
// ============================================================================

func TestGraphQLRouteReconciler_reconcileGraphQLRoute_Success(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact: "/graphql",
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
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, recorder)

	// Act
	err := reconciler.reconcileGraphQLRoute(context.Background(), graphqlRoute)

	// Assert
	if err != nil {
		t.Errorf("reconcileGraphQLRoute() error = %v, want nil", err)
	}
}

func TestGraphQLRouteReconciler_reconcileGraphQLRoute_NilGRPCServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact: "/graphql",
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconcilerWithNilServer(fakeClient, recorder)

	// Act
	err := reconciler.reconcileGraphQLRoute(context.Background(), graphqlRoute)

	// Assert
	if err != nil {
		t.Errorf("reconcileGraphQLRoute() with nil server error = %v, want nil", err)
	}
}

func TestGraphQLRouteReconciler_reconcileGraphQLRoute_MarshalSpec(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	introspectionEnabled := true
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{
						Exact: "/graphql",
					},
					OperationType: "query",
					OperationName: &avapigwv1alpha1.StringMatch{
						Exact: "GetUser",
					},
					Headers: []avapigwv1alpha1.GraphQLHeaderMatch{
						{
							Name:  "X-Custom-Header",
							Exact: "value",
						},
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
			DepthLimit:           10,
			ComplexityLimit:      100,
			IntrospectionEnabled: &introspectionEnabled,
			AllowedOperations:    []string{"query", "mutation"},
		},
	}

	// Verify spec can be marshaled to JSON
	configJSON, err := json.Marshal(graphqlRoute.Spec)
	if err != nil {
		t.Fatalf("Failed to marshal GraphQLRoute spec: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(configJSON, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if _, ok := parsed["match"]; !ok {
		t.Error("Marshaled JSON should contain 'match' field")
	}
	if _, ok := parsed["route"]; !ok {
		t.Error("Marshaled JSON should contain 'route' field")
	}

	// Now test the full reconcile
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	// Act
	err = reconciler.reconcileGraphQLRoute(context.Background(), graphqlRoute)

	// Assert
	if err != nil {
		t.Errorf("reconcileGraphQLRoute() error = %v", err)
	}
}

func TestGraphQLRouteReconciler_reconcileGraphQLRoute_ContextCanceled(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	err := reconciler.reconcileGraphQLRoute(ctx, graphqlRoute)

	// Assert
	if err == nil {
		t.Error("reconcileGraphQLRoute() with canceled context should return error, got nil")
	}
}

// ============================================================================
// GraphQLRoute Controller - cleanupGraphQLRoute Tests
// ============================================================================

func TestGraphQLRouteReconciler_cleanupGraphQLRoute_Success(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, recorder)

	// Act
	err := reconciler.cleanupGraphQLRoute(context.Background(), graphqlRoute)

	// Assert
	if err != nil {
		t.Errorf("cleanupGraphQLRoute() error = %v, want nil", err)
	}
}

func TestGraphQLRouteReconciler_cleanupGraphQLRoute_NilGRPCServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconcilerWithNilServer(fakeClient, recorder)

	// Act
	err := reconciler.cleanupGraphQLRoute(context.Background(), graphqlRoute)

	// Assert
	if err != nil {
		t.Errorf("cleanupGraphQLRoute() with nil server error = %v, want nil", err)
	}
}

func TestGraphQLRouteReconciler_cleanupGraphQLRoute_ContextCanceled(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	err := reconciler.cleanupGraphQLRoute(ctx, graphqlRoute)

	// Assert
	if err == nil {
		t.Error("cleanupGraphQLRoute() with canceled context should return error, got nil")
	}
}

// ============================================================================
// GraphQLRoute Controller - Error Path Tests
// ============================================================================

func TestGraphQLRouteReconciler_Reconcile_GetError(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		Build()

	errClient := &testErrorClient{
		Client: fakeClient,
		getErr: errors.NewInternalError(fmt.Errorf("internal error")),
	}

	reconciler := &GraphQLRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	_, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err == nil {
		t.Error("Reconcile() should return error when Get fails")
	}
}

func TestGraphQLRouteReconciler_Reconcile_UpdateFinalizerError(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		Build()

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &GraphQLRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	_, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err == nil {
		t.Error("Reconcile() should return error when finalizer update fails")
	}
}

func TestGraphQLRouteReconciler_Reconcile_StatusUpdateError(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()

	errClient := &testErrorClient{
		Client:          fakeClient,
		statusUpdateErr: errors.NewInternalError(fmt.Errorf("status update error")),
	}

	reconciler := &GraphQLRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(context.Background(), req)

	// Assert - Status update failure should not return error but should requeue
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil (status update failure should requeue)", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("Reconcile() should requeue after status update failure")
	}
}

func TestGraphQLRouteReconciler_Deletion_RemoveFinalizerError(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	now := metav1.Now()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-graphql-route",
			Namespace:         "default",
			Finalizers:        []string{GraphQLRouteFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		Build()

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &GraphQLRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil, // No gRPC server to avoid cleanup errors
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	_, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err == nil {
		t.Error("Reconcile() should return error when finalizer removal fails")
	}
}

func TestGraphQLRouteReconciler_Deletion_WithOtherFinalizer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	now := metav1.Now()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-graphql-route",
			Namespace:         "default",
			Finalizers:        []string{"other-finalizer"}, // Different finalizer
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(context.Background(), req)

	// Assert
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue when our finalizer is not present")
	}
}

func TestGraphQLRouteReconciler_Reconcile_GRPCServerError_FullPath(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route-error",
			Namespace:  "default",
			Finalizers: []string{GraphQLRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	// Use a deadline exceeded context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-route-error",
			Namespace: "default",
		},
	}

	// Act
	result, err := reconciler.Reconcile(ctx, req)

	// Assert
	if err == nil {
		t.Error("Reconcile() with deadline exceeded context should return error, got nil")
	}
	_ = result
}

// ============================================================================
// GraphQLRoute Controller - Status Update Tests
// ============================================================================

func TestGraphQLRouteReconciler_updateStatus(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)
	ctx := context.Background()

	// Act - Test updating status to ready
	err := statusUpdater.UpdateRouteStatus(ctx, graphqlRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Route applied")

	// Assert
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	var updated avapigwv1alpha1.GraphQLRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLRoute: %v", err)
	}

	if len(updated.Status.Conditions) == 0 {
		t.Error("UpdateRouteStatus() should add conditions")
	}

	// Act - Test updating status to not ready
	err = statusUpdater.UpdateRouteStatus(ctx, &updated, false, string(avapigwv1alpha1.ReasonReconcileFailed), "Failed")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLRoute: %v", err)
	}

	foundReady := false
	for _, c := range updated.Status.Conditions {
		if c.Type == avapigwv1alpha1.ConditionReady {
			foundReady = true
			if c.Status != metav1.ConditionFalse {
				t.Error("UpdateRouteStatus() should set Ready to False")
			}
		}
	}
	if !foundReady {
		t.Error("UpdateRouteStatus() should have Ready condition")
	}
}

func TestGraphQLRouteReconciler_updateStatus_NoConditions(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec:   avapigwv1alpha1.GraphQLRouteSpec{},
		Status: avapigwv1alpha1.GraphQLRouteStatus{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)
	ctx := context.Background()

	// Act
	err := statusUpdater.UpdateRouteStatus(ctx, graphqlRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Route applied")

	// Assert
	if err != nil {
		t.Errorf("UpdateRouteStatus() error = %v, want nil", err)
	}

	var updated avapigwv1alpha1.GraphQLRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLRoute: %v", err)
	}

	if len(updated.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(updated.Status.Conditions))
	}
}

func TestGraphQLRouteReconciler_updateStatus_ExistingCondition(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Generation: 2,
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
		Status: avapigwv1alpha1.GraphQLRouteStatus{
			Conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             avapigwv1alpha1.ReasonReconciled,
					Message:            "Previously reconciled",
					ObservedGeneration: 1,
				},
			},
			ObservedGeneration: 1,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)
	ctx := context.Background()

	// Act - Update status with same ready state but different message
	err := statusUpdater.UpdateRouteStatus(ctx, graphqlRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Updated message")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	// Assert
	var updated avapigwv1alpha1.GraphQLRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLRoute: %v", err)
	}

	if updated.Status.ObservedGeneration != 2 {
		t.Errorf("UpdateRouteStatus() ObservedGeneration = %d, want 2", updated.Status.ObservedGeneration)
	}

	// Act - Update to not ready (status change)
	err = statusUpdater.UpdateRouteStatus(ctx, &updated, false, string(avapigwv1alpha1.ReasonReconcileFailed), "Failed")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLRoute: %v", err)
	}

	for _, c := range updated.Status.Conditions {
		if c.Type == avapigwv1alpha1.ConditionReady {
			if c.Status != metav1.ConditionFalse {
				t.Error("UpdateRouteStatus() should change Ready to False")
			}
		}
	}
}

// ============================================================================
// GraphQLRoute Controller - Finalizer Name Test
// ============================================================================

func TestGraphQLRouteFinalizerName(t *testing.T) {
	if GraphQLRouteFinalizerName == "" {
		t.Error("GraphQLRouteFinalizerName should not be empty")
	}
	if GraphQLRouteFinalizerName != "graphqlroute.avapigw.io/finalizer" {
		t.Errorf("GraphQLRouteFinalizerName = %q, want %q", GraphQLRouteFinalizerName, "graphqlroute.avapigw.io/finalizer")
	}
}

// ============================================================================
// GraphQLRoute Controller - Callbacks Tests
// ============================================================================

func TestGraphQLRouteReconciler_callbacks(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	// Act
	cb := reconciler.callbacks()

	// Assert
	if cb.ResourceKind != "GraphQLRoute" {
		t.Errorf("callbacks().ResourceKind = %q, want %q", cb.ResourceKind, "GraphQLRoute")
	}
	if cb.ControllerName != "graphqlroute" {
		t.Errorf("callbacks().ControllerName = %q, want %q", cb.ControllerName, "graphqlroute")
	}
	if cb.FinalizerName != GraphQLRouteFinalizerName {
		t.Errorf("callbacks().FinalizerName = %q, want %q", cb.FinalizerName, GraphQLRouteFinalizerName)
	}
	if cb.NewResource == nil {
		t.Error("callbacks().NewResource should not be nil")
	}
	if cb.Reconcile == nil {
		t.Error("callbacks().Reconcile should not be nil")
	}
	if cb.Cleanup == nil {
		t.Error("callbacks().Cleanup should not be nil")
	}
	if cb.UpdateStatus == nil {
		t.Error("callbacks().UpdateStatus should not be nil")
	}
	if cb.UpdateFailureStatus == nil {
		t.Error("callbacks().UpdateFailureStatus should not be nil")
	}
	if cb.RecordSuccessEvent == nil {
		t.Error("callbacks().RecordSuccessEvent should not be nil")
	}
	if cb.RecordFailureEvent == nil {
		t.Error("callbacks().RecordFailureEvent should not be nil")
	}
	if cb.SetSuccessMetrics == nil {
		t.Error("callbacks().SetSuccessMetrics should not be nil")
	}
	if cb.SetFailureMetrics == nil {
		t.Error("callbacks().SetFailureMetrics should not be nil")
	}
	if cb.IsApplied == nil {
		t.Error("callbacks().IsApplied should not be nil")
	}

	// Test NewResource returns correct type
	resource := cb.NewResource()
	if _, ok := resource.(*avapigwv1alpha1.GraphQLRoute); !ok {
		t.Error("callbacks().NewResource() should return *GraphQLRoute")
	}
}

func TestGraphQLRouteReconciler_callbacks_IsApplied_NilServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGraphQLRouteReconcilerWithNilServer(fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()

	resource := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	// Act
	result := cb.IsApplied(context.Background(), resource)

	// Assert - nil server should return true
	if !result {
		t.Error("IsApplied() with nil server should return true")
	}
}

func TestGraphQLRouteReconciler_callbacks_RecordEvents(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, recorder)

	cb := reconciler.callbacks()

	resource := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	// Act - Record success event
	cb.RecordSuccessEvent(recorder, resource)
	events := recorder.getEvents()
	if len(events) != 1 {
		t.Errorf("Expected 1 event after success, got %d", len(events))
	}

	// Act - Record failure event
	cb.RecordFailureEvent(recorder, resource, fmt.Errorf("test error"))
	events = recorder.getEvents()
	if len(events) != 2 {
		t.Errorf("Expected 2 events after failure, got %d", len(events))
	}
}

func TestGraphQLRouteReconciler_callbacks_SetMetrics(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()
	metrics := GetControllerMetrics()

	resource := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	// Act & Assert - Should not panic
	cb.SetSuccessMetrics(metrics, resource)
	cb.SetFailureMetrics(metrics, resource)
}

func TestGraphQLRouteReconciler_callbacks_UpdateStatus(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()
	statusUpdater := NewStatusUpdater(fakeClient)

	// Act - Call UpdateStatus callback
	err := cb.UpdateStatus(context.Background(), statusUpdater, graphqlRoute)

	// Assert
	if err != nil {
		t.Errorf("UpdateStatus callback error = %v, want nil", err)
	}
}

func TestGraphQLRouteReconciler_callbacks_UpdateFailureStatus(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlRoute).
		WithStatusSubresource(graphqlRoute).
		Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()
	statusUpdater := NewStatusUpdater(fakeClient)

	// Act - Call UpdateFailureStatus callback
	reconcileErr := fmt.Errorf("test reconcile error")
	err := cb.UpdateFailureStatus(context.Background(), statusUpdater, graphqlRoute, reconcileErr)

	// Assert
	if err != nil {
		t.Errorf("UpdateFailureStatus callback error = %v, want nil", err)
	}
}

func TestGraphQLRouteReconciler_callbacks_IsApplied_WithServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()

	resource := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-existent-route",
			Namespace: "default",
		},
	}

	// Act - Check IsApplied for a non-existent route (should return false)
	result := cb.IsApplied(context.Background(), resource)

	// Assert - route not applied yet, should return false
	if result {
		t.Error("IsApplied() for non-existent route should return false")
	}
}

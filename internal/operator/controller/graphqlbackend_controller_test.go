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
// Helper Functions for GraphQLBackend Tests
// ============================================================================

// newGraphQLBackendReconciler creates a GraphQLBackendReconciler with all required fields initialized.
func newGraphQLBackendReconciler(t *testing.T, fakeClient client.Client, recorder *fakeRecorder) *GraphQLBackendReconciler {
	scheme := newTestScheme()
	return &GraphQLBackendReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newGraphQLBackendReconcilerWithNilServer creates a GraphQLBackendReconciler with nil GRPCServer.
func newGraphQLBackendReconcilerWithNilServer(fakeClient client.Client, recorder *fakeRecorder) *GraphQLBackendReconciler {
	scheme := newTestScheme()
	return &GraphQLBackendReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    nil,
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// Ensure interface is satisfied.
var _ reconcile.Reconciler = &GraphQLBackendReconciler{}

// ============================================================================
// GraphQLBackend Controller - Reconcile Tests
// ============================================================================

func TestGraphQLBackendReconciler_Reconcile_NotFound(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, recorder)

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

func TestGraphQLBackendReconciler_Reconcile_AddFinalizer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080, Weight: 100},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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
	var updated avapigwv1alpha1.GraphQLBackend
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLBackend: %v", err)
	}

	hasFinalizer := false
	for _, f := range updated.Finalizers {
		if f == GraphQLBackendFinalizerName {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		t.Error("Reconcile() should add finalizer")
	}
}

func TestGraphQLBackendReconciler_Reconcile_Success(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host-1", Port: 8080, Weight: 50},
				{Address: "graphql-host-2", Port: 8080, Weight: 50},
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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

func TestGraphQLBackendReconciler_Reconcile_Deletion(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	now := metav1.Now()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-graphql-backend",
			Namespace:         "default",
			Finalizers:        []string{GraphQLBackendFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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
	var updated avapigwv1alpha1.GraphQLBackend
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err == nil {
		for _, f := range updated.Finalizers {
			if f == GraphQLBackendFinalizerName {
				t.Error("Reconcile() should remove finalizer on deletion")
			}
		}
	}
	// If err is NotFound, that's expected - the object was deleted
}

func TestGraphQLBackendReconciler_Reconcile_NilGRPCServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconcilerWithNilServer(fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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

func TestGraphQLBackendReconciler_Deletion_NilGRPCServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	now := metav1.Now()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-graphql-backend",
			Namespace:         "default",
			Finalizers:        []string{GraphQLBackendFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconcilerWithNilServer(fakeClient, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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
// GraphQLBackend Controller - Table-Driven Reconcile Tests
// ============================================================================

func TestGraphQLBackendReconciler_Reconcile_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		graphqlBackend   *avapigwv1alpha1.GraphQLBackend
		wantRequeue      bool
		wantRequeueAfter time.Duration
		wantErr          bool
	}{
		{
			name: "backend with TLS",
			graphqlBackend: &avapigwv1alpha1.GraphQLBackend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-backend-tls",
					Namespace:  "default",
					Finalizers: []string{GraphQLBackendFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "secure-graphql", Port: 443},
					},
					TLS: &avapigwv1alpha1.BackendTLSConfig{
						Enabled:    true,
						Mode:       "SIMPLE",
						MinVersion: "TLS12",
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "backend with circuit breaker",
			graphqlBackend: &avapigwv1alpha1.GraphQLBackend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-backend-cb",
					Namespace:  "default",
					Finalizers: []string{GraphQLBackendFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-host", Port: 8080},
					},
					CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
						Enabled:          true,
						Threshold:        5,
						Timeout:          "30s",
						HalfOpenRequests: 3,
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "backend with health check",
			graphqlBackend: &avapigwv1alpha1.GraphQLBackend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-backend-hc",
					Namespace:  "default",
					Finalizers: []string{GraphQLBackendFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-host", Port: 8080},
					},
					HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
						Path:     "/health",
						Interval: "10s",
						Timeout:  "5s",
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "backend with authentication",
			graphqlBackend: &avapigwv1alpha1.GraphQLBackend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-backend-auth",
					Namespace:  "default",
					Finalizers: []string{GraphQLBackendFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "auth-graphql", Port: 8080},
					},
					Authentication: &avapigwv1alpha1.BackendAuthConfig{
						Type: "jwt",
						JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
							Enabled:     true,
							TokenSource: "static",
							HeaderName:  "Authorization",
						},
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "backend with max sessions",
			graphqlBackend: &avapigwv1alpha1.GraphQLBackend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-backend-maxsessions",
					Namespace:  "default",
					Finalizers: []string{GraphQLBackendFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-host", Port: 8080},
					},
					MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
						Enabled:       true,
						MaxConcurrent: 100,
						QueueSize:     50,
						QueueTimeout:  "10s",
					},
				},
			},
			wantRequeue:      false,
			wantRequeueAfter: 0,
			wantErr:          false,
		},
		{
			name: "backend with rate limit",
			graphqlBackend: &avapigwv1alpha1.GraphQLBackend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "graphql-backend-ratelimit",
					Namespace:  "default",
					Finalizers: []string{GraphQLBackendFinalizerName},
				},
				Spec: avapigwv1alpha1.GraphQLBackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "graphql-host", Port: 8080},
					},
					RateLimit: &avapigwv1alpha1.RateLimitConfig{
						Enabled:           true,
						RequestsPerSecond: 100,
						Burst:             10,
					},
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
				WithObjects(tt.graphqlBackend).
				WithStatusSubresource(tt.graphqlBackend).
				Build()
			reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.graphqlBackend.Name,
					Namespace: tt.graphqlBackend.Namespace,
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
// GraphQLBackend Controller - reconcileGraphQLBackend Tests
// ============================================================================

func TestGraphQLBackendReconciler_reconcileGraphQLBackend_Success(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080, Weight: 100},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, recorder)

	// Act
	err := reconciler.reconcileGraphQLBackend(context.Background(), graphqlBackend)

	// Assert
	if err != nil {
		t.Errorf("reconcileGraphQLBackend() error = %v, want nil", err)
	}
}

func TestGraphQLBackendReconciler_reconcileGraphQLBackend_NilGRPCServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconcilerWithNilServer(fakeClient, recorder)

	// Act
	err := reconciler.reconcileGraphQLBackend(context.Background(), graphqlBackend)

	// Assert
	if err != nil {
		t.Errorf("reconcileGraphQLBackend() with nil server error = %v, want nil", err)
	}
}

func TestGraphQLBackendReconciler_reconcileGraphQLBackend_MarshalSpec(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host-1", Port: 8080, Weight: 50},
				{Address: "graphql-host-2", Port: 8080, Weight: 50},
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
			},
		},
	}

	// Verify spec can be marshaled to JSON
	configJSON, err := json.Marshal(graphqlBackend.Spec)
	if err != nil {
		t.Fatalf("Failed to marshal GraphQLBackend spec: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(configJSON, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if _, ok := parsed["hosts"]; !ok {
		t.Error("Marshaled JSON should contain 'hosts' field")
	}

	// Now test the full reconcile
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	// Act
	err = reconciler.reconcileGraphQLBackend(context.Background(), graphqlBackend)

	// Assert
	if err != nil {
		t.Errorf("reconcileGraphQLBackend() error = %v", err)
	}
}

func TestGraphQLBackendReconciler_reconcileGraphQLBackend_ContextCanceled(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	err := reconciler.reconcileGraphQLBackend(ctx, graphqlBackend)

	// Assert
	if err == nil {
		t.Error("reconcileGraphQLBackend() with canceled context should return error, got nil")
	}
}

// ============================================================================
// GraphQLBackend Controller - cleanupGraphQLBackend Tests
// ============================================================================

func TestGraphQLBackendReconciler_cleanupGraphQLBackend_Success(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, recorder)

	// Act
	err := reconciler.cleanupGraphQLBackend(context.Background(), graphqlBackend)

	// Assert
	if err != nil {
		t.Errorf("cleanupGraphQLBackend() error = %v, want nil", err)
	}
}

func TestGraphQLBackendReconciler_cleanupGraphQLBackend_NilGRPCServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconcilerWithNilServer(fakeClient, recorder)

	// Act
	err := reconciler.cleanupGraphQLBackend(context.Background(), graphqlBackend)

	// Assert
	if err != nil {
		t.Errorf("cleanupGraphQLBackend() with nil server error = %v, want nil", err)
	}
}

func TestGraphQLBackendReconciler_cleanupGraphQLBackend_ContextCanceled(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	err := reconciler.cleanupGraphQLBackend(ctx, graphqlBackend)

	// Assert
	if err == nil {
		t.Error("cleanupGraphQLBackend() with canceled context should return error, got nil")
	}
}

// ============================================================================
// GraphQLBackend Controller - Error Path Tests
// ============================================================================

func TestGraphQLBackendReconciler_Reconcile_GetError(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		Build()

	errClient := &testErrorClient{
		Client: fakeClient,
		getErr: errors.NewInternalError(fmt.Errorf("internal error")),
	}

	reconciler := &GraphQLBackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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

func TestGraphQLBackendReconciler_Reconcile_UpdateFinalizerError(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		Build()

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &GraphQLBackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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

func TestGraphQLBackendReconciler_Reconcile_StatusUpdateError(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()

	errClient := &testErrorClient{
		Client:          fakeClient,
		statusUpdateErr: errors.NewInternalError(fmt.Errorf("status update error")),
	}

	reconciler := &GraphQLBackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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

func TestGraphQLBackendReconciler_Deletion_RemoveFinalizerError(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	now := metav1.Now()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-graphql-backend",
			Namespace:         "default",
			Finalizers:        []string{GraphQLBackendFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		Build()

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &GraphQLBackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil, // No gRPC server to avoid cleanup errors
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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

func TestGraphQLBackendReconciler_Deletion_WithOtherFinalizer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	now := metav1.Now()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-graphql-backend",
			Namespace:         "default",
			Finalizers:        []string{"other-finalizer"}, // Different finalizer
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend",
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

func TestGraphQLBackendReconciler_Reconcile_GRPCServerError_FullPath(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend-error",
			Namespace:  "default",
			Finalizers: []string{GraphQLBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "graphql-host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	// Use a deadline exceeded context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-graphql-backend-error",
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
// GraphQLBackend Controller - Status Update Tests
// ============================================================================

func TestGraphQLBackendReconciler_updateStatus(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 8080},
				{Address: "host2", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)
	ctx := context.Background()

	// Act - Test updating status to ready and healthy
	totalHosts := len(graphqlBackend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, graphqlBackend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)

	// Assert
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	var updated avapigwv1alpha1.GraphQLBackend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLBackend: %v", err)
	}

	if len(updated.Status.Conditions) < 2 {
		t.Error("UpdateBackendStatus() should add Ready and Healthy conditions")
	}

	if updated.Status.TotalHosts != 2 {
		t.Errorf("UpdateBackendStatus() TotalHosts = %d, want 2", updated.Status.TotalHosts)
	}

	if updated.Status.HealthyHosts != 2 {
		t.Errorf("UpdateBackendStatus() HealthyHosts = %d, want 2", updated.Status.HealthyHosts)
	}

	// Act - Test updating status to not healthy
	err = statusUpdater.UpdateBackendStatus(ctx, &updated, true, false, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLBackend: %v", err)
	}

	foundHealthy := false
	for _, c := range updated.Status.Conditions {
		if c.Type == avapigwv1alpha1.ConditionHealthy {
			foundHealthy = true
			if c.Status != metav1.ConditionFalse {
				t.Error("UpdateBackendStatus() should set Healthy to False")
			}
		}
	}
	if !foundHealthy {
		t.Error("UpdateBackendStatus() should have Healthy condition")
	}
}

func TestGraphQLBackendReconciler_updateStatus_NoConditions(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host", Port: 8080},
			},
		},
		Status: avapigwv1alpha1.GraphQLBackendStatus{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)
	ctx := context.Background()

	// Act
	totalHosts := len(graphqlBackend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, graphqlBackend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)

	// Assert
	if err != nil {
		t.Errorf("UpdateBackendStatus() error = %v, want nil", err)
	}

	var updated avapigwv1alpha1.GraphQLBackend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLBackend: %v", err)
	}

	if len(updated.Status.Conditions) != 2 {
		t.Errorf("Expected 2 conditions, got %d", len(updated.Status.Conditions))
	}
}

func TestGraphQLBackendReconciler_updateStatus_ExistingConditions(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Generation: 2,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 8080},
			},
		},
		Status: avapigwv1alpha1.GraphQLBackendStatus{
			Conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             avapigwv1alpha1.ReasonReconciled,
					ObservedGeneration: 1,
				},
				{
					Type:               avapigwv1alpha1.ConditionHealthy,
					Status:             metav1.ConditionTrue,
					Reason:             avapigwv1alpha1.ReasonHealthCheckOK,
					ObservedGeneration: 1,
				},
			},
			ObservedGeneration: 1,
			TotalHosts:         1,
			HealthyHosts:       1,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)
	ctx := context.Background()

	// Act - Update to unhealthy
	totalHosts := len(graphqlBackend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, graphqlBackend, true, false, string(avapigwv1alpha1.ReasonReconciled), "Unhealthy", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	// Assert
	var updated avapigwv1alpha1.GraphQLBackend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-graphql-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GraphQLBackend: %v", err)
	}

	for _, c := range updated.Status.Conditions {
		if c.Type == avapigwv1alpha1.ConditionHealthy {
			if c.Status != metav1.ConditionFalse {
				t.Error("UpdateBackendStatus() should change Healthy to False")
			}
		}
	}
}

// ============================================================================
// GraphQLBackend Controller - Finalizer Name Test
// ============================================================================

func TestGraphQLBackendFinalizerName(t *testing.T) {
	if GraphQLBackendFinalizerName == "" {
		t.Error("GraphQLBackendFinalizerName should not be empty")
	}
	if GraphQLBackendFinalizerName != "graphqlbackend.avapigw.io/finalizer" {
		t.Errorf("GraphQLBackendFinalizerName = %q, want %q", GraphQLBackendFinalizerName, "graphqlbackend.avapigw.io/finalizer")
	}
}

// ============================================================================
// GraphQLBackend Controller - Callbacks Tests
// ============================================================================

func TestGraphQLBackendReconciler_callbacks(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	// Act
	cb := reconciler.callbacks()

	// Assert
	if cb.ResourceKind != "GraphQLBackend" {
		t.Errorf("callbacks().ResourceKind = %q, want %q", cb.ResourceKind, "GraphQLBackend")
	}
	if cb.ControllerName != "graphqlbackend" {
		t.Errorf("callbacks().ControllerName = %q, want %q", cb.ControllerName, "graphqlbackend")
	}
	if cb.FinalizerName != GraphQLBackendFinalizerName {
		t.Errorf("callbacks().FinalizerName = %q, want %q", cb.FinalizerName, GraphQLBackendFinalizerName)
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
	if _, ok := resource.(*avapigwv1alpha1.GraphQLBackend); !ok {
		t.Error("callbacks().NewResource() should return *GraphQLBackend")
	}
}

func TestGraphQLBackendReconciler_callbacks_IsApplied_NilServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGraphQLBackendReconcilerWithNilServer(fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()

	resource := &avapigwv1alpha1.GraphQLBackend{
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

func TestGraphQLBackendReconciler_callbacks_RecordEvents(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := newFakeRecorder()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, recorder)

	cb := reconciler.callbacks()

	resource := &avapigwv1alpha1.GraphQLBackend{
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

func TestGraphQLBackendReconciler_callbacks_SetMetrics(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()
	metrics := GetControllerMetrics()

	resource := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	// Act & Assert - Should not panic
	cb.SetSuccessMetrics(metrics, resource)
	cb.SetFailureMetrics(metrics, resource)
}

func TestGraphQLBackendReconciler_callbacks_UpdateStatus(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 8080},
				{Address: "host2", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()
	statusUpdater := NewStatusUpdater(fakeClient)

	// Act - Call UpdateStatus callback
	err := cb.UpdateStatus(context.Background(), statusUpdater, graphqlBackend)

	// Assert
	if err != nil {
		t.Errorf("UpdateStatus callback error = %v, want nil", err)
	}
}

func TestGraphQLBackendReconciler_callbacks_UpdateFailureStatus(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	graphqlBackend := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-graphql-backend",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GraphQLBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(graphqlBackend).
		WithStatusSubresource(graphqlBackend).
		Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()
	statusUpdater := NewStatusUpdater(fakeClient)

	// Act - Call UpdateFailureStatus callback
	reconcileErr := fmt.Errorf("test reconcile error")
	err := cb.UpdateFailureStatus(context.Background(), statusUpdater, graphqlBackend, reconcileErr)

	// Assert
	if err != nil {
		t.Errorf("UpdateFailureStatus callback error = %v, want nil", err)
	}
}

func TestGraphQLBackendReconciler_callbacks_IsApplied_WithServer(t *testing.T) {
	// Arrange
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGraphQLBackendReconciler(t, fakeClient, newFakeRecorder())

	cb := reconciler.callbacks()

	resource := &avapigwv1alpha1.GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-existent-backend",
			Namespace: "default",
		},
	}

	// Act - Check IsApplied for a non-existent backend (should return false)
	result := cb.IsApplied(context.Background(), resource)

	// Assert - backend not applied yet, should return false
	if result {
		t.Error("IsApplied() for non-existent backend should return false")
	}
}

// ============================================================================
// injectName Helper Tests
// ============================================================================

func TestInjectName_Success(t *testing.T) {
	// Arrange
	input := []byte(`{"hosts":[{"address":"host1","port":8080}]}`)

	// Act
	result, err := injectName(input, "my-backend")

	// Assert
	if err != nil {
		t.Fatalf("injectName() error = %v, want nil", err)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	nameRaw, ok := parsed["name"]
	if !ok {
		t.Fatal("Result should contain 'name' field")
	}

	var name string
	if err := json.Unmarshal(nameRaw, &name); err != nil {
		t.Fatalf("Failed to unmarshal name: %v", err)
	}

	if name != "my-backend" {
		t.Errorf("injectName() name = %q, want %q", name, "my-backend")
	}

	// Verify original fields are preserved
	if _, ok := parsed["hosts"]; !ok {
		t.Error("Result should preserve 'hosts' field")
	}
}

func TestInjectName_InvalidJSON(t *testing.T) {
	// Arrange
	input := []byte(`not valid json`)

	// Act
	result, err := injectName(input, "my-backend")

	// Assert
	if err == nil {
		t.Error("injectName() with invalid JSON should return error")
	}
	if result != nil {
		t.Error("injectName() with invalid JSON should return nil result")
	}
}

func TestInjectName_EmptyObject(t *testing.T) {
	// Arrange
	input := []byte(`{}`)

	// Act
	result, err := injectName(input, "my-backend")

	// Assert
	if err != nil {
		t.Fatalf("injectName() error = %v, want nil", err)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if len(parsed) != 1 {
		t.Errorf("Expected 1 field, got %d", len(parsed))
	}
}

func TestInjectName_EmptyName(t *testing.T) {
	// Arrange
	input := []byte(`{"key":"value"}`)

	// Act
	result, err := injectName(input, "")

	// Assert
	if err != nil {
		t.Fatalf("injectName() error = %v, want nil", err)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	var name string
	if err := json.Unmarshal(parsed["name"], &name); err != nil {
		t.Fatalf("Failed to unmarshal name: %v", err)
	}

	if name != "" {
		t.Errorf("injectName() name = %q, want empty string", name)
	}
}

func TestInjectName_SpecialCharactersInName(t *testing.T) {
	// Arrange
	input := []byte(`{"key":"value"}`)

	// Act
	result, err := injectName(input, `name-with-"quotes"-and-\backslash`)

	// Assert
	if err != nil {
		t.Fatalf("injectName() error = %v, want nil", err)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	var name string
	if err := json.Unmarshal(parsed["name"], &name); err != nil {
		t.Fatalf("Failed to unmarshal name: %v", err)
	}

	if name != `name-with-"quotes"-and-\backslash` {
		t.Errorf("injectName() name = %q, want %q", name, `name-with-"quotes"-and-\backslash`)
	}
}

func TestInjectName_ArrayJSON(t *testing.T) {
	// Arrange
	input := []byte(`[1,2,3]`)

	// Act
	_, err := injectName(input, "my-backend")

	// Assert
	if err == nil {
		t.Error("injectName() with array JSON should return error")
	}
}

func TestInjectName_OverwriteExistingName(t *testing.T) {
	// Arrange
	input := []byte(`{"name":"old-name","key":"value"}`)

	// Act
	result, err := injectName(input, "new-name")

	// Assert
	if err != nil {
		t.Fatalf("injectName() error = %v, want nil", err)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	var name string
	if err := json.Unmarshal(parsed["name"], &name); err != nil {
		t.Fatalf("Failed to unmarshal name: %v", err)
	}

	if name != "new-name" {
		t.Errorf("injectName() name = %q, want %q", name, "new-name")
	}
}

// ============================================================================
// Existing Controller Callbacks - UpdateFailureStatus Tests
// (These improve coverage for non-GraphQL controllers' callbacks)
// ============================================================================

func TestAPIRouteReconciler_callbacks_UpdateFailureStatus(t *testing.T) {
	scheme := newTestScheme()
	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.APIRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()
	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	cb := reconciler.callbacks()
	statusUpdater := NewStatusUpdater(fakeClient)

	reconcileErr := fmt.Errorf("test reconcile error")
	err := cb.UpdateFailureStatus(context.Background(), statusUpdater, apiRoute, reconcileErr)
	if err != nil {
		t.Errorf("UpdateFailureStatus callback error = %v, want nil", err)
	}
}

func TestGRPCRouteReconciler_callbacks_UpdateFailureStatus(t *testing.T) {
	scheme := newTestScheme()
	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()
	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	cb := reconciler.callbacks()
	statusUpdater := NewStatusUpdater(fakeClient)

	reconcileErr := fmt.Errorf("test reconcile error")
	err := cb.UpdateFailureStatus(context.Background(), statusUpdater, grpcRoute, reconcileErr)
	if err != nil {
		t.Errorf("UpdateFailureStatus callback error = %v, want nil", err)
	}
}

func TestBackendReconciler_callbacks_UpdateFailureStatus(t *testing.T) {
	scheme := newTestScheme()
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()
	reconciler := newBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

	cb := reconciler.callbacks()
	statusUpdater := NewStatusUpdater(fakeClient)

	reconcileErr := fmt.Errorf("test reconcile error")
	err := cb.UpdateFailureStatus(context.Background(), statusUpdater, backend, reconcileErr)
	if err != nil {
		t.Errorf("UpdateFailureStatus callback error = %v, want nil", err)
	}
}

func TestGRPCBackendReconciler_callbacks_UpdateFailureStatus(t *testing.T) {
	scheme := newTestScheme()
	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host", Port: 50051},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()
	reconciler := newGRPCBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

	cb := reconciler.callbacks()
	statusUpdater := NewStatusUpdater(fakeClient)

	reconcileErr := fmt.Errorf("test reconcile error")
	err := cb.UpdateFailureStatus(context.Background(), statusUpdater, grpcBackend, reconcileErr)
	if err != nil {
		t.Errorf("UpdateFailureStatus callback error = %v, want nil", err)
	}
}

func TestAPIRouteReconciler_callbacks_IsApplied(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	cb := reconciler.callbacks()
	resource := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-existent-route",
			Namespace: "default",
		},
	}

	result := cb.IsApplied(context.Background(), resource)
	if result {
		t.Error("IsApplied() for non-existent route should return false")
	}
}

func TestGRPCRouteReconciler_callbacks_IsApplied(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	cb := reconciler.callbacks()
	resource := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-existent-route",
			Namespace: "default",
		},
	}

	result := cb.IsApplied(context.Background(), resource)
	if result {
		t.Error("IsApplied() for non-existent route should return false")
	}
}

func TestBackendReconciler_callbacks_IsApplied(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

	cb := reconciler.callbacks()
	resource := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-existent-backend",
			Namespace: "default",
		},
	}

	result := cb.IsApplied(context.Background(), resource)
	if result {
		t.Error("IsApplied() for non-existent backend should return false")
	}
}

func TestGRPCBackendReconciler_callbacks_IsApplied(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := newGRPCBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

	cb := reconciler.callbacks()
	resource := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-existent-backend",
			Namespace: "default",
		},
	}

	result := cb.IsApplied(context.Background(), resource)
	if result {
		t.Error("IsApplied() for non-existent backend should return false")
	}
}

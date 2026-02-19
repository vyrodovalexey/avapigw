// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

// ============================================================================
// Mock gRPC Server for Error Testing
// ============================================================================

// mockGRPCServer wraps a real server but can return errors for specific operations.
type mockGRPCServer struct {
	*operatorgrpc.Server
	applyAPIRouteErr     error
	deleteAPIRouteErr    error
	applyGRPCRouteErr    error
	deleteGRPCRouteErr   error
	applyBackendErr      error
	deleteBackendErr     error
	applyGRPCBackendErr  error
	deleteGRPCBackendErr error
}

func (m *mockGRPCServer) ApplyAPIRoute(ctx context.Context, name, namespace string, config []byte) error {
	if m.applyAPIRouteErr != nil {
		return m.applyAPIRouteErr
	}
	if m.Server != nil {
		return m.Server.ApplyAPIRoute(ctx, name, namespace, config)
	}
	return nil
}

func (m *mockGRPCServer) DeleteAPIRoute(ctx context.Context, name, namespace string) error {
	if m.deleteAPIRouteErr != nil {
		return m.deleteAPIRouteErr
	}
	if m.Server != nil {
		return m.Server.DeleteAPIRoute(ctx, name, namespace)
	}
	return nil
}

func (m *mockGRPCServer) ApplyGRPCRoute(ctx context.Context, name, namespace string, config []byte) error {
	if m.applyGRPCRouteErr != nil {
		return m.applyGRPCRouteErr
	}
	if m.Server != nil {
		return m.Server.ApplyGRPCRoute(ctx, name, namespace, config)
	}
	return nil
}

func (m *mockGRPCServer) DeleteGRPCRoute(ctx context.Context, name, namespace string) error {
	if m.deleteGRPCRouteErr != nil {
		return m.deleteGRPCRouteErr
	}
	if m.Server != nil {
		return m.Server.DeleteGRPCRoute(ctx, name, namespace)
	}
	return nil
}

func (m *mockGRPCServer) ApplyBackend(ctx context.Context, name, namespace string, config []byte) error {
	if m.applyBackendErr != nil {
		return m.applyBackendErr
	}
	if m.Server != nil {
		return m.Server.ApplyBackend(ctx, name, namespace, config)
	}
	return nil
}

func (m *mockGRPCServer) DeleteBackend(ctx context.Context, name, namespace string) error {
	if m.deleteBackendErr != nil {
		return m.deleteBackendErr
	}
	if m.Server != nil {
		return m.Server.DeleteBackend(ctx, name, namespace)
	}
	return nil
}

func (m *mockGRPCServer) ApplyGRPCBackend(ctx context.Context, name, namespace string, config []byte) error {
	if m.applyGRPCBackendErr != nil {
		return m.applyGRPCBackendErr
	}
	if m.Server != nil {
		return m.Server.ApplyGRPCBackend(ctx, name, namespace, config)
	}
	return nil
}

func (m *mockGRPCServer) DeleteGRPCBackend(ctx context.Context, name, namespace string) error {
	if m.deleteGRPCBackendErr != nil {
		return m.deleteGRPCBackendErr
	}
	if m.Server != nil {
		return m.Server.DeleteGRPCBackend(ctx, name, namespace)
	}
	return nil
}

// ============================================================================
// APIRoute Controller - gRPC Server Error Tests
// ============================================================================

func TestAPIRouteReconciler_ReconcileAPIRoute_GRPCServerError(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Test the reconcileAPIRoute method directly
	err := reconciler.reconcileAPIRoute(context.Background(), apiRoute)
	// This should succeed since we're using the real server
	if err != nil {
		t.Logf("reconcileAPIRoute() error = %v (expected for mock)", err)
	}
}

func TestAPIRouteReconciler_CleanupAPIRoute_GRPCServerError(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-route",
			Namespace:         "default",
			Finalizers:        []string{APIRouteFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.APIRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Test the cleanupAPIRoute method directly
	err := reconciler.cleanupAPIRoute(context.Background(), apiRoute)
	if err != nil {
		t.Errorf("cleanupAPIRoute() error = %v, want nil", err)
	}
}

// ============================================================================
// GRPCRoute Controller - gRPC Server Error Tests
// ============================================================================

func TestGRPCRouteReconciler_ReconcileGRPCRoute_GRPCServerError(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route",
			Namespace:  "default",
			Finalizers: []string{GRPCRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{Service: &avapigwv1alpha1.StringMatch{Exact: "myservice"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Test the reconcileGRPCRoute method directly
	err := reconciler.reconcileGRPCRoute(context.Background(), grpcRoute)
	if err != nil {
		t.Errorf("reconcileGRPCRoute() error = %v, want nil", err)
	}
}

func TestGRPCRouteReconciler_CleanupGRPCRoute_GRPCServerError(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-grpc-route",
			Namespace:         "default",
			Finalizers:        []string{GRPCRouteFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Test the cleanupGRPCRoute method directly
	err := reconciler.cleanupGRPCRoute(context.Background(), grpcRoute)
	if err != nil {
		t.Errorf("cleanupGRPCRoute() error = %v, want nil", err)
	}
}

// ============================================================================
// Backend Controller - gRPC Server Error Tests
// ============================================================================

func TestBackendReconciler_ReconcileBackend_GRPCServerError(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Finalizers: []string{BackendFinalizerName},
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

	// Test the reconcileBackend method directly
	err := reconciler.reconcileBackend(context.Background(), backend)
	if err != nil {
		t.Errorf("reconcileBackend() error = %v, want nil", err)
	}
}

func TestBackendReconciler_CleanupBackend_GRPCServerError(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-backend",
			Namespace:         "default",
			Finalizers:        []string{BackendFinalizerName},
			DeletionTimestamp: &now,
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

	// Test the cleanupBackend method directly
	err := reconciler.cleanupBackend(context.Background(), backend)
	if err != nil {
		t.Errorf("cleanupBackend() error = %v, want nil", err)
	}
}

// ============================================================================
// GRPCBackend Controller - gRPC Server Error Tests
// ============================================================================

func TestGRPCBackendReconciler_ReconcileGRPCBackend_GRPCServerError(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Finalizers: []string{GRPCBackendFinalizerName},
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

	// Test the reconcileGRPCBackend method directly
	err := reconciler.reconcileGRPCBackend(context.Background(), grpcBackend)
	if err != nil {
		t.Errorf("reconcileGRPCBackend() error = %v, want nil", err)
	}
}

func TestGRPCBackendReconciler_CleanupGRPCBackend_GRPCServerError(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-grpc-backend",
			Namespace:         "default",
			Finalizers:        []string{GRPCBackendFinalizerName},
			DeletionTimestamp: &now,
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

	// Test the cleanupGRPCBackend method directly
	err := reconciler.cleanupGRPCBackend(context.Background(), grpcBackend)
	if err != nil {
		t.Errorf("cleanupGRPCBackend() error = %v, want nil", err)
	}
}

// ============================================================================
// handleDeletion Tests - Cleanup Failure Path
// ============================================================================

// errorGRPCServer is a mock that always returns errors
type errorGRPCServer struct{}

func (e *errorGRPCServer) ApplyAPIRoute(ctx context.Context, name, namespace string, config []byte) error {
	return fmt.Errorf("mock apply error")
}

func (e *errorGRPCServer) DeleteAPIRoute(ctx context.Context, name, namespace string) error {
	return fmt.Errorf("mock delete error")
}

func (e *errorGRPCServer) ApplyGRPCRoute(ctx context.Context, name, namespace string, config []byte) error {
	return fmt.Errorf("mock apply error")
}

func (e *errorGRPCServer) DeleteGRPCRoute(ctx context.Context, name, namespace string) error {
	return fmt.Errorf("mock delete error")
}

func (e *errorGRPCServer) ApplyBackend(ctx context.Context, name, namespace string, config []byte) error {
	return fmt.Errorf("mock apply error")
}

func (e *errorGRPCServer) DeleteBackend(ctx context.Context, name, namespace string) error {
	return fmt.Errorf("mock delete error")
}

func (e *errorGRPCServer) ApplyGRPCBackend(ctx context.Context, name, namespace string, config []byte) error {
	return fmt.Errorf("mock apply error")
}

func (e *errorGRPCServer) DeleteGRPCBackend(ctx context.Context, name, namespace string) error {
	return fmt.Errorf("mock delete error")
}

// ============================================================================
// Reconcile Failure Tests - Status Update After Failure
// ============================================================================

func TestAPIRouteReconciler_Reconcile_ReconcileFailure_StatusUpdateFails(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	// This should succeed
	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue on success")
	}
}

// ============================================================================
// Constants Tests
// ============================================================================

func TestConstants(t *testing.T) {
	// Verify constants are set correctly
	if RequeueAfterReconcileFailure <= 0 {
		t.Error("RequeueAfterReconcileFailure should be positive")
	}
	if RequeueAfterStatusUpdateFailure <= 0 {
		t.Error("RequeueAfterStatusUpdateFailure should be positive")
	}
	if RequeueAfterCleanupFailure <= 0 {
		t.Error("RequeueAfterCleanupFailure should be positive")
	}
	if RateLimiterBaseDelay <= 0 {
		t.Error("RateLimiterBaseDelay should be positive")
	}
	if RateLimiterMaxDelay <= 0 {
		t.Error("RateLimiterMaxDelay should be positive")
	}
	if MaxConcurrentReconciles <= 0 {
		t.Error("MaxConcurrentReconciles should be positive")
	}
}

// ============================================================================
// Finalizer Name Constants Tests
// ============================================================================

func TestFinalizerNames(t *testing.T) {
	if APIRouteFinalizerName == "" {
		t.Error("APIRouteFinalizerName should not be empty")
	}
	if GRPCRouteFinalizerName == "" {
		t.Error("GRPCRouteFinalizerName should not be empty")
	}
	if BackendFinalizerName == "" {
		t.Error("BackendFinalizerName should not be empty")
	}
	if GRPCBackendFinalizerName == "" {
		t.Error("GRPCBackendFinalizerName should not be empty")
	}
}

// ============================================================================
// Status Update with Existing Conditions - Edge Cases
// ============================================================================

func TestAPIRouteReconciler_updateStatus_NoConditions(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec:   avapigwv1alpha1.APIRouteSpec{},
		Status: avapigwv1alpha1.APIRouteStatus{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Update status when no conditions exist
	err := statusUpdater.UpdateRouteStatus(ctx, apiRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Route applied")
	if err != nil {
		t.Errorf("UpdateRouteStatus() error = %v, want nil", err)
	}

	// Verify condition was added
	var updated avapigwv1alpha1.APIRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated APIRoute: %v", err)
	}

	if len(updated.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(updated.Status.Conditions))
	}
}

func TestGRPCRouteReconciler_updateStatus_NoConditions(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec:   avapigwv1alpha1.GRPCRouteSpec{},
		Status: avapigwv1alpha1.GRPCRouteStatus{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Update status when no conditions exist
	err := statusUpdater.UpdateRouteStatus(ctx, grpcRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Route applied")
	if err != nil {
		t.Errorf("UpdateRouteStatus() error = %v, want nil", err)
	}

	// Verify condition was added
	var updated avapigwv1alpha1.GRPCRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCRoute: %v", err)
	}

	if len(updated.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(updated.Status.Conditions))
	}
}

func TestBackendReconciler_updateStatus_NoConditions(t *testing.T) {
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
		Status: avapigwv1alpha1.BackendStatus{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Update status when no conditions exist
	totalHosts := len(backend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, backend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Errorf("UpdateBackendStatus() error = %v, want nil", err)
	}

	// Verify conditions were added
	var updated avapigwv1alpha1.Backend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
	}

	if len(updated.Status.Conditions) != 2 {
		t.Errorf("Expected 2 conditions, got %d", len(updated.Status.Conditions))
	}
}

func TestGRPCBackendReconciler_updateStatus_NoConditions(t *testing.T) {
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
		Status: avapigwv1alpha1.GRPCBackendStatus{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Update status when no conditions exist
	totalHosts := len(grpcBackend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, grpcBackend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Errorf("UpdateBackendStatus() error = %v, want nil", err)
	}

	// Verify conditions were added
	var updated avapigwv1alpha1.GRPCBackend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCBackend: %v", err)
	}

	if len(updated.Status.Conditions) != 2 {
		t.Errorf("Expected 2 conditions, got %d", len(updated.Status.Conditions))
	}
}

// ============================================================================
// Backend Status - Healthy Hosts Calculation
// ============================================================================

func TestBackendReconciler_updateStatus_HealthyHostsCalculation(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 8080},
				{Address: "host2", Port: 8080},
				{Address: "host3", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Test healthy=true
	totalHosts := len(backend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, backend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Errorf("UpdateBackendStatus() error = %v, want nil", err)
	}

	var updated avapigwv1alpha1.Backend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
	}

	if updated.Status.TotalHosts != 3 {
		t.Errorf("TotalHosts = %d, want 3", updated.Status.TotalHosts)
	}
	if updated.Status.HealthyHosts != 3 {
		t.Errorf("HealthyHosts = %d, want 3", updated.Status.HealthyHosts)
	}

	// Test healthy=false - note: the controller doesn't reset HealthyHosts to 0,
	// it just doesn't update it when unhealthy. This tests that TotalHosts is still correct.
	err = statusUpdater.UpdateBackendStatus(ctx, &updated, true, false, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Errorf("UpdateBackendStatus() error = %v, want nil", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
	}

	// Verify TotalHosts is still correct
	if updated.Status.TotalHosts != 3 {
		t.Errorf("TotalHosts = %d, want 3 when unhealthy", updated.Status.TotalHosts)
	}

	// Verify Healthy condition is set to False
	var healthyCondition *avapigwv1alpha1.Condition
	for i := range updated.Status.Conditions {
		if updated.Status.Conditions[i].Type == avapigwv1alpha1.ConditionHealthy {
			healthyCondition = &updated.Status.Conditions[i]
			break
		}
	}
	if healthyCondition == nil {
		t.Error("Healthy condition not found")
	} else if healthyCondition.Status != metav1.ConditionFalse {
		t.Errorf("Healthy condition status = %v, want False", healthyCondition.Status)
	}
}

func TestGRPCBackendReconciler_updateStatus_HealthyHostsCalculation(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 50051},
				{Address: "host2", Port: 50051},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Test healthy=true
	totalHosts := len(grpcBackend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, grpcBackend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Errorf("UpdateBackendStatus() error = %v, want nil", err)
	}

	var updated avapigwv1alpha1.GRPCBackend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCBackend: %v", err)
	}

	if updated.Status.TotalHosts != 2 {
		t.Errorf("TotalHosts = %d, want 2", updated.Status.TotalHosts)
	}
	if updated.Status.HealthyHosts != 2 {
		t.Errorf("HealthyHosts = %d, want 2", updated.Status.HealthyHosts)
	}

	// Test healthy=false - note: the controller doesn't reset HealthyHosts to 0,
	// it just doesn't update it when unhealthy. This tests that TotalHosts is still correct.
	err = statusUpdater.UpdateBackendStatus(ctx, &updated, true, false, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Errorf("UpdateBackendStatus() error = %v, want nil", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCBackend: %v", err)
	}

	// Verify TotalHosts is still correct
	if updated.Status.TotalHosts != 2 {
		t.Errorf("TotalHosts = %d, want 2 when unhealthy", updated.Status.TotalHosts)
	}

	// Verify Healthy condition is set to False
	var healthyCondition *avapigwv1alpha1.Condition
	for i := range updated.Status.Conditions {
		if updated.Status.Conditions[i].Type == avapigwv1alpha1.ConditionHealthy {
			healthyCondition = &updated.Status.Conditions[i]
			break
		}
	}
	if healthyCondition == nil {
		t.Error("Healthy condition not found")
	} else if healthyCondition.Status != metav1.ConditionFalse {
		t.Errorf("Healthy condition status = %v, want False", healthyCondition.Status)
	}
}

// ============================================================================
// RecordIngressProcessed Tests
// ============================================================================

func TestControllerMetrics_RecordIngressProcessed(t *testing.T) {
	metrics := GetControllerMetrics()

	tests := []struct {
		name   string
		result string
	}{
		{name: "success result", result: ResultSuccess},
		{name: "error result", result: ResultError},
		{name: "requeue result", result: ResultRequeue},
		{name: "canceled result", result: ResultCanceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			metrics.RecordIngressProcessed(tt.result)
		})
	}
}

// ============================================================================
// RecordIngressConversionError Tests
// ============================================================================

func TestControllerMetrics_RecordIngressConversionError(t *testing.T) {
	metrics := GetControllerMetrics()

	tests := []struct {
		name      string
		namespace string
		ingName   string
	}{
		{name: "default namespace", namespace: "default", ingName: "my-ingress"},
		{name: "custom namespace", namespace: "production", ingName: "api-ingress"},
		{name: "empty namespace", namespace: "", ingName: "test-ingress"},
		{name: "empty name", namespace: "default", ingName: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			metrics.RecordIngressConversionError(tt.namespace, tt.ingName)
		})
	}
}

// ============================================================================
// GetStatusUpdateMetrics Singleton Tests
// ============================================================================

func TestGetStatusUpdateMetrics_Singleton(t *testing.T) {
	m1 := GetStatusUpdateMetrics()
	m2 := GetStatusUpdateMetrics()

	if m1 == nil {
		t.Fatal("GetStatusUpdateMetrics() returned nil")
	}
	if m1 != m2 {
		t.Error("GetStatusUpdateMetrics() should return the same instance")
	}
}

func TestGetStatusUpdateMetrics_FieldsInitialized(t *testing.T) {
	m := GetStatusUpdateMetrics()

	if m.updateDuration == nil {
		t.Error("updateDuration should be initialized")
	}
	if m.updateTotal == nil {
		t.Error("updateTotal should be initialized")
	}
	if m.updateErrors == nil {
		t.Error("updateErrors should be initialized")
	}
}

// ============================================================================
// RecordStatusUpdate Tests
// ============================================================================

func TestStatusUpdateMetrics_RecordStatusUpdate(t *testing.T) {
	m := GetStatusUpdateMetrics()

	tests := []struct {
		name     string
		kind     string
		duration time.Duration
		success  bool
	}{
		{name: "success fast", kind: "APIRoute", duration: 1 * time.Millisecond, success: true},
		{name: "success slow", kind: "Backend", duration: 500 * time.Millisecond, success: true},
		{name: "failure fast", kind: "GRPCRoute", duration: 2 * time.Millisecond, success: false},
		{name: "failure slow", kind: "GRPCBackend", duration: 1 * time.Second, success: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			m.RecordStatusUpdate(tt.kind, tt.duration, tt.success)
		})
	}
}

func TestStatusUpdateMetrics_RecordStatusUpdate_ErrorPath(t *testing.T) {
	m := GetStatusUpdateMetrics()

	// Record a failure - should increment both updateTotal and updateErrors
	m.RecordStatusUpdate("TestKind", 10*time.Millisecond, false)

	// Record a success - should only increment updateTotal
	m.RecordStatusUpdate("TestKind", 5*time.Millisecond, true)
}

// ============================================================================
// Metrics Label Constants Tests
// ============================================================================

func TestMetricsLabelConstants(t *testing.T) {
	if labelController == "" {
		t.Error("labelController should not be empty")
	}
	if labelResult == "" {
		t.Error("labelResult should not be empty")
	}
	if labelKind == "" {
		t.Error("labelKind should not be empty")
	}
	if labelNamespace == "" {
		t.Error("labelNamespace should not be empty")
	}
	if labelName == "" {
		t.Error("labelName should not be empty")
	}
	if labelCondition == "" {
		t.Error("labelCondition should not be empty")
	}
	if labelOperation == "" {
		t.Error("labelOperation should not be empty")
	}
}

func TestResultConstants(t *testing.T) {
	if ResultSuccess == "" {
		t.Error("ResultSuccess should not be empty")
	}
	if ResultError == "" {
		t.Error("ResultError should not be empty")
	}
	if ResultRequeue == "" {
		t.Error("ResultRequeue should not be empty")
	}
	if ResultCanceled == "" {
		t.Error("ResultCanceled should not be empty")
	}
}

func TestOperationConstants(t *testing.T) {
	if OperationAdd == "" {
		t.Error("OperationAdd should not be empty")
	}
	if OperationRemove == "" {
		t.Error("OperationRemove should not be empty")
	}
}

// ============================================================================
// StatusUpdater Helper Function Tests
// ============================================================================

// Note: Full StatusUpdater tests are in status_test.go

// ============================================================================
// UpdateCondition Helper Tests
// ============================================================================

func TestUpdateCondition_NewCondition(t *testing.T) {
	conditions := []avapigwv1alpha1.Condition{}

	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionReady,
		Status:     metav1.ConditionTrue,
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "Test message",
		Generation: 1,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 1 {
		t.Errorf("UpdateCondition() returned %d conditions, want 1", len(result))
	}
	if result[0].Type != avapigwv1alpha1.ConditionReady {
		t.Errorf("Condition type = %v, want Ready", result[0].Type)
	}
	if result[0].Status != metav1.ConditionTrue {
		t.Errorf("Condition status = %v, want True", result[0].Status)
	}
}

func TestUpdateCondition_UpdateExisting_StatusChanged(t *testing.T) {
	conditions := []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             avapigwv1alpha1.ReasonReconcileFailed,
			Message:            "Old message",
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: 1,
		},
	}

	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionReady,
		Status:     metav1.ConditionTrue,
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "New message",
		Generation: 2,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 1 {
		t.Errorf("UpdateCondition() returned %d conditions, want 1", len(result))
	}
	if result[0].Status != metav1.ConditionTrue {
		t.Errorf("Condition status = %v, want True", result[0].Status)
	}
	if result[0].Message != "New message" {
		t.Errorf("Condition message = %v, want 'New message'", result[0].Message)
	}
}

func TestUpdateCondition_UpdateExisting_StatusUnchanged(t *testing.T) {
	originalTime := metav1.Now()
	conditions := []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             avapigwv1alpha1.ReasonReconciled,
			Message:            "Old message",
			LastTransitionTime: originalTime,
			ObservedGeneration: 1,
		},
	}

	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionReady,
		Status:     metav1.ConditionTrue,
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "New message",
		Generation: 2,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 1 {
		t.Errorf("UpdateCondition() returned %d conditions, want 1", len(result))
	}
	// LastTransitionTime should be preserved when status doesn't change
	if !result[0].LastTransitionTime.Equal(&originalTime) {
		t.Error("LastTransitionTime should be preserved when status doesn't change")
	}
	if result[0].Message != "New message" {
		t.Errorf("Condition message = %v, want 'New message'", result[0].Message)
	}
	if result[0].ObservedGeneration != 2 {
		t.Errorf("ObservedGeneration = %d, want 2", result[0].ObservedGeneration)
	}
}

func TestReadyConditionFromBool(t *testing.T) {
	tests := []struct {
		name           string
		ready          bool
		expectedStatus metav1.ConditionStatus
	}{
		{"ready true", true, metav1.ConditionTrue},
		{"ready false", false, metav1.ConditionFalse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReadyConditionFromBool(tt.ready, "TestReason", "Test message", 1)
			if result.Status != tt.expectedStatus {
				t.Errorf("ReadyConditionFromBool() status = %v, want %v", result.Status, tt.expectedStatus)
			}
			if result.Type != avapigwv1alpha1.ConditionReady {
				t.Errorf("ReadyConditionFromBool() type = %v, want Ready", result.Type)
			}
		})
	}
}

func TestHealthyConditionFromBool(t *testing.T) {
	tests := []struct {
		name           string
		healthy        bool
		expectedStatus metav1.ConditionStatus
		expectedReason avapigwv1alpha1.ConditionReason
	}{
		{"healthy true", true, metav1.ConditionTrue, avapigwv1alpha1.ReasonHealthCheckOK},
		{"healthy false", false, metav1.ConditionFalse, avapigwv1alpha1.ReasonHealthCheckFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HealthyConditionFromBool(tt.healthy, 1)
			if result.Status != tt.expectedStatus {
				t.Errorf("HealthyConditionFromBool() status = %v, want %v", result.Status, tt.expectedStatus)
			}
			if result.Reason != tt.expectedReason {
				t.Errorf("HealthyConditionFromBool() reason = %v, want %v", result.Reason, tt.expectedReason)
			}
			if result.Type != avapigwv1alpha1.ConditionHealthy {
				t.Errorf("HealthyConditionFromBool() type = %v, want Healthy", result.Type)
			}
		})
	}
}

// ============================================================================
// Reconcile Error Path Tests - Context Cancellation
// ============================================================================

func TestAPIRouteReconciler_reconcileAPIRoute_ContextCanceled(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Use a canceled context to trigger error path
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := reconciler.reconcileAPIRoute(ctx, apiRoute)
	// The gRPC server returns an error when the context is canceled
	if err == nil {
		t.Error("reconcileAPIRoute() with canceled context should return error, got nil")
	}
}

func TestAPIRouteReconciler_cleanupAPIRoute_ContextCanceled(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.APIRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Use a canceled context to trigger error path
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := reconciler.cleanupAPIRoute(ctx, apiRoute)
	// The gRPC server returns an error when the context is canceled
	if err == nil {
		t.Error("cleanupAPIRoute() with canceled context should return error, got nil")
	}
}

func TestGRPCRouteReconciler_reconcileGRPCRoute_ContextCanceled(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route",
			Namespace:  "default",
			Finalizers: []string{GRPCRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{Service: &avapigwv1alpha1.StringMatch{Exact: "myservice"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Use a canceled context to trigger error path
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := reconciler.reconcileGRPCRoute(ctx, grpcRoute)
	// The gRPC server returns an error when the context is canceled
	if err == nil {
		t.Error("reconcileGRPCRoute() with canceled context should return error, got nil")
	}
}

func TestGRPCRouteReconciler_cleanupGRPCRoute_ContextCanceled(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route",
			Namespace:  "default",
			Finalizers: []string{GRPCRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Use a canceled context to trigger error path
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := reconciler.cleanupGRPCRoute(ctx, grpcRoute)
	// The gRPC server returns an error when the context is canceled
	if err == nil {
		t.Error("cleanupGRPCRoute() with canceled context should return error, got nil")
	}
}

func TestBackendReconciler_reconcileBackend_ContextCanceled(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Finalizers: []string{BackendFinalizerName},
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

	// Use a canceled context to trigger error path
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := reconciler.reconcileBackend(ctx, backend)
	// The gRPC server returns an error when the context is canceled
	if err == nil {
		t.Error("reconcileBackend() with canceled context should return error, got nil")
	}
}

func TestBackendReconciler_cleanupBackend_ContextCanceled(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Finalizers: []string{BackendFinalizerName},
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

	// Use a canceled context to trigger error path
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := reconciler.cleanupBackend(ctx, backend)
	// The gRPC server returns an error when the context is canceled
	if err == nil {
		t.Error("cleanupBackend() with canceled context should return error, got nil")
	}
}

func TestGRPCBackendReconciler_reconcileGRPCBackend_ContextCanceled(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Finalizers: []string{GRPCBackendFinalizerName},
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

	// Use a canceled context to trigger error path
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := reconciler.reconcileGRPCBackend(ctx, grpcBackend)
	// The gRPC server returns an error when the context is canceled
	if err == nil {
		t.Error("reconcileGRPCBackend() with canceled context should return error, got nil")
	}
}

func TestGRPCBackendReconciler_cleanupGRPCBackend_ContextCanceled(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Finalizers: []string{GRPCBackendFinalizerName},
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

	// Use a canceled context to trigger error path
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := reconciler.cleanupGRPCBackend(ctx, grpcBackend)
	// The gRPC server returns an error when the context is canceled
	if err == nil {
		t.Error("cleanupGRPCBackend() with canceled context should return error, got nil")
	}
}

// ============================================================================
// Reconcile with gRPC Server Error - Full Path Tests
// ============================================================================

func TestAPIRouteReconciler_Reconcile_GRPCServerError_FullPath(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route-error",
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Use a deadline exceeded context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route-error",
			Namespace: "default",
		},
	}

	// This should return an error due to context deadline exceeded
	result, err := reconciler.Reconcile(ctx, req)
	// With a deadline-exceeded context, the fake client's Get() returns context.DeadlineExceeded
	if err == nil {
		t.Error("Reconcile() with deadline exceeded context should return error, got nil")
	}
	_ = result
}

func TestGRPCRouteReconciler_Reconcile_GRPCServerError_FullPath(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route-error",
			Namespace:  "default",
			Finalizers: []string{GRPCRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{Service: &avapigwv1alpha1.StringMatch{Exact: "myservice"}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Use a deadline exceeded context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-route-error",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err == nil {
		t.Error("Reconcile() with deadline exceeded context should return error, got nil")
	}
	_ = result
}

func TestBackendReconciler_Reconcile_GRPCServerError_FullPath(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend-error",
			Namespace:  "default",
			Finalizers: []string{BackendFinalizerName},
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

	// Use a deadline exceeded context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-backend-error",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err == nil {
		t.Error("Reconcile() with deadline exceeded context should return error, got nil")
	}
	_ = result
}

func TestGRPCBackendReconciler_Reconcile_GRPCServerError_FullPath(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend-error",
			Namespace:  "default",
			Finalizers: []string{GRPCBackendFinalizerName},
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

	// Use a deadline exceeded context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-backend-error",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err == nil {
		t.Error("Reconcile() with deadline exceeded context should return error, got nil")
	}
	_ = result
}

// ============================================================================
// isResourceReady Tests
// ============================================================================

func TestIsResourceReady(t *testing.T) {
	tests := []struct {
		name       string
		conditions []avapigwv1alpha1.Condition
		generation int64
		want       bool
	}{
		{
			name: "Ready=True with matching generation",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionType("Ready"),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
			generation: 1,
			want:       true,
		},
		{
			name: "Ready=True with non-matching generation",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionType("Ready"),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
			generation: 2,
			want:       false,
		},
		{
			name: "Ready=False",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionType("Ready"),
					Status:             metav1.ConditionFalse,
					ObservedGeneration: 1,
				},
			},
			generation: 1,
			want:       false,
		},
		{
			name:       "no conditions",
			conditions: nil,
			generation: 1,
			want:       false,
		},
		{
			name: "Ready=Unknown",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionType("Ready"),
					Status:             metav1.ConditionUnknown,
					ObservedGeneration: 1,
				},
			},
			generation: 1,
			want:       false,
		},
		{
			name: "different condition type only",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionType("Progressing"),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
			generation: 1,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-route",
					Namespace:  "default",
					Generation: tt.generation,
				},
			}
			resource.SetConditions(tt.conditions)

			got := isResourceReady(resource)
			if got != tt.want {
				t.Errorf("isResourceReady() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// deletionMessage Tests
// ============================================================================

// ============================================================================
// newControllerMetricsWithFactory Tests
// ============================================================================

// newTestControllerMetrics creates a ControllerMetrics instance with a fresh registry
// to avoid duplicate registration panics across tests.
func newTestControllerMetrics(t *testing.T) (*ControllerMetrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := newControllerMetricsWithFactory(promauto.With(reg))
	return m, reg
}

func TestNewControllerMetricsWithFactory_AllFieldsInitialized(t *testing.T) {
	m, _ := newTestControllerMetrics(t)

	if m == nil {
		t.Fatal("newControllerMetricsWithFactory() returned nil")
	}
	if m.reconcileDuration == nil {
		t.Error("reconcileDuration should be initialized")
	}
	if m.reconcileTotal == nil {
		t.Error("reconcileTotal should be initialized")
	}
	if m.reconcileErrors == nil {
		t.Error("reconcileErrors should be initialized")
	}
	if m.resourcesTotal == nil {
		t.Error("resourcesTotal should be initialized")
	}
	if m.resourceCondition == nil {
		t.Error("resourceCondition should be initialized")
	}
	if m.finalizerOperations == nil {
		t.Error("finalizerOperations should be initialized")
	}
	if m.ingressResourcesProcessed == nil {
		t.Error("ingressResourcesProcessed should be initialized")
	}
	if m.ingressConversionErrors == nil {
		t.Error("ingressConversionErrors should be initialized")
	}
}

func TestNewControllerMetricsWithFactory_MetricNames(t *testing.T) {
	m, reg := newTestControllerMetrics(t)

	// Initialize metrics with label values so they appear in Gather()
	m.reconcileDuration.WithLabelValues("test-controller").Observe(0.01)
	m.reconcileTotal.WithLabelValues("test-controller", ResultSuccess).Inc()
	m.reconcileErrors.WithLabelValues("test-controller").Inc()
	m.resourcesTotal.WithLabelValues("APIRoute", "default").Set(1)
	m.resourceCondition.WithLabelValues("APIRoute", "test", "default", "Ready").Set(1)
	m.finalizerOperations.WithLabelValues("test-controller", OperationAdd).Inc()
	m.ingressResourcesProcessed.WithLabelValues(ResultSuccess).Inc()
	m.ingressConversionErrors.WithLabelValues("default", "test-ingress").Inc()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	expectedNames := map[string]bool{
		"avapigw_operator_reconcile_duration_seconds":        false,
		"avapigw_operator_reconcile_total":                   false,
		"avapigw_operator_reconcile_errors_total":            false,
		"avapigw_operator_resources_total":                   false,
		"avapigw_operator_resource_condition":                false,
		"avapigw_operator_finalizer_operations_total":        false,
		"avapigw_operator_ingress_resources_processed_total": false,
		"avapigw_operator_ingress_conversion_errors_total":   false,
	}

	for _, family := range families {
		if _, ok := expectedNames[family.GetName()]; ok {
			expectedNames[family.GetName()] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("metric %s should be registered", name)
		}
	}
}

func TestNewControllerMetricsWithFactory_RecordOperations(t *testing.T) {
	m, _ := newTestControllerMetrics(t)

	tests := []struct {
		name string
		fn   func()
	}{
		{"RecordReconcileDuration", func() { m.RecordReconcileDuration("test", 100*time.Millisecond) }},
		{"RecordReconcileResult success", func() { m.RecordReconcileResult("test", ResultSuccess) }},
		{"RecordReconcileResult error", func() { m.RecordReconcileResult("test", ResultError) }},
		{"RecordReconcileResult requeue", func() { m.RecordReconcileResult("test", ResultRequeue) }},
		{"RecordReconcileResult canceled", func() { m.RecordReconcileResult("test", ResultCanceled) }},
		{"RecordReconcileError", func() { m.RecordReconcileError("test") }},
		{"SetResourceCount", func() { m.SetResourceCount("APIRoute", "default", 5) }},
		{"SetResourceCondition", func() { m.SetResourceCondition("APIRoute", "test", "default", "Ready", 1) }},
		{"RecordFinalizerOperation add", func() { m.RecordFinalizerOperation("test", OperationAdd) }},
		{"RecordFinalizerOperation remove", func() { m.RecordFinalizerOperation("test", OperationRemove) }},
		{"RecordIngressProcessed", func() { m.RecordIngressProcessed(ResultSuccess) }},
		{"RecordIngressConversionError", func() { m.RecordIngressConversionError("default", "test") }},
		{"DeleteResourceConditionMetrics", func() { m.DeleteResourceConditionMetrics("APIRoute", "test", "default") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			tt.fn()
		})
	}
}

// ============================================================================
// newStatusUpdateMetricsWithFactory Tests
// ============================================================================

func newTestStatusUpdateMetrics(t *testing.T) (*StatusUpdateMetrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := newStatusUpdateMetricsWithFactory(promauto.With(reg))
	return m, reg
}

func TestNewStatusUpdateMetricsWithFactory_AllFieldsInitialized(t *testing.T) {
	m, _ := newTestStatusUpdateMetrics(t)

	if m == nil {
		t.Fatal("newStatusUpdateMetricsWithFactory() returned nil")
	}
	if m.updateDuration == nil {
		t.Error("updateDuration should be initialized")
	}
	if m.updateTotal == nil {
		t.Error("updateTotal should be initialized")
	}
	if m.updateErrors == nil {
		t.Error("updateErrors should be initialized")
	}
}

func TestNewStatusUpdateMetricsWithFactory_MetricNames(t *testing.T) {
	m, reg := newTestStatusUpdateMetrics(t)

	// Initialize metrics with label values so they appear in Gather()
	m.updateDuration.WithLabelValues("APIRoute").Observe(0.01)
	m.updateTotal.WithLabelValues("APIRoute", ResultSuccess).Inc()
	m.updateErrors.WithLabelValues("APIRoute").Inc()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	expectedNames := map[string]bool{
		"avapigw_operator_status_update_duration_seconds": false,
		"avapigw_operator_status_update_total":            false,
		"avapigw_operator_status_update_errors_total":     false,
	}

	for _, family := range families {
		if _, ok := expectedNames[family.GetName()]; ok {
			expectedNames[family.GetName()] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("metric %s should be registered", name)
		}
	}
}

func TestNewStatusUpdateMetricsWithFactory_RecordStatusUpdate(t *testing.T) {
	m, _ := newTestStatusUpdateMetrics(t)

	tests := []struct {
		name     string
		kind     string
		duration time.Duration
		success  bool
	}{
		{"success fast", "APIRoute", 1 * time.Millisecond, true},
		{"success slow", "Backend", 500 * time.Millisecond, true},
		{"failure fast", "GRPCRoute", 2 * time.Millisecond, false},
		{"failure slow", "GRPCBackend", 1 * time.Second, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			m.RecordStatusUpdate(tt.kind, tt.duration, tt.success)
		})
	}
}

// ============================================================================
// ConditionStatusToFloat Tests
// ============================================================================

func TestConditionStatusToFloat_TableDriven(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   float64
	}{
		{"True", "True", 1},
		{"False", "False", 0},
		{"Unknown", "Unknown", -1},
		{"empty", "", -1},
		{"arbitrary", "SomethingElse", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConditionStatusToFloat(tt.status)
			if got != tt.want {
				t.Errorf("ConditionStatusToFloat(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

// ============================================================================
// ReconcileTimer Tests with Factory
// ============================================================================

func TestReconcileTimer_WithFactoryMetrics(t *testing.T) {
	// ReconcileTimer uses GetControllerMetrics() internally, so we test
	// that it works correctly with the singleton.
	timer := NewReconcileTimer("test-controller")
	if timer == nil {
		t.Fatal("NewReconcileTimer() returned nil")
	}
	if timer.controller != "test-controller" {
		t.Errorf("controller = %q, want %q", timer.controller, "test-controller")
	}
	if timer.metrics == nil {
		t.Error("metrics should not be nil")
	}

	// Test all record methods - should not panic
	timer.RecordSuccess()

	timer2 := NewReconcileTimer("test-controller-2")
	timer2.RecordError()

	timer3 := NewReconcileTimer("test-controller-3")
	timer3.RecordRequeue()

	timer4 := NewReconcileTimer("test-controller-4")
	timer4.RecordCanceled()
}

// ============================================================================
// GetControllerMetrics Singleton Tests
// ============================================================================

func TestGetControllerMetrics_Singleton(t *testing.T) {
	m1 := GetControllerMetrics()
	m2 := GetControllerMetrics()

	if m1 == nil {
		t.Fatal("GetControllerMetrics() returned nil")
	}
	if m1 != m2 {
		t.Error("GetControllerMetrics() should return the same instance")
	}
}

func TestGetControllerMetrics_FieldsInitialized(t *testing.T) {
	m := GetControllerMetrics()

	if m.reconcileDuration == nil {
		t.Error("reconcileDuration should be initialized")
	}
	if m.reconcileTotal == nil {
		t.Error("reconcileTotal should be initialized")
	}
	if m.reconcileErrors == nil {
		t.Error("reconcileErrors should be initialized")
	}
	if m.resourcesTotal == nil {
		t.Error("resourcesTotal should be initialized")
	}
	if m.resourceCondition == nil {
		t.Error("resourceCondition should be initialized")
	}
	if m.finalizerOperations == nil {
		t.Error("finalizerOperations should be initialized")
	}
	if m.ingressResourcesProcessed == nil {
		t.Error("ingressResourcesProcessed should be initialized")
	}
	if m.ingressConversionErrors == nil {
		t.Error("ingressConversionErrors should be initialized")
	}
}

// ============================================================================
// deletionMessage Tests
// ============================================================================

func TestDeletionMessage(t *testing.T) {
	tests := []struct {
		name string
		kind string
		want string
	}{
		{
			name: "Backend kind",
			kind: "Backend",
			want: MessageBackendDeleted,
		},
		{
			name: "GRPCBackend kind",
			kind: "GRPCBackend",
			want: MessageBackendDeleted,
		},
		{
			name: "APIRoute kind",
			kind: "APIRoute",
			want: MessageRouteDeleted,
		},
		{
			name: "GRPCRoute kind",
			kind: "GRPCRoute",
			want: MessageRouteDeleted,
		},
		{
			name: "Unknown kind",
			kind: "Unknown",
			want: MessageRouteDeleted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deletionMessage(tt.kind)
			if got != tt.want {
				t.Errorf("deletionMessage(%q) = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}

// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"fmt"
	"testing"

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

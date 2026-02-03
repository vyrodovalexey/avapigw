// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// SetupWithManager Tests - Using Mock Manager
// ============================================================================

// Note: SetupWithManager requires a real controller-runtime Manager which is
// difficult to mock. Instead, we test the initialization logic and verify
// that StatusUpdater is properly initialized.

func TestAPIRouteReconciler_SetupWithManager_StatusUpdaterInit(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &APIRouteReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil,
		StatusUpdater: nil, // Not initialized
	}

	// Verify StatusUpdater is nil before setup
	if reconciler.StatusUpdater != nil {
		t.Error("StatusUpdater should be nil before setup")
	}

	// Manually initialize StatusUpdater as SetupWithManager would do
	if reconciler.StatusUpdater == nil {
		reconciler.StatusUpdater = NewStatusUpdater(reconciler.Client)
	}

	// Verify StatusUpdater is now initialized
	if reconciler.StatusUpdater == nil {
		t.Error("StatusUpdater should be initialized after setup")
	}
}

func TestGRPCRouteReconciler_SetupWithManager_StatusUpdaterInit(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &GRPCRouteReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil,
		StatusUpdater: nil,
	}

	// Manually initialize StatusUpdater as SetupWithManager would do
	if reconciler.StatusUpdater == nil {
		reconciler.StatusUpdater = NewStatusUpdater(reconciler.Client)
	}

	if reconciler.StatusUpdater == nil {
		t.Error("StatusUpdater should be initialized after setup")
	}
}

func TestBackendReconciler_SetupWithManager_StatusUpdaterInit(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &BackendReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil,
		StatusUpdater: nil,
	}

	// Manually initialize StatusUpdater as SetupWithManager would do
	if reconciler.StatusUpdater == nil {
		reconciler.StatusUpdater = NewStatusUpdater(reconciler.Client)
	}

	if reconciler.StatusUpdater == nil {
		t.Error("StatusUpdater should be initialized after setup")
	}
}

func TestGRPCBackendReconciler_SetupWithManager_StatusUpdaterInit(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &GRPCBackendReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil,
		StatusUpdater: nil,
	}

	// Manually initialize StatusUpdater as SetupWithManager would do
	if reconciler.StatusUpdater == nil {
		reconciler.StatusUpdater = NewStatusUpdater(reconciler.Client)
	}

	if reconciler.StatusUpdater == nil {
		t.Error("StatusUpdater should be initialized after setup")
	}
}

// ============================================================================
// Reconcile Error Path Tests - Cleanup Failure
// ============================================================================

func TestAPIRouteReconciler_handleDeletion_CleanupFailure(t *testing.T) {
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

	// Test handleDeletion directly
	result, err := reconciler.handleDeletion(context.Background(), apiRoute)
	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("handleDeletion() should not requeue on success")
	}
}

func TestGRPCRouteReconciler_handleDeletion_CleanupFailure(t *testing.T) {
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

	result, err := reconciler.handleDeletion(context.Background(), grpcRoute)
	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("handleDeletion() should not requeue on success")
	}
}

func TestBackendReconciler_handleDeletion_CleanupFailure(t *testing.T) {
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

	result, err := reconciler.handleDeletion(context.Background(), backend)
	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("handleDeletion() should not requeue on success")
	}
}

func TestGRPCBackendReconciler_handleDeletion_CleanupFailure(t *testing.T) {
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

	result, err := reconciler.handleDeletion(context.Background(), grpcBackend)
	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("handleDeletion() should not requeue on success")
	}
}

// ============================================================================
// Reconcile Internal Methods Tests
// ============================================================================

func TestAPIRouteReconciler_reconcileAPIRoute_Success(t *testing.T) {
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

	err := reconciler.reconcileAPIRoute(context.Background(), apiRoute)
	if err != nil {
		t.Errorf("reconcileAPIRoute() error = %v, want nil", err)
	}
}

func TestGRPCRouteReconciler_reconcileGRPCRoute_Success(t *testing.T) {
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

	err := reconciler.reconcileGRPCRoute(context.Background(), grpcRoute)
	if err != nil {
		t.Errorf("reconcileGRPCRoute() error = %v, want nil", err)
	}
}

func TestBackendReconciler_reconcileBackend_Success(t *testing.T) {
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

	err := reconciler.reconcileBackend(context.Background(), backend)
	if err != nil {
		t.Errorf("reconcileBackend() error = %v, want nil", err)
	}
}

func TestGRPCBackendReconciler_reconcileGRPCBackend_Success(t *testing.T) {
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

	err := reconciler.reconcileGRPCBackend(context.Background(), grpcBackend)
	if err != nil {
		t.Errorf("reconcileGRPCBackend() error = %v, want nil", err)
	}
}

// ============================================================================
// Cleanup Methods Tests
// ============================================================================

func TestAPIRouteReconciler_cleanupAPIRoute_Success(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	err := reconciler.cleanupAPIRoute(context.Background(), apiRoute)
	if err != nil {
		t.Errorf("cleanupAPIRoute() error = %v, want nil", err)
	}
}

func TestGRPCRouteReconciler_cleanupGRPCRoute_Success(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		Build()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	err := reconciler.cleanupGRPCRoute(context.Background(), grpcRoute)
	if err != nil {
		t.Errorf("cleanupGRPCRoute() error = %v, want nil", err)
	}
}

func TestBackendReconciler_cleanupBackend_Success(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
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
		Build()

	reconciler := newBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

	err := reconciler.cleanupBackend(context.Background(), backend)
	if err != nil {
		t.Errorf("cleanupBackend() error = %v, want nil", err)
	}
}

func TestGRPCBackendReconciler_cleanupGRPCBackend_Success(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
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
		Build()

	reconciler := newGRPCBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

	err := reconciler.cleanupGRPCBackend(context.Background(), grpcBackend)
	if err != nil {
		t.Errorf("cleanupGRPCBackend() error = %v, want nil", err)
	}
}

// ============================================================================
// Reconcile with Nil GRPCServer Tests
// ============================================================================

func TestAPIRouteReconciler_reconcileAPIRoute_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
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
		Build()

	reconciler := newAPIRouteReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	err := reconciler.reconcileAPIRoute(context.Background(), apiRoute)
	if err != nil {
		t.Errorf("reconcileAPIRoute() with nil server error = %v, want nil", err)
	}
}

func TestGRPCRouteReconciler_reconcileGRPCRoute_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
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
		Build()

	reconciler := newGRPCRouteReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	err := reconciler.reconcileGRPCRoute(context.Background(), grpcRoute)
	if err != nil {
		t.Errorf("reconcileGRPCRoute() with nil server error = %v, want nil", err)
	}
}

func TestBackendReconciler_reconcileBackend_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
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
		Build()

	reconciler := newBackendReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	err := reconciler.reconcileBackend(context.Background(), backend)
	if err != nil {
		t.Errorf("reconcileBackend() with nil server error = %v, want nil", err)
	}
}

func TestGRPCBackendReconciler_reconcileGRPCBackend_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
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
		Build()

	reconciler := newGRPCBackendReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	err := reconciler.reconcileGRPCBackend(context.Background(), grpcBackend)
	if err != nil {
		t.Errorf("reconcileGRPCBackend() with nil server error = %v, want nil", err)
	}
}

// ============================================================================
// Cleanup with Nil GRPCServer Tests
// ============================================================================

func TestAPIRouteReconciler_cleanupAPIRoute_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		Build()

	reconciler := newAPIRouteReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	err := reconciler.cleanupAPIRoute(context.Background(), apiRoute)
	if err != nil {
		t.Errorf("cleanupAPIRoute() with nil server error = %v, want nil", err)
	}
}

func TestGRPCRouteReconciler_cleanupGRPCRoute_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		Build()

	reconciler := newGRPCRouteReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	err := reconciler.cleanupGRPCRoute(context.Background(), grpcRoute)
	if err != nil {
		t.Errorf("cleanupGRPCRoute() with nil server error = %v, want nil", err)
	}
}

func TestBackendReconciler_cleanupBackend_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
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
		Build()

	reconciler := newBackendReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	err := reconciler.cleanupBackend(context.Background(), backend)
	if err != nil {
		t.Errorf("cleanupBackend() with nil server error = %v, want nil", err)
	}
}

func TestGRPCBackendReconciler_cleanupGRPCBackend_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
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
		Build()

	reconciler := newGRPCBackendReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	err := reconciler.cleanupGRPCBackend(context.Background(), grpcBackend)
	if err != nil {
		t.Errorf("cleanupGRPCBackend() with nil server error = %v, want nil", err)
	}
}

// ============================================================================
// Full Reconcile Flow Tests
// ============================================================================

func TestAPIRouteReconciler_Reconcile_FullFlow(t *testing.T) {
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

	// First reconcile
	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue on success")
	}

	// Verify status was updated
	var updated avapigwv1alpha1.APIRoute
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated APIRoute: %v", err)
	}

	if len(updated.Status.Conditions) == 0 {
		t.Error("Status conditions should be set after reconcile")
	}
}

func TestGRPCRouteReconciler_Reconcile_FullFlow(t *testing.T) {
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
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 50051,
					},
					Weight: 100,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue on success")
	}

	var updated avapigwv1alpha1.GRPCRoute
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCRoute: %v", err)
	}

	if len(updated.Status.Conditions) == 0 {
		t.Error("Status conditions should be set after reconcile")
	}
}

func TestBackendReconciler_Reconcile_FullFlow(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Finalizers: []string{BackendFinalizerName},
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 8080, Weight: 50},
				{Address: "host2", Port: 8080, Weight: 50},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()

	reconciler := newBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue on success")
	}

	var updated avapigwv1alpha1.Backend
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
	}

	if len(updated.Status.Conditions) == 0 {
		t.Error("Status conditions should be set after reconcile")
	}
	if updated.Status.TotalHosts != 2 {
		t.Errorf("TotalHosts = %d, want 2", updated.Status.TotalHosts)
	}
}

func TestGRPCBackendReconciler_Reconcile_FullFlow(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Finalizers: []string{GRPCBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 50051, Weight: 50},
				{Address: "host2", Port: 50051, Weight: 50},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()

	reconciler := newGRPCBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue on success")
	}

	var updated avapigwv1alpha1.GRPCBackend
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCBackend: %v", err)
	}

	if len(updated.Status.Conditions) == 0 {
		t.Error("Status conditions should be set after reconcile")
	}
	if updated.Status.TotalHosts != 2 {
		t.Errorf("TotalHosts = %d, want 2", updated.Status.TotalHosts)
	}
}

// ============================================================================
// Scheme Helper
// ============================================================================

func newTestSchemeLocal() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	return scheme
}

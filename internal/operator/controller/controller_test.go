// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

// testGRPCServer is a shared server instance for tests to avoid duplicate metrics registration.
var (
	testGRPCServer     *operatorgrpc.Server
	testGRPCServerOnce sync.Once
	testGRPCServerErr  error
)

func getTestGRPCServer(t *testing.T) *operatorgrpc.Server {
	testGRPCServerOnce.Do(func() {
		testGRPCServer, testGRPCServerErr = operatorgrpc.NewServer(&operatorgrpc.ServerConfig{})
	})
	if testGRPCServerErr != nil {
		t.Fatalf("Failed to create test gRPC server: %v", testGRPCServerErr)
	}
	return testGRPCServer
}

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	return scheme
}

// fakeRecorder is a simple event recorder for testing.
type fakeRecorder struct {
	events []string
	mu     sync.Mutex
}

func (r *fakeRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, eventtype+"/"+reason+": "+message)
}

func (r *fakeRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	r.Event(object, eventtype, reason, messageFmt)
}

func (r *fakeRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	r.Event(object, eventtype, reason, messageFmt)
}

func (r *fakeRecorder) getEvents() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, len(r.events))
	copy(result, r.events)
	return result
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{events: make([]string, 0)}
}

// newAPIRouteReconciler creates an APIRouteReconciler with all required fields initialized.
func newAPIRouteReconciler(t *testing.T, fakeClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *APIRouteReconciler {
	return &APIRouteReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newGRPCRouteReconciler creates a GRPCRouteReconciler with all required fields initialized.
func newGRPCRouteReconciler(t *testing.T, fakeClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *GRPCRouteReconciler {
	return &GRPCRouteReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newBackendReconciler creates a BackendReconciler with all required fields initialized.
func newBackendReconciler(t *testing.T, fakeClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *BackendReconciler {
	return &BackendReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newGRPCBackendReconciler creates a GRPCBackendReconciler with all required fields initialized.
func newGRPCBackendReconciler(t *testing.T, fakeClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *GRPCBackendReconciler {
	return &GRPCBackendReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newAPIRouteReconcilerWithNilServer creates an APIRouteReconciler with nil GRPCServer for testing.
func newAPIRouteReconcilerWithNilServer(fakeClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *APIRouteReconciler {
	return &APIRouteReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    nil,
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newGRPCRouteReconcilerWithNilServer creates a GRPCRouteReconciler with nil GRPCServer for testing.
func newGRPCRouteReconcilerWithNilServer(fakeClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *GRPCRouteReconciler {
	return &GRPCRouteReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    nil,
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newBackendReconcilerWithNilServer creates a BackendReconciler with nil GRPCServer for testing.
func newBackendReconcilerWithNilServer(fakeClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *BackendReconciler {
	return &BackendReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    nil,
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// newGRPCBackendReconcilerWithNilServer creates a GRPCBackendReconciler with nil GRPCServer for testing.
func newGRPCBackendReconcilerWithNilServer(fakeClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *GRPCBackendReconciler {
	return &GRPCBackendReconciler{
		Client:        fakeClient,
		Scheme:        scheme,
		Recorder:      recorder,
		GRPCServer:    nil,
		StatusUpdater: NewStatusUpdater(fakeClient),
	}
}

// ============================================================================
// APIRoute Controller Tests
// ============================================================================

func TestAPIRouteReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := newFakeRecorder()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "non-existent",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue for not found")
	}
}

func TestAPIRouteReconciler_Reconcile_AddFinalizer(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
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

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()
	recorder := newFakeRecorder()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	// Patch triggers a watch event automatically; no explicit requeue needed.
	if result.Requeue {
		t.Error("Reconcile() should not requeue after adding finalizer (Patch triggers watch event)")
	}

	// Verify finalizer was added
	var updated avapigwv1alpha1.APIRoute
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated APIRoute: %v", err)
	}

	hasFinalizer := false
	for _, f := range updated.Finalizers {
		if f == APIRouteFinalizerName {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		t.Error("Reconcile() should add finalizer")
	}
}

func TestAPIRouteReconciler_Reconcile_Success(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api",
					},
				},
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
	recorder := newFakeRecorder()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
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

	// Verify event was recorded
	events := recorder.getEvents()
	if len(events) == 0 {
		t.Error("Reconcile() should record an event")
	}
}

func TestAPIRouteReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-route",
			Namespace:         "default",
			Finalizers:        []string{APIRouteFinalizerName},
			DeletionTimestamp: &now,
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

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()
	recorder := newFakeRecorder()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue after deletion")
	}

	// Verify the object was deleted (finalizer removed allows deletion to complete)
	var updated avapigwv1alpha1.APIRoute
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	// The object should be deleted or have no finalizer
	if err == nil {
		// If object still exists, verify finalizer was removed
		for _, f := range updated.Finalizers {
			if f == APIRouteFinalizerName {
				t.Error("Reconcile() should remove finalizer on deletion")
			}
		}
	}
	// If err is NotFound, that's expected - the object was deleted
}

func TestAPIRouteReconciler_Reconcile_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
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

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()
	recorder := newFakeRecorder()

	reconciler := newAPIRouteReconcilerWithNilServer(fakeClient, scheme, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue with nil gRPC server")
	}
}

func TestAPIRouteReconciler_updateStatus(t *testing.T) {
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

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Test updating status to ready
	err := statusUpdater.UpdateRouteStatus(ctx, apiRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Route applied")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	// Verify status was updated
	var updated avapigwv1alpha1.APIRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated APIRoute: %v", err)
	}

	if len(updated.Status.Conditions) == 0 {
		t.Error("UpdateRouteStatus() should add conditions")
	}

	// Test updating status to not ready
	err = statusUpdater.UpdateRouteStatus(ctx, &updated, false, string(avapigwv1alpha1.ReasonReconcileFailed), "Failed")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated APIRoute: %v", err)
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

// ============================================================================
// GRPCRoute Controller Tests
// ============================================================================

func TestGRPCRouteReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "non-existent",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue for not found")
	}
}

func TestGRPCRouteReconciler_Reconcile_AddFinalizer(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Exact: "myservice",
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, recorder)

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
	// Patch triggers a watch event automatically; no explicit requeue needed.
	if result.Requeue {
		t.Error("Reconcile() should not requeue after adding finalizer (Patch triggers watch event)")
	}

	// Verify finalizer was added
	var updated avapigwv1alpha1.GRPCRoute
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCRoute: %v", err)
	}

	hasFinalizer := false
	for _, f := range updated.Finalizers {
		if f == GRPCRouteFinalizerName {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		t.Error("Reconcile() should add finalizer")
	}
}

func TestGRPCRouteReconciler_Reconcile_Success(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route",
			Namespace:  "default",
			Finalizers: []string{GRPCRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Exact: "myservice",
					},
					Method: &avapigwv1alpha1.StringMatch{
						Exact: "MyMethod",
					},
				},
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
	recorder := newFakeRecorder()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, recorder)

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

	// Verify event was recorded
	events := recorder.getEvents()
	if len(events) == 0 {
		t.Error("Reconcile() should record an event")
	}
}

func TestGRPCRouteReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-grpc-route",
			Namespace:         "default",
			Finalizers:        []string{GRPCRouteFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Exact: "myservice",
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, recorder)

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
		t.Error("Reconcile() should not requeue after deletion")
	}

	// Verify the object was deleted (finalizer removed allows deletion to complete)
	var updated avapigwv1alpha1.GRPCRoute
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	// The object should be deleted or have no finalizer
	if err == nil {
		// If object still exists, verify finalizer was removed
		for _, f := range updated.Finalizers {
			if f == GRPCRouteFinalizerName {
				t.Error("Reconcile() should remove finalizer on deletion")
			}
		}
	}
	// If err is NotFound, that's expected - the object was deleted
}

func TestGRPCRouteReconciler_updateStatus(t *testing.T) {
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

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Test updating status to ready
	err := statusUpdater.UpdateRouteStatus(ctx, grpcRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Route applied")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	// Verify status was updated
	var updated avapigwv1alpha1.GRPCRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCRoute: %v", err)
	}

	if len(updated.Status.Conditions) == 0 {
		t.Error("UpdateRouteStatus() should add conditions")
	}
}

// ============================================================================
// Backend Controller Tests
// ============================================================================

func TestBackendReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := newFakeRecorder()

	reconciler := newBackendReconciler(t, fakeClient, scheme, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "non-existent",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue for not found")
	}
}

func TestBackendReconciler_Reconcile_AddFinalizer(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-host",
					Port:    8080,
					Weight:  100,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()
	recorder := newFakeRecorder()

	reconciler := newBackendReconciler(t, fakeClient, scheme, recorder)

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
	// Patch triggers a watch event automatically; no explicit requeue needed.
	if result.Requeue {
		t.Error("Reconcile() should not requeue after adding finalizer (Patch triggers watch event)")
	}

	// Verify finalizer was added
	var updated avapigwv1alpha1.Backend
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
	}

	hasFinalizer := false
	for _, f := range updated.Finalizers {
		if f == BackendFinalizerName {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		t.Error("Reconcile() should add finalizer")
	}
}

func TestBackendReconciler_Reconcile_Success(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Finalizers: []string{BackendFinalizerName},
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "backend-host-1",
					Port:    8080,
					Weight:  50,
				},
				{
					Address: "backend-host-2",
					Port:    8080,
					Weight:  50,
				},
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:     "/health",
				Interval: "10s",
				Timeout:  "5s",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()
	recorder := newFakeRecorder()

	reconciler := newBackendReconciler(t, fakeClient, scheme, recorder)

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

	// Verify event was recorded
	events := recorder.getEvents()
	if len(events) == 0 {
		t.Error("Reconcile() should record an event")
	}
}

func TestBackendReconciler_Reconcile_Deletion(t *testing.T) {
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
				{
					Address: "backend-host",
					Port:    8080,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()
	recorder := newFakeRecorder()

	reconciler := newBackendReconciler(t, fakeClient, scheme, recorder)

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
		t.Error("Reconcile() should not requeue after deletion")
	}

	// Verify the object was deleted (finalizer removed allows deletion to complete)
	var updated avapigwv1alpha1.Backend
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	// The object should be deleted or have no finalizer
	if err == nil {
		// If object still exists, verify finalizer was removed
		for _, f := range updated.Finalizers {
			if f == BackendFinalizerName {
				t.Error("Reconcile() should remove finalizer on deletion")
			}
		}
	}
	// If err is NotFound, that's expected - the object was deleted
}

func TestBackendReconciler_updateStatus(t *testing.T) {
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

	// Test updating status to ready and healthy
	totalHosts := len(backend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, backend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	// Verify status was updated
	var updated avapigwv1alpha1.Backend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
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

	// Test updating status to not healthy
	err = statusUpdater.UpdateBackendStatus(ctx, &updated, true, false, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
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

// ============================================================================
// GRPCBackend Controller Tests
// ============================================================================

func TestGRPCBackendReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCBackendReconciler(t, fakeClient, scheme, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "non-existent",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue {
		t.Error("Reconcile() should not requeue for not found")
	}
}

func TestGRPCBackendReconciler_Reconcile_AddFinalizer(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-backend-host",
					Port:    50051,
					Weight:  100,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCBackendReconciler(t, fakeClient, scheme, recorder)

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
	// Patch triggers a watch event automatically; no explicit requeue needed.
	if result.Requeue {
		t.Error("Reconcile() should not requeue after adding finalizer (Patch triggers watch event)")
	}

	// Verify finalizer was added
	var updated avapigwv1alpha1.GRPCBackend
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCBackend: %v", err)
	}

	hasFinalizer := false
	for _, f := range updated.Finalizers {
		if f == GRPCBackendFinalizerName {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		t.Error("Reconcile() should add finalizer")
	}
}

func TestGRPCBackendReconciler_Reconcile_Success(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Finalizers: []string{GRPCBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-backend-host-1",
					Port:    50051,
					Weight:  50,
				},
				{
					Address: "grpc-backend-host-2",
					Port:    50051,
					Weight:  50,
				},
			},
			LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerLeastConn,
			},
			HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Enabled:  true,
				Service:  "grpc.health.v1.Health",
				Interval: "10s",
				Timeout:  "5s",
			},
			ConnectionPool: &avapigwv1alpha1.GRPCConnectionPoolConfig{
				MaxIdleConns:    10,
				MaxConnsPerHost: 100,
				IdleConnTimeout: "5m",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCBackendReconciler(t, fakeClient, scheme, recorder)

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

	// Verify event was recorded
	events := recorder.getEvents()
	if len(events) == 0 {
		t.Error("Reconcile() should record an event")
	}
}

func TestGRPCBackendReconciler_Reconcile_Deletion(t *testing.T) {
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
				{
					Address: "grpc-backend-host",
					Port:    50051,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCBackendReconciler(t, fakeClient, scheme, recorder)

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
		t.Error("Reconcile() should not requeue after deletion")
	}

	// Verify the object was deleted (finalizer removed allows deletion to complete)
	var updated avapigwv1alpha1.GRPCBackend
	err = fakeClient.Get(context.Background(), req.NamespacedName, &updated)
	// The object should be deleted or have no finalizer
	if err == nil {
		// If object still exists, verify finalizer was removed
		for _, f := range updated.Finalizers {
			if f == GRPCBackendFinalizerName {
				t.Error("Reconcile() should remove finalizer on deletion")
			}
		}
	}
	// If err is NotFound, that's expected - the object was deleted
}

func TestGRPCBackendReconciler_updateStatus(t *testing.T) {
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
				{Address: "host3", Port: 50051},
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

	// Test updating status to ready and healthy
	totalHosts := len(grpcBackend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, grpcBackend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Backend applied", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	// Verify status was updated
	var updated avapigwv1alpha1.GRPCBackend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCBackend: %v", err)
	}

	if len(updated.Status.Conditions) < 2 {
		t.Error("UpdateBackendStatus() should add Ready and Healthy conditions")
	}

	if updated.Status.TotalHosts != 3 {
		t.Errorf("UpdateBackendStatus() TotalHosts = %d, want 3", updated.Status.TotalHosts)
	}

	if updated.Status.HealthyHosts != 3 {
		t.Errorf("UpdateBackendStatus() HealthyHosts = %d, want 3", updated.Status.HealthyHosts)
	}

	if updated.Status.LastHealthCheck == nil {
		t.Error("UpdateBackendStatus() should set LastHealthCheck")
	}
}

// ============================================================================
// Table-Driven Tests for Edge Cases
// ============================================================================

func TestAPIRouteReconciler_Reconcile_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		apiRoute         *avapigwv1alpha1.APIRoute
		wantRequeue      bool
		wantRequeueAfter time.Duration
		wantErr          bool
	}{
		{
			name: "route with timeout",
			apiRoute: &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "route-with-timeout",
					Namespace:  "default",
					Finalizers: []string{APIRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.APIRouteSpec{
					Match: []avapigwv1alpha1.RouteMatch{
						{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
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
			apiRoute: &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "route-with-retries",
					Namespace:  "default",
					Finalizers: []string{APIRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.APIRouteSpec{
					Match: []avapigwv1alpha1.RouteMatch{
						{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
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
			apiRoute: &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "route-with-ratelimit",
					Namespace:  "default",
					Finalizers: []string{APIRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.APIRouteSpec{
					Match: []avapigwv1alpha1.RouteMatch{
						{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
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
			apiRoute: &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "route-with-cors",
					Namespace:  "default",
					Finalizers: []string{APIRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.APIRouteSpec{
					Match: []avapigwv1alpha1.RouteMatch{
						{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
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
			apiRoute: &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "route-with-cache",
					Namespace:  "default",
					Finalizers: []string{APIRouteFinalizerName},
				},
				Spec: avapigwv1alpha1.APIRouteSpec{
					Match: []avapigwv1alpha1.RouteMatch{
						{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.apiRoute).
				WithStatusSubresource(tt.apiRoute).
				Build()

			reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.apiRoute.Name,
					Namespace: tt.apiRoute.Namespace,
				},
			}

			result, err := reconciler.Reconcile(context.Background(), req)
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

func TestBackendReconciler_Reconcile_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		backend          *avapigwv1alpha1.Backend
		wantRequeue      bool
		wantRequeueAfter time.Duration
		wantErr          bool
	}{
		{
			name: "backend with TLS",
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "backend-with-tls",
					Namespace:  "default",
					Finalizers: []string{BackendFinalizerName},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "secure-backend", Port: 443},
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
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "backend-with-cb",
					Namespace:  "default",
					Finalizers: []string{BackendFinalizerName},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "backend", Port: 8080},
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
			name: "backend with authentication",
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "backend-with-auth",
					Namespace:  "default",
					Finalizers: []string{BackendFinalizerName},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "auth-backend", Port: 8080},
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
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "backend-with-maxsessions",
					Namespace:  "default",
					Finalizers: []string{BackendFinalizerName},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Hosts: []avapigwv1alpha1.BackendHost{
						{Address: "backend", Port: 8080},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.backend).
				WithStatusSubresource(tt.backend).
				Build()

			reconciler := newBackendReconciler(t, fakeClient, scheme, newFakeRecorder())

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.backend.Name,
					Namespace: tt.backend.Namespace,
				},
			}

			result, err := reconciler.Reconcile(context.Background(), req)
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
// Helper Function Tests
// ============================================================================

func TestReconcileAPIRoute_MarshalSpec(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1",
					},
					Methods: []string{"GET", "POST"},
					Headers: []avapigwv1alpha1.HeaderMatch{
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
						Host: "backend-svc",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	// Verify spec can be marshaled to JSON
	configJSON, err := json.Marshal(apiRoute.Spec)
	if err != nil {
		t.Fatalf("Failed to marshal APIRoute spec: %v", err)
	}

	// Verify JSON contains expected fields
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
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	ctx := context.Background()
	err = reconciler.reconcileAPIRoute(ctx, apiRoute)
	if err != nil {
		t.Errorf("reconcileAPIRoute() error = %v", err)
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestConcurrentReconciliation(t *testing.T) {
	scheme := newTestScheme()

	// Create multiple resources
	var objects []client.Object
	for i := 0; i < 10; i++ {
		apiRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "route-" + string(rune('a'+i)),
				Namespace:  "default",
				Finalizers: []string{APIRouteFinalizerName},
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
				},
			},
		}
		objects = append(objects, apiRoute)
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(objects...).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	// Run reconciliations concurrently
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "route-" + string(rune('a'+idx)),
					Namespace: "default",
				},
			}
			_, err := reconciler.Reconcile(context.Background(), req)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent reconciliation error: %v", err)
	}
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

func TestAPIRouteReconciler_updateStatus_ExistingCondition(t *testing.T) {
	scheme := newTestScheme()

	// Create APIRoute with existing Ready condition
	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 2,
		},
		Spec: avapigwv1alpha1.APIRouteSpec{},
		Status: avapigwv1alpha1.APIRouteStatus{
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
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Update status with same ready state but different message
	err := statusUpdater.UpdateRouteStatus(ctx, apiRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Updated message")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	// Verify status was updated
	var updated avapigwv1alpha1.APIRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated APIRoute: %v", err)
	}

	if updated.Status.ObservedGeneration != 2 {
		t.Errorf("UpdateRouteStatus() ObservedGeneration = %d, want 2", updated.Status.ObservedGeneration)
	}

	// Now update to not ready (status change)
	err = statusUpdater.UpdateRouteStatus(ctx, &updated, false, string(avapigwv1alpha1.ReasonReconcileFailed), "Failed")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated APIRoute: %v", err)
	}

	for _, c := range updated.Status.Conditions {
		if c.Type == avapigwv1alpha1.ConditionReady {
			if c.Status != metav1.ConditionFalse {
				t.Error("UpdateRouteStatus() should change Ready to False")
			}
		}
	}
}

func TestGRPCRouteReconciler_updateStatus_ExistingCondition(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route",
			Namespace:  "default",
			Generation: 2,
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{},
		Status: avapigwv1alpha1.GRPCRouteStatus{
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
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Update status with same ready state
	err := statusUpdater.UpdateRouteStatus(ctx, grpcRoute, true, string(avapigwv1alpha1.ReasonReconciled), "Updated")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	var updated avapigwv1alpha1.GRPCRoute
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCRoute: %v", err)
	}

	if updated.Status.ObservedGeneration != 2 {
		t.Errorf("UpdateRouteStatus() ObservedGeneration = %d, want 2", updated.Status.ObservedGeneration)
	}

	// Update to not ready
	err = statusUpdater.UpdateRouteStatus(ctx, &updated, false, string(avapigwv1alpha1.ReasonReconcileFailed), "Failed")
	if err != nil {
		t.Fatalf("UpdateRouteStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-route", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCRoute: %v", err)
	}

	for _, c := range updated.Status.Conditions {
		if c.Type == avapigwv1alpha1.ConditionReady {
			if c.Status != metav1.ConditionFalse {
				t.Error("UpdateRouteStatus() should change Ready to False")
			}
		}
	}
}

func TestBackendReconciler_updateStatus_ExistingConditions(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Generation: 2,
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 8080},
			},
		},
		Status: avapigwv1alpha1.BackendStatus{
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
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Update with same ready/healthy state
	totalHosts := len(backend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, backend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Updated", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	var updated avapigwv1alpha1.Backend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
	}

	// Update to unhealthy
	err = statusUpdater.UpdateBackendStatus(ctx, &updated, true, false, string(avapigwv1alpha1.ReasonReconciled), "Unhealthy", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Backend: %v", err)
	}

	for _, c := range updated.Status.Conditions {
		if c.Type == avapigwv1alpha1.ConditionHealthy {
			if c.Status != metav1.ConditionFalse {
				t.Error("UpdateBackendStatus() should change Healthy to False")
			}
		}
	}
}

func TestGRPCBackendReconciler_updateStatus_ExistingConditions(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Generation: 2,
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "host1", Port: 50051},
			},
		},
		Status: avapigwv1alpha1.GRPCBackendStatus{
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
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()

	statusUpdater := NewStatusUpdater(fakeClient)

	ctx := context.Background()

	// Update with same ready/healthy state
	totalHosts := len(grpcBackend.Spec.Hosts)
	err := statusUpdater.UpdateBackendStatus(ctx, grpcBackend, true, true, string(avapigwv1alpha1.ReasonReconciled), "Updated", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	var updated avapigwv1alpha1.GRPCBackend
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCBackend: %v", err)
	}

	// Update to unhealthy
	err = statusUpdater.UpdateBackendStatus(ctx, &updated, true, false, string(avapigwv1alpha1.ReasonReconciled), "Unhealthy", totalHosts)
	if err != nil {
		t.Fatalf("UpdateBackendStatus() error = %v", err)
	}

	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-grpc-backend", Namespace: "default"}, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated GRPCBackend: %v", err)
	}

	for _, c := range updated.Status.Conditions {
		if c.Type == avapigwv1alpha1.ConditionHealthy {
			if c.Status != metav1.ConditionFalse {
				t.Error("UpdateBackendStatus() should change Healthy to False")
			}
		}
	}
}

func TestGRPCRouteReconciler_Reconcile_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-route",
			Namespace:  "default",
			Finalizers: []string{GRPCRouteFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Exact: "myservice",
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithStatusSubresource(grpcRoute).
		Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCRouteReconcilerWithNilServer(fakeClient, scheme, recorder)

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
		t.Error("Reconcile() should not requeue with nil gRPC server")
	}
}

func TestBackendReconciler_Reconcile_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-backend",
			Namespace:  "default",
			Finalizers: []string{BackendFinalizerName},
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()
	recorder := newFakeRecorder()

	reconciler := newBackendReconcilerWithNilServer(fakeClient, scheme, recorder)

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
		t.Error("Reconcile() should not requeue with nil gRPC server")
	}
}

func TestGRPCBackendReconciler_Reconcile_NilGRPCServer(t *testing.T) {
	scheme := newTestScheme()

	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-grpc-backend",
			Namespace:  "default",
			Finalizers: []string{GRPCBackendFinalizerName},
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{Address: "grpc-backend", Port: 50051},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()
	recorder := newFakeRecorder()

	reconciler := newGRPCBackendReconcilerWithNilServer(fakeClient, scheme, recorder)

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
		t.Error("Reconcile() should not requeue with nil gRPC server")
	}
}

func TestAPIRouteReconciler_Deletion_NilGRPCServer(t *testing.T) {
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

	reconciler := newAPIRouteReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue after deletion with nil gRPC server")
	}
}

func TestGRPCRouteReconciler_Deletion_NilGRPCServer(t *testing.T) {
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

	reconciler := &GRPCRouteReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: nil, // No gRPC server
	}

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
		t.Error("Reconcile() should not requeue after deletion with nil gRPC server")
	}
}

func TestBackendReconciler_Deletion_NilGRPCServer(t *testing.T) {
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
				{Address: "backend", Port: 8080},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(backend).
		WithStatusSubresource(backend).
		Build()

	reconciler := newBackendReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

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
		t.Error("Reconcile() should not requeue after deletion with nil gRPC server")
	}
}

func TestGRPCBackendReconciler_Deletion_NilGRPCServer(t *testing.T) {
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
				{Address: "grpc-backend", Port: 50051},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcBackend).
		WithStatusSubresource(grpcBackend).
		Build()

	reconciler := newGRPCBackendReconcilerWithNilServer(fakeClient, scheme, newFakeRecorder())

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
		t.Error("Reconcile() should not requeue after deletion with nil gRPC server")
	}
}

// Ensure interfaces are satisfied
var _ reconcile.Reconciler = &APIRouteReconciler{}
var _ reconcile.Reconciler = &GRPCRouteReconciler{}
var _ reconcile.Reconciler = &BackendReconciler{}
var _ reconcile.Reconciler = &GRPCBackendReconciler{}
var _ record.EventRecorder = &fakeRecorder{}

// ============================================================================
// Metrics Tests
// ============================================================================

func TestControllerMetrics_SetResourceCount(t *testing.T) {
	metrics := GetControllerMetrics()

	// Should not panic
	metrics.SetResourceCount("APIRoute", "default", 5)
	metrics.SetResourceCount("Backend", "production", 10)
}

func TestConditionStatusToFloat(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected float64
	}{
		{"True", "True", 1},
		{"False", "False", 0},
		{"Unknown", "Unknown", -1},
		{"Empty", "", -1},
		{"Other", "Other", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConditionStatusToFloat(tt.status)
			if result != tt.expected {
				t.Errorf("ConditionStatusToFloat(%q) = %f, want %f", tt.status, result, tt.expected)
			}
		})
	}
}

func TestReconcileTimer_RecordCanceled(t *testing.T) {
	timer := NewReconcileTimer("test-controller")

	// Should not panic
	timer.RecordCanceled()
}

// ============================================================================
// Error Client Tests for Error Paths
// ============================================================================

// testErrorClient wraps a client and returns errors for specific operations.
type testErrorClient struct {
	client.Client
	getErr          error
	updateErr       error
	patchErr        error
	statusUpdateErr error
}

func (e *testErrorClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if e.getErr != nil {
		return e.getErr
	}
	return e.Client.Get(ctx, key, obj, opts...)
}

func (e *testErrorClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if e.updateErr != nil {
		return e.updateErr
	}
	return e.Client.Update(ctx, obj, opts...)
}

func (e *testErrorClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if e.patchErr != nil {
		return e.patchErr
	}
	return e.Client.Patch(ctx, obj, patch, opts...)
}

func (e *testErrorClient) Status() client.SubResourceWriter {
	return &testErrorStatusWriter{
		SubResourceWriter: e.Client.Status(),
		err:               e.statusUpdateErr,
	}
}

type testErrorStatusWriter struct {
	client.SubResourceWriter
	err error
}

func (e *testErrorStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if e.err != nil {
		return e.err
	}
	return e.SubResourceWriter.Update(ctx, obj, opts...)
}

func (e *testErrorStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if e.err != nil {
		return e.err
	}
	return e.SubResourceWriter.Patch(ctx, obj, patch, opts...)
}

// TestAPIRouteReconciler_Reconcile_GetError tests error handling when Get fails
func TestAPIRouteReconciler_Reconcile_GetError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client: fakeClient,
		getErr: errors.NewInternalError(fmt.Errorf("internal error")),
	}

	reconciler := &APIRouteReconciler{
		Client:     errClient,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: getTestGRPCServer(t),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when Get fails")
	}
}

// TestAPIRouteReconciler_Reconcile_UpdateFinalizerError tests error handling when finalizer patch fails
func TestAPIRouteReconciler_Reconcile_UpdateFinalizerError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &APIRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when finalizer update fails")
	}
}

// TestAPIRouteReconciler_Reconcile_StatusUpdateError tests error handling when status update fails
func TestAPIRouteReconciler_Reconcile_StatusUpdateError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client:          fakeClient,
		statusUpdateErr: errors.NewInternalError(fmt.Errorf("status update error")),
	}

	reconciler := &APIRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	// Status update failure should not return error but should requeue
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil (status update failure should requeue)", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("Reconcile() should requeue after status update failure")
	}
}

// TestGRPCRouteReconciler_Reconcile_GetError tests error handling when Get fails
func TestGRPCRouteReconciler_Reconcile_GetError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client: fakeClient,
		getErr: errors.NewInternalError(fmt.Errorf("internal error")),
	}

	reconciler := &GRPCRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when Get fails")
	}
}

// TestBackendReconciler_Reconcile_GetError tests error handling when Get fails
func TestBackendReconciler_Reconcile_GetError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client: fakeClient,
		getErr: errors.NewInternalError(fmt.Errorf("internal error")),
	}

	reconciler := &BackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when Get fails")
	}
}

// TestGRPCBackendReconciler_Reconcile_GetError tests error handling when Get fails
func TestGRPCBackendReconciler_Reconcile_GetError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client: fakeClient,
		getErr: errors.NewInternalError(fmt.Errorf("internal error")),
	}

	reconciler := &GRPCBackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when Get fails")
	}
}

// TestAPIRouteReconciler_Deletion_RemoveFinalizerError tests error handling when finalizer removal fails
func TestAPIRouteReconciler_Deletion_RemoveFinalizerError(t *testing.T) {
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
		Build()

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &APIRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil, // No gRPC server to avoid cleanup errors
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when finalizer removal fails")
	}
}

// TestAPIRouteReconciler_Deletion_WithOtherFinalizer tests deletion with a different finalizer
func TestAPIRouteReconciler_Deletion_WithOtherFinalizer(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-route",
			Namespace:         "default",
			Finalizers:        []string{"other-finalizer"}, // Different finalizer
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.APIRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		Build()

	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue when our finalizer is not present")
	}
}

// TestGRPCRouteReconciler_Deletion_WithOtherFinalizer tests deletion with a different finalizer
func TestGRPCRouteReconciler_Deletion_WithOtherFinalizer(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-grpc-route",
			Namespace:         "default",
			Finalizers:        []string{"other-finalizer"}, // Different finalizer
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
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
		t.Error("Reconcile() should not requeue when our finalizer is not present")
	}
}

// TestBackendReconciler_Deletion_WithOtherFinalizer tests deletion with a different finalizer
func TestBackendReconciler_Deletion_WithOtherFinalizer(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-backend",
			Namespace:         "default",
			Finalizers:        []string{"other-finalizer"}, // Different finalizer
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
		t.Error("Reconcile() should not requeue when our finalizer is not present")
	}
}

// TestGRPCBackendReconciler_Deletion_WithOtherFinalizer tests deletion with a different finalizer
func TestGRPCBackendReconciler_Deletion_WithOtherFinalizer(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	grpcBackend := &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-grpc-backend",
			Namespace:         "default",
			Finalizers:        []string{"other-finalizer"}, // Different finalizer
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
		t.Error("Reconcile() should not requeue when our finalizer is not present")
	}
}

// TestGRPCRouteReconciler_Reconcile_UpdateFinalizerError tests error handling when finalizer patch fails
func TestGRPCRouteReconciler_Reconcile_UpdateFinalizerError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &GRPCRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when finalizer update fails")
	}
}

// TestBackendReconciler_Reconcile_UpdateFinalizerError tests error handling when finalizer patch fails
func TestBackendReconciler_Reconcile_UpdateFinalizerError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &BackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when finalizer update fails")
	}
}

// TestGRPCBackendReconciler_Reconcile_UpdateFinalizerError tests error handling when finalizer patch fails
func TestGRPCBackendReconciler_Reconcile_UpdateFinalizerError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &GRPCBackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when finalizer update fails")
	}
}

// ============================================================================
// Additional Deletion Error Path Tests
// ============================================================================

// TestGRPCRouteReconciler_Deletion_RemoveFinalizerError tests error handling when finalizer removal fails
func TestGRPCRouteReconciler_Deletion_RemoveFinalizerError(t *testing.T) {
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
		Build()

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &GRPCRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil, // No gRPC server to avoid cleanup errors
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when finalizer removal fails")
	}
}

// TestBackendReconciler_Deletion_RemoveFinalizerError tests error handling when finalizer removal fails
func TestBackendReconciler_Deletion_RemoveFinalizerError(t *testing.T) {
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
		Build()

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &BackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil, // No gRPC server to avoid cleanup errors
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when finalizer removal fails")
	}
}

// TestGRPCBackendReconciler_Deletion_RemoveFinalizerError tests error handling when finalizer removal fails
func TestGRPCBackendReconciler_Deletion_RemoveFinalizerError(t *testing.T) {
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
		Build()

	errClient := &testErrorClient{
		Client:   fakeClient,
		patchErr: errors.NewInternalError(fmt.Errorf("patch error")),
	}

	reconciler := &GRPCBackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    nil, // No gRPC server to avoid cleanup errors
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error when finalizer removal fails")
	}
}

// ============================================================================
// Status Update Error Path Tests
// ============================================================================

// TestGRPCRouteReconciler_Reconcile_StatusUpdateError tests error handling when status update fails
func TestGRPCRouteReconciler_Reconcile_StatusUpdateError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client:          fakeClient,
		statusUpdateErr: errors.NewInternalError(fmt.Errorf("status update error")),
	}

	reconciler := &GRPCRouteReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	// Status update failure should not return error but should requeue
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil (status update failure should requeue)", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("Reconcile() should requeue after status update failure")
	}
}

// TestBackendReconciler_Reconcile_StatusUpdateError tests error handling when status update fails
func TestBackendReconciler_Reconcile_StatusUpdateError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client:          fakeClient,
		statusUpdateErr: errors.NewInternalError(fmt.Errorf("status update error")),
	}

	reconciler := &BackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	// Status update failure should not return error but should requeue
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil (status update failure should requeue)", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("Reconcile() should requeue after status update failure")
	}
}

// TestGRPCBackendReconciler_Reconcile_StatusUpdateError tests error handling when status update fails
func TestGRPCBackendReconciler_Reconcile_StatusUpdateError(t *testing.T) {
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

	errClient := &testErrorClient{
		Client:          fakeClient,
		statusUpdateErr: errors.NewInternalError(fmt.Errorf("status update error")),
	}

	reconciler := &GRPCBackendReconciler{
		Client:        errClient,
		Scheme:        scheme,
		Recorder:      newFakeRecorder(),
		GRPCServer:    getTestGRPCServer(t),
		StatusUpdater: NewStatusUpdater(errClient),
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	// Status update failure should not return error but should requeue
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil (status update failure should requeue)", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("Reconcile() should requeue after status update failure")
	}
}

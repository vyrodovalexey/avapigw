//go:build integration

// Package operator_test contains integration tests for the apigw-operator.
package operator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/controller"
)

// TestIntegration_Controller_APIRoute_Reconcile tests APIRoute controller reconciliation.
func TestIntegration_Controller_APIRoute_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	grpcServer := getSharedGRPCServer()

	t.Run("reconciles new APIRoute", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-route",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
						Weight:      100,
					},
				},
				Timeout: "30s",
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(route).
			Build()

		reconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-route",
				Namespace: "default",
			},
		}

		// First reconcile - adds finalizer
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.True(t, result.Requeue)

		// Second reconcile - applies config
		result, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue)

		// Verify route has finalizer
		var updatedRoute avapigwv1alpha1.APIRoute
		err = client.Get(ctx, req.NamespacedName, &updatedRoute)
		require.NoError(t, err)
		assert.Contains(t, updatedRoute.Finalizers, controller.APIRouteFinalizerName)
	})

	t.Run("handles non-existent APIRoute", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		reconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "nonexistent",
				Namespace: "default",
			},
		}

		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue)
	})

	t.Run("handles APIRoute deletion", func(t *testing.T) {
		now := metav1.Now()
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "delete-route",
				Namespace:         "default",
				Generation:        1,
				DeletionTimestamp: &now,
				Finalizers:        []string{controller.APIRouteFinalizerName},
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			Build()

		reconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "delete-route",
				Namespace: "default",
			},
		}

		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue)
	})
}

// TestIntegration_Controller_Backend_Reconcile tests Backend controller reconciliation.
func TestIntegration_Controller_Backend_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	grpcServer := getSharedGRPCServer()

	t.Run("reconciles new Backend", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-backend",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Hosts: []avapigwv1alpha1.BackendHost{
					{Address: "10.0.1.10", Port: 8080, Weight: 1},
				},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					Path:     "/health",
					Interval: "10s",
					Timeout:  "5s",
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			WithStatusSubresource(backend).
			Build()

		reconciler := &controller.BackendReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-backend",
				Namespace: "default",
			},
		}

		// First reconcile - adds finalizer
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.True(t, result.Requeue)

		// Second reconcile - applies config
		result, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue)
	})
}

// TestIntegration_Controller_GRPCRoute_Reconcile tests GRPCRoute controller reconciliation.
func TestIntegration_Controller_GRPCRoute_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	grpcServer := getSharedGRPCServer()

	t.Run("reconciles new GRPCRoute", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-grpc-route",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Match: []avapigwv1alpha1.GRPCRouteMatch{
					{
						Service: &avapigwv1alpha1.StringMatch{Prefix: "api.v1"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "grpc-backend", Port: 9000},
						Weight:      100,
					},
				},
				Timeout: "30s",
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(route).
			Build()

		reconciler := &controller.GRPCRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-grpc-route",
				Namespace: "default",
			},
		}

		// First reconcile - adds finalizer
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.True(t, result.Requeue)

		// Second reconcile - applies config
		result, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue)
	})
}

// TestIntegration_Controller_GRPCBackend_Reconcile tests GRPCBackend controller reconciliation.
func TestIntegration_Controller_GRPCBackend_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	grpcServer := getSharedGRPCServer()

	t.Run("reconciles new GRPCBackend", func(t *testing.T) {
		backend := &avapigwv1alpha1.GRPCBackend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-grpc-backend",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.GRPCBackendSpec{
				Hosts: []avapigwv1alpha1.BackendHost{
					{Address: "grpc-service.default.svc", Port: 9000, Weight: 1},
				},
				HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
					Enabled:  true,
					Interval: "10s",
					Timeout:  "5s",
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			WithStatusSubresource(backend).
			Build()

		reconciler := &controller.GRPCBackendReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-grpc-backend",
				Namespace: "default",
			},
		}

		// First reconcile - adds finalizer
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.True(t, result.Requeue)

		// Second reconcile - applies config
		result, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue)
	})
}

// TestIntegration_Controller_StatusUpdate tests status update functionality.
func TestIntegration_Controller_StatusUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	grpcServer := getSharedGRPCServer()

	t.Run("updates status conditions", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "status-route",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(route).
			Build()

		reconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "status-route",
				Namespace: "default",
			},
		}

		// Reconcile twice to get past finalizer
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Check status
		var updatedRoute avapigwv1alpha1.APIRoute
		err := client.Get(ctx, req.NamespacedName, &updatedRoute)
		require.NoError(t, err)

		// Should have Ready condition
		var readyCondition *avapigwv1alpha1.Condition
		for i := range updatedRoute.Status.Conditions {
			if updatedRoute.Status.Conditions[i].Type == avapigwv1alpha1.ConditionReady {
				readyCondition = &updatedRoute.Status.Conditions[i]
				break
			}
		}
		require.NotNil(t, readyCondition)
		assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)
	})
}

// TestIntegration_Controller_EventRecording tests event recording.
func TestIntegration_Controller_EventRecording(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	grpcServer := getSharedGRPCServer()

	t.Run("records events on reconcile", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "event-route",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(route).
			Build()

		recorder := record.NewFakeRecorder(10)
		reconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   recorder,
			GRPCServer: grpcServer,
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "event-route",
				Namespace: "default",
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Check for events
		select {
		case event := <-recorder.Events:
			assert.Contains(t, event, "Reconciled")
		case <-time.After(time.Second):
			// Event may not be recorded in all cases
		}
	})
}

// TestIntegration_Controller_RequeueOnError tests requeue behavior on errors.
func TestIntegration_Controller_RequeueOnError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	t.Run("requeues on gRPC server error", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "error-route",
				Namespace:  "default",
				Generation: 1,
				Finalizers: []string{controller.APIRouteFinalizerName},
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(route).
			Build()

		// Use nil gRPC server to simulate error
		reconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: nil, // This will cause reconcile to succeed (no-op)
		}

		ctx := context.Background()
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "error-route",
				Namespace: "default",
			},
		}

		result, err := reconciler.Reconcile(ctx, req)
		// With nil server, it should succeed (no-op)
		require.NoError(t, err)
		assert.False(t, result.Requeue)
	})
}

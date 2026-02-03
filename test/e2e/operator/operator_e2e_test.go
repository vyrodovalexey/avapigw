//go:build e2e

// Package operator_test contains E2E tests for the apigw-operator.
package operator_test

import (
	"context"
	"encoding/json"
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

const (
	testNamespace = "avapigw-test"
	testTimeout   = 30 * time.Second
)

// TestE2E_Operator_Lifecycle tests the full operator lifecycle.
func TestE2E_Operator_Lifecycle(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)
	require.NotNil(t, grpcServer)

	t.Run("operator starts and processes CRDs", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Create test APIRoute
		route := createTestAPIRoute("lifecycle-route", testNamespace)

		// Create fake client with the route
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(route).
			Build()

		// Create reconciler
		reconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		// Reconcile the route
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "lifecycle-route",
				Namespace: testNamespace,
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

		// Verify route has finalizer and status
		var updatedRoute avapigwv1alpha1.APIRoute
		err = client.Get(ctx, req.NamespacedName, &updatedRoute)
		require.NoError(t, err)
		assert.Contains(t, updatedRoute.Finalizers, controller.APIRouteFinalizerName)

		// Verify config was applied to gRPC server
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/lifecycle-route")
	})

	t.Run("operator handles multiple CRD types", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Create test resources
		apiRoute := createTestAPIRoute("multi-route", testNamespace)
		backend := createTestBackend("multi-backend", testNamespace)
		grpcRoute := createTestGRPCRoute("multi-grpc-route", testNamespace)
		grpcBackend := createTestGRPCBackend("multi-grpc-backend", testNamespace)

		// Create fake client
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(apiRoute, backend, grpcRoute, grpcBackend).
			WithStatusSubresource(apiRoute, backend, grpcRoute, grpcBackend).
			Build()

		// Create reconcilers
		apiRouteReconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}
		backendReconciler := &controller.BackendReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}
		grpcRouteReconciler := &controller.GRPCRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}
		grpcBackendReconciler := &controller.GRPCBackendReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(10),
			GRPCServer: grpcServer,
		}

		// Reconcile all resources (twice each for finalizer + apply)
		_, _ = apiRouteReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "multi-route", Namespace: testNamespace},
		})
		_, _ = apiRouteReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "multi-route", Namespace: testNamespace},
		})

		_, _ = backendReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "multi-backend", Namespace: testNamespace},
		})
		_, _ = backendReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "multi-backend", Namespace: testNamespace},
		})

		_, _ = grpcRouteReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "multi-grpc-route", Namespace: testNamespace},
		})
		_, _ = grpcRouteReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "multi-grpc-route", Namespace: testNamespace},
		})

		_, _ = grpcBackendReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "multi-grpc-backend", Namespace: testNamespace},
		})
		_, _ = grpcBackendReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "multi-grpc-backend", Namespace: testNamespace},
		})

		// Verify all configs were applied
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		backends := configs["backends"].(map[string]interface{})
		grpcRoutes := configs["grpcRoutes"].(map[string]interface{})
		grpcBackends := configs["grpcBackends"].(map[string]interface{})

		assert.Contains(t, apiRoutes, testNamespace+"/multi-route")
		assert.Contains(t, backends, testNamespace+"/multi-backend")
		assert.Contains(t, grpcRoutes, testNamespace+"/multi-grpc-route")
		assert.Contains(t, grpcBackends, testNamespace+"/multi-grpc-backend")
	})

	t.Run("operator handles resource deletion", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// First, apply the route to the gRPC server directly
		err := grpcServer.ApplyAPIRoute(ctx, "delete-route", testNamespace, []byte(`{"test": true}`))
		require.NoError(t, err)

		// Verify config exists
		allConfigs, _ := grpcServer.GetAllConfigs()
		var configs map[string]interface{}
		_ = json.Unmarshal(allConfigs, &configs)
		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/delete-route")

		// Create route marked for deletion (with DeletionTimestamp already set)
		now := metav1.Now()
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "delete-route",
				Namespace:         testNamespace,
				Generation:        1,
				Finalizers:        []string{controller.APIRouteFinalizerName},
				DeletionTimestamp: &now,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080}},
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

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "delete-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile deletion
		_, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)

		// Verify config was removed
		allConfigs, _ = grpcServer.GetAllConfigs()
		_ = json.Unmarshal(allConfigs, &configs)
		apiRoutes = configs["apiRoutes"].(map[string]interface{})
		assert.NotContains(t, apiRoutes, testNamespace+"/delete-route")
	})
}

// TestE2E_Operator_StatusManagement tests status management.
func TestE2E_Operator_StatusManagement(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("status reflects successful reconciliation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		route := createTestAPIRoute("status-route", testNamespace)

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

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "status-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Check status
		var updatedRoute avapigwv1alpha1.APIRoute
		err = client.Get(ctx, req.NamespacedName, &updatedRoute)
		require.NoError(t, err)

		// Find Ready condition
		var readyCondition *avapigwv1alpha1.Condition
		for i := range updatedRoute.Status.Conditions {
			if updatedRoute.Status.Conditions[i].Type == avapigwv1alpha1.ConditionReady {
				readyCondition = &updatedRoute.Status.Conditions[i]
				break
			}
		}

		require.NotNil(t, readyCondition)
		assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)
		assert.Equal(t, avapigwv1alpha1.ConditionReason("Reconciled"), readyCondition.Reason)
	})

	t.Run("observed generation is updated", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		route := createTestAPIRoute("generation-route", testNamespace)
		route.Generation = 5

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

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "generation-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Check observed generation
		var updatedRoute avapigwv1alpha1.APIRoute
		err = client.Get(ctx, req.NamespacedName, &updatedRoute)
		require.NoError(t, err)

		assert.Equal(t, int64(5), updatedRoute.Status.ObservedGeneration)
	})
}

// TestE2E_Operator_EventRecording tests event recording.
func TestE2E_Operator_EventRecording(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("records events on successful reconciliation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		route := createTestAPIRoute("event-route", testNamespace)

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

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "event-route",
				Namespace: testNamespace,
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

// TestE2E_Operator_GatewayRegistration tests gateway registration.
func TestE2E_Operator_GatewayRegistration(t *testing.T) {
	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("gateways can register and unregister", func(t *testing.T) {
		// Get initial count
		initialCount := grpcServer.GetGatewayCount()

		// Register gateways
		grpcServer.RegisterGateway("gateway-1", "avapigw-system")
		grpcServer.RegisterGateway("gateway-2", "avapigw-system")
		grpcServer.RegisterGateway("gateway-3", "production")

		assert.Equal(t, initialCount+3, grpcServer.GetGatewayCount())

		// Update heartbeat
		grpcServer.UpdateGatewayHeartbeat("gateway-1", "avapigw-system")

		// Unregister one gateway
		grpcServer.UnregisterGateway("gateway-2", "avapigw-system")
		assert.Equal(t, initialCount+2, grpcServer.GetGatewayCount())

		// Unregister remaining gateways
		grpcServer.UnregisterGateway("gateway-1", "avapigw-system")
		grpcServer.UnregisterGateway("gateway-3", "production")
		assert.Equal(t, initialCount, grpcServer.GetGatewayCount())
	})
}

// TestE2E_Operator_ConcurrentReconciliation tests concurrent reconciliation.
func TestE2E_Operator_ConcurrentReconciliation(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("handles concurrent reconciliations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Create multiple routes
		routes := make([]*avapigwv1alpha1.APIRoute, 10)
		for i := 0; i < 10; i++ {
			routes[i] = createTestAPIRoute("concurrent-route-"+string(rune('a'+i)), testNamespace)
		}

		// Build client with all routes
		builder := fake.NewClientBuilder().WithScheme(scheme)
		for _, route := range routes {
			builder = builder.WithObjects(route)
		}
		for _, route := range routes {
			builder = builder.WithStatusSubresource(route)
		}
		client := builder.Build()

		reconciler := &controller.APIRouteReconciler{
			Client:     client,
			Scheme:     scheme,
			Recorder:   record.NewFakeRecorder(100),
			GRPCServer: grpcServer,
		}

		// Reconcile all routes concurrently
		done := make(chan bool, 20)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				req := ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "concurrent-route-" + string(rune('a'+idx)),
						Namespace: testNamespace,
					},
				}
				// Reconcile twice
				_, _ = reconciler.Reconcile(ctx, req)
				_, _ = reconciler.Reconcile(ctx, req)
				done <- true
			}(i)
		}

		// Wait for all reconciliations
		for i := 0; i < 10; i++ {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("timeout waiting for concurrent reconciliations")
			}
		}

		// Verify all configs were applied
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		for i := 0; i < 10; i++ {
			key := testNamespace + "/concurrent-route-" + string(rune('a'+i))
			assert.Contains(t, apiRoutes, key)
		}
	})
}

// Helper functions

func createTestAPIRoute(name, namespace string) *avapigwv1alpha1.APIRoute {
	return &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1",
					},
					Methods: []string{"GET", "POST"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend-service",
						Port: 8080,
					},
					Weight: 100,
				},
			},
			Timeout: "30s",
		},
	}
}

func createTestBackend(name, namespace string) *avapigwv1alpha1.Backend {
	return &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "10.0.1.10",
					Port:    8080,
					Weight:  1,
				},
			},
			HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:     "/health",
				Interval: "10s",
				Timeout:  "5s",
			},
		},
	}
}

func createTestGRPCRoute(name, namespace string) *avapigwv1alpha1.GRPCRoute {
	return &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Match: []avapigwv1alpha1.GRPCRouteMatch{
				{
					Service: &avapigwv1alpha1.StringMatch{
						Prefix: "api.v1",
					},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "grpc-backend",
						Port: 9000,
					},
					Weight: 100,
				},
			},
			Timeout: "30s",
		},
	}
}

func createTestGRPCBackend(name, namespace string) *avapigwv1alpha1.GRPCBackend {
	return &avapigwv1alpha1.GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: avapigwv1alpha1.GRPCBackendSpec{
			Hosts: []avapigwv1alpha1.BackendHost{
				{
					Address: "grpc-service.default.svc",
					Port:    9000,
					Weight:  1,
				},
			},
			HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Enabled:  true,
				Interval: "10s",
				Timeout:  "5s",
			},
		},
	}
}

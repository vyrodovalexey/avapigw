//go:build e2e

// Package operator_test contains E2E tests for operator-gateway integration.
package operator_test

import (
	"context"
	"encoding/json"
	"sync"
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

// TestE2E_GatewayIntegration_ConfigPush tests configuration push to gateways.
func TestE2E_GatewayIntegration_ConfigPush(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("config is pushed to gRPC server on reconcile", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Get initial gateway count
		initialCount := grpcServer.GetGatewayCount()

		// Register a gateway
		grpcServer.RegisterGateway("test-gateway", "avapigw-system")
		assert.Equal(t, initialCount+1, grpcServer.GetGatewayCount())

		// Create and reconcile a route
		route := createTestAPIRoute("push-route", testNamespace)

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(route).
			Build()

		reconciler := &controller.APIRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "push-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was pushed
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/push-route")

		// Cleanup
		grpcServer.UnregisterGateway("test-gateway", "avapigw-system")
	})

	t.Run("config update is pushed to gRPC server", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "update-push-route",
				Namespace:  testNamespace,
				Generation: 1,
				Finalizers: []string{controller.APIRouteFinalizerName},
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080}},
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
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "update-push-route",
				Namespace: testNamespace,
			},
		}

		// Initial reconcile
		_, _ = reconciler.Reconcile(ctx, req)

		// Get initial config
		allConfigs, _ := grpcServer.GetAllConfigs()
		var configs1 map[string]interface{}
		_ = json.Unmarshal(allConfigs, &configs1)

		// Update the route
		var updatedRoute avapigwv1alpha1.APIRoute
		err = client.Get(ctx, req.NamespacedName, &updatedRoute)
		require.NoError(t, err)

		updatedRoute.Spec.Timeout = "60s"
		updatedRoute.Generation = 2
		err = client.Update(ctx, &updatedRoute)
		require.NoError(t, err)

		// Reconcile again
		_, _ = reconciler.Reconcile(ctx, req)

		// Get updated config
		allConfigs, _ = grpcServer.GetAllConfigs()
		var configs2 map[string]interface{}
		_ = json.Unmarshal(allConfigs, &configs2)

		// Verify config was updated (both should contain the route)
		apiRoutes1 := configs1["apiRoutes"].(map[string]interface{})
		apiRoutes2 := configs2["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes1, testNamespace+"/update-push-route")
		assert.Contains(t, apiRoutes2, testNamespace+"/update-push-route")
	})

	t.Run("config deletion is pushed to gRPC server", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// First apply a route
		err := grpcServer.ApplyAPIRoute(ctx, "delete-push-route", testNamespace, []byte(`{"test": true}`))
		require.NoError(t, err)

		// Verify it exists
		allConfigs, _ := grpcServer.GetAllConfigs()
		var configs map[string]interface{}
		_ = json.Unmarshal(allConfigs, &configs)
		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/delete-push-route")

		// Create route marked for deletion
		now := metav1.Now()
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "delete-push-route",
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
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "delete-push-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile deletion
		_, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)

		// Verify config was deleted
		allConfigs, _ = grpcServer.GetAllConfigs()
		_ = json.Unmarshal(allConfigs, &configs)
		apiRoutes = configs["apiRoutes"].(map[string]interface{})
		assert.NotContains(t, apiRoutes, testNamespace+"/delete-push-route")
	})
}

// TestE2E_GatewayIntegration_MultipleGateways tests multiple gateway scenarios.
func TestE2E_GatewayIntegration_MultipleGateways(t *testing.T) {
	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("multiple gateways can register", func(t *testing.T) {
		initialCount := grpcServer.GetGatewayCount()

		// Register multiple gateways
		gateways := []struct {
			name      string
			namespace string
		}{
			{"multi-gateway-1", "avapigw-system"},
			{"multi-gateway-2", "avapigw-system"},
			{"multi-gateway-3", "production"},
			{"multi-gateway-4", "staging"},
		}

		for _, gw := range gateways {
			grpcServer.RegisterGateway(gw.name, gw.namespace)
		}

		assert.Equal(t, initialCount+4, grpcServer.GetGatewayCount())

		// Unregister all gateways
		for _, gw := range gateways {
			grpcServer.UnregisterGateway(gw.name, gw.namespace)
		}

		assert.Equal(t, initialCount, grpcServer.GetGatewayCount())
	})

	t.Run("gateway heartbeat updates", func(t *testing.T) {
		initialCount := grpcServer.GetGatewayCount()

		// Register gateway
		grpcServer.RegisterGateway("heartbeat-gateway", "avapigw-system")

		// Update heartbeat multiple times
		for i := 0; i < 5; i++ {
			grpcServer.UpdateGatewayHeartbeat("heartbeat-gateway", "avapigw-system")
			time.Sleep(10 * time.Millisecond)
		}

		// Gateway should still be registered
		assert.Equal(t, initialCount+1, grpcServer.GetGatewayCount())

		// Cleanup
		grpcServer.UnregisterGateway("heartbeat-gateway", "avapigw-system")
	})
}

// TestE2E_GatewayIntegration_ConfigSync tests configuration synchronization.
func TestE2E_GatewayIntegration_ConfigSync(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("all CRD types are synced", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Create all CRD types
		apiRoute := createTestAPIRoute("sync-route", testNamespace)
		backend := createTestBackend("sync-backend", testNamespace)
		grpcRoute := createTestGRPCRoute("sync-grpc-route", testNamespace)
		grpcBackend := createTestGRPCBackend("sync-grpc-backend", testNamespace)

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(apiRoute, backend, grpcRoute, grpcBackend).
			WithStatusSubresource(apiRoute, backend, grpcRoute, grpcBackend).
			Build()

		// Create reconcilers
		apiRouteReconciler := &controller.APIRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}
		backendReconciler := &controller.BackendReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}
		grpcRouteReconciler := &controller.GRPCRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}
		grpcBackendReconciler := &controller.GRPCBackendReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		// Reconcile all
		_, _ = apiRouteReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "sync-route", Namespace: testNamespace},
		})
		_, _ = apiRouteReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "sync-route", Namespace: testNamespace},
		})

		_, _ = backendReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "sync-backend", Namespace: testNamespace},
		})
		_, _ = backendReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "sync-backend", Namespace: testNamespace},
		})

		_, _ = grpcRouteReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "sync-grpc-route", Namespace: testNamespace},
		})
		_, _ = grpcRouteReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "sync-grpc-route", Namespace: testNamespace},
		})

		_, _ = grpcBackendReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "sync-grpc-backend", Namespace: testNamespace},
		})
		_, _ = grpcBackendReconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "sync-grpc-backend", Namespace: testNamespace},
		})

		// Verify all configs are synced
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		backends := configs["backends"].(map[string]interface{})
		grpcRoutes := configs["grpcRoutes"].(map[string]interface{})
		grpcBackends := configs["grpcBackends"].(map[string]interface{})

		assert.Contains(t, apiRoutes, testNamespace+"/sync-route")
		assert.Contains(t, backends, testNamespace+"/sync-backend")
		assert.Contains(t, grpcRoutes, testNamespace+"/sync-grpc-route")
		assert.Contains(t, grpcBackends, testNamespace+"/sync-grpc-backend")
	})
}

// TestE2E_GatewayIntegration_ConcurrentUpdates tests concurrent configuration updates.
func TestE2E_GatewayIntegration_ConcurrentUpdates(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("handles concurrent config updates", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Create multiple routes
		numRoutes := 20
		routes := make([]*avapigwv1alpha1.APIRoute, numRoutes)
		for i := 0; i < numRoutes; i++ {
			routes[i] = &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "concurrent-int-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
					Namespace:  testNamespace,
					Generation: 1,
				},
				Spec: avapigwv1alpha1.APIRouteSpec{
					Match: []avapigwv1alpha1.RouteMatch{
						{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v" + string(rune('0'+i))}},
					},
					Route: []avapigwv1alpha1.RouteDestination{
						{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080}},
					},
				},
			}
		}

		builder := fake.NewClientBuilder().WithScheme(scheme)
		for _, route := range routes {
			builder = builder.WithObjects(route)
		}
		for _, route := range routes {
			builder = builder.WithStatusSubresource(route)
		}
		client := builder.Build()

		reconciler := &controller.APIRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(100),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		// Reconcile all routes concurrently
		var wg sync.WaitGroup
		for i := 0; i < numRoutes; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				req := ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "concurrent-int-" + string(rune('a'+idx%26)) + string(rune('0'+idx/26)),
						Namespace: testNamespace,
					},
				}
				_, _ = reconciler.Reconcile(ctx, req)
				_, _ = reconciler.Reconcile(ctx, req)
			}(i)
		}

		// Wait with timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Success
		case <-time.After(30 * time.Second):
			t.Fatal("timeout waiting for concurrent reconciliations")
		}

		// Verify all configs were applied
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		for i := 0; i < numRoutes; i++ {
			key := testNamespace + "/concurrent-int-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			assert.Contains(t, apiRoutes, key, "Route %d should exist", i)
		}
	})
}

// TestE2E_GatewayIntegration_HotReload tests hot reload scenarios.
func TestE2E_GatewayIntegration_HotReload(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("config changes are applied without restart", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Get initial gateway count
		initialCount := grpcServer.GetGatewayCount()

		// Register a gateway
		grpcServer.RegisterGateway("hot-reload-gateway", "avapigw-system")

		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "hot-reload-route",
				Namespace:  testNamespace,
				Generation: 1,
				Finalizers: []string{controller.APIRouteFinalizerName},
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend-v1", Port: 8080}},
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
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "hot-reload-route",
				Namespace: testNamespace,
			},
		}

		// Initial reconcile
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify initial config
		allConfigs, _ := grpcServer.GetAllConfigs()
		var configs map[string]interface{}
		_ = json.Unmarshal(allConfigs, &configs)
		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/hot-reload-route")

		// Simulate multiple updates
		for i := 0; i < 5; i++ {
			var updatedRoute avapigwv1alpha1.APIRoute
			err := client.Get(ctx, req.NamespacedName, &updatedRoute)
			require.NoError(t, err)

			updatedRoute.Spec.Timeout = avapigwv1alpha1.Duration(string(rune('0'+i+1)) + "0s")
			updatedRoute.Generation = int64(i + 2)
			err = client.Update(ctx, &updatedRoute)
			require.NoError(t, err)

			_, _ = reconciler.Reconcile(ctx, req)
		}

		// Verify gateway is still registered
		assert.Equal(t, initialCount+1, grpcServer.GetGatewayCount())

		// Verify config still exists
		allConfigs, _ = grpcServer.GetAllConfigs()
		_ = json.Unmarshal(allConfigs, &configs)
		apiRoutes = configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/hot-reload-route")

		// Cleanup
		grpcServer.UnregisterGateway("hot-reload-gateway", "avapigw-system")
	})
}

// TestE2E_GatewayIntegration_FailureRecovery tests failure recovery scenarios.
func TestE2E_GatewayIntegration_FailureRecovery(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("reconciler handles nil gRPC server gracefully", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "nil-server-route",
				Namespace:  testNamespace,
				Generation: 1,
				Finalizers: []string{controller.APIRouteFinalizerName},
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
			WithStatusSubresource(route).
			Build()

		// Create reconciler with nil gRPC server
		reconciler := &controller.APIRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    nil, // Nil server
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "nil-server-route",
				Namespace: testNamespace,
			},
		}

		// Should not panic
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue)
	})

	t.Run("reconciler handles non-existent resource", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		reconciler := &controller.APIRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "non-existent-route",
				Namespace: testNamespace,
			},
		}

		// Should not error for non-existent resource
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue)
	})
}

// TestE2E_GatewayIntegration_ScaleTest tests scaling scenarios.
func TestE2E_GatewayIntegration_ScaleTest(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("handles large number of CRDs", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Create many routes
		numRoutes := 50
		routes := make([]*avapigwv1alpha1.APIRoute, numRoutes)
		for i := 0; i < numRoutes; i++ {
			routes[i] = &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "scale-route-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
					Namespace:  testNamespace,
					Generation: 1,
				},
				Spec: avapigwv1alpha1.APIRouteSpec{
					Match: []avapigwv1alpha1.RouteMatch{
						{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/scale/" + string(rune('0'+i))}},
					},
					Route: []avapigwv1alpha1.RouteDestination{
						{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080}},
					},
				},
			}
		}

		builder := fake.NewClientBuilder().WithScheme(scheme)
		for _, route := range routes {
			builder = builder.WithObjects(route)
		}
		for _, route := range routes {
			builder = builder.WithStatusSubresource(route)
		}
		client := builder.Build()

		reconciler := &controller.APIRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(200),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		// Reconcile all routes
		start := time.Now()
		for i := 0; i < numRoutes; i++ {
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "scale-route-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
					Namespace: testNamespace,
				},
			}
			_, _ = reconciler.Reconcile(ctx, req)
			_, _ = reconciler.Reconcile(ctx, req)
		}
		elapsed := time.Since(start)

		t.Logf("Reconciled %d routes in %v", numRoutes, elapsed)

		// Verify all configs were applied
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		// Check at least some routes exist (shared server may have other routes)
		for i := 0; i < numRoutes; i++ {
			key := testNamespace + "/scale-route-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			assert.Contains(t, apiRoutes, key)
		}
	})

	t.Run("handles many gateways", func(t *testing.T) {
		initialCount := grpcServer.GetGatewayCount()

		// Register many gateways
		numGateways := 100
		for i := 0; i < numGateways; i++ {
			grpcServer.RegisterGateway(
				"scale-gateway-"+string(rune('a'+i%26))+string(rune('a'+i/26)),
				"namespace-"+string(rune('0'+i%10)),
			)
		}

		assert.Equal(t, initialCount+numGateways, grpcServer.GetGatewayCount())

		// Update heartbeats
		for i := 0; i < numGateways; i++ {
			grpcServer.UpdateGatewayHeartbeat(
				"scale-gateway-"+string(rune('a'+i%26))+string(rune('a'+i/26)),
				"namespace-"+string(rune('0'+i%10)),
			)
		}

		// Unregister all
		for i := 0; i < numGateways; i++ {
			grpcServer.UnregisterGateway(
				"scale-gateway-"+string(rune('a'+i%26))+string(rune('a'+i/26)),
				"namespace-"+string(rune('0'+i%10)),
			)
		}

		assert.Equal(t, initialCount, grpcServer.GetGatewayCount())
	})
}

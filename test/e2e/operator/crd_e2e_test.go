//go:build e2e

// Package operator_test contains E2E tests for the apigw-operator CRD operations.
package operator_test

import (
	"context"
	"encoding/json"
	"testing"

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

// TestE2E_CRD_APIRoute_CRUD tests APIRoute CRUD operations.
func TestE2E_CRD_APIRoute_CRUD(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("create APIRoute", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "crud-route",
				Namespace:  testNamespace,
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI:     &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"},
						Methods: []string{"GET", "POST", "PUT", "DELETE"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
						Weight:      100,
					},
				},
				Timeout: "30s",
				Retries: &avapigwv1alpha1.RetryPolicy{
					Attempts:      3,
					PerTryTimeout: "10s",
					RetryOn:       "5xx,reset",
				},
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
				Name:      "crud-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was created
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/crud-route")
	})

	t.Run("update APIRoute", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "update-route",
				Namespace:  testNamespace,
				Generation: 1,
				Finalizers: []string{controller.APIRouteFinalizerName},
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"}},
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
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "update-route",
				Namespace: testNamespace,
			},
		}

		// Initial reconcile
		_, _ = reconciler.Reconcile(ctx, req)

		// Update the route
		var updatedRoute avapigwv1alpha1.APIRoute
		err := client.Get(ctx, req.NamespacedName, &updatedRoute)
		require.NoError(t, err)

		updatedRoute.Spec.Timeout = "60s"
		updatedRoute.Generation = 2
		err = client.Update(ctx, &updatedRoute)
		require.NoError(t, err)

		// Reconcile again
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was updated
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/update-route")
	})

	t.Run("delete APIRoute", func(t *testing.T) {
		now := metav1.Now()
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "delete-crud-route",
				Namespace:         testNamespace,
				Generation:        1,
				Finalizers:        []string{controller.APIRouteFinalizerName},
				DeletionTimestamp: &now,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
					},
				},
			},
		}

		// First apply the route
		err := grpcServer.ApplyAPIRoute(ctx, "delete-crud-route", testNamespace, []byte(`{"test": true}`))
		require.NoError(t, err)

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
				Name:      "delete-crud-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile deletion
		_, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)

		// Verify config was deleted
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.NotContains(t, apiRoutes, testNamespace+"/delete-crud-route")
	})
}

// TestE2E_CRD_Backend_CRUD tests Backend CRUD operations.
func TestE2E_CRD_Backend_CRUD(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("create Backend with full config", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "full-backend",
				Namespace:  testNamespace,
				Generation: 1,
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Hosts: []avapigwv1alpha1.BackendHost{
					{Address: "10.0.1.10", Port: 8080, Weight: 50},
					{Address: "10.0.1.11", Port: 8080, Weight: 50},
				},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					Path:               "/health",
					Interval:           "10s",
					Timeout:            "5s",
					HealthyThreshold:   3,
					UnhealthyThreshold: 2,
				},
				LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
					Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
				},
				CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
					Enabled:          true,
					Threshold:        10,
					Timeout:          "30s",
					HalfOpenRequests: 5,
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			WithStatusSubresource(backend).
			Build()

		reconciler := &controller.BackendReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "full-backend",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was created
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		backends := configs["backends"].(map[string]interface{})
		assert.Contains(t, backends, testNamespace+"/full-backend")
	})

	t.Run("update Backend hosts", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "update-backend",
				Namespace:  testNamespace,
				Generation: 1,
				Finalizers: []string{controller.BackendFinalizerName},
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Hosts: []avapigwv1alpha1.BackendHost{
					{Address: "10.0.1.10", Port: 8080, Weight: 1},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			WithStatusSubresource(backend).
			Build()

		reconciler := &controller.BackendReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "update-backend",
				Namespace: testNamespace,
			},
		}

		// Initial reconcile
		_, _ = reconciler.Reconcile(ctx, req)

		// Update the backend
		var updatedBackend avapigwv1alpha1.Backend
		err := client.Get(ctx, req.NamespacedName, &updatedBackend)
		require.NoError(t, err)

		updatedBackend.Spec.Hosts = append(updatedBackend.Spec.Hosts, avapigwv1alpha1.BackendHost{
			Address: "10.0.1.11",
			Port:    8080,
			Weight:  1,
		})
		updatedBackend.Generation = 2
		err = client.Update(ctx, &updatedBackend)
		require.NoError(t, err)

		// Reconcile again
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was updated
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		backends := configs["backends"].(map[string]interface{})
		assert.Contains(t, backends, testNamespace+"/update-backend")
	})
}

// TestE2E_CRD_GRPCRoute_CRUD tests GRPCRoute CRUD operations.
func TestE2E_CRD_GRPCRoute_CRUD(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("create GRPCRoute with full config", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "full-grpc-route",
				Namespace:  testNamespace,
				Generation: 1,
			},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Match: []avapigwv1alpha1.GRPCRouteMatch{
					{
						Service: &avapigwv1alpha1.StringMatch{Prefix: "api.v1"},
						Method:  &avapigwv1alpha1.StringMatch{Exact: "GetUser"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "grpc-backend", Port: 9000},
						Weight:      100,
					},
				},
				Timeout: "30s",
				Retries: &avapigwv1alpha1.GRPCRetryPolicy{
					Attempts:      3,
					PerTryTimeout: "10s",
					RetryOn:       "unavailable,resource-exhausted",
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route).
			WithStatusSubresource(route).
			Build()

		reconciler := &controller.GRPCRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "full-grpc-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was created
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		grpcRoutes := configs["grpcRoutes"].(map[string]interface{})
		assert.Contains(t, grpcRoutes, testNamespace+"/full-grpc-route")
	})
}

// TestE2E_CRD_GRPCBackend_CRUD tests GRPCBackend CRUD operations.
func TestE2E_CRD_GRPCBackend_CRUD(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("create GRPCBackend with full config", func(t *testing.T) {
		backend := &avapigwv1alpha1.GRPCBackend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "full-grpc-backend",
				Namespace:  testNamespace,
				Generation: 1,
			},
			Spec: avapigwv1alpha1.GRPCBackendSpec{
				Hosts: []avapigwv1alpha1.BackendHost{
					{Address: "grpc-service-1.default.svc", Port: 9000, Weight: 50},
					{Address: "grpc-service-2.default.svc", Port: 9000, Weight: 50},
				},
				HealthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
					Enabled:            true,
					Service:            "grpc.health.v1.Health",
					Interval:           "10s",
					Timeout:            "5s",
					HealthyThreshold:   3,
					UnhealthyThreshold: 2,
				},
				LoadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
					Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
				},
				ConnectionPool: &avapigwv1alpha1.GRPCConnectionPoolConfig{
					MaxIdleConns:    10,
					MaxConnsPerHost: 100,
					IdleConnTimeout: "5m",
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			WithStatusSubresource(backend).
			Build()

		reconciler := &controller.GRPCBackendReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "full-grpc-backend",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was created
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		grpcBackends := configs["grpcBackends"].(map[string]interface{})
		assert.Contains(t, grpcBackends, testNamespace+"/full-grpc-backend")
	})
}

// TestE2E_CRD_NamespaceIsolation tests namespace isolation for CRDs.
func TestE2E_CRD_NamespaceIsolation(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("same name in different namespaces", func(t *testing.T) {
		route1 := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "shared-name",
				Namespace:  "namespace-1",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/ns1"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend-1", Port: 8080}},
				},
			},
		}

		route2 := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "shared-name",
				Namespace:  "namespace-2",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/ns2"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend-2", Port: 8080}},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(route1, route2).
			WithStatusSubresource(route1, route2).
			Build()

		reconciler := &controller.APIRouteReconciler{
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		// Reconcile both routes
		for _, ns := range []string{"namespace-1", "namespace-2"} {
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "shared-name",
					Namespace: ns,
				},
			}
			_, _ = reconciler.Reconcile(ctx, req)
			_, _ = reconciler.Reconcile(ctx, req)
		}

		// Verify both configs exist
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, "namespace-1/shared-name")
		assert.Contains(t, apiRoutes, "namespace-2/shared-name")
	})

	t.Run("delete only affects specific namespace", func(t *testing.T) {
		// Delete from namespace-1
		err := grpcServer.DeleteAPIRoute(ctx, "shared-name", "namespace-1")
		require.NoError(t, err)

		// Verify only namespace-1 was deleted
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.NotContains(t, apiRoutes, "namespace-1/shared-name")
		assert.Contains(t, apiRoutes, "namespace-2/shared-name")
	})
}

// TestE2E_CRD_ComplexRouteMatching tests complex route matching configurations.
func TestE2E_CRD_ComplexRouteMatching(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("route with multiple match conditions", func(t *testing.T) {
		present := true
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "complex-match-route",
				Namespace:  testNamespace,
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI:     &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"},
						Methods: []string{"GET", "POST"},
						Headers: []avapigwv1alpha1.HeaderMatch{
							{Name: "Authorization", Present: &present},
							{Name: "X-API-Version", Exact: "v1"},
						},
						QueryParams: []avapigwv1alpha1.QueryParamMatch{
							{Name: "format", Exact: "json"},
						},
					},
					{
						URI:     &avapigwv1alpha1.URIMatch{Regex: "^/api/v[0-9]+/.*$"},
						Methods: []string{"PUT", "DELETE"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend-1", Port: 8080},
						Weight:      70,
					},
					{
						Destination: avapigwv1alpha1.Destination{Host: "backend-2", Port: 8080},
						Weight:      30,
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
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "complex-match-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was created
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/complex-match-route")
	})
}

// TestE2E_CRD_AdvancedFeatures tests advanced CRD features.
func TestE2E_CRD_AdvancedFeatures(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("route with rate limiting and caching", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "advanced-route",
				Namespace:  testNamespace,
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080}},
				},
				RateLimit: &avapigwv1alpha1.RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 100,
					Burst:             200,
					PerClient:         true,
				},
				Cache: &avapigwv1alpha1.CacheConfig{
					Enabled:              true,
					TTL:                  "5m",
					KeyComponents:        []string{"path", "query", "header:Accept"},
					StaleWhileRevalidate: "1m",
				},
				CORS: &avapigwv1alpha1.CORSConfig{
					AllowOrigins:     []string{"https://example.com", "https://app.example.com"},
					AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
					AllowHeaders:     []string{"Content-Type", "Authorization", "X-Request-ID"},
					ExposeHeaders:    []string{"X-Request-ID", "X-Response-Time"},
					MaxAge:           86400,
					AllowCredentials: true,
				},
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
				Name:      "advanced-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was created
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/advanced-route")
	})

	t.Run("route with transformation", func(t *testing.T) {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "transform-route",
				Namespace:  testNamespace,
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080}},
				},
				Transform: &avapigwv1alpha1.TransformConfig{
					Request: &avapigwv1alpha1.RequestTransform{
						Template: `{"wrapped": {{.Body}}}`,
					},
					Response: &avapigwv1alpha1.ResponseTransform{
						AllowFields: []string{"id", "name", "email"},
						DenyFields:  []string{"password", "secret"},
						FieldMappings: map[string]string{
							"user_id":   "id",
							"user_name": "name",
						},
					},
				},
				Headers: &avapigwv1alpha1.HeaderManipulation{
					Request: &avapigwv1alpha1.HeaderOperation{
						Set:    map[string]string{"X-Gateway": "avapigw"},
						Add:    map[string]string{"X-Request-ID": "{{.RequestID}}"},
						Remove: []string{"X-Internal-Header"},
					},
					Response: &avapigwv1alpha1.HeaderOperation{
						Set: map[string]string{"X-Response-Time": "{{.ResponseTime}}"},
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
			Client:        client,
			Scheme:        scheme,
			Recorder:      record.NewFakeRecorder(10),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "transform-route",
				Namespace: testNamespace,
			},
		}

		// Reconcile twice
		_, _ = reconciler.Reconcile(ctx, req)
		_, _ = reconciler.Reconcile(ctx, req)

		// Verify config was created
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		assert.Contains(t, apiRoutes, testNamespace+"/transform-route")
	})
}

// TestE2E_CRD_BatchOperations tests batch operations on CRDs.
func TestE2E_CRD_BatchOperations(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	t.Run("batch create multiple routes", func(t *testing.T) {
		routes := make([]*avapigwv1alpha1.APIRoute, 5)
		for i := 0; i < 5; i++ {
			routes[i] = &avapigwv1alpha1.APIRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "batch-route-" + string(rune('a'+i)),
					Namespace:  testNamespace,
					Generation: 1,
				},
				Spec: avapigwv1alpha1.APIRouteSpec{
					Match: []avapigwv1alpha1.RouteMatch{
						{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v" + string(rune('1'+i))}},
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
			Recorder:      record.NewFakeRecorder(50),
			GRPCServer:    grpcServer,
			StatusUpdater: controller.NewStatusUpdater(client),
		}

		// Reconcile all routes
		for i := 0; i < 5; i++ {
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "batch-route-" + string(rune('a'+i)),
					Namespace: testNamespace,
				},
			}
			_, _ = reconciler.Reconcile(ctx, req)
			_, _ = reconciler.Reconcile(ctx, req)
		}

		// Verify all configs were created
		allConfigs, err := grpcServer.GetAllConfigs()
		require.NoError(t, err)

		var configs map[string]interface{}
		err = json.Unmarshal(allConfigs, &configs)
		require.NoError(t, err)

		apiRoutes := configs["apiRoutes"].(map[string]interface{})
		for i := 0; i < 5; i++ {
			key := testNamespace + "/batch-route-" + string(rune('a'+i))
			assert.Contains(t, apiRoutes, key)
		}
	})
}

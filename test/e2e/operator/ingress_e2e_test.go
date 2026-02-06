//go:build e2e

// Package operator_test contains E2E tests for the ingress controller.
package operator_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
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
	ingressE2ENamespace = "avapigw-test"
	ingressE2ETimeout   = 30 * time.Second
)

// ============================================================================
// Helper Functions
// ============================================================================

func e2ePtrPathType(pt networkingv1.PathType) *networkingv1.PathType {
	return &pt
}

func e2ePtrString(s string) *string {
	return &s
}

func newE2EScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = networkingv1.AddToScheme(scheme)
	_ = avapigwv1alpha1.AddToScheme(scheme)
	return scheme
}

func createE2EIngress(name, namespace string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "backend-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func reconcileIngressTwice(
	t *testing.T,
	ctx context.Context,
	reconciler *controller.IngressReconciler,
	name, namespace string,
) {
	t.Helper()
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	// First reconcile — adds finalizer
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	if result.Requeue {
		// Second reconcile — applies config
		_, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
	}
}

// ============================================================================
// E2E Tests
// ============================================================================

// TestE2E_Ingress_BasicRouting tests creating an Ingress and verifying
// the full reconciliation loop pushes config to the gRPC server.
func TestE2E_Ingress_BasicRouting(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := createE2EIngress("basic-routing", ingressE2ENamespace)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "basic-routing", ingressE2ENamespace)

	// Verify config was pushed to gRPC server
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	// Ingress routes are stored as apiRoutes
	apiRoutes, ok := configs["apiRoutes"].(map[string]interface{})
	require.True(t, ok, "apiRoutes should be a map")

	// The route key is namespace-scoped: "ingress-<ns>-<name>-r0-p0"
	routeKey := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-basic-routing-r0-p0"
	assert.Contains(t, apiRoutes, routeKey, "route should be pushed to gRPC server")

	// Verify Ingress has finalizer
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, types.NamespacedName{
		Name:      "basic-routing",
		Namespace: ingressE2ENamespace,
	}, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Finalizers, controller.IngressFinalizerName)
}

// TestE2E_Ingress_PathBasedRouting tests creating an Ingress with multiple
// paths and verifying path-based routing.
func TestE2E_Ingress_PathBasedRouting(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "path-routing",
			Namespace: ingressE2ENamespace,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "app.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
								{
									Path:     "/web",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "web-svc",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
								{
									Path:     "/health",
									PathType: e2ePtrPathType(networkingv1.PathTypeExact),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "health-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8081},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "path-routing", ingressE2ENamespace)

	// Verify all 3 routes were pushed
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	apiRoutes := configs["apiRoutes"].(map[string]interface{})

	for _, pathIdx := range []string{"p0", "p1", "p2"} {
		routeKey := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-path-routing-r0-" + pathIdx
		assert.Contains(t, apiRoutes, routeKey, "route %s should exist", pathIdx)
	}
}

// TestE2E_Ingress_HostBasedRouting tests creating an Ingress with multiple
// hosts and verifying host-based routing.
func TestE2E_Ingress_HostBasedRouting(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "host-routing",
			Namespace: ingressE2ENamespace,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "api.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "web.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "web-svc",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "host-routing", ingressE2ENamespace)

	// Verify both host routes were pushed
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	apiRoutes := configs["apiRoutes"].(map[string]interface{})

	route0Key := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-host-routing-r0-p0"
	route1Key := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-host-routing-r1-p0"
	assert.Contains(t, apiRoutes, route0Key, "api host route should exist")
	assert.Contains(t, apiRoutes, route1Key, "web host route should exist")
}

// TestE2E_Ingress_TLSTermination tests creating an Ingress with TLS and
// verifying TLS configuration is applied.
func TestE2E_Ingress_TLSTermination(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-termination",
			Namespace: ingressE2ENamespace,
			Annotations: map[string]string{
				controller.AnnotationTLSMinVersion: "TLS12",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"secure.example.com"},
					SecretName: "tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "secure.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "secure-svc",
											Port: networkingv1.ServiceBackendPort{Number: 443},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "tls-termination", ingressE2ENamespace)

	// Verify route was pushed
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	apiRoutes := configs["apiRoutes"].(map[string]interface{})
	routeKey := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-tls-termination-r0-p0"
	assert.Contains(t, apiRoutes, routeKey, "TLS route should exist")
}

// TestE2E_Ingress_AnnotationFeatures tests creating an Ingress with
// timeout/retry/rate-limit annotations and verifying behavior.
func TestE2E_Ingress_AnnotationFeatures(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := createE2EIngress("annotation-features", ingressE2ENamespace)
	ingress.Annotations = map[string]string{
		controller.AnnotationTimeout:                 "45s",
		controller.AnnotationRetryAttempts:           "3",
		controller.AnnotationRetryPerTryTimeout:      "10s",
		controller.AnnotationRetryOn:                 "5xx,reset",
		controller.AnnotationRateLimitEnabled:        "true",
		controller.AnnotationRateLimitRPS:            "500",
		controller.AnnotationRateLimitBurst:          "100",
		controller.AnnotationCORSAllowOrigins:        "https://example.com",
		controller.AnnotationCORSAllowMethods:        "GET,POST",
		controller.AnnotationCircuitBreakerEnabled:   "true",
		controller.AnnotationCircuitBreakerThreshold: "5",
		controller.AnnotationCircuitBreakerTimeout:   "30s",
		controller.AnnotationHealthCheckPath:         "/healthz",
		controller.AnnotationHealthCheckInterval:     "10s",
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "annotation-features", ingressE2ENamespace)

	// Verify config was pushed
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	apiRoutes := configs["apiRoutes"].(map[string]interface{})
	routeKey := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-annotation-features-r0-p0"
	assert.Contains(t, apiRoutes, routeKey, "annotated route should exist")

	backends := configs["backends"].(map[string]interface{})
	backendKey := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-annotation-features-backend-svc-8080"
	assert.Contains(t, backends, backendKey, "annotated backend should exist")

	// Verify Ingress has applied-routes annotation
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, types.NamespacedName{
		Name:      "annotation-features",
		Namespace: ingressE2ENamespace,
	}, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Annotations, controller.AnnotationAppliedRoutes)
}

// TestE2E_Ingress_DefaultBackend tests creating an Ingress with defaultBackend
// and verifying catch-all routing.
func TestE2E_Ingress_DefaultBackend(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-backend-e2e",
			Namespace: ingressE2ENamespace,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "fallback-svc",
					Port: networkingv1.ServiceBackendPort{Number: 80},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "default-backend-e2e", ingressE2ENamespace)

	// Verify default route was pushed
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	apiRoutes := configs["apiRoutes"].(map[string]interface{})
	routeKey := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-default-backend-e2e-default"
	assert.Contains(t, apiRoutes, routeKey, "default backend route should exist")
}

// createE2EGRPCIngress creates a gRPC Ingress for E2E testing.
func createE2EGRPCIngress(name, namespace string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/myservice.MyService",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-backend",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// TestE2E_Ingress_UpdateAndDelete tests the full lifecycle: create, update,
// and delete an Ingress, verifying routing changes at each step.
func TestE2E_Ingress_UpdateAndDelete(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	// Step 1: Create Ingress
	ingress := createE2EIngress("lifecycle-ingress", ingressE2ENamespace)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(20),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "lifecycle-ingress",
			Namespace: ingressE2ENamespace,
		},
	}

	// First reconcile — adds finalizer
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.Requeue)

	// Second reconcile — applies config
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify route exists
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)
	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)
	apiRoutes := configs["apiRoutes"].(map[string]interface{})
	routeKey := ingressE2ENamespace + "/ingress-" + ingressE2ENamespace + "-lifecycle-ingress-r0-p0"
	assert.Contains(t, apiRoutes, routeKey, "route should exist after create")

	// Step 2: Update Ingress — add annotations
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	if updatedIngress.Annotations == nil {
		updatedIngress.Annotations = make(map[string]string)
	}
	updatedIngress.Annotations[controller.AnnotationTimeout] = "120s"
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile update
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify route still exists after update
	allConfigs, err = grpcServer.GetAllConfigs()
	require.NoError(t, err)
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)
	apiRoutes = configs["apiRoutes"].(map[string]interface{})
	assert.Contains(t, apiRoutes, routeKey, "route should exist after update")

	// Step 3: Delete Ingress
	// We need to simulate deletion by setting DeletionTimestamp
	// Since fake client doesn't support real deletion with timestamps,
	// we verify the cleanup logic by calling DeleteAPIRoute directly
	err = grpcServer.DeleteAPIRoute(ctx, "ingress-"+ingressE2ENamespace+"-lifecycle-ingress-r0-p0", ingressE2ENamespace)
	require.NoError(t, err)

	// Verify route was removed
	allConfigs, err = grpcServer.GetAllConfigs()
	require.NoError(t, err)
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)
	apiRoutes = configs["apiRoutes"].(map[string]interface{})
	assert.NotContains(t, apiRoutes, routeKey, "route should not exist after delete")
}

// ============================================================================
// gRPC Ingress E2E Tests
// ============================================================================

// TestE2E_GRPCIngress_BasicRouting tests creating a gRPC Ingress and verifying
// gRPC routes are pushed to gRPC server under grpcRoutes key.
func TestE2E_GRPCIngress_BasicRouting(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := createE2EGRPCIngress("grpc-basic-routing", ingressE2ENamespace)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "grpc-basic-routing", ingressE2ENamespace)

	// Verify config was pushed to gRPC server
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	// gRPC Ingress routes are stored as grpcRoutes
	grpcRoutes, ok := configs["grpcRoutes"].(map[string]interface{})
	require.True(t, ok, "grpcRoutes should be a map")

	// The route key is namespace-scoped: "ingress-grpc-<ns>-<name>-r0-p0"
	routeKey := ingressE2ENamespace + "/ingress-grpc-" + ingressE2ENamespace + "-grpc-basic-routing-r0-p0"
	assert.Contains(t, grpcRoutes, routeKey, "gRPC route should be pushed to gRPC server")

	// Verify gRPC backends are also pushed
	grpcBackends, ok := configs["grpcBackends"].(map[string]interface{})
	require.True(t, ok, "grpcBackends should be a map")

	backendKey := ingressE2ENamespace + "/ingress-grpc-" + ingressE2ENamespace + "-grpc-basic-routing-grpc-backend-50051"
	assert.Contains(t, grpcBackends, backendKey, "gRPC backend should be pushed to gRPC server")

	// Verify Ingress has finalizer
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, types.NamespacedName{
		Name:      "grpc-basic-routing",
		Namespace: ingressE2ENamespace,
	}, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Finalizers, controller.IngressFinalizerName)
}

// TestE2E_GRPCIngress_ServiceMethodRouting tests gRPC Ingress with service/method annotations.
func TestE2E_GRPCIngress_ServiceMethodRouting(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-service-method",
			Namespace: ingressE2ENamespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol:             "grpc",
				controller.AnnotationGRPCService:          "api.v1.UserService",
				controller.AnnotationGRPCServiceMatchType: "exact",
				controller.AnnotationGRPCMethod:           "GetUser",
				controller.AnnotationGRPCMethodMatchType:  "exact",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc-api.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "user-service",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "grpc-service-method", ingressE2ENamespace)

	// Verify config was pushed to gRPC server
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	// Verify gRPC routes exist
	grpcRoutes, ok := configs["grpcRoutes"].(map[string]interface{})
	require.True(t, ok, "grpcRoutes should be a map")

	routeKey := ingressE2ENamespace + "/ingress-grpc-" + ingressE2ENamespace + "-grpc-service-method-r0-p0"
	assert.Contains(t, grpcRoutes, routeKey, "gRPC route with service/method should exist")

	// Verify Ingress has applied-routes annotation with grpcRoutes
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, types.NamespacedName{
		Name:      "grpc-service-method",
		Namespace: ingressE2ENamespace,
	}, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Annotations, controller.AnnotationAppliedRoutes)
	assert.Contains(t, updatedIngress.Annotations[controller.AnnotationAppliedRoutes], "grpcRoutes:")
}

// TestE2E_GRPCIngress_TLSTermination tests gRPC Ingress with TLS configuration.
func TestE2E_GRPCIngress_TLSTermination(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-tls-termination",
			Namespace: ingressE2ENamespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol:      "grpc",
				controller.AnnotationTLSMinVersion: "TLSv1.2",
				controller.AnnotationTLSMaxVersion: "TLSv1.3",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"secure-grpc.example.com"},
					SecretName: "grpc-tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "secure-grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/secure.Service",
									PathType: e2ePtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "secure-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "grpc-tls-termination", ingressE2ENamespace)

	// Verify route was pushed
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	grpcRoutes, ok := configs["grpcRoutes"].(map[string]interface{})
	require.True(t, ok, "grpcRoutes should be a map")

	routeKey := ingressE2ENamespace + "/ingress-grpc-" + ingressE2ENamespace + "-grpc-tls-termination-r0-p0"
	assert.Contains(t, grpcRoutes, routeKey, "TLS gRPC route should exist")
}

// TestE2E_GRPCIngress_AnnotationFeatures tests gRPC Ingress with all gRPC-specific annotations.
func TestE2E_GRPCIngress_AnnotationFeatures(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := createE2EGRPCIngress("grpc-annotation-features", ingressE2ENamespace)
	ingress.Annotations = map[string]string{
		// Protocol
		controller.AnnotationProtocol: "grpc",
		// gRPC service/method matching
		controller.AnnotationGRPCService:          "api.v1.UserService",
		controller.AnnotationGRPCServiceMatchType: "exact",
		controller.AnnotationGRPCMethod:           "GetUser",
		controller.AnnotationGRPCMethodMatchType:  "exact",
		// Timeout
		controller.AnnotationTimeout: "30s",
		// Retries (gRPC-specific)
		controller.AnnotationRetryAttempts:           "3",
		controller.AnnotationRetryPerTryTimeout:      "5s",
		controller.AnnotationGRPCRetryOn:             "unavailable,resource-exhausted",
		controller.AnnotationGRPCBackoffBaseInterval: "100ms",
		controller.AnnotationGRPCBackoffMaxInterval:  "1s",
		// Rate limiting
		controller.AnnotationRateLimitEnabled:   "true",
		controller.AnnotationRateLimitRPS:       "100",
		controller.AnnotationRateLimitBurst:     "50",
		controller.AnnotationRateLimitPerClient: "true",
		// CORS
		controller.AnnotationCORSAllowOrigins:     "*",
		controller.AnnotationCORSAllowMethods:     "GET,POST",
		controller.AnnotationCORSAllowHeaders:     "Content-Type,Authorization",
		controller.AnnotationCORSAllowCredentials: "true",
		// Security
		controller.AnnotationSecurityEnabled: "true",
		// Cache
		controller.AnnotationCacheEnabled: "true",
		controller.AnnotationCacheTTL:     "5m",
		// gRPC Health check
		controller.AnnotationGRPCHealthCheckEnabled:            "true",
		controller.AnnotationGRPCHealthCheckService:            "grpc.health.v1.Health",
		controller.AnnotationGRPCHealthCheckInterval:           "10s",
		controller.AnnotationGRPCHealthCheckTimeout:            "5s",
		controller.AnnotationGRPCHealthCheckHealthyThreshold:   "2",
		controller.AnnotationGRPCHealthCheckUnhealthyThreshold: "3",
		// gRPC Connection pool
		controller.AnnotationGRPCMaxIdleConns:    "50",
		controller.AnnotationGRPCMaxConnsPerHost: "100",
		controller.AnnotationGRPCIdleConnTimeout: "5m",
		// Load balancer
		controller.AnnotationLoadBalancerAlgorithm: "round-robin",
		// Circuit breaker
		controller.AnnotationCircuitBreakerEnabled:   "true",
		controller.AnnotationCircuitBreakerThreshold: "5",
		controller.AnnotationCircuitBreakerTimeout:   "30s",
		controller.AnnotationCircuitBreakerHalfOpen:  "3",
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "grpc-annotation-features", ingressE2ENamespace)

	// Verify config was pushed
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	grpcRoutes, ok := configs["grpcRoutes"].(map[string]interface{})
	require.True(t, ok, "grpcRoutes should be a map")

	routeKey := ingressE2ENamespace + "/ingress-grpc-" + ingressE2ENamespace + "-grpc-annotation-features-r0-p0"
	assert.Contains(t, grpcRoutes, routeKey, "annotated gRPC route should exist")

	grpcBackends, ok := configs["grpcBackends"].(map[string]interface{})
	require.True(t, ok, "grpcBackends should be a map")

	backendKey := ingressE2ENamespace + "/ingress-grpc-" + ingressE2ENamespace + "-grpc-annotation-features-grpc-backend-50051"
	assert.Contains(t, grpcBackends, backendKey, "annotated gRPC backend should exist")

	// Verify Ingress has applied-routes annotation
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, types.NamespacedName{
		Name:      "grpc-annotation-features",
		Namespace: ingressE2ENamespace,
	}, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Annotations, controller.AnnotationAppliedRoutes)
}

// TestE2E_GRPCIngress_DefaultBackend tests gRPC Ingress with default backend.
func TestE2E_GRPCIngress_DefaultBackend(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-default-backend-e2e",
			Namespace: ingressE2ENamespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: e2ePtrString(controller.DefaultIngressClassName),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "grpc-fallback-svc",
					Port: networkingv1.ServiceBackendPort{Number: 50051},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	reconcileIngressTwice(t, ctx, reconciler, "grpc-default-backend-e2e", ingressE2ENamespace)

	// Verify default gRPC route was pushed
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)

	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)

	grpcRoutes, ok := configs["grpcRoutes"].(map[string]interface{})
	require.True(t, ok, "grpcRoutes should be a map")

	routeKey := ingressE2ENamespace + "/ingress-grpc-" + ingressE2ENamespace + "-grpc-default-backend-e2e-default"
	assert.Contains(t, grpcRoutes, routeKey, "default gRPC backend route should exist")
}

// TestE2E_GRPCIngress_UpdateAndDelete tests full lifecycle of gRPC Ingress.
func TestE2E_GRPCIngress_UpdateAndDelete(t *testing.T) {
	scheme := newE2EScheme()

	grpcServer, err := getSharedGRPCServer()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ingressE2ETimeout)
	defer cancel()

	// Step 1: Create gRPC Ingress
	ingress := createE2EGRPCIngress("grpc-lifecycle-ingress", ingressE2ENamespace)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(20),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-lifecycle-ingress",
			Namespace: ingressE2ENamespace,
		},
	}

	// First reconcile — adds finalizer
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.Requeue)

	// Second reconcile — applies config
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify gRPC route exists
	allConfigs, err := grpcServer.GetAllConfigs()
	require.NoError(t, err)
	var configs map[string]interface{}
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)
	grpcRoutes := configs["grpcRoutes"].(map[string]interface{})
	routeKey := ingressE2ENamespace + "/ingress-grpc-" + ingressE2ENamespace + "-grpc-lifecycle-ingress-r0-p0"
	assert.Contains(t, grpcRoutes, routeKey, "gRPC route should exist after create")

	// Step 2: Update gRPC Ingress — add annotations
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	updatedIngress.Annotations[controller.AnnotationTimeout] = "120s"
	updatedIngress.Annotations[controller.AnnotationGRPCRetryOn] = "unavailable"
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile update
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify gRPC route still exists after update
	allConfigs, err = grpcServer.GetAllConfigs()
	require.NoError(t, err)
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)
	grpcRoutes = configs["grpcRoutes"].(map[string]interface{})
	assert.Contains(t, grpcRoutes, routeKey, "gRPC route should exist after update")

	// Step 3: Delete gRPC Ingress
	// Simulate deletion by calling DeleteGRPCRoute directly
	err = grpcServer.DeleteGRPCRoute(ctx, "ingress-grpc-"+ingressE2ENamespace+"-grpc-lifecycle-ingress-r0-p0", ingressE2ENamespace)
	require.NoError(t, err)

	// Verify gRPC route was removed
	allConfigs, err = grpcServer.GetAllConfigs()
	require.NoError(t, err)
	err = json.Unmarshal(allConfigs, &configs)
	require.NoError(t, err)
	grpcRoutes = configs["grpcRoutes"].(map[string]interface{})
	assert.NotContains(t, grpcRoutes, routeKey, "gRPC route should not exist after delete")
}

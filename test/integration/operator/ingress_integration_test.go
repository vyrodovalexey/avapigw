//go:build integration

// Package operator_test contains integration tests for the ingress controller.
package operator_test

import (
	"context"
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

	"github.com/vyrodovalexey/avapigw/internal/operator/controller"
)

const (
	ingressTestNamespace = "avapigw-test"
	ingressTestTimeout   = 30 * time.Second
)

// ============================================================================
// Helper Functions
// ============================================================================

func ingressPtrPathType(pt networkingv1.PathType) *networkingv1.PathType {
	return &pt
}

func ingressPtrString(s string) *string {
	return &s
}

func newIngressScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = networkingv1.AddToScheme(scheme)
	return scheme
}

func createTestIngress(name, namespace string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ingressPtrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ingressPtrPathType(networkingv1.PathTypePrefix),
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

func newIngressReconciler(
	client fake.ClientBuilder,
	scheme *runtime.Scheme,
	recorder *record.FakeRecorder,
) *controller.IngressReconciler {
	c := client.Build()
	return &controller.IngressReconciler{
		Client:              c,
		Scheme:              scheme,
		Recorder:            recorder,
		GRPCServer:          getSharedGRPCServer(),
		IngressStatusUpdate: controller.NewIngressStatusUpdater(c, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

// TestIntegration_IngressReconciler_CreateIngress tests creating an Ingress
// resource and verifying the reconciler processes it and pushes config.
func TestIntegration_IngressReconciler_CreateIngress(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := createTestIngress("create-ingress", ingressTestNamespace)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            recorder,
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "create-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// First reconcile — adds finalizer
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.Requeue, "first reconcile should requeue to add finalizer")

	// Second reconcile — applies config
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify Ingress has finalizer
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Finalizers, controller.IngressFinalizerName)

	// Verify event was recorded
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, controller.EventReasonIngressReconciled)
	case <-time.After(time.Second):
		// Event may not be recorded in all cases with fake recorder
	}
}

// TestIntegration_IngressReconciler_UpdateIngress tests updating an Ingress
// and verifying config is updated.
func TestIntegration_IngressReconciler_UpdateIngress(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := createTestIngress("update-ingress", ingressTestNamespace)
	ingress.Finalizers = []string{controller.IngressFinalizerName}

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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "update-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// Initial reconcile
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Update the Ingress — add a new path
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	updatedIngress.Spec.Rules[0].HTTP.Paths = append(
		updatedIngress.Spec.Rules[0].HTTP.Paths,
		networkingv1.HTTPIngressPath{
			Path:     "/web",
			PathType: ingressPtrPathType(networkingv1.PathTypePrefix),
			Backend: networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "web-svc",
					Port: networkingv1.ServiceBackendPort{Number: 80},
				},
			},
		},
	)
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile again
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify the applied-routes annotation was updated
	var finalIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &finalIngress)
	require.NoError(t, err)
	assert.Contains(t, finalIngress.Annotations, controller.AnnotationAppliedRoutes)
}

// TestIntegration_IngressReconciler_DeleteIngress tests deleting an Ingress
// and verifying routes are cleaned up.
func TestIntegration_IngressReconciler_DeleteIngress(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	now := metav1.Now()
	ingress := createTestIngress("delete-ingress", ingressTestNamespace)
	ingress.Finalizers = []string{controller.IngressFinalizerName}
	ingress.DeletionTimestamp = &now

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "delete-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// Reconcile deletion
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)
}

// TestIntegration_IngressReconciler_IngressClassMatching tests that only
// Ingress resources with matching IngressClass are processed.
func TestIntegration_IngressReconciler_IngressClassMatching(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	t.Run("matching IngressClass via spec", func(t *testing.T) {
		ingress := createTestIngress("matching-class", ingressTestNamespace)
		ingress.Spec.IngressClassName = ingressPtrString(controller.DefaultIngressClassName)

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

		ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
		defer cancel()

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "matching-class",
				Namespace: ingressTestNamespace,
			},
		}

		// Should process (add finalizer)
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.True(t, result.Requeue, "matching IngressClass should be processed")
	})

	t.Run("non-matching IngressClass via spec", func(t *testing.T) {
		ingress := createTestIngress("non-matching-class", ingressTestNamespace)
		ingress.Spec.IngressClassName = ingressPtrString("nginx")

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

		ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
		defer cancel()

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "non-matching-class",
				Namespace: ingressTestNamespace,
			},
		}

		// Should be ignored (no requeue, no error)
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue, "non-matching IngressClass should be ignored")

		// Verify no finalizer was added
		var updatedIngress networkingv1.Ingress
		err = client.Get(ctx, req.NamespacedName, &updatedIngress)
		require.NoError(t, err)
		assert.NotContains(t, updatedIngress.Finalizers, controller.IngressFinalizerName)
	})

	t.Run("matching IngressClass via legacy annotation", func(t *testing.T) {
		ingress := createTestIngress("legacy-class", ingressTestNamespace)
		ingress.Spec.IngressClassName = nil
		ingress.Annotations = map[string]string{
			controller.AnnotationIngressClass: controller.DefaultIngressClassName,
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

		ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
		defer cancel()

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "legacy-class",
				Namespace: ingressTestNamespace,
			},
		}

		// Should process (add finalizer)
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.True(t, result.Requeue, "legacy annotation IngressClass should be processed")
	})

	t.Run("no IngressClass specified", func(t *testing.T) {
		ingress := createTestIngress("no-class", ingressTestNamespace)
		ingress.Spec.IngressClassName = nil

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

		ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
		defer cancel()

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "no-class",
				Namespace: ingressTestNamespace,
			},
		}

		// Should be ignored
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, result.Requeue, "Ingress with no class should be ignored")
	})
}

// TestIntegration_IngressReconciler_StatusUpdate tests that Ingress status
// is updated with LoadBalancer address.
func TestIntegration_IngressReconciler_StatusUpdate(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := createTestIngress("status-ingress", ingressTestNamespace)
	ingress.Finalizers = []string{controller.IngressFinalizerName}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	statusUpdater := controller.NewIngressStatusUpdater(client, "10.0.0.100")

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(10),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: statusUpdater,
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "status-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// Reconcile
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify status was updated with LoadBalancer IP
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	require.Len(t, updatedIngress.Status.LoadBalancer.Ingress, 1)
	assert.Equal(t, "10.0.0.100", updatedIngress.Status.LoadBalancer.Ingress[0].IP)
}

// TestIntegration_IngressReconciler_MultipleIngresses tests creating multiple
// Ingresses and verifying all are processed.
func TestIntegration_IngressReconciler_MultipleIngresses(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingresses := make([]*networkingv1.Ingress, 5)
	for i := 0; i < 5; i++ {
		name := "multi-ingress-" + string(rune('a'+i))
		ingresses[i] = createTestIngress(name, ingressTestNamespace)
		ingresses[i].Finalizers = []string{controller.IngressFinalizerName}
		ingresses[i].Spec.Rules[0].Host = name + ".example.com"
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, ing := range ingresses {
		builder = builder.WithObjects(ing)
	}
	for _, ing := range ingresses {
		builder = builder.WithStatusSubresource(ing)
	}
	client := builder.Build()

	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(50),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	// Reconcile all Ingresses
	for i := 0; i < 5; i++ {
		name := "multi-ingress-" + string(rune('a'+i))
		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      name,
				Namespace: ingressTestNamespace,
			},
		}

		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err, "reconcile %s", name)
		assert.False(t, result.Requeue, "reconcile %s should not requeue", name)
	}

	// Verify all Ingresses have applied-routes annotation
	for i := 0; i < 5; i++ {
		name := "multi-ingress-" + string(rune('a'+i))
		var ing networkingv1.Ingress
		err := client.Get(ctx, types.NamespacedName{
			Name:      name,
			Namespace: ingressTestNamespace,
		}, &ing)
		require.NoError(t, err)
		assert.Contains(t, ing.Annotations, controller.AnnotationAppliedRoutes,
			"Ingress %s should have applied-routes annotation", name)
	}
}

// ============================================================================
// gRPC Ingress Helper Functions
// ============================================================================

func createGRPCTestIngress(name, namespace string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ingressPtrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/myservice.MyService",
									PathType: ingressPtrPathType(networkingv1.PathTypePrefix),
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

// ============================================================================
// gRPC Ingress Integration Tests
// ============================================================================

// TestIntegration_IngressReconciler_GRPCIngress tests creating a gRPC Ingress
// resource and verifying the reconciler processes it and pushes gRPC config.
func TestIntegration_IngressReconciler_GRPCIngress(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := createGRPCTestIngress("grpc-create-ingress", ingressTestNamespace)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &controller.IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            recorder,
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(client, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    controller.DefaultIngressClassName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-create-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// First reconcile — adds finalizer
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.Requeue, "first reconcile should requeue to add finalizer")

	// Second reconcile — applies gRPC config
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify Ingress has finalizer
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Finalizers, controller.IngressFinalizerName)

	// Verify applied-routes annotation contains gRPC route keys
	appliedRoutes, ok := updatedIngress.Annotations[controller.AnnotationAppliedRoutes]
	require.True(t, ok, "expected applied-routes annotation")
	assert.Contains(t, appliedRoutes, "ingress-grpc-", "expected gRPC route key in applied-routes")

	// Verify event was recorded
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, controller.EventReasonIngressReconciled)
	case <-time.After(time.Second):
		// Event may not be recorded in all cases with fake recorder
	}
}

// TestIntegration_IngressReconciler_GRPCIngressUpdate tests updating a gRPC Ingress
// and verifying gRPC config is updated.
func TestIntegration_IngressReconciler_GRPCIngressUpdate(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := createGRPCTestIngress("grpc-update-ingress", ingressTestNamespace)
	ingress.Finalizers = []string{controller.IngressFinalizerName}

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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-update-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// Initial reconcile
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Update the gRPC Ingress — add a new path
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	updatedIngress.Spec.Rules[0].HTTP.Paths = append(
		updatedIngress.Spec.Rules[0].HTTP.Paths,
		networkingv1.HTTPIngressPath{
			Path:     "/another.Service",
			PathType: ingressPtrPathType(networkingv1.PathTypePrefix),
			Backend: networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "another-grpc-svc",
					Port: networkingv1.ServiceBackendPort{Number: 50052},
				},
			},
		},
	)
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile again
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify the applied-routes annotation was updated
	var finalIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &finalIngress)
	require.NoError(t, err)
	assert.Contains(t, finalIngress.Annotations, controller.AnnotationAppliedRoutes)

	// Should have 2 gRPC routes now
	appliedRoutes := finalIngress.Annotations[controller.AnnotationAppliedRoutes]
	assert.Contains(t, appliedRoutes, "r0-p0", "expected first path route")
	assert.Contains(t, appliedRoutes, "r0-p1", "expected second path route")
}

// TestIntegration_IngressReconciler_GRPCIngressDelete tests deleting a gRPC Ingress
// and verifying gRPC routes are cleaned up.
func TestIntegration_IngressReconciler_GRPCIngressDelete(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	now := metav1.Now()
	ingress := createGRPCTestIngress("grpc-delete-ingress", ingressTestNamespace)
	ingress.Finalizers = []string{controller.IngressFinalizerName}
	ingress.DeletionTimestamp = &now

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-delete-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// Reconcile deletion
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)
}

// TestIntegration_IngressReconciler_GRPCAnnotationChanges tests updating gRPC-specific
// annotations and verifying config changes propagate.
func TestIntegration_IngressReconciler_GRPCAnnotationChanges(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := createGRPCTestIngress("grpc-annotation-change", ingressTestNamespace)
	ingress.Finalizers = []string{controller.IngressFinalizerName}

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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-annotation-change",
			Namespace: ingressTestNamespace,
		},
	}

	// Initial reconcile (basic gRPC annotations)
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Add gRPC-specific annotations
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	updatedIngress.Annotations[controller.AnnotationGRPCService] = "api.v1.UserService"
	updatedIngress.Annotations[controller.AnnotationGRPCServiceMatchType] = "exact"
	updatedIngress.Annotations[controller.AnnotationGRPCMethod] = "GetUser"
	updatedIngress.Annotations[controller.AnnotationGRPCMethodMatchType] = "exact"
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile again with service/method annotations
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Add retry annotations
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	updatedIngress.Annotations[controller.AnnotationRetryAttempts] = "5"
	updatedIngress.Annotations[controller.AnnotationGRPCRetryOn] = "unavailable,resource-exhausted"
	updatedIngress.Annotations[controller.AnnotationGRPCBackoffBaseInterval] = "100ms"
	updatedIngress.Annotations[controller.AnnotationGRPCBackoffMaxInterval] = "1s"
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile again with retry annotations
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Add health check and connection pool annotations
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	updatedIngress.Annotations[controller.AnnotationGRPCHealthCheckEnabled] = "true"
	updatedIngress.Annotations[controller.AnnotationGRPCHealthCheckService] = "grpc.health.v1.Health"
	updatedIngress.Annotations[controller.AnnotationGRPCHealthCheckInterval] = "10s"
	updatedIngress.Annotations[controller.AnnotationGRPCMaxIdleConns] = "50"
	updatedIngress.Annotations[controller.AnnotationGRPCMaxConnsPerHost] = "100"
	updatedIngress.Annotations[controller.AnnotationGRPCIdleConnTimeout] = "5m"
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile again with health check and connection pool annotations
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify the Ingress still has the finalizer and applied-routes annotation
	var finalIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &finalIngress)
	require.NoError(t, err)
	assert.Contains(t, finalIngress.Finalizers, controller.IngressFinalizerName)
	assert.Contains(t, finalIngress.Annotations, controller.AnnotationAppliedRoutes)
}

// TestIntegration_IngressReconciler_GRPCWithTLS tests gRPC Ingress with TLS configuration.
func TestIntegration_IngressReconciler_GRPCWithTLS(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-tls-ingress",
			Namespace: ingressTestNamespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol:      "grpc",
				controller.AnnotationTLSMinVersion: "TLS12",
				controller.AnnotationTLSMaxVersion: "TLS13",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ingressPtrString(controller.DefaultIngressClassName),
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
									Path:     "/",
									PathType: ingressPtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "secure-grpc-svc",
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
	ingress.Finalizers = []string{controller.IngressFinalizerName}

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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-tls-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// Reconcile
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify the Ingress has applied-routes annotation with gRPC route
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Annotations, controller.AnnotationAppliedRoutes)
	assert.Contains(t, updatedIngress.Annotations[controller.AnnotationAppliedRoutes], "ingress-grpc-")
}

// TestIntegration_IngressReconciler_GRPCDefaultBackend tests gRPC Ingress with default backend.
func TestIntegration_IngressReconciler_GRPCDefaultBackend(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-default-backend-ingress",
			Namespace: ingressTestNamespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ingressPtrString(controller.DefaultIngressClassName),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "grpc-fallback-svc",
					Port: networkingv1.ServiceBackendPort{Number: 50051},
				},
			},
		},
	}
	ingress.Finalizers = []string{controller.IngressFinalizerName}

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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-default-backend-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// Reconcile
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify the Ingress has applied-routes annotation with default gRPC route
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Annotations, controller.AnnotationAppliedRoutes)
	assert.Contains(t, updatedIngress.Annotations[controller.AnnotationAppliedRoutes], "default")
}

// TestIntegration_IngressReconciler_GRPCMultipleRules tests gRPC Ingress with multiple rules.
func TestIntegration_IngressReconciler_GRPCMultipleRules(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-multi-rule-ingress",
			Namespace: ingressTestNamespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ingressPtrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "api.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ingressPtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "user-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
								{
									Path:     "/api.v1.OrderService",
									PathType: ingressPtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "order-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50052},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "internal.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/internal.AdminService",
									PathType: ingressPtrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "admin-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50053},
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
	ingress.Finalizers = []string{controller.IngressFinalizerName}

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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-multi-rule-ingress",
			Namespace: ingressTestNamespace,
		},
	}

	// Reconcile
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify the Ingress has applied-routes annotation with multiple gRPC routes
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)
	assert.Contains(t, updatedIngress.Annotations, controller.AnnotationAppliedRoutes)

	appliedRoutes := updatedIngress.Annotations[controller.AnnotationAppliedRoutes]
	// Should have 3 routes: r0-p0, r0-p1, r1-p0
	assert.Contains(t, appliedRoutes, "r0-p0")
	assert.Contains(t, appliedRoutes, "r0-p1")
	assert.Contains(t, appliedRoutes, "r1-p0")
}

// ============================================================================
// HTTP Ingress Integration Tests (continued)
// ============================================================================

// TestIntegration_IngressReconciler_AnnotationChanges tests updating annotations
// and verifying config changes propagate.
func TestIntegration_IngressReconciler_AnnotationChanges(t *testing.T) {
	scheme := newIngressScheme()
	grpcServer := getSharedGRPCServer()

	ingress := createTestIngress("annotation-change", ingressTestNamespace)
	ingress.Finalizers = []string{controller.IngressFinalizerName}

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

	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "annotation-change",
			Namespace: ingressTestNamespace,
		},
	}

	// Initial reconcile (no annotations)
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Add timeout annotation
	var updatedIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	if updatedIngress.Annotations == nil {
		updatedIngress.Annotations = make(map[string]string)
	}
	updatedIngress.Annotations[controller.AnnotationTimeout] = "60s"
	updatedIngress.Annotations[controller.AnnotationRateLimitEnabled] = "true"
	updatedIngress.Annotations[controller.AnnotationRateLimitRPS] = "100"
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile again with new annotations
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Add CORS annotations
	err = client.Get(ctx, req.NamespacedName, &updatedIngress)
	require.NoError(t, err)

	updatedIngress.Annotations[controller.AnnotationCORSAllowOrigins] = "https://example.com"
	updatedIngress.Annotations[controller.AnnotationCORSAllowMethods] = "GET,POST"
	err = client.Update(ctx, &updatedIngress)
	require.NoError(t, err)

	// Reconcile again
	result, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify the Ingress still has the finalizer and applied-routes annotation
	var finalIngress networkingv1.Ingress
	err = client.Get(ctx, req.NamespacedName, &finalIngress)
	require.NoError(t, err)
	assert.Contains(t, finalIngress.Finalizers, controller.IngressFinalizerName)
	assert.Contains(t, finalIngress.Annotations, controller.AnnotationAppliedRoutes)
}

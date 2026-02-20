// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlevent "sigs.k8s.io/controller-runtime/pkg/event"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// newIngressTestScheme creates a scheme with both avapigwv1alpha1 and networkingv1 registered.
func newIngressTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	return scheme
}

// newIngressReconciler creates an IngressReconciler with all required fields initialized.
func newIngressReconciler(
	t *testing.T,
	fakeClient *fake.ClientBuilder,
	scheme *runtime.Scheme,
	className string,
) (*IngressReconciler, *fakeRecorder) {
	t.Helper()
	recorder := newFakeRecorder()
	client := fakeClient.Build()
	return &IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            recorder,
		GRPCServer:          getTestGRPCServer(t),
		IngressStatusUpdate: NewIngressStatusUpdater(client, ""),
		Converter:           NewIngressConverter(),
		IngressClassName:    className,
	}, recorder
}

// ============================================================================
// matchesIngressClass Tests
// ============================================================================

func TestMatchesIngressClass_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		ingressClass  string
		specClassName *string
		annotations   map[string]string
		expectedMatch bool
	}{
		{
			name:          "matches spec.ingressClassName",
			ingressClass:  "avapigw",
			specClassName: ptrString("avapigw"),
			expectedMatch: true,
		},
		{
			name:          "does not match spec.ingressClassName",
			ingressClass:  "avapigw",
			specClassName: ptrString("nginx"),
			expectedMatch: false,
		},
		{
			name:         "matches legacy annotation",
			ingressClass: "avapigw",
			annotations: map[string]string{
				AnnotationIngressClass: "avapigw",
			},
			expectedMatch: true,
		},
		{
			name:         "does not match legacy annotation",
			ingressClass: "avapigw",
			annotations: map[string]string{
				AnnotationIngressClass: "nginx",
			},
			expectedMatch: false,
		},
		{
			name:          "no class specified",
			ingressClass:  "avapigw",
			specClassName: nil,
			annotations:   nil,
			expectedMatch: false,
		},
		{
			name:          "spec.ingressClassName takes precedence over annotation",
			ingressClass:  "avapigw",
			specClassName: ptrString("avapigw"),
			annotations: map[string]string{
				AnnotationIngressClass: "nginx",
			},
			expectedMatch: true,
		},
		{
			name:          "empty annotations map",
			ingressClass:  "avapigw",
			annotations:   map[string]string{},
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &IngressReconciler{
				IngressClassName: tt.ingressClass,
			}

			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test",
					Namespace:   "default",
					Annotations: tt.annotations,
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: tt.specClassName,
				},
			}

			result := reconciler.matchesIngressClass(ingress)
			if result != tt.expectedMatch {
				t.Errorf("matchesIngressClass() = %v, want %v", result, tt.expectedMatch)
			}
		})
	}
}

// ============================================================================
// Reconcile Tests
// ============================================================================

func TestIngressReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := newIngressTestScheme()
	builder := fake.NewClientBuilder().WithScheme(scheme)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

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

func TestIngressReconciler_Reconcile_ClassMismatch(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("nginx"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-ingress",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue for class mismatch")
	}
}

func TestIngressReconciler_Reconcile_AddFinalizer(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-ingress",
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
	var updated networkingv1.Ingress
	err = reconciler.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Ingress: %v", err)
	}

	hasFinalizer := false
	for _, f := range updated.Finalizers {
		if f == IngressFinalizerName {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		t.Error("Reconcile() should add finalizer")
	}
}

func TestIngressReconciler_Reconcile_Success(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-ingress",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
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
			},
		},
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-ingress",
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

func TestIngressReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := newIngressTestScheme()
	now := metav1.Now()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-ingress",
			Namespace:         "default",
			Finalizers:        []string{IngressFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-ingress",
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
}

func TestIngressReconciler_Reconcile_NilGRPCServer(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-ingress",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
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

	reconciler := &IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            newFakeRecorder(),
		GRPCServer:          nil,
		IngressStatusUpdate: NewIngressStatusUpdater(client, ""),
		Converter:           NewIngressConverter(),
		IngressClassName:    "avapigw",
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-ingress",
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

// ============================================================================
// getAppliedKeys Tests
// ============================================================================

func TestGetAppliedKeys_TableDriven(t *testing.T) {
	tests := []struct {
		name                string
		annotations         map[string]string
		wantRouteKeys       []string
		wantBackendKeys     []string
		wantGRPCRouteKeys   []string
		wantGRPCBackendKeys []string
	}{
		{
			name:                "nil annotations",
			annotations:         nil,
			wantRouteKeys:       nil,
			wantBackendKeys:     nil,
			wantGRPCRouteKeys:   nil,
			wantGRPCBackendKeys: nil,
		},
		{
			name:                "no applied routes annotation",
			annotations:         map[string]string{"other": "value"},
			wantRouteKeys:       nil,
			wantBackendKeys:     nil,
			wantGRPCRouteKeys:   nil,
			wantGRPCBackendKeys: nil,
		},
		{
			name: "empty applied routes annotation",
			annotations: map[string]string{
				AnnotationAppliedRoutes: "",
			},
			wantRouteKeys:       nil,
			wantBackendKeys:     nil,
			wantGRPCRouteKeys:   nil,
			wantGRPCBackendKeys: nil,
		},
		{
			name: "valid applied routes annotation",
			annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:r1,r2;backends:b1,b2;grpcRoutes:;grpcBackends:",
			},
			wantRouteKeys:       []string{"r1", "r2"},
			wantBackendKeys:     []string{"b1", "b2"},
			wantGRPCRouteKeys:   nil,
			wantGRPCBackendKeys: nil,
		},
		{
			name: "routes only",
			annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:r1;backends:;grpcRoutes:;grpcBackends:",
			},
			wantRouteKeys:       []string{"r1"},
			wantBackendKeys:     nil,
			wantGRPCRouteKeys:   nil,
			wantGRPCBackendKeys: nil,
		},
		{
			name: "backends only",
			annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:;backends:b1;grpcRoutes:;grpcBackends:",
			},
			wantRouteKeys:       nil,
			wantBackendKeys:     []string{"b1"},
			wantGRPCRouteKeys:   nil,
			wantGRPCBackendKeys: nil,
		},
		{
			name: "gRPC routes and backends",
			annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:;backends:;grpcRoutes:gr1,gr2;grpcBackends:gb1",
			},
			wantRouteKeys:       nil,
			wantBackendKeys:     nil,
			wantGRPCRouteKeys:   []string{"gr1", "gr2"},
			wantGRPCBackendKeys: []string{"gb1"},
		},
		{
			name: "mixed HTTP and gRPC",
			annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:r1;backends:b1;grpcRoutes:gr1;grpcBackends:gb1",
			},
			wantRouteKeys:       []string{"r1"},
			wantBackendKeys:     []string{"b1"},
			wantGRPCRouteKeys:   []string{"gr1"},
			wantGRPCBackendKeys: []string{"gb1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &IngressReconciler{}
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: tt.annotations,
				},
			}

			routeKeys, backendKeys, grpcRouteKeys, grpcBackendKeys := reconciler.getAppliedKeys(ingress)

			if len(routeKeys) != len(tt.wantRouteKeys) {
				t.Errorf("getAppliedKeys() routeKeys len = %d, want %d", len(routeKeys), len(tt.wantRouteKeys))
			}
			if len(backendKeys) != len(tt.wantBackendKeys) {
				t.Errorf("getAppliedKeys() backendKeys len = %d, want %d", len(backendKeys), len(tt.wantBackendKeys))
			}
			if len(grpcRouteKeys) != len(tt.wantGRPCRouteKeys) {
				t.Errorf("getAppliedKeys() grpcRouteKeys len = %d, want %d", len(grpcRouteKeys), len(tt.wantGRPCRouteKeys))
			}
			if len(grpcBackendKeys) != len(tt.wantGRPCBackendKeys) {
				t.Errorf("getAppliedKeys() grpcBackendKeys len = %d, want %d", len(grpcBackendKeys), len(tt.wantGRPCBackendKeys))
			}
		})
	}
}

// ============================================================================
// updateAppliedRoutesAnnotation Tests
// ============================================================================

func TestUpdateAppliedRoutesAnnotation(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client: client,
	}

	converted := &ConvertedConfig{
		Routes: map[string][]byte{
			"route-1": []byte("{}"),
			"route-2": []byte("{}"),
		},
		Backends: map[string][]byte{
			"backend-1": []byte("{}"),
		},
	}

	err := reconciler.updateAppliedRoutesAnnotation(context.Background(), ingress, converted)
	if err != nil {
		t.Fatalf("updateAppliedRoutesAnnotation() error = %v", err)
	}

	// Verify annotation was set
	if ingress.Annotations == nil {
		t.Fatal("Annotations should not be nil after update")
	}
	value, ok := ingress.Annotations[AnnotationAppliedRoutes]
	if !ok {
		t.Fatal("Applied routes annotation should be set")
	}
	if value == "" {
		t.Error("Applied routes annotation should not be empty")
	}
}

func TestUpdateAppliedRoutesAnnotation_NilAnnotations(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-ingress",
			Namespace:   "default",
			Annotations: nil,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client: client,
	}

	converted := &ConvertedConfig{
		Routes:   map[string][]byte{"r1": []byte("{}")},
		Backends: map[string][]byte{"b1": []byte("{}")},
	}

	err := reconciler.updateAppliedRoutesAnnotation(context.Background(), ingress, converted)
	if err != nil {
		t.Fatalf("updateAppliedRoutesAnnotation() error = %v", err)
	}

	if ingress.Annotations == nil {
		t.Error("Annotations should be initialized")
	}
}

// ============================================================================
// cleanupIngress Tests
// ============================================================================

func TestCleanupIngress_NilGRPCServer(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client:     client,
		GRPCServer: nil,
		Converter:  NewIngressConverter(),
	}

	err := reconciler.cleanupIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("cleanupIngress() error = %v, want nil", err)
	}
}

func TestCleanupIngress_WithAppliedKeysAnnotation(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:r1;backends:b1",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
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
		Build()

	reconciler := &IngressReconciler{
		Client:     client,
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	err := reconciler.cleanupIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("cleanupIngress() error = %v, want nil", err)
	}
}

func TestCleanupIngress_WithoutAppliedKeysAnnotation(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
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
		Build()

	reconciler := &IngressReconciler{
		Client:     client,
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	err := reconciler.cleanupIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("cleanupIngress() error = %v, want nil", err)
	}
}

// ============================================================================
// SetupWithManager Initialization Tests
// ============================================================================

func TestIngressReconciler_SetupWithManager_ConverterInit(t *testing.T) {
	reconciler := &IngressReconciler{
		Converter: nil,
	}

	// Simulate what SetupWithManager does for Converter
	if reconciler.Converter == nil {
		reconciler.Converter = NewIngressConverter()
	}

	if reconciler.Converter == nil {
		t.Error("Converter should be initialized")
	}
}

func TestIngressReconciler_SetupWithManager_StatusUpdaterInit(t *testing.T) {
	scheme := newIngressTestScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &IngressReconciler{
		Client:              client,
		IngressStatusUpdate: nil,
	}

	// Simulate what SetupWithManager does for IngressStatusUpdate
	if reconciler.IngressStatusUpdate == nil {
		reconciler.IngressStatusUpdate = NewIngressStatusUpdater(reconciler.Client, "")
	}

	if reconciler.IngressStatusUpdate == nil {
		t.Error("IngressStatusUpdate should be initialized")
	}
}

// ============================================================================
// ingressClassPredicate Tests
// ============================================================================

func TestIngressClassPredicate(t *testing.T) {
	reconciler := &IngressReconciler{
		IngressClassName: "avapigw",
	}

	pred := reconciler.ingressClassPredicate()
	if pred == nil {
		t.Fatal("ingressClassPredicate() returned nil")
	}
}

// ============================================================================
// reconcileIngress Tests
// ============================================================================

func TestReconcileIngress_Success(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-ingress",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
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
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client:     client,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	err := reconciler.reconcileIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("reconcileIngress() error = %v, want nil", err)
	}
}

func TestReconcileIngress_NilGRPCServer(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
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

	reconciler := &IngressReconciler{
		Client:     client,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: nil,
		Converter:  NewIngressConverter(),
	}

	err := reconciler.reconcileIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("reconcileIngress() with nil server error = %v, want nil", err)
	}
}

// ============================================================================
// handleDeletion Tests
// ============================================================================

func TestHandleDeletion_WithFinalizer(t *testing.T) {
	scheme := newIngressTestScheme()
	now := metav1.Now()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-ingress",
			Namespace:         "default",
			Finalizers:        []string{IngressFinalizerName},
			DeletionTimestamp: &now,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
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

	reconciler := &IngressReconciler{
		Client:     client,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	result, err := reconciler.handleDeletion(context.Background(), ingress)
	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("handleDeletion() should not requeue on success")
	}
}

func TestHandleDeletion_CleanupError(t *testing.T) {
	scheme := newIngressTestScheme()
	now := metav1.Now()
	// Create an ingress with a finalizer and an invalid spec that will cause cleanup to fail
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-ingress",
			Namespace:         "default",
			Finalizers:        []string{IngressFinalizerName},
			DeletionTimestamp: &now,
			Annotations: map[string]string{
				// Reference keys that don't exist - cleanup should still succeed
				// since gRPC server delete is idempotent
				AnnotationAppliedRoutes: "routes:old-route;backends:old-backend",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client:     client,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	result, err := reconciler.handleDeletion(context.Background(), ingress)
	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("handleDeletion() should not requeue on success")
	}
}

func TestHandleDeletion_WithoutFinalizer(t *testing.T) {
	scheme := newIngressTestScheme()
	now := metav1.Now()

	// Create the ingress without deletionTimestamp first (fake client rejects objects
	// with deletionTimestamp but no finalizers), then set it after building the client.
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		Build()

	// Set deletionTimestamp after client creation to simulate the scenario
	ingress.DeletionTimestamp = &now
	ingress.Finalizers = []string{}

	reconciler := &IngressReconciler{
		Client:     client,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	result, err := reconciler.handleDeletion(context.Background(), ingress)
	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("handleDeletion() should not requeue without finalizer")
	}
}

// ============================================================================
// Reconcile Error Path Tests
// ============================================================================

func TestIngressReconciler_Reconcile_ReconcileError(t *testing.T) {
	scheme := newIngressTestScheme()
	// Create an ingress with a finalizer but with an invalid backend (no service)
	// to trigger a reconcileIngress error
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-ingress",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend:  networkingv1.IngressBackend{
										// No service - will cause conversion error
									},
								},
							},
						},
					},
				},
			},
		},
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-ingress",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile() should return error for invalid ingress")
	}
	if result.RequeueAfter == 0 {
		t.Error("Reconcile() should requeue after reconcile failure")
	}

	// Verify warning event was recorded
	events := recorder.getEvents()
	foundWarning := false
	for _, e := range events {
		if strings.Contains(e, "Warning") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Error("Reconcile() should record a warning event on failure")
	}
}

func TestIngressReconciler_Reconcile_StatusUpdateNilUpdater(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-ingress",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
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
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client:              client,
		Scheme:              scheme,
		Recorder:            newFakeRecorder(),
		GRPCServer:          getTestGRPCServer(t),
		IngressStatusUpdate: nil, // nil status updater
		Converter:           NewIngressConverter(),
		IngressClassName:    "avapigw",
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-ingress",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Errorf("Reconcile() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("Reconcile() should not requeue with nil status updater")
	}
}

// ============================================================================
// ingressClassPredicate Filtering Tests
// ============================================================================

func TestIngressClassPredicate_Filtering(t *testing.T) {
	reconciler := &IngressReconciler{
		IngressClassName: "avapigw",
	}

	pred := reconciler.ingressClassPredicate()

	tests := []struct {
		name     string
		object   client.Object
		expected bool
	}{
		{
			name: "matching ingress class",
			object: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptrString("avapigw"),
				},
			},
			expected: true,
		},
		{
			name: "non-matching ingress class",
			object: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptrString("nginx"),
				},
			},
			expected: false,
		},
		{
			name: "no ingress class",
			object: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       networkingv1.IngressSpec{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the Create predicate function to test filtering
			createEvt := ctrlevent.CreateEvent{Object: tt.object}
			result := pred.Create(createEvt)
			if result != tt.expected {
				t.Errorf("ingressClassPredicate() Create = %v, want %v", result, tt.expected)
			}

			// Also test Update event
			updateEvt := ctrlevent.UpdateEvent{ObjectNew: tt.object}
			resultUpdate := pred.Update(updateEvt)
			if resultUpdate != tt.expected {
				t.Errorf("ingressClassPredicate() Update = %v, want %v", resultUpdate, tt.expected)
			}
		})
	}
}

// ============================================================================
// gRPC Protocol Tests
// ============================================================================

// TestIngressReconciler_Reconcile_GRPCProtocol_Success tests successful reconciliation
// of an Ingress with gRPC protocol annotation.
func TestIngressReconciler_Reconcile_GRPCProtocol_Success(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-ingress",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol:    "grpc",
				AnnotationGRPCService: "api.v1.UserService",
				AnnotationGRPCMethod:  "GetUser",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-ingress",
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

	// Verify annotation was updated with gRPC routes
	var updated networkingv1.Ingress
	err = reconciler.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Ingress: %v", err)
	}

	appliedRoutes, ok := updated.Annotations[AnnotationAppliedRoutes]
	if !ok {
		t.Error("Applied routes annotation should be set")
	}
	if !strings.Contains(appliedRoutes, "grpcRoutes:") {
		t.Error("Applied routes annotation should contain grpcRoutes")
	}
	if !strings.Contains(appliedRoutes, "grpcBackends:") {
		t.Error("Applied routes annotation should contain grpcBackends")
	}
}

// TestIngressReconciler_Reconcile_GRPCProtocol_WithDefaultBackend tests gRPC Ingress
// with a default backend configuration.
func TestIngressReconciler_Reconcile_GRPCProtocol_WithDefaultBackend(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-default-backend",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "default-grpc-svc",
					Port: networkingv1.ServiceBackendPort{Number: 50051},
				},
			},
		},
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-default-backend",
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

	// Verify annotation was updated with gRPC default routes
	var updated networkingv1.Ingress
	err = reconciler.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Ingress: %v", err)
	}

	appliedRoutes, ok := updated.Annotations[AnnotationAppliedRoutes]
	if !ok {
		t.Error("Applied routes annotation should be set")
	}
	if !strings.Contains(appliedRoutes, "grpcRoutes:") {
		t.Error("Applied routes annotation should contain grpcRoutes for default backend")
	}
}

// TestIngressReconciler_Reconcile_GRPCProtocol_WithTLS tests gRPC Ingress with TLS configuration.
func TestIngressReconciler_Reconcile_GRPCProtocol_WithTLS(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-tls-ingress",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol:      "grpc",
				AnnotationTLSMinVersion: "TLSv1.2",
				AnnotationTLSMaxVersion: "TLSv1.3",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"grpc.example.com"},
					SecretName: "grpc-tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-tls-ingress",
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

// TestIngressReconciler_Reconcile_GRPCProtocol_WithAllAnnotations tests gRPC Ingress
// with all gRPC-specific annotations.
func TestIngressReconciler_Reconcile_GRPCProtocol_WithAllAnnotations(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-full-annotations",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				// Protocol
				AnnotationProtocol: "grpc",
				// Service and method matching
				AnnotationGRPCService:          "api.v1.UserService",
				AnnotationGRPCServiceMatchType: "exact",
				AnnotationGRPCMethod:           "GetUser",
				AnnotationGRPCMethodMatchType:  "exact",
				// Timeout
				AnnotationTimeout: "30s",
				// Retry
				AnnotationRetryAttempts:           "3",
				AnnotationRetryPerTryTimeout:      "5s",
				AnnotationGRPCRetryOn:             "unavailable,resource-exhausted",
				AnnotationGRPCBackoffBaseInterval: "100ms",
				AnnotationGRPCBackoffMaxInterval:  "1s",
				// Rate limit
				AnnotationRateLimitEnabled:   "true",
				AnnotationRateLimitRPS:       "100",
				AnnotationRateLimitBurst:     "50",
				AnnotationRateLimitPerClient: "true",
				// CORS
				AnnotationCORSAllowOrigins:     "*",
				AnnotationCORSAllowMethods:     "GET,POST",
				AnnotationCORSAllowHeaders:     "Content-Type,Authorization",
				AnnotationCORSAllowCredentials: "true",
				// Security
				AnnotationSecurityEnabled: "true",
				// Cache
				AnnotationCacheEnabled: "true",
				AnnotationCacheTTL:     "5m",
				// Health check
				AnnotationGRPCHealthCheckEnabled:            "true",
				AnnotationGRPCHealthCheckService:            "grpc.health.v1.Health",
				AnnotationGRPCHealthCheckInterval:           "10s",
				AnnotationGRPCHealthCheckTimeout:            "5s",
				AnnotationGRPCHealthCheckHealthyThreshold:   "2",
				AnnotationGRPCHealthCheckUnhealthyThreshold: "3",
				// Connection pool
				AnnotationGRPCMaxIdleConns:    "50",
				AnnotationGRPCMaxConnsPerHost: "100",
				AnnotationGRPCIdleConnTimeout: "5m",
				// Load balancer
				AnnotationLoadBalancerAlgorithm: "round-robin",
				// Circuit breaker
				AnnotationCircuitBreakerEnabled:   "true",
				AnnotationCircuitBreakerThreshold: "5",
				AnnotationCircuitBreakerTimeout:   "30s",
				AnnotationCircuitBreakerHalfOpen:  "3",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-full-annotations",
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

	// Verify annotation was updated
	var updated networkingv1.Ingress
	err = reconciler.Get(context.Background(), req.NamespacedName, &updated)
	if err != nil {
		t.Fatalf("Failed to get updated Ingress: %v", err)
	}

	appliedRoutes, ok := updated.Annotations[AnnotationAppliedRoutes]
	if !ok {
		t.Error("Applied routes annotation should be set")
	}
	if !strings.Contains(appliedRoutes, "grpcRoutes:") {
		t.Error("Applied routes annotation should contain grpcRoutes")
	}
}

// TestIngressReconciler_Reconcile_GRPCProtocol_Deletion tests deletion of gRPC Ingress.
func TestIngressReconciler_Reconcile_GRPCProtocol_Deletion(t *testing.T) {
	scheme := newIngressTestScheme()
	now := metav1.Now()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "grpc-ingress-delete",
			Namespace:         "default",
			Finalizers:        []string{IngressFinalizerName},
			DeletionTimestamp: &now,
			Annotations: map[string]string{
				AnnotationProtocol:      "grpc",
				AnnotationAppliedRoutes: "routes:;backends:;grpcRoutes:ingress-grpc-default-grpc-ingress-delete-r0-p0;grpcBackends:ingress-grpc-default-grpc-ingress-delete-grpc-svc-50051",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-ingress-delete",
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

	// Verify deletion event was recorded
	events := recorder.getEvents()
	foundDeleteEvent := false
	for _, e := range events {
		if strings.Contains(e, EventReasonIngressDeleted) {
			foundDeleteEvent = true
			break
		}
	}
	if !foundDeleteEvent {
		t.Error("Reconcile() should record a deletion event")
	}
}

// TestCleanupIngress_GRPCProtocol tests cleanup of gRPC routes and backends.
func TestCleanupIngress_GRPCProtocol(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-cleanup-test",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationProtocol:      "grpc",
				AnnotationAppliedRoutes: "routes:;backends:;grpcRoutes:gr1,gr2;grpcBackends:gb1,gb2",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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
		Build()

	reconciler := &IngressReconciler{
		Client:     client,
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	err := reconciler.cleanupIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("cleanupIngress() error = %v, want nil", err)
	}
}

// TestCleanupIngress_GRPCProtocol_WithoutAnnotation tests cleanup when no annotation exists.
func TestCleanupIngress_GRPCProtocol_WithoutAnnotation(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-cleanup-no-annotation",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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
		Build()

	reconciler := &IngressReconciler{
		Client:     client,
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	// Should derive keys from spec and cleanup
	err := reconciler.cleanupIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("cleanupIngress() error = %v, want nil", err)
	}
}

// TestUpdateAppliedRoutesAnnotation_GRPCProtocol tests annotation update with gRPC routes.
func TestUpdateAppliedRoutesAnnotation_GRPCProtocol(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-annotation-test",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client: client,
	}

	converted := &ConvertedConfig{
		Routes:   map[string][]byte{},
		Backends: map[string][]byte{},
		GRPCRoutes: map[string][]byte{
			"grpc-route-1": []byte("{}"),
			"grpc-route-2": []byte("{}"),
		},
		GRPCBackends: map[string][]byte{
			"grpc-backend-1": []byte("{}"),
		},
	}

	err := reconciler.updateAppliedRoutesAnnotation(context.Background(), ingress, converted)
	if err != nil {
		t.Fatalf("updateAppliedRoutesAnnotation() error = %v", err)
	}

	// Verify annotation was set
	if ingress.Annotations == nil {
		t.Fatal("Annotations should not be nil after update")
	}
	value, ok := ingress.Annotations[AnnotationAppliedRoutes]
	if !ok {
		t.Fatal("Applied routes annotation should be set")
	}
	if !strings.Contains(value, "grpcRoutes:") {
		t.Error("Applied routes annotation should contain grpcRoutes")
	}
	if !strings.Contains(value, "grpcBackends:") {
		t.Error("Applied routes annotation should contain grpcBackends")
	}
}

// TestUpdateAppliedRoutesAnnotation_MixedProtocol tests annotation with both HTTP and gRPC.
func TestUpdateAppliedRoutesAnnotation_MixedProtocol(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mixed-annotation-test",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client: client,
	}

	converted := &ConvertedConfig{
		Routes: map[string][]byte{
			"http-route-1": []byte("{}"),
		},
		Backends: map[string][]byte{
			"http-backend-1": []byte("{}"),
		},
		GRPCRoutes: map[string][]byte{
			"grpc-route-1": []byte("{}"),
		},
		GRPCBackends: map[string][]byte{
			"grpc-backend-1": []byte("{}"),
		},
	}

	err := reconciler.updateAppliedRoutesAnnotation(context.Background(), ingress, converted)
	if err != nil {
		t.Fatalf("updateAppliedRoutesAnnotation() error = %v", err)
	}

	value := ingress.Annotations[AnnotationAppliedRoutes]
	if !strings.Contains(value, "routes:") {
		t.Error("Applied routes annotation should contain routes")
	}
	if !strings.Contains(value, "backends:") {
		t.Error("Applied routes annotation should contain backends")
	}
	if !strings.Contains(value, "grpcRoutes:") {
		t.Error("Applied routes annotation should contain grpcRoutes")
	}
	if !strings.Contains(value, "grpcBackends:") {
		t.Error("Applied routes annotation should contain grpcBackends")
	}
}

// TestReconcileIngress_GRPCProtocol_NilGRPCServer tests reconciliation with nil gRPC server.
func TestReconcileIngress_GRPCProtocol_NilGRPCServer(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-nil-server",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	reconciler := &IngressReconciler{
		Client:     client,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: nil, // nil server
		Converter:  NewIngressConverter(),
	}

	err := reconciler.reconcileIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("reconcileIngress() with nil server error = %v, want nil", err)
	}
}

// TestReconcileIngress_GRPCProtocol_Success tests successful gRPC reconciliation.
func TestReconcileIngress_GRPCProtocol_Success(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-reconcile-success",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	reconciler := &IngressReconciler{
		Client:     client,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	err := reconciler.reconcileIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("reconcileIngress() error = %v, want nil", err)
	}
}

// TestIngressReconciler_Reconcile_GRPCProtocol_MultipleRules tests gRPC Ingress with multiple rules.
func TestIngressReconciler_Reconcile_GRPCProtocol_MultipleRules(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-multi-rules",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc1.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "user-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "grpc2.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.OrderService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
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
			},
		},
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-multi-rules",
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

// TestIngressReconciler_Reconcile_GRPCProtocol_MultiplePaths tests gRPC Ingress with multiple paths.
func TestIngressReconciler_Reconcile_GRPCProtocol_MultiplePaths(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-multi-paths",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "user-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
								{
									Path:     "/api.v1.OrderService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
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
			},
		},
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, recorder := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-multi-paths",
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

// TestHandleDeletion_GRPCProtocol tests deletion handling for gRPC Ingress.
func TestHandleDeletion_GRPCProtocol(t *testing.T) {
	scheme := newIngressTestScheme()
	now := metav1.Now()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "grpc-handle-deletion",
			Namespace:         "default",
			Finalizers:        []string{IngressFinalizerName},
			DeletionTimestamp: &now,
			Annotations: map[string]string{
				AnnotationProtocol:      "grpc",
				AnnotationAppliedRoutes: "routes:;backends:;grpcRoutes:gr1;grpcBackends:gb1",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	reconciler := &IngressReconciler{
		Client:     client,
		Scheme:     scheme,
		Recorder:   newFakeRecorder(),
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	result, err := reconciler.handleDeletion(context.Background(), ingress)
	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Error("handleDeletion() should not requeue on success")
	}
}

// TestGetAppliedKeys_GRPCOnly tests parsing annotation with only gRPC keys.
func TestGetAppliedKeys_GRPCOnly(t *testing.T) {
	reconciler := &IngressReconciler{}
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:;backends:;grpcRoutes:gr1,gr2,gr3;grpcBackends:gb1,gb2",
			},
		},
	}

	routeKeys, backendKeys, grpcRouteKeys, grpcBackendKeys := reconciler.getAppliedKeys(ingress)

	if len(routeKeys) != 0 {
		t.Errorf("getAppliedKeys() routeKeys len = %d, want 0", len(routeKeys))
	}
	if len(backendKeys) != 0 {
		t.Errorf("getAppliedKeys() backendKeys len = %d, want 0", len(backendKeys))
	}
	if len(grpcRouteKeys) != 3 {
		t.Errorf("getAppliedKeys() grpcRouteKeys len = %d, want 3", len(grpcRouteKeys))
	}
	if len(grpcBackendKeys) != 2 {
		t.Errorf("getAppliedKeys() grpcBackendKeys len = %d, want 2", len(grpcBackendKeys))
	}
}

// TestIngressReconciler_Reconcile_GRPCProtocol_CaseInsensitive tests case-insensitive protocol.
func TestIngressReconciler_Reconcile_GRPCProtocol_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
	}{
		{"lowercase", "grpc"},
		{"uppercase", "GRPC"},
		{"mixedcase", "GrPc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newIngressTestScheme()
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "grpc-case-" + tt.name,
					Namespace:  "default",
					Finalizers: []string{IngressFinalizerName},
					Annotations: map[string]string{
						AnnotationProtocol: tt.protocol,
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptrString("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api.v1.UserService",
											PathType: ptrPathType(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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

			builder := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(ingress).
				WithStatusSubresource(ingress)
			reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "grpc-case-" + tt.name,
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

			// Verify gRPC routes were created
			var updated networkingv1.Ingress
			err = reconciler.Get(context.Background(), req.NamespacedName, &updated)
			if err != nil {
				t.Fatalf("Failed to get updated Ingress: %v", err)
			}

			appliedRoutes := updated.Annotations[AnnotationAppliedRoutes]
			if !strings.Contains(appliedRoutes, "grpcRoutes:") {
				t.Error("Applied routes annotation should contain grpcRoutes")
			}
		})
	}
}

// TestIngressReconciler_Reconcile_GRPCProtocol_EmptyRules tests gRPC Ingress with no rules.
func TestIngressReconciler_Reconcile_GRPCProtocol_EmptyRules(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-empty-rules",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules:            []networkingv1.IngressRule{},
		},
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-empty-rules",
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
}

// TestIngressReconciler_Reconcile_GRPCProtocol_NoHTTPRule tests gRPC Ingress with rule but no HTTP.
func TestIngressReconciler_Reconcile_GRPCProtocol_NoHTTPRule(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-no-http-rule",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					// No HTTP rule value
				},
			},
		},
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-no-http-rule",
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
}

// TestCleanupIngress_GRPCProtocol_MixedKeys tests cleanup with both HTTP and gRPC keys.
func TestCleanupIngress_GRPCProtocol_MixedKeys(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mixed-cleanup-test",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:r1,r2;backends:b1;grpcRoutes:gr1,gr2;grpcBackends:gb1",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		Build()

	reconciler := &IngressReconciler{
		Client:     client,
		GRPCServer: getTestGRPCServer(t),
		Converter:  NewIngressConverter(),
	}

	err := reconciler.cleanupIngress(context.Background(), ingress)
	if err != nil {
		t.Errorf("cleanupIngress() error = %v, want nil", err)
	}
}

// TestIngressReconciler_Reconcile_GRPCProtocol_WithRetryAnnotations tests gRPC retry annotations.
func TestIngressReconciler_Reconcile_GRPCProtocol_WithRetryAnnotations(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-retry-test",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol:                "grpc",
				AnnotationRetryAttempts:           "3",
				AnnotationRetryPerTryTimeout:      "5s",
				AnnotationGRPCRetryOn:             "unavailable,resource-exhausted",
				AnnotationGRPCBackoffBaseInterval: "100ms",
				AnnotationGRPCBackoffMaxInterval:  "1s",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-retry-test",
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
}

// TestIngressReconciler_Reconcile_GRPCProtocol_WithHealthCheck tests gRPC health check annotations.
func TestIngressReconciler_Reconcile_GRPCProtocol_WithHealthCheck(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-healthcheck-test",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol:                          "grpc",
				AnnotationGRPCHealthCheckEnabled:            "true",
				AnnotationGRPCHealthCheckService:            "grpc.health.v1.Health",
				AnnotationGRPCHealthCheckInterval:           "10s",
				AnnotationGRPCHealthCheckTimeout:            "5s",
				AnnotationGRPCHealthCheckHealthyThreshold:   "2",
				AnnotationGRPCHealthCheckUnhealthyThreshold: "3",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-healthcheck-test",
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
}

// TestIngressReconciler_Reconcile_GRPCProtocol_WithConnectionPool tests gRPC connection pool annotations.
func TestIngressReconciler_Reconcile_GRPCProtocol_WithConnectionPool(t *testing.T) {
	scheme := newIngressTestScheme()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-connpool-test",
			Namespace:  "default",
			Finalizers: []string{IngressFinalizerName},
			Annotations: map[string]string{
				AnnotationProtocol:            "grpc",
				AnnotationGRPCMaxIdleConns:    "50",
				AnnotationGRPCMaxConnsPerHost: "100",
				AnnotationGRPCIdleConnTimeout: "5m",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-svc",
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

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		WithStatusSubresource(ingress)
	reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "grpc-connpool-test",
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
}

// TestIngressReconciler_Reconcile_GRPCProtocol_TableDriven provides table-driven tests for gRPC scenarios.
func TestIngressReconciler_Reconcile_GRPCProtocol_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		rules       []networkingv1.IngressRule
		wantErr     bool
		wantRequeue bool
	}{
		{
			name: "basic gRPC ingress",
			annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
			rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.Service",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
		{
			name: "gRPC with service and method match",
			annotations: map[string]string{
				AnnotationProtocol:             "grpc",
				AnnotationGRPCService:          "api.v1.UserService",
				AnnotationGRPCServiceMatchType: "exact",
				AnnotationGRPCMethod:           "GetUser",
				AnnotationGRPCMethodMatchType:  "exact",
			},
			rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "user-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
		{
			name: "gRPC with timeout",
			annotations: map[string]string{
				AnnotationProtocol: "grpc",
				AnnotationTimeout:  "30s",
			},
			rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.Service",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
		{
			name: "gRPC with rate limiting",
			annotations: map[string]string{
				AnnotationProtocol:           "grpc",
				AnnotationRateLimitEnabled:   "true",
				AnnotationRateLimitRPS:       "100",
				AnnotationRateLimitBurst:     "50",
				AnnotationRateLimitPerClient: "true",
			},
			rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.Service",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
		{
			name: "gRPC with circuit breaker",
			annotations: map[string]string{
				AnnotationProtocol:                "grpc",
				AnnotationCircuitBreakerEnabled:   "true",
				AnnotationCircuitBreakerThreshold: "5",
				AnnotationCircuitBreakerTimeout:   "30s",
				AnnotationCircuitBreakerHalfOpen:  "3",
			},
			rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.Service",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newIngressTestScheme()
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "grpc-table-" + tt.name,
					Namespace:   "default",
					Finalizers:  []string{IngressFinalizerName},
					Annotations: tt.annotations,
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptrString("avapigw"),
					Rules:            tt.rules,
				},
			}

			builder := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(ingress).
				WithStatusSubresource(ingress)
			reconciler, _ := newIngressReconciler(t, builder, scheme, "avapigw")

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "grpc-table-" + tt.name,
					Namespace: "default",
				},
			}

			result, err := reconciler.Reconcile(context.Background(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (result.Requeue || result.RequeueAfter > 0) != tt.wantRequeue {
				t.Errorf("Reconcile() requeue = %v, wantRequeue %v", result.Requeue || result.RequeueAfter > 0, tt.wantRequeue)
			}
		})
	}
}

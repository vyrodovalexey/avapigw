package controller

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// Test Helpers
// ============================================================================

func newBackendReconciler(cl client.Client, scheme *runtime.Scheme) *BackendReconciler {
	return &BackendReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
}

// ============================================================================
// BackendReconciler.Reconcile Tests
// ============================================================================

func TestBackendReconciler_Reconcile(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name       string
		objects    []client.Object
		request    ctrl.Request
		wantResult ctrl.Result
		wantErr    bool
		validate   func(t *testing.T, cl client.Client)
	}{
		{
			name:    "resource not found returns nil",
			objects: []client.Object{},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent",
					Namespace: "default",
				},
			},
			wantResult: ctrl.Result{},
			wantErr:    false,
		},
		{
			name: "adds finalizer when not present",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-backend",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Endpoints: []avapigwv1alpha1.EndpointConfig{
							{Address: "10.0.0.1", Port: 8080},
						},
					},
				},
			},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-backend",
					Namespace: "default",
				},
			},
			wantResult: ctrl.Result{Requeue: true},
			wantErr:    false,
			validate: func(t *testing.T, cl client.Client) {
				backend := &avapigwv1alpha1.Backend{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, backend)
				require.NoError(t, err)
				assert.Contains(t, backend.Finalizers, backendFinalizer)
			},
		},
		{
			name: "successful reconciliation with direct endpoints",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-backend",
						Namespace:  "default",
						Finalizers: []string{backendFinalizer},
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Endpoints: []avapigwv1alpha1.EndpointConfig{
							{Address: "10.0.0.1", Port: 8080},
							{Address: "10.0.0.2", Port: 8080},
						},
					},
				},
			},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-backend",
					Namespace: "default",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				backend := &avapigwv1alpha1.Backend{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, backend)
				require.NoError(t, err)
				assert.Equal(t, int32(2), backend.Status.TotalEndpoints)
				assert.Equal(t, int32(2), backend.Status.HealthyEndpoints)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				WithStatusSubresource(&avapigwv1alpha1.Backend{}).
				Build()

			r := newBackendReconciler(cl, scheme)

			result, err := r.Reconcile(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.wantResult.Requeue {
				assert.True(t, result.Requeue)
			}

			if tt.validate != nil {
				tt.validate(t, cl)
			}
		})
	}
}

// ============================================================================
// BackendReconciler.handleDeletion Tests
// ============================================================================

func TestBackendReconciler_handleDeletion(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("removes finalizer on deletion", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-backend",
				Namespace:  "default",
				Finalizers: []string{backendFinalizer},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			Build()

		r := newBackendReconciler(cl, scheme)

		// Re-fetch the backend to get the version from the fake client
		fetchedBackend := &avapigwv1alpha1.Backend{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, fetchedBackend)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedBackend)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify finalizer was removed
		updatedBackend := &avapigwv1alpha1.Backend{}
		err = cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, updatedBackend)
		require.NoError(t, err)
		assert.NotContains(t, updatedBackend.Finalizers, backendFinalizer)
	})

	t.Run("no-op when finalizer not present", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-backend",
				Namespace:  "default",
				Finalizers: []string{},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			Build()

		r := newBackendReconciler(cl, scheme)

		// Re-fetch the backend
		fetchedBackend := &avapigwv1alpha1.Backend{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, fetchedBackend)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedBackend)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})
}

// ============================================================================
// BackendReconciler.reconcileBackend Tests
// ============================================================================

func TestBackendReconciler_reconcileBackend(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name     string
		objects  []client.Object
		backend  *avapigwv1alpha1.Backend
		wantErr  bool
		validate func(t *testing.T, cl client.Client)
	}{
		{
			name:    "successful reconciliation with direct endpoints",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-backend",
					Namespace:  "default",
					Finalizers: []string{backendFinalizer},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Endpoints: []avapigwv1alpha1.EndpointConfig{
						{Address: "10.0.0.1", Port: 8080},
						{Address: "10.0.0.2", Port: 8080},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				backend := &avapigwv1alpha1.Backend{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, backend)
				require.NoError(t, err)
				assert.Equal(t, int32(2), backend.Status.TotalEndpoints)
				assert.Equal(t, int32(2), backend.Status.HealthyEndpoints)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, backend.Status.Phase)
			},
		},
		{
			name: "successful reconciliation with service reference",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Port: 8080},
						},
					},
				},
				&corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
					Subsets: []corev1.EndpointSubset{
						{
							Addresses: []corev1.EndpointAddress{
								{IP: "10.0.0.1"},
								{IP: "10.0.0.2"},
							},
							Ports: []corev1.EndpointPort{
								{Port: 8080},
							},
						},
					},
				},
			},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-backend",
					Namespace:  "default",
					Finalizers: []string{backendFinalizer},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: "test-service",
						Port: 8080,
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				backend := &avapigwv1alpha1.Backend{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, backend)
				require.NoError(t, err)
				assert.Equal(t, int32(2), backend.Status.TotalEndpoints)
				assert.Equal(t, int32(2), backend.Status.HealthyEndpoints)
			},
		},
		{
			name:    "error when no endpoints or service specified",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-backend",
					Namespace:  "default",
					Finalizers: []string{backendFinalizer},
				},
				Spec: avapigwv1alpha1.BackendSpec{},
			},
			wantErr: false, // Error is handled internally, status is updated
			validate: func(t *testing.T, cl client.Client) {
				backend := &avapigwv1alpha1.Backend{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, backend)
				require.NoError(t, err)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusError, backend.Status.Phase)
			},
		},
		{
			name:    "error when service not found",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-backend",
					Namespace:  "default",
					Finalizers: []string{backendFinalizer},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: "missing-service",
						Port: 8080,
					},
				},
			},
			wantErr: false, // Error is handled internally, status is updated
			validate: func(t *testing.T, cl client.Client) {
				backend := &avapigwv1alpha1.Backend{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, backend)
				require.NoError(t, err)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusError, backend.Status.Phase)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allObjects := append(tt.objects, tt.backend)
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(allObjects...).
				WithStatusSubresource(&avapigwv1alpha1.Backend{}).
				Build()

			r := newBackendReconciler(cl, scheme)

			err := r.reconcileBackend(context.Background(), tt.backend)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, cl)
			}
		})
	}
}

// ============================================================================
// BackendReconciler.discoverEndpoints Tests
// ============================================================================

func TestBackendReconciler_discoverEndpoints(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name          string
		objects       []client.Object
		backend       *avapigwv1alpha1.Backend
		wantEndpoints int
		wantErr       bool
	}{
		{
			name:    "discovers direct endpoints",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Endpoints: []avapigwv1alpha1.EndpointConfig{
						{Address: "10.0.0.1", Port: 8080},
						{Address: "10.0.0.2", Port: 8080},
						{Address: "10.0.0.3", Port: 8080},
					},
				},
			},
			wantEndpoints: 3,
			wantErr:       false,
		},
		{
			name: "discovers service endpoints",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
				},
				&corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
					Subsets: []corev1.EndpointSubset{
						{
							Addresses: []corev1.EndpointAddress{
								{IP: "10.0.0.1"},
								{IP: "10.0.0.2"},
							},
							Ports: []corev1.EndpointPort{
								{Port: 8080},
							},
						},
					},
				},
			},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: "test-service",
						Port: 8080,
					},
				},
			},
			wantEndpoints: 2,
			wantErr:       false,
		},
		{
			name:    "error when no endpoints or service",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{},
			},
			wantEndpoints: 0,
			wantErr:       true,
		},
		{
			name:    "error when service not found",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: "missing-service",
						Port: 8080,
					},
				},
			},
			wantEndpoints: 0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newBackendReconciler(cl, scheme)

			endpoints, err := r.discoverEndpoints(context.Background(), tt.backend)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, endpoints, tt.wantEndpoints)
			}
		})
	}
}

// ============================================================================
// BackendReconciler.discoverServiceEndpoints Tests
// ============================================================================

func TestBackendReconciler_discoverServiceEndpoints(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name          string
		objects       []client.Object
		backend       *avapigwv1alpha1.Backend
		wantEndpoints int
		wantErr       bool
	}{
		{
			name: "discovers endpoints from Endpoints resource",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
				},
				&corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
					Subsets: []corev1.EndpointSubset{
						{
							Addresses: []corev1.EndpointAddress{
								{IP: "10.0.0.1"},
								{IP: "10.0.0.2"},
							},
							NotReadyAddresses: []corev1.EndpointAddress{
								{IP: "10.0.0.3"},
							},
							Ports: []corev1.EndpointPort{
								{Port: 8080},
							},
						},
					},
				},
			},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: "test-service",
						Port: 8080,
					},
				},
			},
			wantEndpoints: 3, // 2 ready + 1 not ready
			wantErr:       false,
		},
		{
			name: "service in different namespace",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "other-namespace",
					},
				},
				&corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "other-namespace",
					},
					Subsets: []corev1.EndpointSubset{
						{
							Addresses: []corev1.EndpointAddress{
								{IP: "10.0.0.1"},
							},
							Ports: []corev1.EndpointPort{
								{Port: 8080},
							},
						},
					},
				},
			},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name:      "test-service",
						Namespace: ptrString("other-namespace"),
						Port:      8080,
					},
				},
			},
			wantEndpoints: 1,
			wantErr:       false,
		},
		{
			name:    "error when service not found",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: "missing-service",
						Port: 8080,
					},
				},
			},
			wantEndpoints: 0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newBackendReconciler(cl, scheme)

			endpoints, err := r.discoverServiceEndpoints(context.Background(), tt.backend)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, endpoints, tt.wantEndpoints)
			}
		})
	}
}

// ============================================================================
// BackendReconciler.findBackendsForService Tests
// ============================================================================

func TestBackendReconciler_findBackendsForService(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name         string
		objects      []client.Object
		service      *corev1.Service
		wantRequests int
	}{
		{
			name: "finds backends referencing service",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Service: &avapigwv1alpha1.ServiceRef{
							Name: "test-service",
							Port: 8080,
						},
					},
				},
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend-2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Service: &avapigwv1alpha1.ServiceRef{
							Name: "test-service",
							Port: 8080,
						},
					},
				},
			},
			service: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: "default",
				},
			},
			wantRequests: 2,
		},
		{
			name: "returns empty for no matches",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Service: &avapigwv1alpha1.ServiceRef{
							Name: "other-service",
							Port: 8080,
						},
					},
				},
			},
			service: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: "default",
				},
			},
			wantRequests: 0,
		},
		{
			name: "ignores backends with direct endpoints",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Endpoints: []avapigwv1alpha1.EndpointConfig{
							{Address: "10.0.0.1", Port: 8080},
						},
					},
				},
			},
			service: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: "default",
				},
			},
			wantRequests: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newBackendReconciler(cl, scheme)

			requests := r.findBackendsForService(context.Background(), tt.service)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// BackendReconciler.findBackendsForEndpoints Tests
// ============================================================================

func TestBackendReconciler_findBackendsForEndpoints(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name         string
		objects      []client.Object
		endpoints    *corev1.Endpoints
		wantRequests int
	}{
		{
			name: "finds backends referencing endpoints",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Service: &avapigwv1alpha1.ServiceRef{
							Name: "test-service",
							Port: 8080,
						},
					},
				},
			},
			endpoints: &corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: "default",
				},
			},
			wantRequests: 1,
		},
		{
			name: "returns empty for no matches",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Service: &avapigwv1alpha1.ServiceRef{
							Name: "other-service",
							Port: 8080,
						},
					},
				},
			},
			endpoints: &corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: "default",
				},
			},
			wantRequests: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newBackendReconciler(cl, scheme)

			requests := r.findBackendsForEndpoints(context.Background(), tt.endpoints)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// BackendReconciler.setCondition Tests
// ============================================================================

func TestBackendReconciler_setCondition(t *testing.T) {
	backend := &avapigwv1alpha1.Backend{}

	r := &BackendReconciler{}
	r.setCondition(backend, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue, "Ready", "Backend is ready")

	condition := backend.Status.GetCondition(avapigwv1alpha1.ConditionTypeReady)
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
	assert.Equal(t, "Ready", condition.Reason)
	assert.Equal(t, "Backend is ready", condition.Message)
}

// ============================================================================
// BackendReconciler.getRequeueStrategy Tests
// ============================================================================

func TestBackendReconciler_getRequeueStrategy_Concurrent(t *testing.T) {
	r := &BackendReconciler{}

	var wg sync.WaitGroup
	const numGoroutines = 100
	strategies := make([]*RequeueStrategy, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			strategies[idx] = r.getRequeueStrategy()
		}(i)
	}

	wg.Wait()

	first := strategies[0]
	require.NotNil(t, first)

	for i, s := range strategies {
		if s != first {
			t.Errorf("goroutine %d got different strategy instance", i)
		}
	}
}

func TestBackendReconciler_getRequeueStrategy_InitializesDefault(t *testing.T) {
	r := &BackendReconciler{}

	strategy := r.getRequeueStrategy()

	require.NotNil(t, strategy)
	assert.NotNil(t, strategy.config)
}

// ============================================================================
// BackendReconciler Reconcile with Deletion Tests
// ============================================================================

func TestBackendReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("handleDeletion removes finalizer", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-backend",
				Namespace:  "default",
				Finalizers: []string{backendFinalizer},
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{
					{Address: "10.0.0.1", Port: 8080},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			Build()

		r := newBackendReconciler(cl, scheme)

		// Fetch the backend to get the version from the fake client
		fetchedBackend := &avapigwv1alpha1.Backend{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, fetchedBackend)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedBackend)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify finalizer was removed
		updatedBackend := &avapigwv1alpha1.Backend{}
		err = cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, updatedBackend)
		require.NoError(t, err)
		assert.NotContains(t, updatedBackend.Finalizers, backendFinalizer)
	})

	t.Run("handleDeletion no-op without finalizer", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-backend",
				Namespace:  "default",
				Finalizers: []string{},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			Build()

		r := newBackendReconciler(cl, scheme)

		// Fetch the backend
		fetchedBackend := &avapigwv1alpha1.Backend{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, fetchedBackend)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedBackend)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})
}

// ============================================================================
// BackendReconciler Reconcile with Health Check Interval Tests
// ============================================================================

func TestBackendReconciler_Reconcile_HealthCheckInterval(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("uses health check interval for requeue", func(t *testing.T) {
		interval := avapigwv1alpha1.Duration("30s")
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-backend",
				Namespace:  "default",
				Finalizers: []string{backendFinalizer},
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{
					{Address: "10.0.0.1", Port: 8080},
				},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					Interval: &interval,
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			WithStatusSubresource(&avapigwv1alpha1.Backend{}).
			Build()

		r := newBackendReconciler(cl, scheme)

		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-backend",
				Namespace: "default",
			},
		})

		assert.NoError(t, err)
		// Should requeue after health check interval
		assert.True(t, result.RequeueAfter > 0)
	})

	t.Run("uses default interval when health check not configured", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-backend",
				Namespace:  "default",
				Finalizers: []string{backendFinalizer},
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{
					{Address: "10.0.0.1", Port: 8080},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			WithStatusSubresource(&avapigwv1alpha1.Backend{}).
			Build()

		r := newBackendReconciler(cl, scheme)

		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-backend",
				Namespace: "default",
			},
		})

		assert.NoError(t, err)
		// Should still have a requeue interval
		assert.True(t, result.RequeueAfter >= 0)
	})
}

// ============================================================================
// BackendReconciler reconcileBackend Status Tests
// ============================================================================

func TestBackendReconciler_reconcileBackend_StatusConditions(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name          string
		objects       []client.Object
		backend       *avapigwv1alpha1.Backend
		expectedPhase avapigwv1alpha1.PhaseStatus
	}{
		{
			name:    "all endpoints healthy - Ready phase",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-backend",
					Namespace:  "default",
					Finalizers: []string{backendFinalizer},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Endpoints: []avapigwv1alpha1.EndpointConfig{
						{Address: "10.0.0.1", Port: 8080},
						{Address: "10.0.0.2", Port: 8080},
					},
				},
			},
			expectedPhase: avapigwv1alpha1.PhaseStatusReady,
		},
		{
			name:    "no endpoints - Error phase",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-backend",
					Namespace:  "default",
					Finalizers: []string{backendFinalizer},
				},
				Spec: avapigwv1alpha1.BackendSpec{},
			},
			expectedPhase: avapigwv1alpha1.PhaseStatusError,
		},
		{
			name:    "service not found - Error phase",
			objects: []client.Object{},
			backend: &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-backend",
					Namespace:  "default",
					Finalizers: []string{backendFinalizer},
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: "missing-service",
						Port: 8080,
					},
				},
			},
			expectedPhase: avapigwv1alpha1.PhaseStatusError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allObjects := append(tt.objects, tt.backend)
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(allObjects...).
				WithStatusSubresource(&avapigwv1alpha1.Backend{}).
				Build()

			r := newBackendReconciler(cl, scheme)

			err := r.reconcileBackend(context.Background(), tt.backend)

			assert.NoError(t, err)

			// Verify status
			updatedBackend := &avapigwv1alpha1.Backend{}
			err = cl.Get(context.Background(), types.NamespacedName{Name: tt.backend.Name, Namespace: tt.backend.Namespace}, updatedBackend)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedPhase, updatedBackend.Status.Phase)
		})
	}
}

// ============================================================================
// BackendReconciler discoverServiceEndpoints with NotReadyAddresses Tests
// ============================================================================

func TestBackendReconciler_discoverServiceEndpoints_NotReadyAddresses(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("includes not ready addresses as unhealthy", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "default",
			},
		}

		eps := &corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "default",
			},
			Subsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{IP: "10.0.0.1"},
					},
					NotReadyAddresses: []corev1.EndpointAddress{
						{IP: "10.0.0.2"},
						{IP: "10.0.0.3"},
					},
					Ports: []corev1.EndpointPort{
						{Port: 8080},
					},
				},
			},
		}

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-backend",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-service",
					Port: 8080,
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(svc, eps).
			Build()

		r := newBackendReconciler(cl, scheme)

		endpoints, err := r.discoverServiceEndpoints(context.Background(), backend)

		assert.NoError(t, err)
		assert.Len(t, endpoints, 3) // 1 ready + 2 not ready

		// Count healthy and unhealthy
		healthyCount := 0
		unhealthyCount := 0
		for _, ep := range endpoints {
			if ep.Healthy {
				healthyCount++
			} else {
				unhealthyCount++
			}
		}
		assert.Equal(t, 1, healthyCount)
		assert.Equal(t, 2, unhealthyCount)
	})
}

// ============================================================================
// BackendReconciler findBackendsForService Cross-Namespace Tests
// ============================================================================

func TestBackendReconciler_findBackendsForService_CrossNamespace(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("finds backends referencing service in different namespace", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "backend-1",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name:      "test-service",
					Namespace: ptrString("other-namespace"),
					Port:      8080,
				},
			},
		}

		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "other-namespace",
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(backend).
			Build()

		r := newBackendReconciler(cl, scheme)

		requests := r.findBackendsForService(context.Background(), service)

		assert.Len(t, requests, 1)
		assert.Equal(t, "backend-1", requests[0].Name)
		assert.Equal(t, "default", requests[0].Namespace)
	})
}

// ============================================================================
// BackendReconciler Reconcile Error Classification Tests
// ============================================================================

func TestBackendReconciler_Reconcile_ErrorClassification(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name           string
		objects        []client.Object
		request        ctrl.Request
		wantErr        bool
		validateResult func(t *testing.T, result ctrl.Result)
	}{
		{
			name: "successful reconciliation with direct endpoints",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-backend",
						Namespace:  "default",
						Finalizers: []string{backendFinalizer},
					},
					Spec: avapigwv1alpha1.BackendSpec{
						Endpoints: []avapigwv1alpha1.EndpointConfig{
							{Address: "10.0.0.1", Port: 8080},
						},
					},
				},
			},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-backend",
					Namespace: "default",
				},
			},
			wantErr: false,
			validateResult: func(t *testing.T, result ctrl.Result) {
				assert.True(t, result.RequeueAfter >= 0)
			},
		},
		{
			name:    "not found resource returns empty result",
			objects: []client.Object{},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent",
					Namespace: "default",
				},
			},
			wantErr: false,
			validateResult: func(t *testing.T, result ctrl.Result) {
				assert.Equal(t, ctrl.Result{}, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				WithStatusSubresource(&avapigwv1alpha1.Backend{}).
				Build()

			r := newBackendReconciler(cl, scheme)

			result, err := r.Reconcile(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

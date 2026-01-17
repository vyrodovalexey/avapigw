package controller

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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
// BackendReconciler.handleReconcileError Tests
// ============================================================================

func TestBackendReconciler_handleReconcileError(t *testing.T) {
	r := &BackendReconciler{}
	r.initBaseComponents()
	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-backend"

	tests := []struct {
		name           string
		reconcileErr   *ReconcileError
		validateResult func(t *testing.T, result ctrl.Result, err error)
	}{
		{
			name: "validation error returns validation result",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypeValidation,
				Op:                 "validate",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          false,
				UserActionRequired: true,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				// Validation errors should not requeue immediately
				assert.False(t, result.Requeue)
			},
		},
		{
			name: "permanent error returns permanent result",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypePermanent,
				Op:                 "reconcile",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          false,
				UserActionRequired: true,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				// Permanent errors should not requeue
				assert.False(t, result.Requeue)
			},
		},
		{
			name: "dependency error returns dependency result with backoff",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypeDependency,
				Op:                 "fetchDependency",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          true,
				UserActionRequired: false,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				// Dependency errors should requeue with backoff
				assert.True(t, result.RequeueAfter > 0)
			},
		},
		{
			name: "transient error returns transient result with backoff",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypeTransient,
				Op:                 "update",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          true,
				UserActionRequired: false,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				// Transient errors should requeue with backoff
				assert.True(t, result.RequeueAfter > 0)
			},
		},
		{
			name: "internal error returns transient result with backoff",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypeInternal,
				Op:                 "internal",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          true,
				UserActionRequired: false,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				// Internal errors (default case) should requeue with backoff
				assert.True(t, result.RequeueAfter > 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := r.handleReconcileError(tt.reconcileErr, strategy, resourceKey)
			tt.validateResult(t, result, err)
		})
	}
}

// ============================================================================
// BackendReconciler.extractEndpointsFromSlice Tests
// ============================================================================

func TestBackendReconciler_extractEndpointsFromSlice(t *testing.T) {
	r := &BackendReconciler{}

	tests := []struct {
		name          string
		slice         *discoveryv1.EndpointSlice
		targetPort    int32
		wantEndpoints int
		wantHealthy   int
	}{
		{
			name: "extracts ready endpoints",
			slice: &discoveryv1.EndpointSlice{
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses:  []string{"10.0.0.1", "10.0.0.2"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
					},
				},
				Ports: []discoveryv1.EndpointPort{
					{Port: ptrInt32(8080)},
				},
			},
			targetPort:    8080,
			wantEndpoints: 2,
			wantHealthy:   2,
		},
		{
			name: "skips not ready endpoints",
			slice: &discoveryv1.EndpointSlice{
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses:  []string{"10.0.0.1"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
					},
					{
						Addresses:  []string{"10.0.0.2"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(false)},
					},
				},
				Ports: []discoveryv1.EndpointPort{
					{Port: ptrInt32(8080)},
				},
			},
			targetPort:    8080,
			wantEndpoints: 1,
			wantHealthy:   1,
		},
		{
			name: "handles nil ready condition as ready",
			slice: &discoveryv1.EndpointSlice{
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses:  []string{"10.0.0.1"},
						Conditions: discoveryv1.EndpointConditions{Ready: nil},
					},
				},
				Ports: []discoveryv1.EndpointPort{
					{Port: ptrInt32(8080)},
				},
			},
			targetPort:    8080,
			wantEndpoints: 1,
			wantHealthy:   1,
		},
		{
			name: "handles multiple addresses per endpoint",
			slice: &discoveryv1.EndpointSlice{
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses:  []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
					},
				},
				Ports: []discoveryv1.EndpointPort{
					{Port: ptrInt32(8080)},
				},
			},
			targetPort:    8080,
			wantEndpoints: 3,
			wantHealthy:   3,
		},
		{
			name: "empty endpoints returns empty slice",
			slice: &discoveryv1.EndpointSlice{
				Endpoints: []discoveryv1.Endpoint{},
				Ports: []discoveryv1.EndpointPort{
					{Port: ptrInt32(8080)},
				},
			},
			targetPort:    8080,
			wantEndpoints: 0,
			wantHealthy:   0,
		},
		{
			name: "uses target port when no matching port found",
			slice: &discoveryv1.EndpointSlice{
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses:  []string{"10.0.0.1"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
					},
				},
				Ports: []discoveryv1.EndpointPort{
					{Port: ptrInt32(9090)}, // Different port
				},
			},
			targetPort:    8080,
			wantEndpoints: 1,
			wantHealthy:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoints := r.extractEndpointsFromSlice(tt.slice, tt.targetPort)

			assert.Len(t, endpoints, tt.wantEndpoints)

			healthyCount := 0
			for _, ep := range endpoints {
				if ep.Healthy {
					healthyCount++
				}
			}
			assert.Equal(t, tt.wantHealthy, healthyCount)
		})
	}
}

// ============================================================================
// BackendReconciler.findMatchingPort Tests
// ============================================================================

func TestBackendReconciler_findMatchingPort(t *testing.T) {
	r := &BackendReconciler{}

	tests := []struct {
		name       string
		ports      []discoveryv1.EndpointPort
		targetPort int32
		wantPort   int32
	}{
		{
			name: "finds matching port",
			ports: []discoveryv1.EndpointPort{
				{Port: ptrInt32(8080)},
				{Port: ptrInt32(9090)},
			},
			targetPort: 8080,
			wantPort:   8080,
		},
		{
			name: "returns target port when no match",
			ports: []discoveryv1.EndpointPort{
				{Port: ptrInt32(9090)},
				{Port: ptrInt32(9091)},
			},
			targetPort: 8080,
			wantPort:   8080,
		},
		{
			name:       "returns target port for empty ports",
			ports:      []discoveryv1.EndpointPort{},
			targetPort: 8080,
			wantPort:   8080,
		},
		{
			name: "handles nil port in slice",
			ports: []discoveryv1.EndpointPort{
				{Port: nil},
				{Port: ptrInt32(8080)},
			},
			targetPort: 8080,
			wantPort:   8080,
		},
		{
			name: "returns target port when all ports are nil",
			ports: []discoveryv1.EndpointPort{
				{Port: nil},
				{Port: nil},
			},
			targetPort: 8080,
			wantPort:   8080,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := r.findMatchingPort(tt.ports, tt.targetPort)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}

// ============================================================================
// BackendReconciler.setEndpointHealthConditions Tests
// ============================================================================

func TestBackendReconciler_setEndpointHealthConditions(t *testing.T) {
	r := &BackendReconciler{}

	tests := []struct {
		name              string
		totalEndpoints    int32
		healthyEndpoints  int32
		healthyCount      int32
		expectedPhase     avapigwv1alpha1.PhaseStatus
		expectedCondition metav1.ConditionStatus
		expectedReason    string
	}{
		{
			name:              "no endpoints - Error phase",
			totalEndpoints:    0,
			healthyEndpoints:  0,
			healthyCount:      0,
			expectedPhase:     avapigwv1alpha1.PhaseStatusError,
			expectedCondition: metav1.ConditionFalse,
			expectedReason:    string(avapigwv1alpha1.ReasonNotReady),
		},
		{
			name:              "no healthy endpoints - Degraded phase",
			totalEndpoints:    3,
			healthyEndpoints:  0,
			healthyCount:      0,
			expectedPhase:     avapigwv1alpha1.PhaseStatusDegraded,
			expectedCondition: metav1.ConditionFalse,
			expectedReason:    string(avapigwv1alpha1.ReasonDegraded),
		},
		{
			name:              "partial healthy endpoints - Degraded phase with True condition",
			totalEndpoints:    3,
			healthyEndpoints:  2,
			healthyCount:      2,
			expectedPhase:     avapigwv1alpha1.PhaseStatusDegraded,
			expectedCondition: metav1.ConditionTrue,
			expectedReason:    string(avapigwv1alpha1.ReasonDegraded),
		},
		{
			name:              "all endpoints healthy - Ready phase",
			totalEndpoints:    3,
			healthyEndpoints:  3,
			healthyCount:      3,
			expectedPhase:     avapigwv1alpha1.PhaseStatusReady,
			expectedCondition: metav1.ConditionTrue,
			expectedReason:    string(avapigwv1alpha1.ReasonReady),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &avapigwv1alpha1.Backend{
				Status: avapigwv1alpha1.BackendStatus{
					TotalEndpoints:   tt.totalEndpoints,
					HealthyEndpoints: tt.healthyEndpoints,
				},
			}

			r.setEndpointHealthConditions(backend, tt.healthyCount)

			assert.Equal(t, tt.expectedPhase, backend.Status.Phase)

			readyCondition := backend.Status.GetCondition(avapigwv1alpha1.ConditionTypeReady)
			require.NotNil(t, readyCondition)
			assert.Equal(t, tt.expectedCondition, readyCondition.Status)
			assert.Equal(t, tt.expectedReason, readyCondition.Reason)

			// Verify ResolvedRefs condition is always set to True
			resolvedRefsCondition := backend.Status.GetCondition(avapigwv1alpha1.ConditionTypeResolvedRefs)
			require.NotNil(t, resolvedRefsCondition)
			assert.Equal(t, metav1.ConditionTrue, resolvedRefsCondition.Status)
		})
	}
}

// ============================================================================
// BackendReconciler.discoverFromEndpointSlices Tests
// ============================================================================

func TestBackendReconciler_discoverFromEndpointSlices(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name          string
		objects       []client.Object
		namespace     string
		serviceRef    *avapigwv1alpha1.ServiceRef
		wantEndpoints int
		wantFound     bool
	}{
		{
			name: "discovers endpoints from EndpointSlices",
			objects: []client.Object{
				&discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service-abc",
						Namespace: "default",
						Labels: map[string]string{
							discoveryv1.LabelServiceName: "test-service",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses:  []string{"10.0.0.1", "10.0.0.2"},
							Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
						},
					},
					Ports: []discoveryv1.EndpointPort{
						{Port: ptrInt32(8080)},
					},
				},
			},
			namespace: "default",
			serviceRef: &avapigwv1alpha1.ServiceRef{
				Name: "test-service",
				Port: 8080,
			},
			wantEndpoints: 2,
			wantFound:     true,
		},
		{
			name: "discovers endpoints from multiple EndpointSlices",
			objects: []client.Object{
				&discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service-abc",
						Namespace: "default",
						Labels: map[string]string{
							discoveryv1.LabelServiceName: "test-service",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses:  []string{"10.0.0.1"},
							Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
						},
					},
					Ports: []discoveryv1.EndpointPort{
						{Port: ptrInt32(8080)},
					},
				},
				&discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service-def",
						Namespace: "default",
						Labels: map[string]string{
							discoveryv1.LabelServiceName: "test-service",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses:  []string{"10.0.0.2", "10.0.0.3"},
							Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
						},
					},
					Ports: []discoveryv1.EndpointPort{
						{Port: ptrInt32(8080)},
					},
				},
			},
			namespace: "default",
			serviceRef: &avapigwv1alpha1.ServiceRef{
				Name: "test-service",
				Port: 8080,
			},
			wantEndpoints: 3,
			wantFound:     true,
		},
		{
			name:      "returns false when no EndpointSlices found",
			objects:   []client.Object{},
			namespace: "default",
			serviceRef: &avapigwv1alpha1.ServiceRef{
				Name: "test-service",
				Port: 8080,
			},
			wantEndpoints: 0,
			wantFound:     false,
		},
		{
			name: "returns false when EndpointSlices for different service",
			objects: []client.Object{
				&discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "other-service-abc",
						Namespace: "default",
						Labels: map[string]string{
							discoveryv1.LabelServiceName: "other-service",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses:  []string{"10.0.0.1"},
							Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
						},
					},
					Ports: []discoveryv1.EndpointPort{
						{Port: ptrInt32(8080)},
					},
				},
			},
			namespace: "default",
			serviceRef: &avapigwv1alpha1.ServiceRef{
				Name: "test-service",
				Port: 8080,
			},
			wantEndpoints: 0,
			wantFound:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newBackendReconciler(cl, scheme)

			endpoints, found := r.discoverFromEndpointSlices(context.Background(), tt.namespace, tt.serviceRef)

			assert.Equal(t, tt.wantFound, found)
			assert.Len(t, endpoints, tt.wantEndpoints)
		})
	}
}

// ============================================================================
// BackendReconciler.fetchBackend Tests
// ============================================================================

func TestBackendReconciler_fetchBackend(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name        string
		objects     []client.Object
		request     ctrl.Request
		wantBackend bool
		wantErr     bool
	}{
		{
			name: "successfully fetches backend",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-backend",
						Namespace: "default",
					},
				},
			},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-backend",
					Namespace: "default",
				},
			},
			wantBackend: true,
			wantErr:     false,
		},
		{
			name:    "returns nil for not found",
			objects: []client.Object{},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent",
					Namespace: "default",
				},
			},
			wantBackend: false,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newBackendReconciler(cl, scheme)
			strategy := DefaultRequeueStrategy()
			resourceKey := tt.request.String()

			backend, _, err := r.fetchBackend(context.Background(), tt.request, strategy, resourceKey)

			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

			if tt.wantBackend {
				assert.NotNil(t, backend)
			} else {
				assert.Nil(t, backend)
			}
		})
	}
}

// ============================================================================
// BackendReconciler.ensureFinalizerAndReconcileBackend Tests
// ============================================================================

func TestBackendReconciler_ensureFinalizerAndReconcileBackend(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name           string
		backend        *avapigwv1alpha1.Backend
		wantErr        bool
		validateResult func(t *testing.T, result ctrl.Result)
		validate       func(t *testing.T, cl client.Client)
	}{
		{
			name: "adds finalizer when not present",
			backend: &avapigwv1alpha1.Backend{
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
			wantErr: false,
			validateResult: func(t *testing.T, result ctrl.Result) {
				assert.True(t, result.Requeue)
			},
			validate: func(t *testing.T, cl client.Client) {
				backend := &avapigwv1alpha1.Backend{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, backend)
				require.NoError(t, err)
				assert.Contains(t, backend.Finalizers, backendFinalizer)
			},
		},
		{
			name: "reconciles when finalizer present",
			backend: &avapigwv1alpha1.Backend{
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
			wantErr: false,
			validateResult: func(t *testing.T, result ctrl.Result) {
				assert.True(t, result.RequeueAfter > 0)
			},
			validate: func(t *testing.T, cl client.Client) {
				backend := &avapigwv1alpha1.Backend{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-backend", Namespace: "default"}, backend)
				require.NoError(t, err)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, backend.Status.Phase)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.backend).
				WithStatusSubresource(&avapigwv1alpha1.Backend{}).
				Build()

			r := newBackendReconciler(cl, scheme)
			r.initBaseComponents()
			strategy := DefaultRequeueStrategy()
			resourceKey := client.ObjectKeyFromObject(tt.backend).String()

			// Fetch the backend to get the version from the fake client
			fetchedBackend := &avapigwv1alpha1.Backend{}
			err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.backend), fetchedBackend)
			require.NoError(t, err)

			var reconcileErr *ReconcileError
			result, err := r.ensureFinalizerAndReconcileBackend(context.Background(), fetchedBackend, strategy, resourceKey, &reconcileErr)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}

			if tt.validate != nil {
				tt.validate(t, cl)
			}
		})
	}
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

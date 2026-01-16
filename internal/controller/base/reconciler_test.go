package base

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// mockRequeueStrategy implements RequeueStrategyProvider for testing
type mockRequeueStrategy struct {
	successResult           ctrl.Result
	immediateRequeueResult  ctrl.Result
	transientErrorResult    ctrl.Result
	validationErrorResult   ctrl.Result
	permanentErrorResult    ctrl.Result
	dependencyErrorResult   ctrl.Result
	failureCounts           map[string]int
	resetFailureCountCalled map[string]bool
}

func newMockRequeueStrategy() *mockRequeueStrategy {
	return &mockRequeueStrategy{
		successResult:           ctrl.Result{RequeueAfter: 5 * time.Minute},
		immediateRequeueResult:  ctrl.Result{Requeue: true},
		transientErrorResult:    ctrl.Result{RequeueAfter: 10 * time.Second, Requeue: true},
		validationErrorResult:   ctrl.Result{RequeueAfter: 5 * time.Minute},
		permanentErrorResult:    ctrl.Result{RequeueAfter: 10 * time.Minute},
		dependencyErrorResult:   ctrl.Result{RequeueAfter: 30 * time.Second, Requeue: true},
		failureCounts:           make(map[string]int),
		resetFailureCountCalled: make(map[string]bool),
	}
}

func (m *mockRequeueStrategy) ForSuccess() ctrl.Result {
	return m.successResult
}

func (m *mockRequeueStrategy) ForImmediateRequeue() ctrl.Result {
	return m.immediateRequeueResult
}

func (m *mockRequeueStrategy) ForTransientErrorWithBackoff(key string) ctrl.Result {
	m.failureCounts[key]++
	return m.transientErrorResult
}

func (m *mockRequeueStrategy) ForValidationError() ctrl.Result {
	return m.validationErrorResult
}

func (m *mockRequeueStrategy) ForPermanentError() ctrl.Result {
	return m.permanentErrorResult
}

func (m *mockRequeueStrategy) ForDependencyErrorWithBackoff(key string) ctrl.Result {
	m.failureCounts[key]++
	return m.dependencyErrorResult
}

func (m *mockRequeueStrategy) GetFailureCount(key string) int {
	return m.failureCounts[key]
}

func (m *mockRequeueStrategy) ResetFailureCount(key string) {
	m.resetFailureCountCalled[key] = true
	delete(m.failureCounts, key)
}

// createTestScheme creates a scheme with corev1 types for testing
func createTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return scheme
}

// createTestMetricsRegistry creates a metrics registry for testing
func createTestMetricsRegistry() *MetricsRegistry {
	return NewMetricsRegistry(prometheus.NewRegistry())
}

func TestNewSimpleReconciler(t *testing.T) {
	scheme := createTestScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)

	tests := []struct {
		name            string
		config          ReconcilerConfig
		expectedName    string
		expectedFin     string
		expectedTimeout time.Duration
	}{
		{
			name: "with all config values",
			config: ReconcilerConfig{
				Name:             "testcontroller1",
				FinalizerName:    "test.example.com/finalizer",
				ReconcileTimeout: 60 * time.Second,
			},
			expectedName:    "testcontroller1",
			expectedFin:     "test.example.com/finalizer",
			expectedTimeout: 60 * time.Second,
		},
		{
			name: "with zero timeout uses default",
			config: ReconcilerConfig{
				Name:             "testcontroller2",
				FinalizerName:    "test.example.com/finalizer",
				ReconcileTimeout: 0,
			},
			expectedName:    "testcontroller2",
			expectedFin:     "test.example.com/finalizer",
			expectedTimeout: DefaultReconcileTimeout,
		},
		{
			name: "with empty finalizer",
			config: ReconcilerConfig{
				Name:             "testcontroller3",
				FinalizerName:    "",
				ReconcileTimeout: 30 * time.Second,
			},
			expectedName:    "testcontroller3",
			expectedFin:     "",
			expectedTimeout: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := NewSimpleReconciler[*corev1.ConfigMap](client, scheme, recorder, tt.config)

			require.NotNil(t, reconciler)
			assert.Equal(t, client, reconciler.Client)
			assert.Equal(t, scheme, reconciler.Scheme)
			assert.Equal(t, recorder, reconciler.Recorder)
			assert.Equal(t, tt.expectedName, reconciler.Config.Name)
			assert.Equal(t, tt.expectedFin, reconciler.Config.FinalizerName)
			assert.Equal(t, tt.expectedTimeout, reconciler.Config.ReconcileTimeout)
			assert.NotNil(t, reconciler.Metrics)
			assert.NotNil(t, reconciler.FinalizerHandler)
		})
	}
}

func TestSimpleReconciler_Reconcile_ResourceNotFound(t *testing.T) {
	scheme := createTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller_notfound",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "non-existent",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	// Verify failure count was reset for deleted resource
	assert.True(t, strategy.resetFailureCountCalled["default/non-existent"])
}

func TestSimpleReconciler_Reconcile_GetError(t *testing.T) {
	scheme := createTestScheme()

	// Create a client that returns an error on Get
	expectedErr := errors.New("get error")
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, client client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return expectedErr
			},
		}).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, strategy.transientErrorResult, result)
}

func TestSimpleReconciler_Reconcile_SuccessfulReconciliation(t *testing.T) {
	scheme := createTestScheme()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cm",
			Namespace:  "default",
			Finalizers: []string{"test.example.com/finalizer"}, // Already has finalizer
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	reconcileCalled := false
	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			reconcileCalled = true
			assert.Equal(t, "test-cm", obj.Name)
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.NoError(t, err)
	assert.Equal(t, strategy.successResult, result)
	assert.True(t, reconcileCalled)
	// Verify failure count was reset on success
	assert.True(t, strategy.resetFailureCountCalled["default/test-cm"])
}

func TestSimpleReconciler_Reconcile_ReconcileError(t *testing.T) {
	scheme := createTestScheme()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cm",
			Namespace:  "default",
			Finalizers: []string{"test.example.com/finalizer"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	reconcileErr := errors.New("reconcile error")
	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return reconcileErr
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.Error(t, err)
	assert.Equal(t, reconcileErr, err)
	assert.Equal(t, strategy.transientErrorResult, result)
	// Verify failure count was incremented
	assert.Equal(t, 1, strategy.failureCounts["default/test-cm"])
}

func TestSimpleReconciler_Reconcile_AddFinalizerAndRequeue(t *testing.T) {
	scheme := createTestScheme()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cm",
			Namespace: "default",
			// No finalizer
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	reconcileCalled := false
	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			reconcileCalled = true
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.NoError(t, err)
	assert.Equal(t, strategy.immediateRequeueResult, result)
	// Reconcile should not be called when finalizer is added
	assert.False(t, reconcileCalled)

	// Verify finalizer was added
	var updatedCM corev1.ConfigMap
	err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-cm", Namespace: "default"}, &updatedCM)
	require.NoError(t, err)
	assert.Contains(t, updatedCM.Finalizers, "test.example.com/finalizer")
}

func TestSimpleReconciler_Reconcile_AddFinalizerError(t *testing.T) {
	scheme := createTestScheme()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cm",
			Namespace: "default",
		},
	}

	updateErr := errors.New("update error")
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				return updateErr
			},
		}).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.Error(t, err)
	assert.Equal(t, updateErr, err)
	assert.Equal(t, strategy.transientErrorResult, result)
}

func TestSimpleReconciler_Reconcile_DeletionWithFinalizer(t *testing.T) {
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			Finalizers:        []string{"test.example.com/finalizer"},
			DeletionTimestamp: &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	deleteCalled := false
	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		DeleteFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			deleteCalled = true
			assert.Equal(t, "test-cm", obj.Name)
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.True(t, deleteCalled)
	// Verify failure count was reset on successful deletion
	assert.True(t, strategy.resetFailureCountCalled["default/test-cm"])

	// When finalizer is removed from an object with deletionTimestamp,
	// the object is deleted by the API server (simulated by fake client)
	// So we just verify the reconciliation completed successfully
}

func TestSimpleReconciler_Reconcile_DeletionWithoutFinalizer(t *testing.T) {
	// This test uses handleDeletion directly because the fake client
	// doesn't allow creating objects with deletionTimestamp but no finalizers
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			DeletionTimestamp: &now,
			// No finalizer - we'll test handleDeletion directly
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	deleteCalled := false
	deleteFunc := func(ctx context.Context, obj *corev1.ConfigMap) error {
		deleteCalled = true
		return nil
	}

	// Test handleDeletion directly with an object that has no finalizer
	result, err := reconciler.handleDeletion(context.Background(), cm, deleteFunc, ctrl.Log, strategy, "default/test-cm")

	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	// Delete should not be called when finalizer is not present
	assert.False(t, deleteCalled)
}

func TestSimpleReconciler_Reconcile_DeletionWithoutDeleteFunc(t *testing.T) {
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			Finalizers:        []string{"test.example.com/finalizer"},
			DeletionTimestamp: &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		// No DeleteFunc
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// When finalizer is removed from an object with deletionTimestamp,
	// the object is deleted by the API server (simulated by fake client)
	// So we just verify the reconciliation completed successfully
}

func TestSimpleReconciler_Reconcile_DeleteFuncError(t *testing.T) {
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			Finalizers:        []string{"test.example.com/finalizer"},
			DeletionTimestamp: &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	deleteErr := errors.New("delete error")
	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		DeleteFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return deleteErr
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.Error(t, err)
	assert.Equal(t, deleteErr, err)
	assert.Equal(t, strategy.transientErrorResult, result)

	// Verify finalizer was NOT removed due to error
	var updatedCM corev1.ConfigMap
	err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-cm", Namespace: "default"}, &updatedCM)
	require.NoError(t, err)
	assert.Contains(t, updatedCM.Finalizers, "test.example.com/finalizer")
}

func TestSimpleReconciler_Reconcile_FinalizerRemovalError(t *testing.T) {
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			Finalizers:        []string{"test.example.com/finalizer"},
			DeletionTimestamp: &now,
		},
	}

	updateErr := errors.New("update error")
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				return updateErr
			},
		}).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		DeleteFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.Error(t, err)
	assert.Equal(t, updateErr, err)
	assert.Equal(t, strategy.transientErrorResult, result)
}

func TestSimpleReconciler_Reconcile_ContextTimeout(t *testing.T) {
	scheme := createTestScheme()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cm",
			Namespace:  "default",
			Finalizers: []string{"test.example.com/finalizer"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 100 * time.Millisecond, // Short timeout
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			// Simulate slow operation
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
				return nil
			}
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
	assert.Equal(t, strategy.transientErrorResult, result)
}

func TestSimpleReconciler_Reconcile_WithExistingFinalizer(t *testing.T) {
	scheme := createTestScheme()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cm",
			Namespace:  "default",
			Finalizers: []string{"test.example.com/finalizer"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	reconcileCalled := false
	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			reconcileCalled = true
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.NoError(t, err)
	assert.Equal(t, strategy.successResult, result)
	// Reconcile should be called when finalizer already exists
	assert.True(t, reconcileCalled)
}

func TestHandleDeletion_WithDeleteFunc(t *testing.T) {
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			Finalizers:        []string{"test.example.com/finalizer"},
			DeletionTimestamp: &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	deleteCalled := false
	deleteFunc := func(ctx context.Context, obj *corev1.ConfigMap) error {
		deleteCalled = true
		return nil
	}

	// Get the object first
	var obj corev1.ConfigMap
	err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-cm", Namespace: "default"}, &obj)
	require.NoError(t, err)

	result, err := reconciler.handleDeletion(context.Background(), &obj, deleteFunc, ctrl.Log, strategy, "default/test-cm")

	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.True(t, deleteCalled)
}

func TestHandleDeletion_WithoutDeleteFunc(t *testing.T) {
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			Finalizers:        []string{"test.example.com/finalizer"},
			DeletionTimestamp: &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	// Get the object first
	var obj corev1.ConfigMap
	err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-cm", Namespace: "default"}, &obj)
	require.NoError(t, err)

	result, err := reconciler.handleDeletion(context.Background(), &obj, nil, ctrl.Log, strategy, "default/test-cm")

	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// When finalizer is removed from an object with deletionTimestamp,
	// the object is deleted by the API server (simulated by fake client)
}

func TestHandleDeletion_NoFinalizer(t *testing.T) {
	// Test handleDeletion directly with an object that has no finalizer
	// We don't use the fake client because it doesn't allow creating objects
	// with deletionTimestamp but no finalizers
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			DeletionTimestamp: &now,
			// No finalizer
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	deleteCalled := false
	deleteFunc := func(ctx context.Context, obj *corev1.ConfigMap) error {
		deleteCalled = true
		return nil
	}

	// Test handleDeletion directly with the object (not from fake client)
	result, err := reconciler.handleDeletion(context.Background(), cm, deleteFunc, ctrl.Log, strategy, "default/test-cm")

	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	// Delete should not be called when finalizer is not present
	assert.False(t, deleteCalled)
}

func TestHandleDeletion_DeleteFuncError(t *testing.T) {
	scheme := createTestScheme()

	now := metav1.Now()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cm",
			Namespace:         "default",
			Finalizers:        []string{"test.example.com/finalizer"},
			DeletionTimestamp: &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	deleteErr := errors.New("delete error")
	deleteFunc := func(ctx context.Context, obj *corev1.ConfigMap) error {
		return deleteErr
	}

	// Get the object first
	var obj corev1.ConfigMap
	err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-cm", Namespace: "default"}, &obj)
	require.NoError(t, err)

	result, err := reconciler.handleDeletion(context.Background(), &obj, deleteFunc, ctrl.Log, strategy, "default/test-cm")

	assert.Error(t, err)
	assert.Equal(t, deleteErr, err)
	assert.Equal(t, strategy.transientErrorResult, result)
}

func TestReconcilerConfig_DefaultTimeout(t *testing.T) {
	assert.Equal(t, 30*time.Second, DefaultReconcileTimeout)
}

func TestSimpleReconciler_Reconcile_NotFoundError(t *testing.T) {
	scheme := createTestScheme()

	// Create a client that returns NotFound error
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, client client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return apierrors.NewNotFound(schema.GroupResource{Group: "", Resource: "configmaps"}, key.Name)
			},
		}).
		Build()
	recorder := record.NewFakeRecorder(10)

	config := ReconcilerConfig{
		Name:             "testcontroller",
		FinalizerName:    "test.example.com/finalizer",
		ReconcileTimeout: 30 * time.Second,
	}

	reconciler := NewSimpleReconciler[*corev1.ConfigMap](fakeClient, scheme, recorder, config)
	strategy := newMockRequeueStrategy()

	params := ReconcileParams[*corev1.ConfigMap]{
		Ctx: context.Background(),
		Req: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-cm",
				Namespace: "default",
			},
		},
		NewObject: func() *corev1.ConfigMap {
			return &corev1.ConfigMap{}
		},
		ReconcileFunc: func(ctx context.Context, obj *corev1.ConfigMap) error {
			return nil
		},
		Strategy: strategy,
	}

	result, err := reconciler.Reconcile(params)

	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	// Verify failure count was reset for deleted resource
	assert.True(t, strategy.resetFailureCountCalled["default/test-cm"])
}

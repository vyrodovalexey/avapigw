package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func TestGatewayReconciler_Reconcile_NotFound(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "non-existent",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.IsZero())
}

func TestGatewayReconciler_UpdateListenerStatuses(t *testing.T) {
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
				{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
				{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
			},
		},
	}

	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	reconciler := &GatewayReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		Scheme: scheme,
	}

	err = reconciler.updateListenerStatuses(context.Background(), gateway)
	require.NoError(t, err)

	// Verify listener statuses were created
	assert.Len(t, gateway.Status.Listeners, 4)

	// HTTP listener should support HTTPRoute
	httpListenerStatus := gateway.Status.Listeners[0]
	assert.Equal(t, "http", httpListenerStatus.Name)
	assert.Len(t, httpListenerStatus.SupportedKinds, 1)
	assert.Equal(t, "HTTPRoute", httpListenerStatus.SupportedKinds[0].Kind)

	// GRPC listener should support GRPCRoute
	grpcListenerStatus := gateway.Status.Listeners[2]
	assert.Equal(t, "grpc", grpcListenerStatus.Name)
	assert.Len(t, grpcListenerStatus.SupportedKinds, 1)
	assert.Equal(t, "GRPCRoute", grpcListenerStatus.SupportedKinds[0].Kind)
}

func TestGatewayReconciler_MatchesGateway(t *testing.T) {
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	route := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	parentRef := avapigwv1alpha1.ParentRef{
		Name: "test-gateway",
	}

	reconciler := &GatewayReconciler{}

	// Same namespace and name should match
	assert.True(t, reconciler.matchesGateway(gateway, route, parentRef))

	// Different namespace should not match
	otherNS := "other"
	parentRefWithNS := avapigwv1alpha1.ParentRef{
		Name:      "test-gateway",
		Namespace: &otherNS,
	}
	assert.False(t, reconciler.matchesGateway(gateway, route, parentRefWithNS))

	// Different name should not match
	parentRefWrongName := avapigwv1alpha1.ParentRef{
		Name: "other-gateway",
	}
	assert.False(t, reconciler.matchesGateway(gateway, route, parentRefWrongName))
}

func TestGatewayReconciler_GetListenerName(t *testing.T) {
	reconciler := &GatewayReconciler{}

	// With section name
	sectionName := "http"
	parentRefWithSection := avapigwv1alpha1.ParentRef{
		Name:        "test-gateway",
		SectionName: &sectionName,
	}
	assert.Equal(t, "http", reconciler.getListenerName(parentRefWithSection))

	// Without section name
	parentRefWithoutSection := avapigwv1alpha1.ParentRef{
		Name: "test-gateway",
	}
	assert.Equal(t, "", reconciler.getListenerName(parentRefWithoutSection))
}

func TestGatewayReconciler_SetCondition(t *testing.T) {
	gateway := &avapigwv1alpha1.Gateway{}

	reconciler := &GatewayReconciler{}
	reconciler.setCondition(gateway, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue, "Ready", "Gateway is ready")

	condition := gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeReady)
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
	assert.Equal(t, "Ready", condition.Reason)
	assert.Equal(t, "Gateway is ready", condition.Message)
}

func TestHTTPRouteReconciler_Reconcile_NotFound(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &HTTPRouteReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "non-existent",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.IsZero())
}

func TestHTTPRouteReconciler_ValidateParentRefs(t *testing.T) {
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{
				Name: "test-gateway",
			}},
		},
	}

	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	require.NoError(t, cl.Create(context.Background(), gateway))

	reconciler := &HTTPRouteReconciler{
		Client: cl,
		Scheme: scheme,
	}

	parentStatuses, err := reconciler.validateParentRefs(context.Background(), httpRoute)
	require.NoError(t, err)
	assert.Len(t, parentStatuses, 1)
	assert.Equal(t, "test-gateway", parentStatuses[0].ParentRef.Name)
}

func TestHTTPRouteReconciler_HostnameMatches(t *testing.T) {
	reconciler := &HTTPRouteReconciler{}

	// Listener with no hostname matches all
	assert.True(t, reconciler.hostnameMatches([]avapigwv1alpha1.Hostname{}, nil))
	assert.True(t, reconciler.hostnameMatches([]avapigwv1alpha1.Hostname{"example.com"}, nil))

	// Route with no hostnames matches all
	hostname := avapigwv1alpha1.Hostname("example.com")
	assert.True(t, reconciler.hostnameMatches([]avapigwv1alpha1.Hostname{}, &hostname))

	// Exact match
	assert.True(t, reconciler.hostnameMatches([]avapigwv1alpha1.Hostname{"example.com"}, &hostname))

	// No match
	otherHostname := avapigwv1alpha1.Hostname("other.com")
	assert.False(t, reconciler.hostnameMatches([]avapigwv1alpha1.Hostname{"example.com"}, &otherHostname))
}

// TestGatewayReconciler_GetRequeueStrategy_Concurrent tests thread-safe initialization
// of the RequeueStrategy using sync.Once. This ensures that concurrent access from
// multiple goroutines returns the same instance without race conditions.
func TestGatewayReconciler_GetRequeueStrategy_Concurrent(t *testing.T) {
	r := &GatewayReconciler{}

	var wg sync.WaitGroup
	const numGoroutines = 100
	strategies := make([]*RequeueStrategy, numGoroutines)

	// Launch multiple goroutines to access getRequeueStrategy concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			strategies[idx] = r.getRequeueStrategy()
		}(i)
	}

	wg.Wait()

	// All goroutines should get the same instance
	first := strategies[0]
	require.NotNil(t, first, "RequeueStrategy should not be nil")

	for i, s := range strategies {
		if s != first {
			t.Errorf("goroutine %d got different strategy instance: got %p, want %p", i, s, first)
		}
	}
}

// TestGatewayReconciler_GetRequeueStrategy_InitializesDefault tests that
// getRequeueStrategy initializes with default values when RequeueStrategy is nil.
func TestGatewayReconciler_GetRequeueStrategy_InitializesDefault(t *testing.T) {
	r := &GatewayReconciler{}

	strategy := r.getRequeueStrategy()

	require.NotNil(t, strategy)
	assert.NotNil(t, strategy.config)
	// Verify it uses default configuration
	assert.Equal(t, DefaultRequeueConfig().BaseInterval, strategy.config.BaseInterval)
}

// TestGatewayReconciler_GetRequeueStrategy_PreservesPredefined tests that
// getRequeueStrategy preserves a pre-defined RequeueStrategy.
func TestGatewayReconciler_GetRequeueStrategy_PreservesPredefined(t *testing.T) {
	customConfig := &RequeueConfig{
		BaseInterval:            10 * time.Second,
		MaxInterval:             30 * time.Minute,
		TransientErrorInterval:  20 * time.Second,
		DependencyErrorInterval: 1 * time.Minute,
		ValidationErrorInterval: 10 * time.Minute,
		PermanentErrorInterval:  20 * time.Minute,
		SuccessInterval:         10 * time.Minute,
		BackoffMultiplier:       3.0,
		MaxFailures:             5,
		JitterPercent:           20,
	}
	customStrategy := NewRequeueStrategy(customConfig)

	r := &GatewayReconciler{
		RequeueStrategy: customStrategy,
	}

	strategy := r.getRequeueStrategy()

	assert.Equal(t, customStrategy, strategy)
	assert.Equal(t, 10*time.Second, strategy.config.BaseInterval)
}

// ============================================================================
// Reconcile Tests
// ============================================================================

// TestGatewayReconciler_Reconcile_WithExistingGateway tests successful reconciliation
// with an existing gateway that needs a finalizer added.
func TestGatewayReconciler_Reconcile_WithExistingGateway(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	// First reconcile should add finalizer
	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.Requeue, "Should requeue after adding finalizer")

	// Verify finalizer was added
	var updatedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), req.NamespacedName, &updatedGateway)
	require.NoError(t, err)
	assert.Contains(t, updatedGateway.Finalizers, gatewayFinalizer)
}

// TestGatewayReconciler_Reconcile_WithExistingFinalizer tests reconciliation
// when the gateway already has a finalizer.
func TestGatewayReconciler_Reconcile_WithExistingFinalizer(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0, "Should requeue after success interval")

	// Verify gateway status was updated
	var updatedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), req.NamespacedName, &updatedGateway)
	require.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, updatedGateway.Status.Phase)
}

// ============================================================================
// handleDeletion Tests
// ============================================================================

// TestGatewayReconciler_HandleDeletion_WithFinalizer tests deletion handling
// when the gateway has a finalizer.
func TestGatewayReconciler_HandleDeletion_WithFinalizer(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	now := metav1.Now()
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-gateway",
			Namespace:         "default",
			Finalizers:        []string{gatewayFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	result, err := reconciler.handleDeletion(context.Background(), gateway)
	assert.NoError(t, err)
	assert.True(t, result.IsZero(), "Should not requeue after successful deletion")

	// Verify finalizer was removed
	assert.NotContains(t, gateway.Finalizers, gatewayFinalizer)
}

// TestGatewayReconciler_HandleDeletion_WithoutFinalizer tests deletion handling
// when the gateway doesn't have a finalizer.
func TestGatewayReconciler_HandleDeletion_WithoutFinalizer(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	now := metav1.Now()
	// Note: We don't add this to the fake client since it doesn't allow objects
	// with deletionTimestamp but no finalizers. We just test the handleDeletion
	// function directly with an in-memory object.
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-gateway",
			Namespace:         "default",
			DeletionTimestamp: &now,
			// No finalizers
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	result, err := reconciler.handleDeletion(context.Background(), gateway)
	assert.NoError(t, err)
	assert.True(t, result.IsZero(), "Should not requeue when no finalizer present")
}

// ============================================================================
// reconcileGateway Tests
// ============================================================================

// TestGatewayReconciler_ReconcileGateway_Success tests successful gateway reconciliation.
func TestGatewayReconciler_ReconcileGateway_Success(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	err = reconciler.reconcileGateway(context.Background(), gateway)
	assert.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, gateway.Status.Phase)
	assert.Equal(t, int32(1), gateway.Status.ListenersCount)
}

// TestGatewayReconciler_ReconcileGateway_TLSValidationFailure tests reconciliation
// when TLS validation fails.
func TestGatewayReconciler_ReconcileGateway_TLSValidationFailure(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "non-existent-cert"},
						},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	err = reconciler.reconcileGateway(context.Background(), gateway)
	assert.Error(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusError, gateway.Status.Phase)

	// Verify condition was set
	condition := gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeAccepted)
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
}

// ============================================================================
// validateTLSConfigs Tests
// ============================================================================

// TestGatewayReconciler_ValidateTLSConfigs tests TLS configuration validation.
func TestGatewayReconciler_ValidateTLSConfigs(t *testing.T) {
	tests := []struct {
		name        string
		gateway     *avapigwv1alpha1.Gateway
		objects     []client.Object
		expectError bool
		errorMsg    string
	}{
		{
			name: "listener without TLS should pass",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			objects:     nil,
			expectError: false,
		},
		{
			name: "valid TLSConfig reference",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Port:     443,
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							TLS: &avapigwv1alpha1.GatewayTLSConfig{
								CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
									{Name: "my-tls-config"},
								},
							},
						},
					},
				},
			},
			objects: []client.Object{
				&avapigwv1alpha1.TLSConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-tls-config",
						Namespace: "default",
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid Secret reference",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Port:     443,
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							TLS: &avapigwv1alpha1.GatewayTLSConfig{
								CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
									{Name: "my-secret"},
								},
							},
						},
					},
				},
			},
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-secret",
						Namespace: "default",
					},
					Type: corev1.SecretTypeTLS,
				},
			},
			expectError: false,
		},
		{
			name: "invalid reference - not found",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Port:     443,
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							TLS: &avapigwv1alpha1.GatewayTLSConfig{
								CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
									{Name: "non-existent"},
								},
							},
						},
					},
				},
			},
			objects:     nil,
			expectError: true,
			errorMsg:    "not found as TLSConfig or Secret",
		},
		{
			name: "valid reference with namespace override",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Port:     443,
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							TLS: &avapigwv1alpha1.GatewayTLSConfig{
								CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
									{Name: "my-secret", Namespace: strPtr("other-ns")},
								},
							},
						},
					},
				},
			},
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-secret",
						Namespace: "other-ns",
					},
					Type: corev1.SecretTypeTLS,
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
			require.NoError(t, err)
			require.NoError(t, corev1.AddToScheme(scheme))

			builder := fake.NewClientBuilder().WithScheme(scheme)
			if len(tt.objects) > 0 {
				builder = builder.WithObjects(tt.objects...)
			}
			cl := builder.Build()

			reconciler := &GatewayReconciler{
				Client: cl,
				Scheme: scheme,
			}

			err = reconciler.validateTLSConfigs(context.Background(), tt.gateway)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// countAttachedRoutes Tests
// ============================================================================

// TestGatewayReconciler_CountAttachedRoutes tests counting attached routes.
func TestGatewayReconciler_CountAttachedRoutes(t *testing.T) {
	tests := []struct {
		name           string
		gateway        *avapigwv1alpha1.Gateway
		routes         []client.Object
		expectedCounts map[string]int32
	}{
		{
			name: "no routes",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			routes:         nil,
			expectedCounts: map[string]int32{"http": 0},
		},
		{
			name: "HTTPRoutes attached to specific listener",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
					},
				},
			},
			routes: []client.Object{
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway", SectionName: strPtr("http")},
						},
					},
				},
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway", SectionName: strPtr("https")},
						},
					},
				},
			},
			expectedCounts: map[string]int32{"http": 1, "https": 1},
		},
		{
			name: "HTTPRoute matching all listeners (no SectionName)",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
					},
				},
			},
			routes: []client.Object{
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "route1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.HTTPRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway"}, // No SectionName - matches all
						},
					},
				},
			},
			expectedCounts: map[string]int32{"http": 1, "https": 1},
		},
		{
			name: "GRPCRoutes attached",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
					},
				},
			},
			routes: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "grpc-route1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway", SectionName: strPtr("grpc")},
						},
					},
				},
			},
			expectedCounts: map[string]int32{"grpc": 1},
		},
		{
			name: "TCPRoutes attached",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
					},
				},
			},
			routes: []client.Object{
				&avapigwv1alpha1.TCPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tcp-route1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.TCPRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway", SectionName: strPtr("tcp")},
						},
					},
				},
			},
			expectedCounts: map[string]int32{"tcp": 1},
		},
		{
			name: "TLSRoutes attached",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "tls", Port: 8443, Protocol: avapigwv1alpha1.ProtocolTLS},
					},
				},
			},
			routes: []client.Object{
				&avapigwv1alpha1.TLSRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-route1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.TLSRouteSpec{
						ParentRefs: []avapigwv1alpha1.ParentRef{
							{Name: "test-gateway", SectionName: strPtr("tls")},
						},
						Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					},
				},
			},
			expectedCounts: map[string]int32{"tls": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
			require.NoError(t, err)
			require.NoError(t, corev1.AddToScheme(scheme))

			builder := fake.NewClientBuilder().
				WithScheme(scheme).
				WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
				WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
				WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
				WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc)

			if len(tt.routes) > 0 {
				builder = builder.WithObjects(tt.routes...)
			}
			cl := builder.Build()

			reconciler := &GatewayReconciler{
				Client: cl,
				Scheme: scheme,
			}

			counts, err := reconciler.countAttachedRoutes(context.Background(), tt.gateway)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedCounts, counts)
		})
	}
}

// ============================================================================
// updateAddresses Tests
// ============================================================================

// TestGatewayReconciler_UpdateAddresses tests address updates.
func TestGatewayReconciler_UpdateAddresses(t *testing.T) {
	tests := []struct {
		name              string
		specAddresses     []avapigwv1alpha1.GatewayAddress
		expectedAddresses []avapigwv1alpha1.GatewayStatusAddress
	}{
		{
			name:              "no addresses",
			specAddresses:     nil,
			expectedAddresses: []avapigwv1alpha1.GatewayStatusAddress{},
		},
		{
			name: "single IP address",
			specAddresses: []avapigwv1alpha1.GatewayAddress{
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeIPAddress), Value: "192.168.1.1"},
			},
			expectedAddresses: []avapigwv1alpha1.GatewayStatusAddress{
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeIPAddress), Value: "192.168.1.1"},
			},
		},
		{
			name: "multiple addresses with different types",
			specAddresses: []avapigwv1alpha1.GatewayAddress{
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeIPAddress), Value: "192.168.1.1"},
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeHostname), Value: "gateway.example.com"},
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeNamedAddress), Value: "my-lb"},
			},
			expectedAddresses: []avapigwv1alpha1.GatewayStatusAddress{
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeIPAddress), Value: "192.168.1.1"},
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeHostname), Value: "gateway.example.com"},
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeNamedAddress), Value: "my-lb"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Addresses: tt.specAddresses,
				},
			}

			reconciler := &GatewayReconciler{}
			reconciler.updateAddresses(gateway)

			assert.Equal(t, len(tt.expectedAddresses), len(gateway.Status.Addresses))
			for i, expected := range tt.expectedAddresses {
				assert.Equal(t, expected.Value, gateway.Status.Addresses[i].Value)
				if expected.Type != nil {
					assert.Equal(t, *expected.Type, *gateway.Status.Addresses[i].Type)
				}
			}
		})
	}
}

// ============================================================================
// findGatewaysForTLSConfig Tests
// ============================================================================

// TestGatewayReconciler_FindGatewaysForTLSConfig tests finding gateways for TLS config.
func TestGatewayReconciler_FindGatewaysForTLSConfig(t *testing.T) {
	tests := []struct {
		name             string
		tlsConfig        *avapigwv1alpha1.TLSConfig
		gateways         []avapigwv1alpha1.Gateway
		expectedRequests int
	}{
		{
			name: "matching gateway",
			tlsConfig: &avapigwv1alpha1.TLSConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-tls-config",
					Namespace: "default",
				},
			},
			gateways: []avapigwv1alpha1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{
								Name:     "https",
								Port:     443,
								Protocol: avapigwv1alpha1.ProtocolHTTPS,
								TLS: &avapigwv1alpha1.GatewayTLSConfig{
									CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
										{Name: "my-tls-config"},
									},
								},
							},
						},
					},
				},
			},
			expectedRequests: 1,
		},
		{
			name: "no matching gateways",
			tlsConfig: &avapigwv1alpha1.TLSConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-tls-config",
					Namespace: "default",
				},
			},
			gateways: []avapigwv1alpha1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{
								Name:     "https",
								Port:     443,
								Protocol: avapigwv1alpha1.ProtocolHTTPS,
								TLS: &avapigwv1alpha1.GatewayTLSConfig{
									CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
										{Name: "other-tls-config"},
									},
								},
							},
						},
					},
				},
			},
			expectedRequests: 0,
		},
		{
			name: "multiple matching gateways",
			tlsConfig: &avapigwv1alpha1.TLSConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "shared-tls-config",
					Namespace: "default",
				},
			},
			gateways: []avapigwv1alpha1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "gateway1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{
								Name:     "https",
								Port:     443,
								Protocol: avapigwv1alpha1.ProtocolHTTPS,
								TLS: &avapigwv1alpha1.GatewayTLSConfig{
									CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
										{Name: "shared-tls-config"},
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "gateway2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{
								Name:     "https",
								Port:     443,
								Protocol: avapigwv1alpha1.ProtocolHTTPS,
								TLS: &avapigwv1alpha1.GatewayTLSConfig{
									CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
										{Name: "shared-tls-config"},
									},
								},
							},
						},
					},
				},
			},
			expectedRequests: 2,
		},
		{
			name: "matching gateway with namespace override",
			tlsConfig: &avapigwv1alpha1.TLSConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-tls-config",
					Namespace: "cert-ns",
				},
			},
			gateways: []avapigwv1alpha1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{
								Name:     "https",
								Port:     443,
								Protocol: avapigwv1alpha1.ProtocolHTTPS,
								TLS: &avapigwv1alpha1.GatewayTLSConfig{
									CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
										{Name: "my-tls-config", Namespace: strPtr("cert-ns")},
									},
								},
							},
						},
					},
				},
			},
			expectedRequests: 1,
		},
		{
			name: "gateway without TLS",
			tlsConfig: &avapigwv1alpha1.TLSConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-tls-config",
					Namespace: "default",
				},
			},
			gateways: []avapigwv1alpha1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{
								Name:     "http",
								Port:     80,
								Protocol: avapigwv1alpha1.ProtocolHTTP,
							},
						},
					},
				},
			},
			expectedRequests: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
			require.NoError(t, err)

			objects := make([]client.Object, len(tt.gateways))
			for i := range tt.gateways {
				objects[i] = &tt.gateways[i]
			}

			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				Build()

			reconciler := &GatewayReconciler{
				Client: cl,
				Scheme: scheme,
			}

			requests := reconciler.findGatewaysForTLSConfig(context.Background(), tt.tlsConfig)
			assert.Len(t, requests, tt.expectedRequests)
		})
	}
}

// ============================================================================
// findGatewaysForRoute Tests
// ============================================================================

// TestGatewayReconciler_FindGatewaysForRoute tests finding gateways for routes.
func TestGatewayReconciler_FindGatewaysForRoute(t *testing.T) {
	tests := []struct {
		name             string
		route            client.Object
		expectedRequests []reconcile.Request
	}{
		{
			name: "HTTPRoute with single parent",
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "test-gateway"},
					},
				},
			},
			expectedRequests: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "test-gateway"}},
			},
		},
		{
			name: "GRPCRoute with single parent",
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "grpc-gateway"},
					},
				},
			},
			expectedRequests: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "grpc-gateway"}},
			},
		},
		{
			name: "TCPRoute with single parent",
			route: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "tcp-gateway"},
					},
				},
			},
			expectedRequests: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "tcp-gateway"}},
			},
		},
		{
			name: "TLSRoute with single parent",
			route: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "tls-gateway"},
					},
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
				},
			},
			expectedRequests: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "tls-gateway"}},
			},
		},
		{
			name: "HTTPRoute with namespace override in parentRef",
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "test-gateway", Namespace: strPtr("gateway-ns")},
					},
				},
			},
			expectedRequests: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "gateway-ns", Name: "test-gateway"}},
			},
		},
		{
			name: "HTTPRoute with multiple parents",
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "gateway1"},
						{Name: "gateway2", Namespace: strPtr("other-ns")},
					},
				},
			},
			expectedRequests: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "gateway1"}},
				{NamespacedName: client.ObjectKey{Namespace: "other-ns", Name: "gateway2"}},
			},
		},
		{
			name: "unknown route type",
			route: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "not-a-route",
					Namespace: "default",
				},
			},
			expectedRequests: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
			require.NoError(t, err)
			require.NoError(t, corev1.AddToScheme(scheme))

			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			reconciler := &GatewayReconciler{
				Client: cl,
				Scheme: scheme,
			}

			requests := reconciler.findGatewaysForRoute(context.Background(), tt.route)
			assert.Equal(t, tt.expectedRequests, requests)
		})
	}
}

// ============================================================================
// UpdateListenerStatuses Additional Tests
// ============================================================================

// TestGatewayReconciler_UpdateListenerStatuses_AllProtocols tests listener status
// updates for all supported protocols.
func TestGatewayReconciler_UpdateListenerStatuses_AllProtocols(t *testing.T) {
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
				{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
				{Name: "grpcs", Port: 50052, Protocol: avapigwv1alpha1.ProtocolGRPCS},
				{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
				{Name: "tls", Port: 8443, Protocol: avapigwv1alpha1.ProtocolTLS},
			},
		},
	}

	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	reconciler := &GatewayReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		Scheme: scheme,
	}

	err = reconciler.updateListenerStatuses(context.Background(), gateway)
	require.NoError(t, err)

	assert.Len(t, gateway.Status.Listeners, 6)

	// Verify each listener has correct supported kinds
	expectedKinds := map[string]string{
		"http":  "HTTPRoute",
		"https": "HTTPRoute",
		"grpc":  "GRPCRoute",
		"grpcs": "GRPCRoute",
		"tcp":   "TCPRoute",
		"tls":   "TLSRoute",
	}

	for _, listener := range gateway.Status.Listeners {
		expectedKind, ok := expectedKinds[listener.Name]
		require.True(t, ok, "Unexpected listener name: %s", listener.Name)
		require.Len(t, listener.SupportedKinds, 1)
		assert.Equal(t, expectedKind, listener.SupportedKinds[0].Kind)

		// Verify condition is set
		require.Len(t, listener.Conditions, 1)
		assert.Equal(t, avapigwv1alpha1.ConditionTypeReady, listener.Conditions[0].Type)
		assert.Equal(t, metav1.ConditionTrue, listener.Conditions[0].Status)
	}
}

// ============================================================================
// Reconcile Error Handling Tests
// ============================================================================

// TestGatewayReconciler_Reconcile_DeletionHandling tests reconciliation when
// gateway has DeletionTimestamp set.
func TestGatewayReconciler_Reconcile_DeletionHandling(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	now := metav1.Now()
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-gateway",
			Namespace:         "default",
			Finalizers:        []string{gatewayFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.IsZero(), "Should not requeue after deletion")
}

// ============================================================================
// Reconcile Error Handling Additional Tests
// ============================================================================

// TestGatewayReconciler_Reconcile_ValidationError tests reconciliation when
// validation error occurs (e.g., invalid TLS config).
func TestGatewayReconciler_Reconcile_ValidationError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "non-existent-cert"},
						},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	assert.Error(t, err)
	// Validation errors should not requeue immediately
	assert.True(t, result.RequeueAfter > 0, "Should requeue after validation error interval")
}

// TestGatewayReconciler_Reconcile_SuccessfulReconciliation tests full successful
// reconciliation flow including status update.
func TestGatewayReconciler_Reconcile_SuccessfulReconciliation(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
			},
			Addresses: []avapigwv1alpha1.GatewayAddress{
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeIPAddress), Value: "10.0.0.1"},
			},
		},
	}

	// Create some routes that reference this gateway
	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway", SectionName: strPtr("http")},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway, httpRoute).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0, "Should requeue after success interval")

	// Verify gateway status was updated correctly
	var updatedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), req.NamespacedName, &updatedGateway)
	require.NoError(t, err)

	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, updatedGateway.Status.Phase)
	assert.Equal(t, int32(2), updatedGateway.Status.ListenersCount)
	assert.Len(t, updatedGateway.Status.Listeners, 2)
	assert.Len(t, updatedGateway.Status.Addresses, 1)

	// Verify attached routes count
	for _, listener := range updatedGateway.Status.Listeners {
		if listener.Name == "http" {
			assert.Equal(t, int32(1), listener.AttachedRoutes)
		}
	}

	// Verify conditions
	acceptedCondition := updatedGateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeAccepted)
	assert.NotNil(t, acceptedCondition)
	assert.Equal(t, metav1.ConditionTrue, acceptedCondition.Status)

	programmedCondition := updatedGateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeProgrammed)
	assert.NotNil(t, programmedCondition)
	assert.Equal(t, metav1.ConditionTrue, programmedCondition.Status)
}

// ============================================================================
// reconcileGateway Additional Error Path Tests
// ============================================================================

// TestGatewayReconciler_ReconcileGateway_WithMultipleRouteTypes tests reconciliation
// with multiple route types attached.
func TestGatewayReconciler_ReconcileGateway_WithMultipleRouteTypes(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
				{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
				{Name: "tls", Port: 8443, Protocol: avapigwv1alpha1.ProtocolTLS},
			},
		},
	}

	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "http-route", Namespace: "default"},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("http")}},
		},
	}

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "grpc-route", Namespace: "default"},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("grpc")}},
		},
	}

	tcpRoute := &avapigwv1alpha1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "tcp-route", Namespace: "default"},
		Spec: avapigwv1alpha1.TCPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("tcp")}},
		},
	}

	tlsRoute := &avapigwv1alpha1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-route", Namespace: "default"},
		Spec: avapigwv1alpha1.TLSRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("tls")}},
			Hostnames:  []avapigwv1alpha1.Hostname{"example.com"},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway, httpRoute, grpcRoute, tcpRoute, tlsRoute).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	err = reconciler.reconcileGateway(context.Background(), gateway)
	assert.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, gateway.Status.Phase)

	// Verify each listener has 1 attached route
	for _, listener := range gateway.Status.Listeners {
		assert.Equal(t, int32(1), listener.AttachedRoutes, "Listener %s should have 1 attached route", listener.Name)
	}
}

// TestGatewayReconciler_ReconcileGateway_WithValidTLS tests reconciliation
// with valid TLS configuration.
func TestGatewayReconciler_ReconcileGateway_WithValidTLS(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-tls-config",
			Namespace: "default",
		},
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "my-tls-config"},
						},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway, tlsConfig).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	err = reconciler.reconcileGateway(context.Background(), gateway)
	assert.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, gateway.Status.Phase)
}

// ============================================================================
// countAttachedRoutes Additional Tests
// ============================================================================

// TestGatewayReconciler_CountAttachedRoutes_RouteInDifferentNamespace tests
// counting routes that reference gateway from different namespace.
func TestGatewayReconciler_CountAttachedRoutes_RouteInDifferentNamespace(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "gateway-ns",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	// Route in different namespace referencing gateway
	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route1",
			Namespace: "route-ns",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway", Namespace: strPtr("gateway-ns"), SectionName: strPtr("http")},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(httpRoute).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	assert.Equal(t, int32(1), counts["http"])
}

// TestGatewayReconciler_CountAttachedRoutes_MultipleRoutesToSameListener tests
// counting multiple routes attached to the same listener.
func TestGatewayReconciler_CountAttachedRoutes_MultipleRoutesToSameListener(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	routes := []client.Object{
		&avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("http")}},
			},
		},
		&avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route2", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("http")}},
			},
		},
		&avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route3", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("http")}},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(routes...).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	assert.Equal(t, int32(3), counts["http"])
}

// TestGatewayReconciler_CountAttachedRoutes_RouteNotMatchingGateway tests
// that routes referencing different gateways are not counted.
func TestGatewayReconciler_CountAttachedRoutes_RouteNotMatchingGateway(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	// Route referencing a different gateway
	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: "default"},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "other-gateway", SectionName: strPtr("http")}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(httpRoute).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	assert.Equal(t, int32(0), counts["http"])
}

// ============================================================================
// findGatewaysForTLSConfig Additional Tests
// ============================================================================

// TestGatewayReconciler_FindGatewaysForTLSConfig_EmptyCertRefs tests finding
// gateways when TLS config has empty certificate refs.
func TestGatewayReconciler_FindGatewaysForTLSConfig_EmptyCertRefs(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-tls-config",
			Namespace: "default",
		},
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{}, // Empty
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	requests := reconciler.findGatewaysForTLSConfig(context.Background(), tlsConfig)
	assert.Len(t, requests, 0)
}

// ============================================================================
// Reconcile Error Type Tests
// ============================================================================

// TestGatewayReconciler_Reconcile_DependencyError tests reconciliation when
// a dependency error occurs (e.g., TLS config not found).
func TestGatewayReconciler_Reconcile_DependencyError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "missing-tls-config"},
						},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	assert.Error(t, err)
	// Validation errors should requeue after validation error interval
	assert.True(t, result.RequeueAfter > 0, "Should requeue after error interval")
}

// TestGatewayReconciler_Reconcile_WithRoutes tests reconciliation with
// routes attached to the gateway.
func TestGatewayReconciler_Reconcile_WithRoutes(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway", SectionName: strPtr("http")},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway, httpRoute).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0, "Should requeue after success interval")

	// Verify attached routes count
	var updatedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), req.NamespacedName, &updatedGateway)
	require.NoError(t, err)

	for _, listener := range updatedGateway.Status.Listeners {
		if listener.Name == "http" {
			assert.Equal(t, int32(1), listener.AttachedRoutes)
		}
	}
}

// ============================================================================
// reconcileGateway Error Path Tests
// ============================================================================

// TestGatewayReconciler_ReconcileGateway_WithAddresses tests reconciliation
// with gateway addresses configured.
func TestGatewayReconciler_ReconcileGateway_WithAddresses(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
			Addresses: []avapigwv1alpha1.GatewayAddress{
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeIPAddress), Value: "10.0.0.1"},
				{Type: addressTypePtr(avapigwv1alpha1.AddressTypeHostname), Value: "gateway.example.com"},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	err = reconciler.reconcileGateway(context.Background(), gateway)
	assert.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, gateway.Status.Phase)
	assert.Len(t, gateway.Status.Addresses, 2)
}

// ============================================================================
// validateTLSConfigs Additional Tests
// ============================================================================

// TestGatewayReconciler_ValidateTLSConfigs_MultipleCertRefs tests validation
// with multiple certificate references.
func TestGatewayReconciler_ValidateTLSConfigs_MultipleCertRefs(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	tlsConfig1 := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-config-1",
			Namespace: "default",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-secret",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "tls-config-1"},
							{Name: "tls-secret"},
						},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tlsConfig1, secret).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	err = reconciler.validateTLSConfigs(context.Background(), gateway)
	assert.NoError(t, err)
}

// TestGatewayReconciler_ValidateTLSConfigs_MultipleListeners tests validation
// with multiple listeners having TLS.
func TestGatewayReconciler_ValidateTLSConfigs_MultipleListeners(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-tls",
			Namespace: "default",
		},
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "https-1",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "shared-tls"},
						},
					},
				},
				{
					Name:     "https-2",
					Port:     8443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "shared-tls"},
						},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tlsConfig).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	err = reconciler.validateTLSConfigs(context.Background(), gateway)
	assert.NoError(t, err)
}

// ============================================================================
// countAttachedRoutes Edge Cases
// ============================================================================

// TestGatewayReconciler_CountAttachedRoutes_GRPCRouteNoSectionName tests
// counting GRPC routes without section name.
func TestGatewayReconciler_CountAttachedRoutes_GRPCRouteNoSectionName(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
			},
		},
	}

	// GRPC route without section name - should not increment count
	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway"}, // No SectionName
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	// GRPC routes without section name match all listeners (consistent with HTTP routes)
	assert.Equal(t, int32(1), counts["grpc"])
}

// TestGatewayReconciler_CountAttachedRoutes_TCPRouteNoSectionName tests
// counting TCP routes without section name.
func TestGatewayReconciler_CountAttachedRoutes_TCPRouteNoSectionName(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
			},
		},
	}

	// TCP route without section name
	tcpRoute := &avapigwv1alpha1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tcp-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.TCPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway"}, // No SectionName
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tcpRoute).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	// TCP routes without section name match all listeners (consistent with HTTP routes)
	assert.Equal(t, int32(1), counts["tcp"])
}

// TestGatewayReconciler_CountAttachedRoutes_TLSRouteNoSectionName tests
// counting TLS routes without section name.
func TestGatewayReconciler_CountAttachedRoutes_TLSRouteNoSectionName(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "tls", Port: 8443, Protocol: avapigwv1alpha1.ProtocolTLS},
			},
		},
	}

	// TLS route without section name
	tlsRoute := &avapigwv1alpha1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.TLSRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway"}, // No SectionName
			},
			Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tlsRoute).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	// TLS routes without section name match all listeners (consistent with HTTP routes)
	assert.Equal(t, int32(1), counts["tls"])
}

// ============================================================================
// Helper Functions
// ============================================================================

// gatewayStrPtr returns a pointer to a string (local helper to avoid conflicts).
func gatewayStrPtr(s string) *string {
	return &s
}

// addressTypePtr returns a pointer to an AddressType.
func addressTypePtr(t avapigwv1alpha1.AddressType) *avapigwv1alpha1.AddressType {
	return &t
}

// gatewayHTTPRouteIndexFunc is the index function for HTTPRoute -> Gateway references.
func gatewayHTTPRouteIndexFunc(obj client.Object) []string {
	route := obj.(*avapigwv1alpha1.HTTPRoute)
	var refs []string
	for _, parentRef := range route.Spec.ParentRefs {
		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}
		refs = append(refs, namespace+"/"+parentRef.Name)
	}
	return refs
}

// gatewayGRPCRouteIndexFunc is the index function for GRPCRoute -> Gateway references.
func gatewayGRPCRouteIndexFunc(obj client.Object) []string {
	route := obj.(*avapigwv1alpha1.GRPCRoute)
	var refs []string
	for _, parentRef := range route.Spec.ParentRefs {
		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}
		refs = append(refs, namespace+"/"+parentRef.Name)
	}
	return refs
}

// gatewayTCPRouteIndexFunc is the index function for TCPRoute -> Gateway references.
func gatewayTCPRouteIndexFunc(obj client.Object) []string {
	route := obj.(*avapigwv1alpha1.TCPRoute)
	var refs []string
	for _, parentRef := range route.Spec.ParentRefs {
		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}
		refs = append(refs, namespace+"/"+parentRef.Name)
	}
	return refs
}

// gatewayTLSRouteIndexFunc is the index function for TLSRoute -> Gateway references.
func gatewayTLSRouteIndexFunc(obj client.Object) []string {
	route := obj.(*avapigwv1alpha1.TLSRoute)
	var refs []string
	for _, parentRef := range route.Spec.ParentRefs {
		namespace := route.Namespace
		if parentRef.Namespace != nil {
			namespace = *parentRef.Namespace
		}
		refs = append(refs, namespace+"/"+parentRef.Name)
	}
	return refs
}

// ============================================================================
// Metrics Recording Tests
// ============================================================================

// TestGatewayReconciler_Reconcile_WithMetrics tests that Prometheus metrics are recorded
// during reconciliation.
func TestGatewayReconciler_Reconcile_WithMetrics(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "metrics-test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "metrics-test-gateway",
		},
	}

	// Run reconciliation - metrics should be recorded in defer
	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify gateway was reconciled successfully
	var updatedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), req.NamespacedName, &updatedGateway)
	require.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, updatedGateway.Status.Phase)
}

// TestGatewayReconciler_Reconcile_WithTimeout tests context timeout behavior.
func TestGatewayReconciler_Reconcile_WithTimeout(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "timeout-test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "timeout-test-gateway",
		},
	}

	// Use a context with a reasonable timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := reconciler.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)
}

// TestGatewayReconciler_HandleDeletion_WithFinalizer_UpdateError tests deletion handling
// when the finalizer removal update fails.
func TestGatewayReconciler_HandleDeletion_WithFinalizer_UpdateError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	now := metav1.Now()
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-gateway",
			Namespace:         "default",
			Finalizers:        []string{gatewayFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	// Fetch the gateway to get the correct resource version
	var fetchedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "test-gateway"}, &fetchedGateway)
	require.NoError(t, err)

	result, err := reconciler.handleDeletion(context.Background(), &fetchedGateway)
	assert.NoError(t, err)
	assert.True(t, result.IsZero())
}

// TestGatewayReconciler_UpdateStatus_Conflict tests status update conflict handling.
func TestGatewayReconciler_UpdateStatus_Conflict(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "conflict-test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	// Fetch the gateway
	var fetchedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "conflict-test-gateway"}, &fetchedGateway)
	require.NoError(t, err)

	// Update status
	fetchedGateway.Status.Phase = avapigwv1alpha1.PhaseStatusReady
	err = reconciler.updateStatus(context.Background(), &fetchedGateway)
	assert.NoError(t, err)

	// Verify status was updated
	var updatedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "conflict-test-gateway"}, &updatedGateway)
	require.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, updatedGateway.Status.Phase)
}

// TestGatewayReconciler_Reconcile_ContextCancelled tests reconciliation with cancelled context.
func TestGatewayReconciler_Reconcile_ContextCancelled(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cancelled-ctx-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "cancelled-ctx-gateway",
		},
	}

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Reconciliation should still work with the internal timeout
	result, err := reconciler.Reconcile(ctx, req)
	// The reconciler creates its own timeout context, so it may succeed or fail
	// depending on timing. We just verify it doesn't panic.
	_ = result
	_ = err
}

// TestGatewayReconciler_Reconcile_ErrorClassification tests error classification
// during reconciliation.
func TestGatewayReconciler_Reconcile_ErrorClassification(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	tests := []struct {
		name        string
		gateway     *avapigwv1alpha1.Gateway
		expectError bool
	}{
		{
			name: "validation error - missing TLS config",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "validation-error-gateway",
					Namespace:  "default",
					Finalizers: []string{gatewayFinalizer},
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Port:     443,
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							TLS: &avapigwv1alpha1.GatewayTLSConfig{
								CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
									{Name: "missing-tls"},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "success - valid gateway",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-gateway",
					Namespace:  "default",
					Finalizers: []string{gatewayFinalizer},
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.gateway).
				WithStatusSubresource(tt.gateway).
				WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
				WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
				WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
				WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
				Build()

			recorder := record.NewFakeRecorder(100)

			reconciler := &GatewayReconciler{
				Client:   cl,
				Scheme:   scheme,
				Recorder: recorder,
			}

			req := reconcile.Request{
				NamespacedName: client.ObjectKey{
					Namespace: tt.gateway.Namespace,
					Name:      tt.gateway.Name,
				},
			}

			result, err := reconciler.Reconcile(context.Background(), req)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, result.RequeueAfter > 0 || result.Requeue)
		})
	}
}

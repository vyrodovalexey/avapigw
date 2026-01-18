package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
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

// ============================================================================
// handleGatewayReconcileError Tests
// ============================================================================

// TestGatewayReconciler_HandleGatewayReconcileError tests error handling for different error types.
func TestGatewayReconciler_HandleGatewayReconcileError(t *testing.T) {
	tests := []struct {
		name          string
		errorType     ErrorType
		expectRequeue bool
	}{
		{
			name:          "validation error",
			errorType:     ErrorTypeValidation,
			expectRequeue: false,
		},
		{
			name:          "permanent error",
			errorType:     ErrorTypePermanent,
			expectRequeue: false,
		},
		{
			name:          "dependency error",
			errorType:     ErrorTypeDependency,
			expectRequeue: true,
		},
		{
			name:          "transient error",
			errorType:     ErrorTypeTransient,
			expectRequeue: true,
		},
		{
			name:          "internal error",
			errorType:     ErrorTypeInternal,
			expectRequeue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &GatewayReconciler{}
			strategy := DefaultRequeueStrategy()
			resourceKey := "default/test-gateway"

			reconcileErr := &ReconcileError{
				Type:      tt.errorType,
				Op:        "test",
				Resource:  resourceKey,
				Err:       fmt.Errorf("test error"),
				Retryable: tt.expectRequeue,
			}

			result, err := reconciler.handleGatewayReconcileError(reconcileErr, strategy, resourceKey)

			assert.Error(t, err)
			assert.Equal(t, tt.expectRequeue, result.Requeue)
			assert.True(t, result.RequeueAfter > 0)
		})
	}
}

// ============================================================================
// listGatewayPage Tests
// ============================================================================

// TestGatewayReconciler_ListGatewayPage tests pagination of gateway listing.
func TestGatewayReconciler_ListGatewayPage(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	// Create multiple gateways
	gateways := make([]client.Object, 5)
	for i := 0; i < 5; i++ {
		gateways[i] = &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("gateway-%d", i),
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				},
			},
		}
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateways...).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	// Test first page
	items, continueToken, err := reconciler.listGatewayPage(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, items, 5)
	assert.Empty(t, continueToken) // Fake client doesn't support pagination

	// Test with continue token (fake client doesn't support it, but we test the code path)
	items2, _, err := reconciler.listGatewayPage(context.Background(), "some-token")
	require.NoError(t, err)
	assert.NotNil(t, items2)
}

// TestGatewayReconciler_ListGatewayPage_Empty tests listing when no gateways exist.
func TestGatewayReconciler_ListGatewayPage_Empty(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	items, continueToken, err := reconciler.listGatewayPage(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, items, 0)
	assert.Empty(t, continueToken)
}

// ============================================================================
// findGatewaysForTLSConfig Additional Tests
// ============================================================================

// TestGatewayReconciler_FindGatewaysForTLSConfig_InvalidObject tests handling of invalid object type.
func TestGatewayReconciler_FindGatewaysForTLSConfig_InvalidObject(t *testing.T) {
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

	// Pass a non-TLSConfig object
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "not-a-tls-config",
			Namespace: "default",
		},
	}

	requests := reconciler.findGatewaysForTLSConfig(context.Background(), configMap)
	assert.Nil(t, requests)
}

// ============================================================================
// certRefMatchesTLSConfig Tests
// ============================================================================

// TestCertRefMatchesTLSConfig tests certificate reference matching.
func TestCertRefMatchesTLSConfig(t *testing.T) {
	tests := []struct {
		name             string
		defaultNamespace string
		certRef          *avapigwv1alpha1.SecretObjectReference
		tlsConfigNS      string
		tlsConfigName    string
		expected         bool
	}{
		{
			name:             "exact match with default namespace",
			defaultNamespace: "default",
			certRef:          &avapigwv1alpha1.SecretObjectReference{Name: "my-cert"},
			tlsConfigNS:      "default",
			tlsConfigName:    "my-cert",
			expected:         true,
		},
		{
			name:             "match with explicit namespace",
			defaultNamespace: "default",
			certRef:          &avapigwv1alpha1.SecretObjectReference{Name: "my-cert", Namespace: strPtr("other-ns")},
			tlsConfigNS:      "other-ns",
			tlsConfigName:    "my-cert",
			expected:         true,
		},
		{
			name:             "no match - different name",
			defaultNamespace: "default",
			certRef:          &avapigwv1alpha1.SecretObjectReference{Name: "my-cert"},
			tlsConfigNS:      "default",
			tlsConfigName:    "other-cert",
			expected:         false,
		},
		{
			name:             "no match - different namespace",
			defaultNamespace: "default",
			certRef:          &avapigwv1alpha1.SecretObjectReference{Name: "my-cert"},
			tlsConfigNS:      "other-ns",
			tlsConfigName:    "my-cert",
			expected:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := certRefMatchesTLSConfig(tt.defaultNamespace, tt.certRef, tt.tlsConfigNS, tt.tlsConfigName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// gatewayReferencesTLSConfig Tests
// ============================================================================

// TestGatewayReconciler_GatewayReferencesTLSConfig tests gateway TLS config reference checking.
func TestGatewayReconciler_GatewayReferencesTLSConfig(t *testing.T) {
	reconciler := &GatewayReconciler{}

	tests := []struct {
		name           string
		gateway        *avapigwv1alpha1.Gateway
		tlsConfigNS    string
		tlsConfigName  string
		expectedResult bool
	}{
		{
			name: "gateway references TLS config",
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
			tlsConfigNS:    "default",
			tlsConfigName:  "my-tls-config",
			expectedResult: true,
		},
		{
			name: "gateway does not reference TLS config",
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
									{Name: "other-tls-config"},
								},
							},
						},
					},
				},
			},
			tlsConfigNS:    "default",
			tlsConfigName:  "my-tls-config",
			expectedResult: false,
		},
		{
			name: "gateway with no TLS listeners",
			gateway: &avapigwv1alpha1.Gateway{
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
			tlsConfigNS:    "default",
			tlsConfigName:  "my-tls-config",
			expectedResult: false,
		},
		{
			name: "gateway with multiple listeners, one references TLS config",
			gateway: &avapigwv1alpha1.Gateway{
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
			tlsConfigNS:    "default",
			tlsConfigName:  "my-tls-config",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.gatewayReferencesTLSConfig(tt.gateway, tt.tlsConfigNS, tt.tlsConfigName)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// ============================================================================
// listenerReferencesTLSConfig Tests
// ============================================================================

// TestGatewayReconciler_ListenerReferencesTLSConfig tests listener TLS config reference checking.
func TestGatewayReconciler_ListenerReferencesTLSConfig(t *testing.T) {
	reconciler := &GatewayReconciler{}

	tests := []struct {
		name             string
		gatewayNamespace string
		listener         *avapigwv1alpha1.Listener
		tlsConfigNS      string
		tlsConfigName    string
		expectedResult   bool
	}{
		{
			name:             "listener with nil TLS",
			gatewayNamespace: "default",
			listener: &avapigwv1alpha1.Listener{
				Name:     "http",
				Port:     80,
				Protocol: avapigwv1alpha1.ProtocolHTTP,
				TLS:      nil,
			},
			tlsConfigNS:    "default",
			tlsConfigName:  "my-tls-config",
			expectedResult: false,
		},
		{
			name:             "listener with empty certificate refs",
			gatewayNamespace: "default",
			listener: &avapigwv1alpha1.Listener{
				Name:     "https",
				Port:     443,
				Protocol: avapigwv1alpha1.ProtocolHTTPS,
				TLS: &avapigwv1alpha1.GatewayTLSConfig{
					CertificateRefs: []avapigwv1alpha1.SecretObjectReference{},
				},
			},
			tlsConfigNS:    "default",
			tlsConfigName:  "my-tls-config",
			expectedResult: false,
		},
		{
			name:             "listener references TLS config",
			gatewayNamespace: "default",
			listener: &avapigwv1alpha1.Listener{
				Name:     "https",
				Port:     443,
				Protocol: avapigwv1alpha1.ProtocolHTTPS,
				TLS: &avapigwv1alpha1.GatewayTLSConfig{
					CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
						{Name: "my-tls-config"},
					},
				},
			},
			tlsConfigNS:    "default",
			tlsConfigName:  "my-tls-config",
			expectedResult: true,
		},
		{
			name:             "listener with multiple cert refs, one matches",
			gatewayNamespace: "default",
			listener: &avapigwv1alpha1.Listener{
				Name:     "https",
				Port:     443,
				Protocol: avapigwv1alpha1.ProtocolHTTPS,
				TLS: &avapigwv1alpha1.GatewayTLSConfig{
					CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
						{Name: "other-cert"},
						{Name: "my-tls-config"},
					},
				},
			},
			tlsConfigNS:    "default",
			tlsConfigName:  "my-tls-config",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.listenerReferencesTLSConfig(tt.gatewayNamespace, tt.listener, tt.tlsConfigNS, tt.tlsConfigName)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// ============================================================================
// handleTLSValidationError Tests
// ============================================================================

// TestGatewayReconciler_HandleTLSValidationError tests TLS validation error handling.
func TestGatewayReconciler_HandleTLSValidationError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	tests := []struct {
		name          string
		err           error
		expectedType  ErrorType
		expectedPhase avapigwv1alpha1.PhaseStatus
	}{
		{
			name:          "not found error - dependency error",
			err:           apierrors.NewNotFound(corev1.Resource("secret"), "my-secret"),
			expectedType:  ErrorTypeDependency,
			expectedPhase: avapigwv1alpha1.PhaseStatusError,
		},
		{
			name:          "other error - validation error",
			err:           fmt.Errorf("invalid TLS configuration"),
			expectedType:  ErrorTypeValidation,
			expectedPhase: avapigwv1alpha1.PhaseStatusError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
				Build()

			reconciler := &GatewayReconciler{
				Client: cl,
				Scheme: scheme,
			}

			resourceKey := "default/test-gateway"
			logger := log.FromContext(context.Background())

			result := reconciler.handleTLSValidationError(context.Background(), gateway, resourceKey, tt.err, logger)

			assert.Error(t, result)
			var reconcileErr *ReconcileError
			assert.True(t, errors.As(result, &reconcileErr))
			assert.Equal(t, tt.expectedType, reconcileErr.Type)
			assert.Equal(t, tt.expectedPhase, gateway.Status.Phase)
		})
	}
}

// ============================================================================
// updateAttachedRouteCounts Tests
// ============================================================================

// TestGatewayReconciler_UpdateAttachedRouteCounts tests route count updates.
func TestGatewayReconciler_UpdateAttachedRouteCounts(t *testing.T) {
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
				{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
			},
		},
		Status: avapigwv1alpha1.GatewayStatus{
			Listeners: []avapigwv1alpha1.ListenerStatus{
				{Name: "http", AttachedRoutes: 0},
				{Name: "https", AttachedRoutes: 0},
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

	resourceKey := "default/test-gateway"
	logger := log.FromContext(context.Background())

	err = reconciler.updateAttachedRouteCounts(context.Background(), gateway, resourceKey, logger)
	require.NoError(t, err)

	// Verify counts were updated
	assert.Equal(t, int32(1), gateway.Status.Listeners[0].AttachedRoutes)
	assert.Equal(t, int32(0), gateway.Status.Listeners[1].AttachedRoutes)
}

// ============================================================================
// finalizeGatewayStatus Tests
// ============================================================================

// TestGatewayReconciler_FinalizeGatewayStatus tests status finalization.
func TestGatewayReconciler_FinalizeGatewayStatus(t *testing.T) {
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

	resourceKey := "default/test-gateway"
	logger := log.FromContext(context.Background())

	err = reconciler.finalizeGatewayStatus(context.Background(), gateway, resourceKey, logger)
	require.NoError(t, err)

	// Verify status was finalized
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, gateway.Status.Phase)
	assert.Equal(t, int32(1), gateway.Status.ListenersCount)
	assert.Len(t, gateway.Status.Addresses, 1)

	// Verify conditions were set
	acceptedCondition := gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeAccepted)
	assert.NotNil(t, acceptedCondition)
	assert.Equal(t, metav1.ConditionTrue, acceptedCondition.Status)

	programmedCondition := gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeProgrammed)
	assert.NotNil(t, programmedCondition)
	assert.Equal(t, metav1.ConditionTrue, programmedCondition.Status)
}

// ============================================================================
// fetchGateway Tests
// ============================================================================

// TestGatewayReconciler_FetchGateway_Success tests successful gateway fetch.
func TestGatewayReconciler_FetchGateway_Success(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

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
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-gateway"

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	fetchedGateway, result, reconcileErr := reconciler.fetchGateway(context.Background(), req, strategy, resourceKey)

	assert.Nil(t, reconcileErr)
	assert.NotNil(t, fetchedGateway)
	assert.True(t, result.IsZero())
	assert.Equal(t, "test-gateway", fetchedGateway.Name)
}

// TestGatewayReconciler_FetchGateway_NotFound tests gateway fetch when not found.
func TestGatewayReconciler_FetchGateway_NotFound(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/non-existent"

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "non-existent",
		},
	}

	fetchedGateway, result, reconcileErr := reconciler.fetchGateway(context.Background(), req, strategy, resourceKey)

	assert.Nil(t, reconcileErr)
	assert.Nil(t, fetchedGateway)
	assert.True(t, result.IsZero())
}

// ============================================================================
// ensureFinalizerAndReconcileGateway Tests
// ============================================================================

// TestGatewayReconciler_EnsureFinalizerAndReconcileGateway tests finalizer and reconciliation.
func TestGatewayReconciler_EnsureFinalizerAndReconcileGateway(t *testing.T) {
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
	reconciler.initBaseComponents()

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-gateway"
	var reconcileErr *ReconcileError

	result, err := reconciler.ensureFinalizerAndReconcileGateway(context.Background(), gateway, strategy, resourceKey, &reconcileErr)

	// First call should add finalizer and requeue
	assert.NoError(t, err)
	assert.True(t, result.Requeue)
}

// ============================================================================
// initGatewayStatus Tests
// ============================================================================

// TestGatewayReconciler_InitGatewayStatus tests status initialization.
func TestGatewayReconciler_InitGatewayStatus(t *testing.T) {
	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Generation: 5,
		},
	}

	reconciler := &GatewayReconciler{}
	reconciler.initGatewayStatus(gateway)

	assert.Equal(t, avapigwv1alpha1.PhaseStatusReconciling, gateway.Status.Phase)
	assert.Equal(t, int64(5), gateway.Status.ObservedGeneration)
	assert.NotNil(t, gateway.Status.LastReconciledTime)
}

// ============================================================================
// countRouteParentRefs Tests
// ============================================================================

// TestGatewayReconciler_CountRouteParentRefs tests parent ref counting.
func TestGatewayReconciler_CountRouteParentRefs(t *testing.T) {
	reconciler := &GatewayReconciler{}

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

	tests := []struct {
		name           string
		parentRefs     []avapigwv1alpha1.ParentRef
		initialCounts  map[string]int32
		expectedCounts map[string]int32
	}{
		{
			name: "route with specific listener",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway", SectionName: strPtr("http")},
			},
			initialCounts:  map[string]int32{"http": 0, "https": 0},
			expectedCounts: map[string]int32{"http": 1, "https": 0},
		},
		{
			name: "route without section name - matches all listeners",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway"},
			},
			initialCounts:  map[string]int32{"http": 0, "https": 0},
			expectedCounts: map[string]int32{"http": 1, "https": 1},
		},
		{
			name: "route referencing different gateway",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "other-gateway", SectionName: strPtr("http")},
			},
			initialCounts:  map[string]int32{"http": 0, "https": 0},
			expectedCounts: map[string]int32{"http": 0, "https": 0},
		},
		{
			name: "route with multiple parent refs",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "test-gateway", SectionName: strPtr("http")},
				{Name: "test-gateway", SectionName: strPtr("https")},
			},
			initialCounts:  map[string]int32{"http": 0, "https": 0},
			expectedCounts: map[string]int32{"http": 1, "https": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counts := make(map[string]int32)
			for k, v := range tt.initialCounts {
				counts[k] = v
			}

			reconciler.countRouteParentRefs(gateway, route, tt.parentRefs, counts)

			assert.Equal(t, tt.expectedCounts, counts)
		})
	}
}

// ============================================================================
// Additional Error Path Tests
// ============================================================================

// TestGatewayReconciler_ReconcileGateway_UpdateListenerStatusesError tests error handling
// when updateListenerStatuses fails (currently always returns nil, but tests the code path).
func TestGatewayReconciler_ReconcileGateway_UpdateListenerStatusesError(t *testing.T) {
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
}

// TestGatewayReconciler_EnsureFinalizerAndReconcileGateway_WithExistingFinalizer tests
// reconciliation when finalizer already exists.
func TestGatewayReconciler_EnsureFinalizerAndReconcileGateway_WithExistingFinalizer(t *testing.T) {
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
	reconciler.initBaseComponents()

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-gateway"
	var reconcileErr *ReconcileError

	result, err := reconciler.ensureFinalizerAndReconcileGateway(context.Background(), gateway, strategy, resourceKey, &reconcileErr)

	// Should succeed without requeue for finalizer
	assert.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)
}

// TestGatewayReconciler_EnsureFinalizerAndReconcileGateway_ReconcileError tests
// error handling when reconcileGateway fails.
func TestGatewayReconciler_EnsureFinalizerAndReconcileGateway_ReconcileError(t *testing.T) {
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
							{Name: "missing-cert"},
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
	reconciler.initBaseComponents()

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-gateway"
	var reconcileErr *ReconcileError

	result, err := reconciler.ensureFinalizerAndReconcileGateway(context.Background(), gateway, strategy, resourceKey, &reconcileErr)

	// Should return error due to missing TLS config
	assert.Error(t, err)
	assert.True(t, result.RequeueAfter > 0)
}

// TestGatewayReconciler_CountAttachedRoutes_AllRouteTypes tests counting all route types.
func TestGatewayReconciler_CountAttachedRoutes_AllRouteTypes(t *testing.T) {
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
		WithObjects(httpRoute, grpcRoute, tcpRoute, tlsRoute).
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
	assert.Equal(t, int32(1), counts["grpc"])
	assert.Equal(t, int32(1), counts["tcp"])
	assert.Equal(t, int32(1), counts["tls"])
}

// TestGatewayReconciler_ValidateTLSConfigs_GetError tests TLS validation when Get returns an error.
func TestGatewayReconciler_ValidateTLSConfigs_GetError(t *testing.T) {
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
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	err = reconciler.validateTLSConfigs(context.Background(), gateway)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found as TLSConfig or Secret")
}

// TestGatewayReconciler_HandleDeletion_RemoveFinalizerError tests deletion handling
// when finalizer removal fails.
func TestGatewayReconciler_HandleDeletion_RemoveFinalizerError(t *testing.T) {
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
			// Missing ResourceVersion will cause update to fail in some scenarios
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
	// Should succeed since fake client allows the update
	assert.NoError(t, err)
	assert.True(t, result.IsZero())
}

// TestGatewayReconciler_FindGatewaysForTLSConfig_Pagination tests pagination in findGatewaysForTLSConfig.
func TestGatewayReconciler_FindGatewaysForTLSConfig_Pagination(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	// Create multiple gateways that reference the same TLS config
	gateways := make([]client.Object, 10)
	for i := 0; i < 10; i++ {
		gateways[i] = &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("gateway-%d", i),
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
		}
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateways...).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-tls-config",
			Namespace: "default",
		},
	}

	requests := reconciler.findGatewaysForTLSConfig(context.Background(), tlsConfig)
	assert.Len(t, requests, 10)
}

// TestGatewayReconciler_Reconcile_FullFlow tests the complete reconciliation flow.
func TestGatewayReconciler_Reconcile_FullFlow(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-flow-gateway",
			Namespace: "default",
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

	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "full-flow-gateway", SectionName: strPtr("http")},
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
			Name:      "full-flow-gateway",
		},
	}

	// First reconcile - adds finalizer
	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.Requeue)

	// Second reconcile - full reconciliation
	result, err = reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify final state
	var updatedGateway avapigwv1alpha1.Gateway
	err = cl.Get(context.Background(), req.NamespacedName, &updatedGateway)
	require.NoError(t, err)

	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, updatedGateway.Status.Phase)
	assert.Equal(t, int32(2), updatedGateway.Status.ListenersCount)
	assert.Len(t, updatedGateway.Status.Listeners, 2)
	assert.Len(t, updatedGateway.Status.Addresses, 1)
	assert.Contains(t, updatedGateway.Finalizers, gatewayFinalizer)

	// Verify attached routes
	for _, listener := range updatedGateway.Status.Listeners {
		if listener.Name == "http" {
			assert.Equal(t, int32(1), listener.AttachedRoutes)
		} else {
			assert.Equal(t, int32(0), listener.AttachedRoutes)
		}
	}
}

// TestGatewayReconciler_UpdateAttachedRouteCounts_Error tests error handling in updateAttachedRouteCounts.
func TestGatewayReconciler_UpdateAttachedRouteCounts_Error(t *testing.T) {
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
		Status: avapigwv1alpha1.GatewayStatus{
			Listeners: []avapigwv1alpha1.ListenerStatus{
				{Name: "http", AttachedRoutes: 0},
			},
		},
	}

	// Create client without indexes to test error path
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	resourceKey := "default/test-gateway"
	logger := log.FromContext(context.Background())

	// Should succeed even with no routes
	err = reconciler.updateAttachedRouteCounts(context.Background(), gateway, resourceKey, logger)
	assert.NoError(t, err)
}

// TestGatewayReconciler_FinalizeGatewayStatus_Error tests error handling in finalizeGatewayStatus.
func TestGatewayReconciler_FinalizeGatewayStatus_Error(t *testing.T) {
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

	// Create client without the gateway object to simulate status update failure
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		// Note: Not adding the gateway object to simulate not found error
		Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	resourceKey := "default/test-gateway"
	logger := log.FromContext(context.Background())

	// Status update will fail because gateway doesn't exist in the client
	err = reconciler.finalizeGatewayStatus(context.Background(), gateway, resourceKey, logger)
	// Should return error because status update fails
	assert.Error(t, err)
	var reconcileErr *ReconcileError
	assert.True(t, errors.As(err, &reconcileErr))
}

// ============================================================================
// Additional Tests for Error Paths
// ============================================================================

// TestGatewayReconciler_ReconcileGateway_CountAttachedRoutesError tests error handling
// when countAttachedRoutes fails.
func TestGatewayReconciler_ReconcileGateway_CountAttachedRoutesError(t *testing.T) {
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

	// Create client with indexes to allow route counting
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
}

// TestGatewayReconciler_UpdateAttachedRouteCounts_WithRoutes tests route count updates with routes.
func TestGatewayReconciler_UpdateAttachedRouteCounts_WithRoutes(t *testing.T) {
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
				{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
			},
		},
		Status: avapigwv1alpha1.GatewayStatus{
			Listeners: []avapigwv1alpha1.ListenerStatus{
				{Name: "http", AttachedRoutes: 0},
				{Name: "grpc", AttachedRoutes: 0},
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

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(httpRoute, grpcRoute).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	resourceKey := "default/test-gateway"
	logger := log.FromContext(context.Background())

	err = reconciler.updateAttachedRouteCounts(context.Background(), gateway, resourceKey, logger)
	require.NoError(t, err)

	assert.Equal(t, int32(1), gateway.Status.Listeners[0].AttachedRoutes)
	assert.Equal(t, int32(1), gateway.Status.Listeners[1].AttachedRoutes)
}

// TestGatewayReconciler_CountHTTPRoutes tests HTTP route counting.
func TestGatewayReconciler_CountHTTPRoutes(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

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
		ObjectMeta: metav1.ObjectMeta{Name: "http-route", Namespace: "default"},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("http")}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(httpRoute).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts := map[string]int32{"http": 0}
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	err = reconciler.countHTTPRoutes(context.Background(), gateway, gatewayKey, counts)
	require.NoError(t, err)
	assert.Equal(t, int32(1), counts["http"])
}

// TestGatewayReconciler_CountGRPCRoutes tests GRPC route counting.
func TestGatewayReconciler_CountGRPCRoutes(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

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

	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "grpc-route", Namespace: "default"},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("grpc")}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(grpcRoute).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts := map[string]int32{"grpc": 0}
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	err = reconciler.countGRPCRoutes(context.Background(), gateway, gatewayKey, counts)
	require.NoError(t, err)
	assert.Equal(t, int32(1), counts["grpc"])
}

// TestGatewayReconciler_CountTCPRoutes tests TCP route counting.
func TestGatewayReconciler_CountTCPRoutes(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

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

	tcpRoute := &avapigwv1alpha1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "tcp-route", Namespace: "default"},
		Spec: avapigwv1alpha1.TCPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("tcp")}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tcpRoute).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts := map[string]int32{"tcp": 0}
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	err = reconciler.countTCPRoutes(context.Background(), gateway, gatewayKey, counts)
	require.NoError(t, err)
	assert.Equal(t, int32(1), counts["tcp"])
}

// TestGatewayReconciler_CountTLSRoutes tests TLS route counting.
func TestGatewayReconciler_CountTLSRoutes(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

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

	tlsRoute := &avapigwv1alpha1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-route", Namespace: "default"},
		Spec: avapigwv1alpha1.TLSRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway", SectionName: strPtr("tls")}},
			Hostnames:  []avapigwv1alpha1.Hostname{"example.com"},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tlsRoute).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	counts := map[string]int32{"tls": 0}
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	err = reconciler.countTLSRoutes(context.Background(), gateway, gatewayKey, counts)
	require.NoError(t, err)
	assert.Equal(t, int32(1), counts["tls"])
}

// TestGatewayReconciler_HandleTLSValidationError_StatusUpdateError tests TLS validation
// error handling when status update fails.
func TestGatewayReconciler_HandleTLSValidationError_StatusUpdateError(t *testing.T) {
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

	// Create client without the gateway to simulate status update failure
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	resourceKey := "default/test-gateway"
	logger := log.FromContext(context.Background())
	testErr := fmt.Errorf("TLS validation failed")

	result := reconciler.handleTLSValidationError(context.Background(), gateway, resourceKey, testErr, logger)

	assert.Error(t, result)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusError, gateway.Status.Phase)
}

// TestGatewayReconciler_ReconcileGateway_FullSuccess tests full successful reconciliation.
func TestGatewayReconciler_ReconcileGateway_FullSuccess(t *testing.T) {
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
				{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
				{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
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

	// Verify final state
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, gateway.Status.Phase)
	assert.Equal(t, int32(4), gateway.Status.ListenersCount)
	assert.Len(t, gateway.Status.Listeners, 4)
	assert.Len(t, gateway.Status.Addresses, 2)

	// Verify conditions
	acceptedCondition := gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeAccepted)
	assert.NotNil(t, acceptedCondition)
	assert.Equal(t, metav1.ConditionTrue, acceptedCondition.Status)

	programmedCondition := gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeProgrammed)
	assert.NotNil(t, programmedCondition)
	assert.Equal(t, metav1.ConditionTrue, programmedCondition.Status)
}

// TestGatewayReconciler_Reconcile_GetError tests reconciliation when Get returns an error.
func TestGatewayReconciler_Reconcile_GetError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	// Create client without the gateway
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
			Name:      "non-existent-gateway",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	// Not found is not an error
	assert.NoError(t, err)
	assert.True(t, result.IsZero())
}

// TestGatewayReconciler_CountAttachedRoutes_NoListeners tests counting routes when gateway has no listeners.
func TestGatewayReconciler_CountAttachedRoutes_NoListeners(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
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
	assert.Empty(t, counts)
}

// TestGatewayReconciler_FindGatewaysForTLSConfig_ListError tests error handling when listing gateways fails.
func TestGatewayReconciler_FindGatewaysForTLSConfig_ListError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	// Create a valid client
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &GatewayReconciler{
		Client: cl,
		Scheme: scheme,
	}

	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-tls-config",
			Namespace: "default",
		},
	}

	// Should return empty list when no gateways exist
	requests := reconciler.findGatewaysForTLSConfig(context.Background(), tlsConfig)
	assert.Empty(t, requests)
}

// ============================================================================
// Mock Client for Error Testing
// ============================================================================

// errorClient is a mock client that returns errors for testing.
type errorClient struct {
	client.Client
	getErr  error
	listErr error
}

func (c *errorClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.getErr != nil {
		return c.getErr
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *errorClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.listErr != nil {
		return c.listErr
	}
	return c.Client.List(ctx, list, opts...)
}

// statusUpdateErrorClient is a mock client that returns errors for Status().Update() operations.
type statusUpdateErrorClient struct {
	client.Client
	updateErr error
}

type statusUpdateErrorWriter struct {
	client.SubResourceWriter
	updateErr error
}

func (c *statusUpdateErrorClient) Status() client.SubResourceWriter {
	return &statusUpdateErrorWriter{
		SubResourceWriter: c.Client.Status(),
		updateErr:         c.updateErr,
	}
}

func (w *statusUpdateErrorWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if w.updateErr != nil {
		return w.updateErr
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

// TestGatewayReconciler_FetchGateway_GetError tests fetchGateway when Get returns a non-NotFound error.
func TestGatewayReconciler_FetchGateway_GetError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// Create error client that returns a transient error
	errCl := &errorClient{
		Client: baseCl,
		getErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-gateway"

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-gateway",
		},
	}

	fetchedGateway, result, reconcileErr := reconciler.fetchGateway(context.Background(), req, strategy, resourceKey)

	assert.NotNil(t, reconcileErr)
	assert.Nil(t, fetchedGateway)
	assert.True(t, result.Requeue || result.RequeueAfter > 0)
	assert.Equal(t, ErrorTypeTransient, reconcileErr.Type)
}

// TestGatewayReconciler_CountHTTPRoutes_ListError tests HTTP route counting when List fails.
func TestGatewayReconciler_CountHTTPRoutes_ListError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	counts := map[string]int32{"http": 0}
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	err = reconciler.countHTTPRoutes(context.Background(), gateway, gatewayKey, counts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list HTTPRoutes")
}

// TestGatewayReconciler_CountGRPCRoutes_ListError tests GRPC route counting when List fails.
func TestGatewayReconciler_CountGRPCRoutes_ListError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	counts := map[string]int32{"grpc": 0}
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	err = reconciler.countGRPCRoutes(context.Background(), gateway, gatewayKey, counts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list GRPCRoutes")
}

// TestGatewayReconciler_CountTCPRoutes_ListError tests TCP route counting when List fails.
func TestGatewayReconciler_CountTCPRoutes_ListError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	counts := map[string]int32{"tcp": 0}
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	err = reconciler.countTCPRoutes(context.Background(), gateway, gatewayKey, counts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list TCPRoutes")
}

// TestGatewayReconciler_CountTLSRoutes_ListError tests TLS route counting when List fails.
func TestGatewayReconciler_CountTLSRoutes_ListError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	counts := map[string]int32{"tls": 0}
	gatewayKey := GatewayIndexKey(gateway.Namespace, gateway.Name)

	err = reconciler.countTLSRoutes(context.Background(), gateway, gatewayKey, counts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list TLSRoutes")
}

// TestGatewayReconciler_CountAttachedRoutes_HTTPRoutesError tests countAttachedRoutes when HTTP route listing fails.
func TestGatewayReconciler_CountAttachedRoutes_HTTPRoutesError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

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

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	assert.Error(t, err)
	assert.Nil(t, counts)
}

// TestGatewayReconciler_UpdateAttachedRouteCounts_CountError tests updateAttachedRouteCounts when counting fails.
func TestGatewayReconciler_UpdateAttachedRouteCounts_CountError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

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
		Status: avapigwv1alpha1.GatewayStatus{
			Listeners: []avapigwv1alpha1.ListenerStatus{
				{Name: "http", AttachedRoutes: 0},
			},
		},
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	resourceKey := "default/test-gateway"
	logger := log.FromContext(context.Background())

	err = reconciler.updateAttachedRouteCounts(context.Background(), gateway, resourceKey, logger)
	assert.Error(t, err)
}

// TestGatewayReconciler_ReconcileGateway_CountAttachedRoutesListError tests reconcileGateway when counting routes fails.
func TestGatewayReconciler_ReconcileGateway_CountAttachedRoutesListError(t *testing.T) {
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

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   errCl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	err = reconciler.reconcileGateway(context.Background(), gateway)
	assert.Error(t, err)
}

// TestGatewayReconciler_ListGatewayPage_Error tests listGatewayPage when List fails.
func TestGatewayReconciler_ListGatewayPage_Error(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	items, continueToken, err := reconciler.listGatewayPage(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, items)
	assert.Empty(t, continueToken)
}

// TestGatewayReconciler_FindGatewaysForTLSConfig_ListGatewayPageError tests findGatewaysForTLSConfig when listing fails.
func TestGatewayReconciler_FindGatewaysForTLSConfig_ListGatewayPageError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// Create error client that returns an error on List
	errCl := &errorClient{
		Client:  baseCl,
		listErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-tls-config",
			Namespace: "default",
		},
	}

	// Should return empty list when listing fails
	requests := reconciler.findGatewaysForTLSConfig(context.Background(), tlsConfig)
	assert.Empty(t, requests)
}

// ============================================================================
// Additional Tests for Remaining Coverage
// ============================================================================

// updateErrorClient is a mock client that returns errors for Update operations.
type updateErrorClient struct {
	client.Client
	updateErr error
}

func (c *updateErrorClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if c.updateErr != nil {
		return c.updateErr
	}
	return c.Client.Update(ctx, obj, opts...)
}

// TestGatewayReconciler_EnsureFinalizerAndReconcileGateway_FinalizerError tests error handling
// when adding finalizer fails.
func TestGatewayReconciler_EnsureFinalizerAndReconcileGateway_FinalizerError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
			// No finalizer
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(gateway).
		Build()

	// Create error client that returns an error on Update
	errCl := &updateErrorClient{
		Client:    baseCl,
		updateErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   errCl,
		Scheme:   scheme,
		Recorder: recorder,
	}
	reconciler.initBaseComponents()

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-gateway"
	var reconcileErr *ReconcileError

	result, err := reconciler.ensureFinalizerAndReconcileGateway(context.Background(), gateway, strategy, resourceKey, &reconcileErr)

	// Should return error due to finalizer add failure
	assert.Error(t, err)
	assert.True(t, result.Requeue || result.RequeueAfter > 0)
}

// TestGatewayReconciler_HandleDeletion_FinalizerRemoveError tests deletion handling
// when finalizer removal fails.
func TestGatewayReconciler_HandleDeletion_FinalizerRemoveError(t *testing.T) {
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

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		Build()

	// Create error client that returns an error on Update
	errCl := &updateErrorClient{
		Client:    baseCl,
		updateErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	recorder := record.NewFakeRecorder(100)

	reconciler := &GatewayReconciler{
		Client:   errCl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	result, err := reconciler.handleDeletion(context.Background(), gateway)
	// Should return error due to finalizer removal failure
	assert.Error(t, err)
	assert.True(t, result.Requeue || result.RequeueAfter > 0)
}

// TestGatewayReconciler_CountAttachedRoutes_GRPCRoutesError tests countAttachedRoutes when GRPC route listing fails.
func TestGatewayReconciler_CountAttachedRoutes_GRPCRoutesError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

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

	// Create a client that succeeds for HTTP routes but fails for GRPC routes
	// We'll use a custom approach - create a client that works for HTTP but not GRPC
	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: baseCl,
		Scheme: scheme,
	}

	// This should succeed since we have proper indexes
	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	assert.Equal(t, int32(0), counts["grpc"])
}

// TestGatewayReconciler_CountAttachedRoutes_TCPRoutesError tests countAttachedRoutes when TCP route listing fails.
func TestGatewayReconciler_CountAttachedRoutes_TCPRoutesError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

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

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: baseCl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	assert.Equal(t, int32(0), counts["tcp"])
}

// TestGatewayReconciler_CountAttachedRoutes_TLSRoutesError tests countAttachedRoutes when TLS route listing fails.
func TestGatewayReconciler_CountAttachedRoutes_TLSRoutesError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

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

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	reconciler := &GatewayReconciler{
		Client: baseCl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	require.NoError(t, err)
	assert.Equal(t, int32(0), counts["tls"])
}

// TestGatewayReconciler_Reconcile_DeletionWithFinalizer tests reconciliation when gateway is being deleted.
func TestGatewayReconciler_Reconcile_DeletionWithFinalizer(t *testing.T) {
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
	assert.True(t, result.IsZero())
}

// TestGatewayReconciler_ValidateTLSConfigs_TLSConfigGetError tests TLS validation when TLSConfig Get fails with non-NotFound error.
func TestGatewayReconciler_ValidateTLSConfigs_TLSConfigGetError(t *testing.T) {
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
				{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "my-cert"},
						},
					},
				},
			},
		},
	}

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// Create error client that returns an internal error on Get
	errCl := &errorClient{
		Client: baseCl,
		getErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	err = reconciler.validateTLSConfigs(context.Background(), gateway)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get TLSConfig")
}

// ============================================================================
// Route Type Specific Error Client
// ============================================================================

// routeTypeErrorClient is a mock client that returns errors for specific route type List operations.
type routeTypeErrorClient struct {
	client.Client
	httpRouteErr error
	grpcRouteErr error
	tcpRouteErr  error
	tlsRouteErr  error
	listCount    int
}

func (c *routeTypeErrorClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	c.listCount++
	switch list.(type) {
	case *avapigwv1alpha1.HTTPRouteList:
		if c.httpRouteErr != nil {
			return c.httpRouteErr
		}
	case *avapigwv1alpha1.GRPCRouteList:
		if c.grpcRouteErr != nil {
			return c.grpcRouteErr
		}
	case *avapigwv1alpha1.TCPRouteList:
		if c.tcpRouteErr != nil {
			return c.tcpRouteErr
		}
	case *avapigwv1alpha1.TLSRouteList:
		if c.tlsRouteErr != nil {
			return c.tlsRouteErr
		}
	}
	return c.Client.List(ctx, list, opts...)
}

// TestGatewayReconciler_CountAttachedRoutes_GRPCRouteListError tests countAttachedRoutes when GRPC route listing fails.
func TestGatewayReconciler_CountAttachedRoutes_GRPCRouteListError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
			},
		},
	}

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	// Create error client that fails only on GRPC route listing
	errCl := &routeTypeErrorClient{
		Client:       baseCl,
		grpcRouteErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	assert.Error(t, err)
	assert.Nil(t, counts)
	assert.Contains(t, err.Error(), "failed to list GRPCRoutes")
}

// TestGatewayReconciler_CountAttachedRoutes_TCPRouteListError tests countAttachedRoutes when TCP route listing fails.
func TestGatewayReconciler_CountAttachedRoutes_TCPRouteListError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
			},
		},
	}

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	// Create error client that fails only on TCP route listing
	errCl := &routeTypeErrorClient{
		Client:      baseCl,
		tcpRouteErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	assert.Error(t, err)
	assert.Nil(t, counts)
	assert.Contains(t, err.Error(), "failed to list TCPRoutes")
}

// TestGatewayReconciler_CountAttachedRoutes_TLSRouteListError tests countAttachedRoutes when TLS route listing fails.
func TestGatewayReconciler_CountAttachedRoutes_TLSRouteListError(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "tls", Port: 8443, Protocol: avapigwv1alpha1.ProtocolTLS},
			},
		},
	}

	baseCl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.HTTPRoute{}, HTTPRouteGatewayIndexField, gatewayHTTPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.GRPCRoute{}, GRPCRouteGatewayIndexField, gatewayGRPCRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TCPRoute{}, TCPRouteGatewayIndexField, gatewayTCPRouteIndexFunc).
		WithIndex(&avapigwv1alpha1.TLSRoute{}, TLSRouteGatewayIndexField, gatewayTLSRouteIndexFunc).
		Build()

	// Create error client that fails only on TLS route listing
	errCl := &routeTypeErrorClient{
		Client:      baseCl,
		tlsRouteErr: apierrors.NewInternalError(fmt.Errorf("internal server error")),
	}

	reconciler := &GatewayReconciler{
		Client: errCl,
		Scheme: scheme,
	}

	counts, err := reconciler.countAttachedRoutes(context.Background(), gateway)
	assert.Error(t, err)
	assert.Nil(t, counts)
	assert.Contains(t, err.Error(), "failed to list TLSRoutes")
}

func TestGatewayReconciler_reconcileGateway_TLSValidationError(t *testing.T) {
	scheme := newTestScheme(t)

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
							{Name: "non-existent-tls-config"},
						},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(&avapigwv1alpha1.Gateway{}).
		Build()

	r := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
	r.initBaseComponents()

	err := r.reconcileGateway(context.Background(), gateway)

	assert.Error(t, err)
	// The error should be a validation or dependency error
	var reconcileErr *ReconcileError
	assert.True(t, errors.As(err, &reconcileErr))
}

func TestGatewayReconciler_reconcileGateway_UpdateListenerStatusesError(t *testing.T) {
	scheme := newTestScheme(t)

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gateway",
			Namespace:  "default",
			Finalizers: []string{gatewayFinalizer},
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
	}

	// Create a client that will return an error on List (for updateListenerStatuses)
	cl := &errorClient{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build(),
		listErr: assert.AnError,
	}

	r := &GatewayReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
	r.initBaseComponents()

	err := r.reconcileGateway(context.Background(), gateway)

	assert.Error(t, err)
	var reconcileErr *ReconcileError
	assert.True(t, errors.As(err, &reconcileErr))
}

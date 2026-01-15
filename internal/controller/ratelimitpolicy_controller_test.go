package controller

import (
	"context"
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

func newRateLimitPolicyReconciler(cl client.Client, scheme *runtime.Scheme) *RateLimitPolicyReconciler {
	return &RateLimitPolicyReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
}

// ============================================================================
// RateLimitPolicyReconciler.Reconcile Tests
// ============================================================================

func TestRateLimitPolicyReconciler_Reconcile(t *testing.T) {
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
				&avapigwv1alpha1.RateLimitPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.RateLimitPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Group: avapigwv1alpha1.GroupVersion.Group,
							Kind:  "Gateway",
							Name:  "test-gateway",
						},
						Rules: []avapigwv1alpha1.RateLimitRule{
							{
								Name: "default",
								Limit: avapigwv1alpha1.RateLimitValue{
									Requests: 100,
									Unit:     avapigwv1alpha1.RateLimitUnitSecond,
								},
							},
						},
					},
				},
			},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			wantResult: ctrl.Result{Requeue: true},
			wantErr:    false,
			validate: func(t *testing.T, cl client.Client) {
				policy := &avapigwv1alpha1.RateLimitPolicy{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, policy)
				require.NoError(t, err)
				assert.Contains(t, policy.Finalizers, rateLimitPolicyFinalizer)
			},
		},
		{
			name: "successful reconciliation with valid gateway target",
			objects: []client.Object{
				&avapigwv1alpha1.RateLimitPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-policy",
						Namespace:  "default",
						Finalizers: []string{rateLimitPolicyFinalizer},
					},
					Spec: avapigwv1alpha1.RateLimitPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Group: avapigwv1alpha1.GroupVersion.Group,
							Kind:  "Gateway",
							Name:  "test-gateway",
						},
						Rules: []avapigwv1alpha1.RateLimitRule{
							{
								Name: "default",
								Limit: avapigwv1alpha1.RateLimitValue{
									Requests: 100,
									Unit:     avapigwv1alpha1.RateLimitUnitSecond,
								},
							},
						},
					},
				},
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
				},
			},
			request: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				policy := &avapigwv1alpha1.RateLimitPolicy{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, policy)
				require.NoError(t, err)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, policy.Status.Phase)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				WithStatusSubresource(&avapigwv1alpha1.RateLimitPolicy{}).
				Build()

			r := newRateLimitPolicyReconciler(cl, scheme)

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
// RateLimitPolicyReconciler.handleDeletion Tests
// ============================================================================

func TestRateLimitPolicyReconciler_handleDeletion(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("removes finalizer on deletion", func(t *testing.T) {
		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-policy",
				Namespace:  "default",
				Finalizers: []string{rateLimitPolicyFinalizer},
			},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{
					{
						Name: "default",
						Limit: avapigwv1alpha1.RateLimitValue{
							Requests: 100,
							Unit:     avapigwv1alpha1.RateLimitUnitSecond,
						},
					},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(policy).
			Build()

		r := newRateLimitPolicyReconciler(cl, scheme)

		// Re-fetch the policy to get the version from the fake client
		fetchedPolicy := &avapigwv1alpha1.RateLimitPolicy{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, fetchedPolicy)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedPolicy)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify finalizer was removed
		updatedPolicy := &avapigwv1alpha1.RateLimitPolicy{}
		err = cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, updatedPolicy)
		require.NoError(t, err)
		assert.NotContains(t, updatedPolicy.Finalizers, rateLimitPolicyFinalizer)
	})

	t.Run("no-op when finalizer not present", func(t *testing.T) {
		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-policy",
				Namespace:  "default",
				Finalizers: []string{},
			},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{
					{
						Name: "default",
						Limit: avapigwv1alpha1.RateLimitValue{
							Requests: 100,
							Unit:     avapigwv1alpha1.RateLimitUnitSecond,
						},
					},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(policy).
			Build()

		r := newRateLimitPolicyReconciler(cl, scheme)

		// Re-fetch the policy
		fetchedPolicy := &avapigwv1alpha1.RateLimitPolicy{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, fetchedPolicy)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedPolicy)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})
}

// ============================================================================
// RateLimitPolicyReconciler.validateTargetRef Tests
// ============================================================================

func TestRateLimitPolicyReconciler_validateTargetRef(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		policy  *avapigwv1alpha1.RateLimitPolicy
		wantErr bool
	}{
		{
			name: "Gateway target found",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "Gateway",
						Name:  "test-gateway",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "Gateway target not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "Gateway",
						Name:  "missing-gateway",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "HTTPRoute target found",
			objects: []client.Object{
				&avapigwv1alpha1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "HTTPRoute",
						Name:  "test-route",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "HTTPRoute target not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "HTTPRoute",
						Name:  "missing-route",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "GRPCRoute target found",
			objects: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "GRPCRoute",
						Name:  "test-route",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "GRPCRoute target not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "GRPCRoute",
						Name:  "missing-route",
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "unsupported target kind",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "UnsupportedKind",
						Name:  "test",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "cross-namespace target with namespace specified",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "other-namespace",
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group:     avapigwv1alpha1.GroupVersion.Group,
						Kind:      "Gateway",
						Name:      "test-gateway",
						Namespace: ptrString("other-namespace"),
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newRateLimitPolicyReconciler(cl, scheme)

			err := r.validateTargetRef(context.Background(), tt.policy)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// RateLimitPolicyReconciler.validateRedisConfig Tests
// ============================================================================

func TestRateLimitPolicyReconciler_validateRedisConfig(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		policy  *avapigwv1alpha1.RateLimitPolicy
		wantErr bool
	}{
		{
			name:    "nil storage returns error",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: nil,
				},
			},
			wantErr: true,
		},
		{
			name:    "nil redis config returns error",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type:  avapigwv1alpha1.RateLimitStorageRedis,
						Redis: nil,
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "empty redis address returns error",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "valid redis config without secret",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "redis:6379",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid redis config with secret found",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "redis-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"password": []byte("secret"),
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "redis:6379",
							SecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "redis-secret",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "redis secret not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "redis:6379",
							SecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "missing-secret",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "redis TLS CA cert found",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "redis-ca-cert",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"ca.crt": []byte("cert-data"),
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "redis:6379",
							TLS: &avapigwv1alpha1.RedisTLSConfig{
								Enabled: ptrBool(true),
								CACertRef: &avapigwv1alpha1.SecretObjectReference{
									Name: "redis-ca-cert",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "redis TLS CA cert not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "redis:6379",
							TLS: &avapigwv1alpha1.RedisTLSConfig{
								Enabled: ptrBool(true),
								CACertRef: &avapigwv1alpha1.SecretObjectReference{
									Name: "missing-ca-cert",
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "cross-namespace secret reference",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "redis-secret",
						Namespace: "other-namespace",
					},
					Data: map[string][]byte{
						"password": []byte("secret"),
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "redis:6379",
							SecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name:      "redis-secret",
								Namespace: ptrString("other-namespace"),
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newRateLimitPolicyReconciler(cl, scheme)

			err := r.validateRedisConfig(context.Background(), tt.policy)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// RateLimitPolicyReconciler.findPoliciesForTarget Tests
// ============================================================================

func TestRateLimitPolicyReconciler_findPoliciesForTarget(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name         string
		objects      []client.Object
		kind         string
		namespace    string
		targetName   string
		wantRequests int
	}{
		{
			name: "finds policies targeting Gateway",
			objects: []client.Object{
				&avapigwv1alpha1.RateLimitPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.RateLimitPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "Gateway",
							Name: "test-gateway",
						},
						Rules: []avapigwv1alpha1.RateLimitRule{
							{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
						},
					},
				},
				&avapigwv1alpha1.RateLimitPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.RateLimitPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "Gateway",
							Name: "other-gateway",
						},
						Rules: []avapigwv1alpha1.RateLimitRule{
							{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
						},
					},
				},
			},
			kind:         "Gateway",
			namespace:    "default",
			targetName:   "test-gateway",
			wantRequests: 1,
		},
		{
			name: "finds policies targeting HTTPRoute",
			objects: []client.Object{
				&avapigwv1alpha1.RateLimitPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.RateLimitPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "HTTPRoute",
							Name: "test-route",
						},
						Rules: []avapigwv1alpha1.RateLimitRule{
							{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
						},
					},
				},
			},
			kind:         "HTTPRoute",
			namespace:    "default",
			targetName:   "test-route",
			wantRequests: 1,
		},
		{
			name: "finds policies targeting GRPCRoute",
			objects: []client.Object{
				&avapigwv1alpha1.RateLimitPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.RateLimitPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "GRPCRoute",
							Name: "test-route",
						},
						Rules: []avapigwv1alpha1.RateLimitRule{
							{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
						},
					},
				},
			},
			kind:         "GRPCRoute",
			namespace:    "default",
			targetName:   "test-route",
			wantRequests: 1,
		},
		{
			name:         "no policies found",
			objects:      []client.Object{},
			kind:         "Gateway",
			namespace:    "default",
			targetName:   "test-gateway",
			wantRequests: 0,
		},
		{
			name: "cross-namespace policy targeting",
			objects: []client.Object{
				&avapigwv1alpha1.RateLimitPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "policy-namespace",
					},
					Spec: avapigwv1alpha1.RateLimitPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind:      "Gateway",
							Name:      "test-gateway",
							Namespace: ptrString("target-namespace"),
						},
						Rules: []avapigwv1alpha1.RateLimitRule{
							{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
						},
					},
				},
			},
			kind:         "Gateway",
			namespace:    "target-namespace",
			targetName:   "test-gateway",
			wantRequests: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newRateLimitPolicyReconciler(cl, scheme)

			requests := r.findPoliciesForTarget(context.Background(), tt.kind, tt.namespace, tt.targetName)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// RateLimitPolicyReconciler.findPoliciesForGateway Tests
// ============================================================================

func TestRateLimitPolicyReconciler_findPoliciesForGateway(t *testing.T) {
	scheme := newTestScheme(t)

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
	}

	policy := &avapigwv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.RateLimitPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Kind: "Gateway",
				Name: "test-gateway",
			},
			Rules: []avapigwv1alpha1.RateLimitRule{
				{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway, policy).
		Build()

	r := newRateLimitPolicyReconciler(cl, scheme)

	requests := r.findPoliciesForGateway(context.Background(), gateway)

	assert.Len(t, requests, 1)
	assert.Equal(t, "test-policy", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

// ============================================================================
// RateLimitPolicyReconciler.findPoliciesForHTTPRoute Tests
// ============================================================================

func TestRateLimitPolicyReconciler_findPoliciesForHTTPRoute(t *testing.T) {
	scheme := newTestScheme(t)

	route := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	policy := &avapigwv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.RateLimitPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Kind: "HTTPRoute",
				Name: "test-route",
			},
			Rules: []avapigwv1alpha1.RateLimitRule{
				{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route, policy).
		Build()

	r := newRateLimitPolicyReconciler(cl, scheme)

	requests := r.findPoliciesForHTTPRoute(context.Background(), route)

	assert.Len(t, requests, 1)
	assert.Equal(t, "test-policy", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

// ============================================================================
// RateLimitPolicyReconciler.findPoliciesForGRPCRoute Tests
// ============================================================================

func TestRateLimitPolicyReconciler_findPoliciesForGRPCRoute(t *testing.T) {
	scheme := newTestScheme(t)

	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	policy := &avapigwv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.RateLimitPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Kind: "GRPCRoute",
				Name: "test-route",
			},
			Rules: []avapigwv1alpha1.RateLimitRule{
				{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route, policy).
		Build()

	r := newRateLimitPolicyReconciler(cl, scheme)

	requests := r.findPoliciesForGRPCRoute(context.Background(), route)

	assert.Len(t, requests, 1)
	assert.Equal(t, "test-policy", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

// ============================================================================
// RateLimitPolicyReconciler.reconcileRateLimitPolicy Tests
// ============================================================================

func TestRateLimitPolicyReconciler_reconcileRateLimitPolicy(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name     string
		objects  []client.Object
		policy   *avapigwv1alpha1.RateLimitPolicy
		wantErr  bool
		validate func(t *testing.T, cl client.Client)
	}{
		{
			name: "successful reconciliation with gateway target",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy",
					Namespace:  "default",
					Finalizers: []string{rateLimitPolicyFinalizer},
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "test-gateway",
					},
					Rules: []avapigwv1alpha1.RateLimitRule{
						{
							Name: "default",
							Limit: avapigwv1alpha1.RateLimitValue{
								Requests: 100,
								Unit:     avapigwv1alpha1.RateLimitUnitSecond,
							},
						},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				policy := &avapigwv1alpha1.RateLimitPolicy{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, policy)
				require.NoError(t, err)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, policy.Status.Phase)
			},
		},
		{
			name:    "target not found returns error",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy",
					Namespace:  "default",
					Finalizers: []string{rateLimitPolicyFinalizer},
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "missing-gateway",
					},
					Rules: []avapigwv1alpha1.RateLimitRule{
						{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
					},
				},
			},
			wantErr: false, // Error is recorded in status, not returned
			validate: func(t *testing.T, cl client.Client) {
				policy := &avapigwv1alpha1.RateLimitPolicy{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, policy)
				require.NoError(t, err)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusError, policy.Status.Phase)
			},
		},
		{
			name: "successful reconciliation with Redis storage",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "redis-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"password": []byte("secret"),
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy",
					Namespace:  "default",
					Finalizers: []string{rateLimitPolicyFinalizer},
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "test-gateway",
					},
					Rules: []avapigwv1alpha1.RateLimitRule{
						{
							Name: "default",
							Limit: avapigwv1alpha1.RateLimitValue{
								Requests: 100,
								Unit:     avapigwv1alpha1.RateLimitUnitSecond,
							},
						},
					},
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "redis:6379",
							SecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "redis-secret",
							},
						},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, cl client.Client) {
				policy := &avapigwv1alpha1.RateLimitPolicy{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, policy)
				require.NoError(t, err)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, policy.Status.Phase)
			},
		},
		{
			name: "Redis secret not found returns error in status",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy",
					Namespace:  "default",
					Finalizers: []string{rateLimitPolicyFinalizer},
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "test-gateway",
					},
					Rules: []avapigwv1alpha1.RateLimitRule{
						{Name: "default", Limit: avapigwv1alpha1.RateLimitValue{Requests: 100, Unit: avapigwv1alpha1.RateLimitUnitSecond}},
					},
					Storage: &avapigwv1alpha1.RateLimitStorageConfig{
						Type: avapigwv1alpha1.RateLimitStorageRedis,
						Redis: &avapigwv1alpha1.RedisStorageConfig{
							Address: "redis:6379",
							SecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "missing-secret",
							},
						},
					},
				},
			},
			wantErr: false, // Error is recorded in status
			validate: func(t *testing.T, cl client.Client) {
				policy := &avapigwv1alpha1.RateLimitPolicy{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, policy)
				require.NoError(t, err)
				assert.Equal(t, avapigwv1alpha1.PhaseStatusError, policy.Status.Phase)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Add the policy to objects
			allObjects := append(tt.objects, tt.policy)

			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(allObjects...).
				WithStatusSubresource(&avapigwv1alpha1.RateLimitPolicy{}).
				Build()

			r := newRateLimitPolicyReconciler(cl, scheme)

			// Re-fetch the policy
			fetchedPolicy := &avapigwv1alpha1.RateLimitPolicy{}
			err := cl.Get(context.Background(), types.NamespacedName{Name: tt.policy.Name, Namespace: tt.policy.Namespace}, fetchedPolicy)
			require.NoError(t, err)

			err = r.reconcileRateLimitPolicy(context.Background(), fetchedPolicy)

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

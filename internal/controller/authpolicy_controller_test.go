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

func newAuthPolicyReconciler(cl client.Client, scheme *runtime.Scheme) *AuthPolicyReconciler {
	return &AuthPolicyReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
}

func ptrBool(b bool) *bool {
	return &b
}

// ============================================================================
// AuthPolicyReconciler.Reconcile Tests
// ============================================================================

func TestAuthPolicyReconciler_Reconcile(t *testing.T) {
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
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Group: avapigwv1alpha1.GroupVersion.Group,
							Kind:  "Gateway",
							Name:  "test-gateway",
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
				policy := &avapigwv1alpha1.AuthPolicy{}
				err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, policy)
				require.NoError(t, err)
				assert.Contains(t, policy.Finalizers, authPolicyFinalizer)
			},
		},
		{
			name: "successful reconciliation with valid gateway target",
			objects: []client.Object{
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-policy",
						Namespace:  "default",
						Finalizers: []string{authPolicyFinalizer},
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Group: avapigwv1alpha1.GroupVersion.Group,
							Kind:  "Gateway",
							Name:  "test-gateway",
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
				policy := &avapigwv1alpha1.AuthPolicy{}
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
				WithStatusSubresource(&avapigwv1alpha1.AuthPolicy{}).
				Build()

			r := newAuthPolicyReconciler(cl, scheme)

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
// AuthPolicyReconciler.handleDeletion Tests
// ============================================================================

func TestAuthPolicyReconciler_handleDeletion(t *testing.T) {
	scheme := newTestScheme(t)

	t.Run("removes finalizer on deletion", func(t *testing.T) {
		// Create policy with finalizer (no DeletionTimestamp in fake client)
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-policy",
				Namespace:  "default",
				Finalizers: []string{authPolicyFinalizer},
			},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(policy).
			Build()

		r := newAuthPolicyReconciler(cl, scheme)

		// Re-fetch the policy to get the version from the fake client
		fetchedPolicy := &avapigwv1alpha1.AuthPolicy{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, fetchedPolicy)
		require.NoError(t, err)

		// Call handleDeletion (it will remove finalizer if present)
		result, err := r.handleDeletion(context.Background(), fetchedPolicy)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify finalizer was removed
		updatedPolicy := &avapigwv1alpha1.AuthPolicy{}
		err = cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, updatedPolicy)
		require.NoError(t, err)
		assert.NotContains(t, updatedPolicy.Finalizers, authPolicyFinalizer)
	})

	t.Run("no-op when finalizer not present", func(t *testing.T) {
		// Create policy without finalizer
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-policy",
				Namespace:  "default",
				Finalizers: []string{},
			},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(policy).
			Build()

		r := newAuthPolicyReconciler(cl, scheme)

		// Re-fetch the policy
		fetchedPolicy := &avapigwv1alpha1.AuthPolicy{}
		err := cl.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, fetchedPolicy)
		require.NoError(t, err)

		result, err := r.handleDeletion(context.Background(), fetchedPolicy)

		assert.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})
}

// ============================================================================
// AuthPolicyReconciler.validateTargetRef Tests
// ============================================================================

func TestAuthPolicyReconciler_validateTargetRef(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		policy  *avapigwv1alpha1.AuthPolicy
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
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
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
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
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
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
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
			name: "GRPCRoute target found",
			objects: []client.Object{
				&avapigwv1alpha1.GRPCRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
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
			name:    "unsupported target kind",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
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
			name: "target in different namespace",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "other-namespace",
					},
				},
			},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
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

			r := newAuthPolicyReconciler(cl, scheme)

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
// AuthPolicyReconciler.validateJWTConfig Tests
// ============================================================================

func TestAuthPolicyReconciler_validateJWTConfig(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		policy  *avapigwv1alpha1.AuthPolicy
		jwt     *avapigwv1alpha1.JWTAuthConfig
		wantErr bool
	}{
		{
			name:    "valid JWT config with JWKS URI",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				JWKSUri: ptrString("https://example.com/.well-known/jwks.json"),
			},
			wantErr: false,
		},
		{
			name: "valid JWT config with JWKS secret",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "jwks-secret",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				JWKS: &avapigwv1alpha1.SecretObjectReference{
					Name: "jwks-secret",
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid JWT config - no JWKS URI or secret",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			jwt:     &avapigwv1alpha1.JWTAuthConfig{},
			wantErr: true,
		},
		{
			name:    "invalid JWT config - JWKS secret not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				JWKS: &avapigwv1alpha1.SecretObjectReference{
					Name: "missing-secret",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newAuthPolicyReconciler(cl, scheme)

			err := r.validateJWTConfig(context.Background(), tt.policy, tt.jwt)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// AuthPolicyReconciler.validateAPIKeyConfig Tests
// ============================================================================

func TestAuthPolicyReconciler_validateAPIKeyConfig(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		policy  *avapigwv1alpha1.AuthPolicy
		apiKey  *avapigwv1alpha1.APIKeyAuthConfig
		wantErr bool
	}{
		{
			name: "valid API key config with secret validation",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "api-key-secret",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Validation: &avapigwv1alpha1.APIKeyValidationConfig{
					Type: avapigwv1alpha1.APIKeyValidationSecret,
					SecretRef: &avapigwv1alpha1.SecretObjectReference{
						Name: "api-key-secret",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid API key config - no validation",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			apiKey:  &avapigwv1alpha1.APIKeyAuthConfig{},
			wantErr: true,
		},
		{
			name:    "invalid API key config - secret validation without secret ref",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Validation: &avapigwv1alpha1.APIKeyValidationConfig{
					Type: avapigwv1alpha1.APIKeyValidationSecret,
				},
			},
			wantErr: true,
		},
		{
			name:    "valid API key config with external validation",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Validation: &avapigwv1alpha1.APIKeyValidationConfig{
					Type: avapigwv1alpha1.APIKeyValidationExternal,
					External: &avapigwv1alpha1.ExternalValidationConfig{
						URL: "https://auth.example.com/validate",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid API key config - external validation without URL",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Validation: &avapigwv1alpha1.APIKeyValidationConfig{
					Type:     avapigwv1alpha1.APIKeyValidationExternal,
					External: &avapigwv1alpha1.ExternalValidationConfig{},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newAuthPolicyReconciler(cl, scheme)

			err := r.validateAPIKeyConfig(context.Background(), tt.policy, tt.apiKey)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// AuthPolicyReconciler.validateBasicAuthConfig Tests
// ============================================================================

func TestAuthPolicyReconciler_validateBasicAuthConfig(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		policy  *avapigwv1alpha1.AuthPolicy
		basic   *avapigwv1alpha1.BasicAuthConfig
		wantErr bool
	}{
		{
			name: "valid basic auth config",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "basic-auth-secret",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			basic: &avapigwv1alpha1.BasicAuthConfig{
				SecretRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "basic-auth-secret",
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid basic auth config - no secret ref",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			basic:   &avapigwv1alpha1.BasicAuthConfig{},
			wantErr: true,
		},
		{
			name:    "invalid basic auth config - secret not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			basic: &avapigwv1alpha1.BasicAuthConfig{
				SecretRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "missing-secret",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newAuthPolicyReconciler(cl, scheme)

			err := r.validateBasicAuthConfig(context.Background(), tt.policy, tt.basic)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// AuthPolicyReconciler.validateOAuth2Config Tests
// ============================================================================

func TestAuthPolicyReconciler_validateOAuth2Config(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		policy  *avapigwv1alpha1.AuthPolicy
		oauth2  *avapigwv1alpha1.OAuth2Config
		wantErr bool
	}{
		{
			name:    "valid OAuth2 config",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			oauth2: &avapigwv1alpha1.OAuth2Config{
				TokenEndpoint: ptrString("https://auth.example.com/token"),
				ClientID:      ptrString("my-client-id"),
			},
			wantErr: false,
		},
		{
			name:    "invalid OAuth2 config - no token endpoint",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			oauth2: &avapigwv1alpha1.OAuth2Config{
				ClientID: ptrString("my-client-id"),
			},
			wantErr: true,
		},
		{
			name:    "invalid OAuth2 config - no client ID",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			oauth2: &avapigwv1alpha1.OAuth2Config{
				TokenEndpoint: ptrString("https://auth.example.com/token"),
			},
			wantErr: true,
		},
		{
			name: "valid OAuth2 config with client secret",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth2-secret",
						Namespace: "default",
					},
				},
			},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			oauth2: &avapigwv1alpha1.OAuth2Config{
				TokenEndpoint: ptrString("https://auth.example.com/token"),
				ClientID:      ptrString("my-client-id"),
				ClientSecretRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "oauth2-secret",
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid OAuth2 config - client secret not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			oauth2: &avapigwv1alpha1.OAuth2Config{
				TokenEndpoint: ptrString("https://auth.example.com/token"),
				ClientID:      ptrString("my-client-id"),
				ClientSecretRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "missing-secret",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			r := newAuthPolicyReconciler(cl, scheme)

			err := r.validateOAuth2Config(context.Background(), tt.policy, tt.oauth2)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// AuthPolicyReconciler.findPoliciesForGateway Tests
// ============================================================================

func TestAuthPolicyReconciler_findPoliciesForGateway(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name         string
		objects      []client.Object
		gateway      *avapigwv1alpha1.Gateway
		wantRequests int
	}{
		{
			name: "finds policies targeting gateway",
			objects: []client.Object{
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Group: avapigwv1alpha1.GroupVersion.Group,
							Kind:  "Gateway",
							Name:  "test-gateway",
						},
					},
				},
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Group: avapigwv1alpha1.GroupVersion.Group,
							Kind:  "Gateway",
							Name:  "test-gateway",
						},
					},
				},
			},
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: "default",
				},
			},
			wantRequests: 2,
		},
		{
			name: "returns empty for no matches",
			objects: []client.Object{
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Group: avapigwv1alpha1.GroupVersion.Group,
							Kind:  "Gateway",
							Name:  "other-gateway",
						},
					},
				},
			},
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
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

			r := newAuthPolicyReconciler(cl, scheme)

			requests := r.findPoliciesForGateway(context.Background(), tt.gateway)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// AuthPolicyReconciler.policyReferencesSecret Tests
// ============================================================================

func TestAuthPolicyReconciler_policyReferencesSecret(t *testing.T) {
	tests := []struct {
		name            string
		policy          *avapigwv1alpha1.AuthPolicy
		secretNamespace string
		secretName      string
		wantResult      bool
	}{
		{
			name: "policy references JWT JWKS secret",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							JWKS: &avapigwv1alpha1.SecretObjectReference{
								Name: "jwks-secret",
							},
						},
					},
				},
			},
			secretNamespace: "default",
			secretName:      "jwks-secret",
			wantResult:      true,
		},
		{
			name: "policy references API key secret",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
							Validation: &avapigwv1alpha1.APIKeyValidationConfig{
								SecretRef: &avapigwv1alpha1.SecretObjectReference{
									Name: "api-key-secret",
								},
							},
						},
					},
				},
			},
			secretNamespace: "default",
			secretName:      "api-key-secret",
			wantResult:      true,
		},
		{
			name: "policy references Basic auth secret",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						Basic: &avapigwv1alpha1.BasicAuthConfig{
							SecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "basic-auth-secret",
							},
						},
					},
				},
			},
			secretNamespace: "default",
			secretName:      "basic-auth-secret",
			wantResult:      true,
		},
		{
			name: "policy references OAuth2 client secret",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						OAuth2: &avapigwv1alpha1.OAuth2Config{
							ClientSecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "oauth2-secret",
							},
						},
					},
				},
			},
			secretNamespace: "default",
			secretName:      "oauth2-secret",
			wantResult:      true,
		},
		{
			name: "policy does not reference secret",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							JWKSUri: ptrString("https://example.com/.well-known/jwks.json"),
						},
					},
				},
			},
			secretNamespace: "default",
			secretName:      "some-secret",
			wantResult:      false,
		},
		{
			name: "policy with no authentication config",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{},
			},
			secretNamespace: "default",
			secretName:      "some-secret",
			wantResult:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &AuthPolicyReconciler{}

			result := r.policyReferencesSecret(tt.policy, tt.secretNamespace, tt.secretName)

			assert.Equal(t, tt.wantResult, result)
		})
	}
}

// ============================================================================
// AuthPolicyReconciler.setCondition Tests
// ============================================================================

func TestAuthPolicyReconciler_setCondition(t *testing.T) {
	policy := &avapigwv1alpha1.AuthPolicy{}

	r := &AuthPolicyReconciler{}
	r.setCondition(policy, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue, "Ready", "Policy is ready")

	condition := policy.Status.GetCondition(avapigwv1alpha1.ConditionTypeReady)
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
	assert.Equal(t, "Ready", condition.Reason)
	assert.Equal(t, "Policy is ready", condition.Message)
}

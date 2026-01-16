package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// newTestScheme creates a scheme with all required types registered.
func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	return scheme
}

// ptrString returns a pointer to the given string.
func ptrString(s string) *string {
	return &s
}

// ============================================================================
// TargetRefValidator Tests
// ============================================================================

func TestTargetRefValidator_ValidateTargetRef(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name    string
		objects []client.Object
		policy  *avapigwv1alpha1.AuthPolicy
		wantErr bool
		errMsg  string
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
			errMsg:  "target Gateway default/missing-gateway not found",
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
			name:    "HTTPRoute target not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "HTTPRoute",
						Name:  "missing-route",
					},
				},
			},
			wantErr: true,
			errMsg:  "target HTTPRoute default/missing-route not found",
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
			name:    "GRPCRoute target not found",
			objects: []client.Object{},
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "GRPCRoute",
						Name:  "missing-route",
					},
				},
			},
			wantErr: true,
			errMsg:  "target GRPCRoute default/missing-route not found",
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
			errMsg:  "unsupported target kind: UnsupportedKind",
		},
		{
			name: "cross-namespace target",
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

			validator := NewTargetRefValidator(cl)
			err := validator.ValidateTargetRef(context.Background(), tt.policy)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// GetTargetNamespace Tests
// ============================================================================

func TestGetTargetNamespace(t *testing.T) {
	tests := []struct {
		name   string
		policy *avapigwv1alpha1.AuthPolicy
		wantNS string
	}{
		{
			name: "uses policy namespace when target namespace not specified",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "test-gateway",
					},
				},
			},
			wantNS: "default",
		},
		{
			name: "uses target namespace when specified",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind:      "Gateway",
						Name:      "test-gateway",
						Namespace: ptrString("other-namespace"),
					},
				},
			},
			wantNS: "other-namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := GetTargetNamespace(tt.policy)
			assert.Equal(t, tt.wantNS, ns)
		})
	}
}

// ============================================================================
// MatchesTarget Tests
// ============================================================================

func TestMatchesTarget(t *testing.T) {
	tests := []struct {
		name       string
		policy     *avapigwv1alpha1.AuthPolicy
		kind       string
		namespace  string
		targetName string
		want       bool
	}{
		{
			name: "matches when all fields match",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "test-gateway",
					},
				},
			},
			kind:       "Gateway",
			namespace:  "default",
			targetName: "test-gateway",
			want:       true,
		},
		{
			name: "does not match when kind differs",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "test-gateway",
					},
				},
			},
			kind:       "HTTPRoute",
			namespace:  "default",
			targetName: "test-gateway",
			want:       false,
		},
		{
			name: "does not match when name differs",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "test-gateway",
					},
				},
			},
			kind:       "Gateway",
			namespace:  "default",
			targetName: "other-gateway",
			want:       false,
		},
		{
			name: "does not match when namespace differs",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind: "Gateway",
						Name: "test-gateway",
					},
				},
			},
			kind:       "Gateway",
			namespace:  "other-namespace",
			targetName: "test-gateway",
			want:       false,
		},
		{
			name: "matches cross-namespace target",
			policy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Kind:      "Gateway",
						Name:      "test-gateway",
						Namespace: ptrString("other-namespace"),
					},
				},
			},
			kind:       "Gateway",
			namespace:  "other-namespace",
			targetName: "test-gateway",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesTarget(tt.policy, tt.kind, tt.namespace, tt.targetName)
			assert.Equal(t, tt.want, result)
		})
	}
}

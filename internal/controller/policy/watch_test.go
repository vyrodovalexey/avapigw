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

// newWatchTestScheme creates a scheme with all required types registered.
func newWatchTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	return scheme
}

// ============================================================================
// PolicyWatchHandler Tests for AuthPolicy
// ============================================================================

func TestPolicyWatchHandler_FindPoliciesForTarget_AuthPolicy(t *testing.T) {
	scheme := newWatchTestScheme(t)

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
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "Gateway",
							Name: "test-gateway",
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
							Kind: "Gateway",
							Name: "test-gateway",
						},
					},
				},
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-3",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "Gateway",
							Name: "other-gateway",
						},
					},
				},
			},
			kind:         "Gateway",
			namespace:    "default",
			targetName:   "test-gateway",
			wantRequests: 2,
		},
		{
			name: "finds policies targeting HTTPRoute",
			objects: []client.Object{
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "HTTPRoute",
							Name: "test-route",
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
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "GRPCRoute",
							Name: "test-route",
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
			name:         "returns empty when no policies exist",
			objects:      []client.Object{},
			kind:         "Gateway",
			namespace:    "default",
			targetName:   "test-gateway",
			wantRequests: 0,
		},
		{
			name: "returns empty when no policies match",
			objects: []client.Object{
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind: "Gateway",
							Name: "other-gateway",
						},
					},
				},
			},
			kind:         "Gateway",
			namespace:    "default",
			targetName:   "test-gateway",
			wantRequests: 0,
		},
		{
			name: "finds cross-namespace policies",
			objects: []client.Object{
				&avapigwv1alpha1.AuthPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-1",
						Namespace: "policy-namespace",
					},
					Spec: avapigwv1alpha1.AuthPolicySpec{
						TargetRef: avapigwv1alpha1.TargetRef{
							Kind:      "Gateway",
							Name:      "test-gateway",
							Namespace: ptrString("target-namespace"),
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

			handler := NewPolicyWatchHandler[*avapigwv1alpha1.AuthPolicy](cl, &avapigwv1alpha1.AuthPolicyList{})
			requests := handler.FindPoliciesForTarget(context.Background(), tt.kind, tt.namespace, tt.targetName)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// PolicyWatchHandler Tests for RateLimitPolicy
// ============================================================================

func TestPolicyWatchHandler_FindPoliciesForTarget_RateLimitPolicy(t *testing.T) {
	scheme := newWatchTestScheme(t)

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
			name:         "returns empty when no policies exist",
			objects:      []client.Object{},
			kind:         "Gateway",
			namespace:    "default",
			targetName:   "test-gateway",
			wantRequests: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			handler := NewPolicyWatchHandler[*avapigwv1alpha1.RateLimitPolicy](cl, &avapigwv1alpha1.RateLimitPolicyList{})
			requests := handler.FindPoliciesForTarget(context.Background(), tt.kind, tt.namespace, tt.targetName)

			assert.Len(t, requests, tt.wantRequests)
		})
	}
}

// ============================================================================
// Convenience Method Tests
// ============================================================================

func TestPolicyWatchHandler_ConvenienceMethods(t *testing.T) {
	scheme := newWatchTestScheme(t)

	objects := []client.Object{
		&avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "gateway-policy",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Kind: "Gateway",
					Name: "test-gateway",
				},
			},
		},
		&avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "httproute-policy",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Kind: "HTTPRoute",
					Name: "test-route",
				},
			},
		},
		&avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "grpcroute-policy",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Kind: "GRPCRoute",
					Name: "test-grpc-route",
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		Build()

	handler := NewPolicyWatchHandler[*avapigwv1alpha1.AuthPolicy](cl, &avapigwv1alpha1.AuthPolicyList{})

	t.Run("FindPoliciesForGateway", func(t *testing.T) {
		requests := handler.FindPoliciesForGateway(context.Background(), "default", "test-gateway")
		assert.Len(t, requests, 1)
		assert.Equal(t, "gateway-policy", requests[0].Name)
	})

	t.Run("FindPoliciesForHTTPRoute", func(t *testing.T) {
		requests := handler.FindPoliciesForHTTPRoute(context.Background(), "default", "test-route")
		assert.Len(t, requests, 1)
		assert.Equal(t, "httproute-policy", requests[0].Name)
	})

	t.Run("FindPoliciesForGRPCRoute", func(t *testing.T) {
		requests := handler.FindPoliciesForGRPCRoute(context.Background(), "default", "test-grpc-route")
		assert.Len(t, requests, 1)
		assert.Equal(t, "grpcroute-policy", requests[0].Name)
	})
}

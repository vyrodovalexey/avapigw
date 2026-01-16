package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAuthPolicy_GetTargetRef(t *testing.T) {
	tests := []struct {
		name   string
		policy *AuthPolicy
		want   TargetRef
	}{
		{
			name: "gateway target",
			policy: &AuthPolicy{
				Spec: AuthPolicySpec{
					TargetRef: TargetRef{
						Group: "gateway.networking.k8s.io",
						Kind:  "Gateway",
						Name:  "my-gateway",
					},
				},
			},
			want: TargetRef{
				Group: "gateway.networking.k8s.io",
				Kind:  "Gateway",
				Name:  "my-gateway",
			},
		},
		{
			name: "httproute target",
			policy: &AuthPolicy{
				Spec: AuthPolicySpec{
					TargetRef: TargetRef{
						Group: "gateway.networking.k8s.io",
						Kind:  "HTTPRoute",
						Name:  "my-route",
					},
				},
			},
			want: TargetRef{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  "my-route",
			},
		},
		{
			name: "empty target ref",
			policy: &AuthPolicy{
				Spec: AuthPolicySpec{},
			},
			want: TargetRef{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.GetTargetRef()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthPolicyList_GetPolicies(t *testing.T) {
	tests := []struct {
		name    string
		list    *AuthPolicyList
		wantLen int
	}{
		{
			name: "multiple policies",
			list: &AuthPolicyList{
				Items: []AuthPolicy{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "policy-1"},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "policy-2"},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "policy-3"},
					},
				},
			},
			wantLen: 3,
		},
		{
			name: "single policy",
			list: &AuthPolicyList{
				Items: []AuthPolicy{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "policy-1"},
					},
				},
			},
			wantLen: 1,
		},
		{
			name: "empty list",
			list: &AuthPolicyList{
				Items: []AuthPolicy{},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies := tt.list.GetPolicies()
			assert.Len(t, policies, tt.wantLen)

			// Verify each policy is correctly referenced
			for i, policy := range policies {
				assert.Equal(t, &tt.list.Items[i], policy)
			}
		})
	}
}

func TestRateLimitPolicy_GetTargetRef(t *testing.T) {
	tests := []struct {
		name   string
		policy *RateLimitPolicy
		want   TargetRef
	}{
		{
			name: "gateway target",
			policy: &RateLimitPolicy{
				Spec: RateLimitPolicySpec{
					TargetRef: TargetRef{
						Group: "gateway.networking.k8s.io",
						Kind:  "Gateway",
						Name:  "my-gateway",
					},
				},
			},
			want: TargetRef{
				Group: "gateway.networking.k8s.io",
				Kind:  "Gateway",
				Name:  "my-gateway",
			},
		},
		{
			name: "httproute target",
			policy: &RateLimitPolicy{
				Spec: RateLimitPolicySpec{
					TargetRef: TargetRef{
						Group: "gateway.networking.k8s.io",
						Kind:  "HTTPRoute",
						Name:  "my-route",
					},
				},
			},
			want: TargetRef{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  "my-route",
			},
		},
		{
			name: "empty target ref",
			policy: &RateLimitPolicy{
				Spec: RateLimitPolicySpec{},
			},
			want: TargetRef{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.GetTargetRef()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRateLimitPolicyList_GetPolicies(t *testing.T) {
	tests := []struct {
		name    string
		list    *RateLimitPolicyList
		wantLen int
	}{
		{
			name: "multiple policies",
			list: &RateLimitPolicyList{
				Items: []RateLimitPolicy{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ratelimit-1"},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ratelimit-2"},
					},
				},
			},
			wantLen: 2,
		},
		{
			name: "single policy",
			list: &RateLimitPolicyList{
				Items: []RateLimitPolicy{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ratelimit-1"},
					},
				},
			},
			wantLen: 1,
		},
		{
			name: "empty list",
			list: &RateLimitPolicyList{
				Items: []RateLimitPolicy{},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies := tt.list.GetPolicies()
			assert.Len(t, policies, tt.wantLen)

			// Verify each policy is correctly referenced
			for i, policy := range policies {
				assert.Equal(t, &tt.list.Items[i], policy)
			}
		})
	}
}

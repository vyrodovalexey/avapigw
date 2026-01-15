package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// GatewayIndexKey Tests
// ============================================================================

func TestGatewayIndexKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		gwName    string
		want      string
	}{
		{
			name:      "simple key",
			namespace: "default",
			gwName:    "my-gateway",
			want:      "default/my-gateway",
		},
		{
			name:      "different namespace",
			namespace: "production",
			gwName:    "prod-gateway",
			want:      "production/prod-gateway",
		},
		{
			name:      "empty namespace",
			namespace: "",
			gwName:    "gateway",
			want:      "/gateway",
		},
		{
			name:      "empty name",
			namespace: "default",
			gwName:    "",
			want:      "default/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GatewayIndexKey(tt.namespace, tt.gwName)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// BackendIndexKey Tests
// ============================================================================

func TestBackendIndexKey(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		backendName string
		want        string
	}{
		{
			name:        "simple key",
			namespace:   "default",
			backendName: "my-backend",
			want:        "default/my-backend",
		},
		{
			name:        "different namespace",
			namespace:   "staging",
			backendName: "staging-backend",
			want:        "staging/staging-backend",
		},
		{
			name:        "empty namespace",
			namespace:   "",
			backendName: "backend",
			want:        "/backend",
		},
		{
			name:        "empty name",
			namespace:   "default",
			backendName: "",
			want:        "default/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BackendIndexKey(tt.namespace, tt.backendName)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// extractGatewayRefs Tests
// ============================================================================

func TestExtractGatewayRefs(t *testing.T) {
	tests := []struct {
		name           string
		routeNamespace string
		parentRefs     []avapigwv1alpha1.ParentRef
		want           []string
	}{
		{
			name:           "empty parent refs",
			routeNamespace: "default",
			parentRefs:     []avapigwv1alpha1.ParentRef{},
			want:           []string{},
		},
		{
			name:           "single parent ref without namespace",
			routeNamespace: "default",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "gateway-1"},
			},
			want: []string{"default/gateway-1"},
		},
		{
			name:           "single parent ref with namespace",
			routeNamespace: "default",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "gateway-1", Namespace: ptrString("other-ns")},
			},
			want: []string{"other-ns/gateway-1"},
		},
		{
			name:           "multiple parent refs",
			routeNamespace: "default",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "gateway-1"},
				{Name: "gateway-2", Namespace: ptrString("prod")},
				{Name: "gateway-3"},
			},
			want: []string{"default/gateway-1", "prod/gateway-2", "default/gateway-3"},
		},
		{
			name:           "parent ref with section name (ignored for indexing)",
			routeNamespace: "default",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "gateway-1", SectionName: ptrString("http")},
			},
			want: []string{"default/gateway-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGatewayRefs(tt.routeNamespace, tt.parentRefs)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// extractBackendRefs Tests
// ============================================================================

func TestExtractBackendRefs(t *testing.T) {
	tests := []struct {
		name           string
		routeNamespace string
		rules          []avapigwv1alpha1.HTTPRouteRule
		want           []string
	}{
		{
			name:           "empty rules",
			routeNamespace: "default",
			rules:          []avapigwv1alpha1.HTTPRouteRule{},
			want:           nil,
		},
		{
			name:           "rule with no backend refs",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{BackendRefs: []avapigwv1alpha1.HTTPBackendRef{}},
			},
			want: nil,
		},
		{
			name:           "Service backend (not indexed)",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
					},
				},
			},
			want: nil, // Services are not indexed, only Backend kind
		},
		{
			name:           "Backend kind without namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-backend",
							Kind: ptrString("Backend"),
						}},
					},
				},
			},
			want: []string{"default/my-backend"},
		},
		{
			name:           "Backend kind with namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "my-backend",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("other-ns"),
						}},
					},
				},
			},
			want: []string{"other-ns/my-backend"},
		},
		{
			name:           "multiple rules with mixed backends",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "service-1"}}, // Service, not indexed
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "backend-1",
							Kind: ptrString("Backend"),
						}},
					},
				},
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "backend-2",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("prod"),
						}},
					},
				},
			},
			want: []string{"default/backend-1", "prod/backend-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBackendRefs(tt.routeNamespace, tt.rules)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Index Field Constants Tests
// ============================================================================

func TestIndexFieldConstants(t *testing.T) {
	// Verify constants are defined correctly
	assert.Equal(t, ".spec.parentRefs.gateway", HTTPRouteGatewayIndexField)
	assert.Equal(t, ".spec.parentRefs.gateway", GRPCRouteGatewayIndexField)
	assert.Equal(t, ".spec.parentRefs.gateway", TCPRouteGatewayIndexField)
	assert.Equal(t, ".spec.parentRefs.gateway", TLSRouteGatewayIndexField)
	assert.Equal(t, ".spec.rules.backendRefs.backend", HTTPRouteBackendIndexField)
}

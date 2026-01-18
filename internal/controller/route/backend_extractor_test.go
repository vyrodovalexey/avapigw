// Package route provides shared utilities for route controllers.
package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func TestHTTPRouteBackendExtractor_ExtractBackendRefs(t *testing.T) {
	namespace := "test-ns"
	kind := "Service"
	group := ""

	tests := []struct {
		name     string
		route    *avapigwv1alpha1.HTTPRoute
		expected []BackendRefInfo
	}{
		{
			name:     "nil route",
			route:    nil,
			expected: nil,
		},
		{
			name: "empty rules",
			route: &avapigwv1alpha1.HTTPRoute{
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{},
				},
			},
			expected: nil,
		},
		{
			name: "single backend ref",
			route: &avapigwv1alpha1.HTTPRoute{
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								{
									BackendRef: avapigwv1alpha1.BackendRef{
										Name:      "backend1",
										Namespace: &namespace,
										Kind:      &kind,
										Group:     &group,
									},
								},
							},
						},
					},
				},
			},
			expected: []BackendRefInfo{
				{Name: "backend1", Namespace: &namespace, Kind: &kind, Group: &group},
			},
		},
		{
			name: "multiple backend refs across rules",
			route: &avapigwv1alpha1.HTTPRoute{
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "backend1"}},
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "backend2"}},
							},
						},
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "backend3"}},
							},
						},
					},
				},
			},
			expected: []BackendRefInfo{
				{Name: "backend1"},
				{Name: "backend2"},
				{Name: "backend3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &HTTPRouteBackendExtractor{Route: tt.route}
			result := extractor.ExtractBackendRefs()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGRPCRouteBackendExtractor_ExtractBackendRefs(t *testing.T) {
	tests := []struct {
		name     string
		route    *avapigwv1alpha1.GRPCRoute
		expected []BackendRefInfo
	}{
		{
			name:     "nil route",
			route:    nil,
			expected: nil,
		},
		{
			name: "single backend ref",
			route: &avapigwv1alpha1.GRPCRoute{
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "grpc-backend"}},
							},
						},
					},
				},
			},
			expected: []BackendRefInfo{
				{Name: "grpc-backend"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &GRPCRouteBackendExtractor{Route: tt.route}
			result := extractor.ExtractBackendRefs()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTCPRouteBackendExtractor_ExtractBackendRefs(t *testing.T) {
	tests := []struct {
		name     string
		route    *avapigwv1alpha1.TCPRoute
		expected []BackendRefInfo
	}{
		{
			name:     "nil route",
			route:    nil,
			expected: nil,
		},
		{
			name: "single backend ref",
			route: &avapigwv1alpha1.TCPRoute{
				Spec: avapigwv1alpha1.TCPRouteSpec{
					Rules: []avapigwv1alpha1.TCPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.TCPBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "tcp-backend"}},
							},
						},
					},
				},
			},
			expected: []BackendRefInfo{
				{Name: "tcp-backend"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &TCPRouteBackendExtractor{Route: tt.route}
			result := extractor.ExtractBackendRefs()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTLSRouteBackendExtractor_ExtractBackendRefs(t *testing.T) {
	tests := []struct {
		name     string
		route    *avapigwv1alpha1.TLSRoute
		expected []BackendRefInfo
	}{
		{
			name:     "nil route",
			route:    nil,
			expected: nil,
		},
		{
			name: "single backend ref",
			route: &avapigwv1alpha1.TLSRoute{
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Rules: []avapigwv1alpha1.TLSRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.TLSBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "tls-backend"}},
							},
						},
					},
				},
			},
			expected: []BackendRefInfo{
				{Name: "tls-backend"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &TLSRouteBackendExtractor{Route: tt.route}
			result := extractor.ExtractBackendRefs()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewBackendExtractor(t *testing.T) {
	tests := []struct {
		name    string
		route   interface{}
		wantNil bool
	}{
		{
			name: "HTTPRoute",
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			wantNil: false,
		},
		{
			name: "GRPCRoute",
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			wantNil: false,
		},
		{
			name: "TCPRoute",
			route: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			wantNil: false,
		},
		{
			name: "TLSRoute",
			route: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			wantNil: false,
		},
		{
			name:    "unsupported type",
			route:   "not a route",
			wantNil: true,
		},
		{
			name:    "nil",
			route:   nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewBackendExtractor(tt.route)
			if tt.wantNil {
				assert.Nil(t, extractor)
			} else {
				assert.NotNil(t, extractor)
			}
		})
	}
}

func TestExtractBackendRefsFromRoute(t *testing.T) {
	t.Run("HTTPRoute", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{BackendRef: avapigwv1alpha1.BackendRef{Name: "backend1"}},
						},
					},
				},
			},
		}
		refs := ExtractBackendRefsFromRoute(route)
		assert.Len(t, refs, 1)
		assert.Equal(t, "backend1", refs[0].Name)
	})

	t.Run("unsupported type returns nil", func(t *testing.T) {
		refs := ExtractBackendRefsFromRoute("not a route")
		assert.Nil(t, refs)
	})

	t.Run("nil returns nil", func(t *testing.T) {
		refs := ExtractBackendRefsFromRoute(nil)
		assert.Nil(t, refs)
	})
}

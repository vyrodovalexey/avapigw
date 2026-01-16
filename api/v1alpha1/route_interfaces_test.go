package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPRoute_GetParentRefs(t *testing.T) {
	tests := []struct {
		name      string
		route     *HTTPRoute
		wantLen   int
		wantFirst string
	}{
		{
			name: "with parent refs",
			route: &HTTPRoute{
				Spec: HTTPRouteSpec{
					ParentRefs: []ParentRef{
						{Name: "gateway-1"},
						{Name: "gateway-2"},
					},
				},
			},
			wantLen:   2,
			wantFirst: "gateway-1",
		},
		{
			name: "empty parent refs",
			route: &HTTPRoute{
				Spec: HTTPRouteSpec{
					ParentRefs: []ParentRef{},
				},
			},
			wantLen: 0,
		},
		{
			name: "nil parent refs",
			route: &HTTPRoute{
				Spec: HTTPRouteSpec{},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := tt.route.GetParentRefs()
			assert.Len(t, refs, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, refs[0].Name)
			}
		})
	}
}

func TestHTTPRoute_GetHostnames(t *testing.T) {
	tests := []struct {
		name      string
		route     *HTTPRoute
		wantLen   int
		wantFirst Hostname
	}{
		{
			name: "with hostnames",
			route: &HTTPRoute{
				Spec: HTTPRouteSpec{
					Hostnames: []Hostname{"example.com", "api.example.com"},
				},
			},
			wantLen:   2,
			wantFirst: "example.com",
		},
		{
			name: "empty hostnames",
			route: &HTTPRoute{
				Spec: HTTPRouteSpec{
					Hostnames: []Hostname{},
				},
			},
			wantLen: 0,
		},
		{
			name: "nil hostnames",
			route: &HTTPRoute{
				Spec: HTTPRouteSpec{},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostnames := tt.route.GetHostnames()
			assert.Len(t, hostnames, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, hostnames[0])
			}
		})
	}
}

func TestGRPCRoute_GetParentRefs(t *testing.T) {
	tests := []struct {
		name      string
		route     *GRPCRoute
		wantLen   int
		wantFirst string
	}{
		{
			name: "with parent refs",
			route: &GRPCRoute{
				Spec: GRPCRouteSpec{
					ParentRefs: []ParentRef{
						{Name: "grpc-gateway"},
					},
				},
			},
			wantLen:   1,
			wantFirst: "grpc-gateway",
		},
		{
			name: "empty parent refs",
			route: &GRPCRoute{
				Spec: GRPCRouteSpec{
					ParentRefs: []ParentRef{},
				},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := tt.route.GetParentRefs()
			assert.Len(t, refs, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, refs[0].Name)
			}
		})
	}
}

func TestGRPCRoute_GetHostnames(t *testing.T) {
	tests := []struct {
		name      string
		route     *GRPCRoute
		wantLen   int
		wantFirst Hostname
	}{
		{
			name: "with hostnames",
			route: &GRPCRoute{
				Spec: GRPCRouteSpec{
					Hostnames: []Hostname{"grpc.example.com"},
				},
			},
			wantLen:   1,
			wantFirst: "grpc.example.com",
		},
		{
			name: "empty hostnames",
			route: &GRPCRoute{
				Spec: GRPCRouteSpec{
					Hostnames: []Hostname{},
				},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostnames := tt.route.GetHostnames()
			assert.Len(t, hostnames, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, hostnames[0])
			}
		})
	}
}

func TestTCPRoute_GetParentRefs(t *testing.T) {
	tests := []struct {
		name      string
		route     *TCPRoute
		wantLen   int
		wantFirst string
	}{
		{
			name: "with parent refs",
			route: &TCPRoute{
				Spec: TCPRouteSpec{
					ParentRefs: []ParentRef{
						{Name: "tcp-gateway"},
					},
				},
			},
			wantLen:   1,
			wantFirst: "tcp-gateway",
		},
		{
			name: "empty parent refs",
			route: &TCPRoute{
				Spec: TCPRouteSpec{
					ParentRefs: []ParentRef{},
				},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := tt.route.GetParentRefs()
			assert.Len(t, refs, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, refs[0].Name)
			}
		})
	}
}

func TestTCPRoute_GetHostnames(t *testing.T) {
	// TCPRoute always returns nil for hostnames
	route := &TCPRoute{
		Spec: TCPRouteSpec{
			ParentRefs: []ParentRef{{Name: "tcp-gateway"}},
		},
	}

	hostnames := route.GetHostnames()
	assert.Nil(t, hostnames)
}

func TestTLSRoute_GetParentRefs(t *testing.T) {
	tests := []struct {
		name      string
		route     *TLSRoute
		wantLen   int
		wantFirst string
	}{
		{
			name: "with parent refs",
			route: &TLSRoute{
				Spec: TLSRouteSpec{
					ParentRefs: []ParentRef{
						{Name: "tls-gateway"},
					},
				},
			},
			wantLen:   1,
			wantFirst: "tls-gateway",
		},
		{
			name: "empty parent refs",
			route: &TLSRoute{
				Spec: TLSRouteSpec{
					ParentRefs: []ParentRef{},
				},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := tt.route.GetParentRefs()
			assert.Len(t, refs, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, refs[0].Name)
			}
		})
	}
}

func TestTLSRoute_GetHostnames(t *testing.T) {
	tests := []struct {
		name      string
		route     *TLSRoute
		wantLen   int
		wantFirst Hostname
	}{
		{
			name: "with hostnames",
			route: &TLSRoute{
				Spec: TLSRouteSpec{
					Hostnames: []Hostname{"secure.example.com"},
				},
			},
			wantLen:   1,
			wantFirst: "secure.example.com",
		},
		{
			name: "empty hostnames",
			route: &TLSRoute{
				Spec: TLSRouteSpec{
					Hostnames: []Hostname{},
				},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostnames := tt.route.GetHostnames()
			assert.Len(t, hostnames, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, hostnames[0])
			}
		})
	}
}

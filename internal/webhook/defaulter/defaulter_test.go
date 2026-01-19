// Package defaulter provides defaulting logic for CRD webhooks.
package defaulter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func TestNewGatewayDefaulter(t *testing.T) {
	d := NewGatewayDefaulter()
	assert.NotNil(t, d)
}

func TestGatewayDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		gateway  *avapigwv1alpha1.Gateway
		validate func(t *testing.T, gateway *avapigwv1alpha1.Gateway)
	}{
		{
			name: "defaults TLS mode to Terminate for HTTPS listener",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							Port:     443,
							TLS:      &avapigwv1alpha1.GatewayTLSConfig{},
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.NotNil(t, gateway.Spec.Listeners[0].TLS.Mode)
				assert.Equal(t, avapigwv1alpha1.TLSModeTerminate, *gateway.Spec.Listeners[0].TLS.Mode)
			},
		},
		{
			name: "defaults AllowedRoutes for listener",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Port:     80,
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.NotNil(t, gateway.Spec.Listeners[0].AllowedRoutes)
				require.NotNil(t, gateway.Spec.Listeners[0].AllowedRoutes.Namespaces)
				require.NotNil(t, gateway.Spec.Listeners[0].AllowedRoutes.Namespaces.From)
				assert.Equal(t, avapigwv1alpha1.NamespacesFromSame, *gateway.Spec.Listeners[0].AllowedRoutes.Namespaces.From)
			},
		},
		{
			name: "defaults allowed kinds for HTTP protocol",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Port:     80,
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.Len(t, gateway.Spec.Listeners[0].AllowedRoutes.Kinds, 1)
				assert.Equal(t, "HTTPRoute", gateway.Spec.Listeners[0].AllowedRoutes.Kinds[0].Kind)
			},
		},
		{
			name: "defaults allowed kinds for HTTPS protocol",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							Port:     443,
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.Len(t, gateway.Spec.Listeners[0].AllowedRoutes.Kinds, 1)
				assert.Equal(t, "HTTPRoute", gateway.Spec.Listeners[0].AllowedRoutes.Kinds[0].Kind)
			},
		},
		{
			name: "defaults allowed kinds for GRPC protocol",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "grpc",
							Protocol: avapigwv1alpha1.ProtocolGRPC,
							Port:     50051,
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.Len(t, gateway.Spec.Listeners[0].AllowedRoutes.Kinds, 1)
				assert.Equal(t, "GRPCRoute", gateway.Spec.Listeners[0].AllowedRoutes.Kinds[0].Kind)
			},
		},
		{
			name: "defaults allowed kinds for GRPCS protocol",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "grpcs",
							Protocol: avapigwv1alpha1.ProtocolGRPCS,
							Port:     50052,
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.Len(t, gateway.Spec.Listeners[0].AllowedRoutes.Kinds, 1)
				assert.Equal(t, "GRPCRoute", gateway.Spec.Listeners[0].AllowedRoutes.Kinds[0].Kind)
			},
		},
		{
			name: "defaults allowed kinds for TCP protocol",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "tcp",
							Protocol: avapigwv1alpha1.ProtocolTCP,
							Port:     3306,
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.Len(t, gateway.Spec.Listeners[0].AllowedRoutes.Kinds, 1)
				assert.Equal(t, "TCPRoute", gateway.Spec.Listeners[0].AllowedRoutes.Kinds[0].Kind)
			},
		},
		{
			name: "defaults allowed kinds for TLS protocol",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "tls",
							Protocol: avapigwv1alpha1.ProtocolTLS,
							Port:     443,
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.Len(t, gateway.Spec.Listeners[0].AllowedRoutes.Kinds, 1)
				assert.Equal(t, "TLSRoute", gateway.Spec.Listeners[0].AllowedRoutes.Kinds[0].Kind)
			},
		},
		{
			name: "does not override existing TLS mode",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "tls",
							Protocol: avapigwv1alpha1.ProtocolTLS,
							Port:     443,
							TLS: &avapigwv1alpha1.GatewayTLSConfig{
								Mode: func() *avapigwv1alpha1.TLSModeType {
									m := avapigwv1alpha1.TLSModePassthrough
									return &m
								}(),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.NotNil(t, gateway.Spec.Listeners[0].TLS.Mode)
				assert.Equal(t, avapigwv1alpha1.TLSModePassthrough, *gateway.Spec.Listeners[0].TLS.Mode)
			},
		},
		{
			name: "does not override existing allowed kinds",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Port:     80,
							AllowedRoutes: &avapigwv1alpha1.AllowedRoutes{
								Kinds: []avapigwv1alpha1.RouteGroupKind{
									{Kind: "CustomRoute"},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, gateway *avapigwv1alpha1.Gateway) {
				require.Len(t, gateway.Spec.Listeners[0].AllowedRoutes.Kinds, 1)
				assert.Equal(t, "CustomRoute", gateway.Spec.Listeners[0].AllowedRoutes.Kinds[0].Kind)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewGatewayDefaulter()
			d.Default(tt.gateway)
			tt.validate(t, tt.gateway)
		})
	}
}

func TestNewHTTPRouteDefaulter(t *testing.T) {
	d := NewHTTPRouteDefaulter()
	assert.NotNil(t, d)
}

func TestHTTPRouteDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		route    *avapigwv1alpha1.HTTPRoute
		validate func(t *testing.T, route *avapigwv1alpha1.HTTPRoute)
	}{
		{
			name: "defaults parent ref group and kind",
			route: &avapigwv1alpha1.HTTPRoute{
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.HTTPRoute) {
				require.NotNil(t, route.Spec.ParentRefs[0].Group)
				require.NotNil(t, route.Spec.ParentRefs[0].Kind)
				assert.Equal(t, avapigwv1alpha1.GroupVersion.Group, *route.Spec.ParentRefs[0].Group)
				assert.Equal(t, "Gateway", *route.Spec.ParentRefs[0].Kind)
			},
		},
		{
			name: "defaults path match type and value",
			route: &avapigwv1alpha1.HTTPRoute{
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.HTTPRoute) {
				require.NotNil(t, route.Spec.Rules[0].Matches[0].Path)
				require.NotNil(t, route.Spec.Rules[0].Matches[0].Path.Type)
				require.NotNil(t, route.Spec.Rules[0].Matches[0].Path.Value)
				assert.Equal(t, avapigwv1alpha1.PathMatchPathPrefix, *route.Spec.Rules[0].Matches[0].Path.Type)
				assert.Equal(t, "/", *route.Spec.Rules[0].Matches[0].Path.Value)
			},
		},
		{
			name: "defaults backend ref group, kind, and weight",
			route: &avapigwv1alpha1.HTTPRoute{
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.HTTPRoute) {
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Group)
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Kind)
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Weight)
				assert.Equal(t, "", *route.Spec.Rules[0].BackendRefs[0].Group)
				assert.Equal(t, "Service", *route.Spec.Rules[0].BackendRefs[0].Kind)
				assert.Equal(t, int32(1), *route.Spec.Rules[0].BackendRefs[0].Weight)
			},
		},
		{
			name: "does not override existing path type",
			route: &avapigwv1alpha1.HTTPRoute{
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type: func() *avapigwv1alpha1.PathMatchType {
											t := avapigwv1alpha1.PathMatchExact
											return &t
										}(),
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.HTTPRoute) {
				assert.Equal(t, avapigwv1alpha1.PathMatchExact, *route.Spec.Rules[0].Matches[0].Path.Type)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewHTTPRouteDefaulter()
			d.Default(tt.route)
			tt.validate(t, tt.route)
		})
	}
}

func TestNewGRPCRouteDefaulter(t *testing.T) {
	d := NewGRPCRouteDefaulter()
	assert.NotNil(t, d)
}

func TestGRPCRouteDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		route    *avapigwv1alpha1.GRPCRoute
		validate func(t *testing.T, route *avapigwv1alpha1.GRPCRoute)
	}{
		{
			name: "defaults parent ref group and kind",
			route: &avapigwv1alpha1.GRPCRoute{
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.GRPCRoute) {
				require.NotNil(t, route.Spec.ParentRefs[0].Group)
				require.NotNil(t, route.Spec.ParentRefs[0].Kind)
				assert.Equal(t, avapigwv1alpha1.GroupVersion.Group, *route.Spec.ParentRefs[0].Group)
				assert.Equal(t, "Gateway", *route.Spec.ParentRefs[0].Kind)
			},
		},
		{
			name: "defaults method match type",
			route: &avapigwv1alpha1.GRPCRoute{
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: func() *string { s := "MyService"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.GRPCRoute) {
				require.NotNil(t, route.Spec.Rules[0].Matches[0].Method.Type)
				assert.Equal(t, avapigwv1alpha1.GRPCMethodMatchExact, *route.Spec.Rules[0].Matches[0].Method.Type)
			},
		},
		{
			name: "defaults retry policy",
			route: &avapigwv1alpha1.GRPCRoute{
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							RetryPolicy: &avapigwv1alpha1.GRPCRetryPolicy{},
						},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.GRPCRoute) {
				require.NotNil(t, route.Spec.Rules[0].RetryPolicy.NumRetries)
				require.NotNil(t, route.Spec.Rules[0].RetryPolicy.Backoff)
				require.NotNil(t, route.Spec.Rules[0].RetryPolicy.Backoff.BaseInterval)
				require.NotNil(t, route.Spec.Rules[0].RetryPolicy.Backoff.MaxInterval)
				assert.Equal(t, int32(1), *route.Spec.Rules[0].RetryPolicy.NumRetries)
				assert.Equal(t, "100ms", *route.Spec.Rules[0].RetryPolicy.Backoff.BaseInterval)
				assert.Equal(t, "10s", *route.Spec.Rules[0].RetryPolicy.Backoff.MaxInterval)
			},
		},
		{
			name: "defaults backend ref group, kind, and weight",
			route: &avapigwv1alpha1.GRPCRoute{
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.GRPCRoute) {
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Group)
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Kind)
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Weight)
				assert.Equal(t, "", *route.Spec.Rules[0].BackendRefs[0].Group)
				assert.Equal(t, "Service", *route.Spec.Rules[0].BackendRefs[0].Kind)
				assert.Equal(t, int32(1), *route.Spec.Rules[0].BackendRefs[0].Weight)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewGRPCRouteDefaulter()
			d.Default(tt.route)
			tt.validate(t, tt.route)
		})
	}
}

func TestNewTCPRouteDefaulter(t *testing.T) {
	d := NewTCPRouteDefaulter()
	assert.NotNil(t, d)
}

func TestTCPRouteDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		route    *avapigwv1alpha1.TCPRoute
		validate func(t *testing.T, route *avapigwv1alpha1.TCPRoute)
	}{
		{
			name: "defaults parent ref group and kind",
			route: &avapigwv1alpha1.TCPRoute{
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.TCPRoute) {
				require.NotNil(t, route.Spec.ParentRefs[0].Group)
				require.NotNil(t, route.Spec.ParentRefs[0].Kind)
				assert.Equal(t, avapigwv1alpha1.GroupVersion.Group, *route.Spec.ParentRefs[0].Group)
				assert.Equal(t, "Gateway", *route.Spec.ParentRefs[0].Kind)
			},
		},
		{
			name: "defaults timeouts",
			route: &avapigwv1alpha1.TCPRoute{
				Spec: avapigwv1alpha1.TCPRouteSpec{
					Rules: []avapigwv1alpha1.TCPRouteRule{
						{},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.TCPRoute) {
				require.NotNil(t, route.Spec.Rules[0].IdleTimeout)
				require.NotNil(t, route.Spec.Rules[0].ConnectTimeout)
				assert.Equal(t, avapigwv1alpha1.Duration("3600s"), *route.Spec.Rules[0].IdleTimeout)
				assert.Equal(t, avapigwv1alpha1.Duration("10s"), *route.Spec.Rules[0].ConnectTimeout)
			},
		},
		{
			name: "defaults backend ref group, kind, and weight",
			route: &avapigwv1alpha1.TCPRoute{
				Spec: avapigwv1alpha1.TCPRouteSpec{
					Rules: []avapigwv1alpha1.TCPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.TCPBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.TCPRoute) {
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Group)
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Kind)
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Weight)
				assert.Equal(t, "", *route.Spec.Rules[0].BackendRefs[0].Group)
				assert.Equal(t, "Service", *route.Spec.Rules[0].BackendRefs[0].Kind)
				assert.Equal(t, int32(1), *route.Spec.Rules[0].BackendRefs[0].Weight)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewTCPRouteDefaulter()
			d.Default(tt.route)
			tt.validate(t, tt.route)
		})
	}
}

func TestNewTLSRouteDefaulter(t *testing.T) {
	d := NewTLSRouteDefaulter()
	assert.NotNil(t, d)
}

func TestTLSRouteDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		route    *avapigwv1alpha1.TLSRoute
		validate func(t *testing.T, route *avapigwv1alpha1.TLSRoute)
	}{
		{
			name: "defaults parent ref group and kind",
			route: &avapigwv1alpha1.TLSRoute{
				Spec: avapigwv1alpha1.TLSRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.TLSRoute) {
				require.NotNil(t, route.Spec.ParentRefs[0].Group)
				require.NotNil(t, route.Spec.ParentRefs[0].Kind)
				assert.Equal(t, avapigwv1alpha1.GroupVersion.Group, *route.Spec.ParentRefs[0].Group)
				assert.Equal(t, "Gateway", *route.Spec.ParentRefs[0].Kind)
			},
		},
		{
			name: "defaults backend ref group, kind, and weight",
			route: &avapigwv1alpha1.TLSRoute{
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Rules: []avapigwv1alpha1.TLSRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.TLSBackendRef{
								{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, route *avapigwv1alpha1.TLSRoute) {
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Group)
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Kind)
				require.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Weight)
				assert.Equal(t, "", *route.Spec.Rules[0].BackendRefs[0].Group)
				assert.Equal(t, "Service", *route.Spec.Rules[0].BackendRefs[0].Kind)
				assert.Equal(t, int32(1), *route.Spec.Rules[0].BackendRefs[0].Weight)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewTLSRouteDefaulter()
			d.Default(tt.route)
			tt.validate(t, tt.route)
		})
	}
}

func TestNewBackendDefaulter(t *testing.T) {
	d := NewBackendDefaulter()
	assert.NotNil(t, d)
}

func TestBackendDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		backend  *avapigwv1alpha1.Backend
		validate func(t *testing.T, backend *avapigwv1alpha1.Backend)
	}{
		{
			name:    "defaults load balancing algorithm",
			backend: &avapigwv1alpha1.Backend{},
			validate: func(t *testing.T, backend *avapigwv1alpha1.Backend) {
				require.NotNil(t, backend.Spec.LoadBalancing)
				require.NotNil(t, backend.Spec.LoadBalancing.Algorithm)
				assert.Equal(t, avapigwv1alpha1.LoadBalancingRoundRobin, *backend.Spec.LoadBalancing.Algorithm)
			},
		},
		{
			name:    "defaults health check settings",
			backend: &avapigwv1alpha1.Backend{},
			validate: func(t *testing.T, backend *avapigwv1alpha1.Backend) {
				require.NotNil(t, backend.Spec.HealthCheck)
				require.NotNil(t, backend.Spec.HealthCheck.Enabled)
				require.NotNil(t, backend.Spec.HealthCheck.Interval)
				require.NotNil(t, backend.Spec.HealthCheck.Timeout)
				require.NotNil(t, backend.Spec.HealthCheck.HealthyThreshold)
				require.NotNil(t, backend.Spec.HealthCheck.UnhealthyThreshold)
				assert.True(t, *backend.Spec.HealthCheck.Enabled)
				assert.Equal(t, avapigwv1alpha1.Duration("10s"), *backend.Spec.HealthCheck.Interval)
				assert.Equal(t, avapigwv1alpha1.Duration("5s"), *backend.Spec.HealthCheck.Timeout)
				assert.Equal(t, int32(2), *backend.Spec.HealthCheck.HealthyThreshold)
				assert.Equal(t, int32(3), *backend.Spec.HealthCheck.UnhealthyThreshold)
			},
		},
		{
			name:    "defaults connection pool settings",
			backend: &avapigwv1alpha1.Backend{},
			validate: func(t *testing.T, backend *avapigwv1alpha1.Backend) {
				require.NotNil(t, backend.Spec.ConnectionPool)
				require.NotNil(t, backend.Spec.ConnectionPool.HTTP)
				require.NotNil(t, backend.Spec.ConnectionPool.HTTP.MaxConnections)
				require.NotNil(t, backend.Spec.ConnectionPool.HTTP.MaxPendingRequests)
				require.NotNil(t, backend.Spec.ConnectionPool.HTTP.IdleTimeout)
				assert.Equal(t, int32(100), *backend.Spec.ConnectionPool.HTTP.MaxConnections)
				assert.Equal(t, int32(100), *backend.Spec.ConnectionPool.HTTP.MaxPendingRequests)
				assert.Equal(t, avapigwv1alpha1.Duration("60s"), *backend.Spec.ConnectionPool.HTTP.IdleTimeout)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewBackendDefaulter()
			d.Default(tt.backend)
			tt.validate(t, tt.backend)
		})
	}
}

func TestNewRateLimitPolicyDefaulter(t *testing.T) {
	d := NewRateLimitPolicyDefaulter()
	assert.NotNil(t, d)
}

func TestRateLimitPolicyDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		policy   *avapigwv1alpha1.RateLimitPolicy
		validate func(t *testing.T, policy *avapigwv1alpha1.RateLimitPolicy)
	}{
		{
			name: "defaults rule algorithm",
			policy: &avapigwv1alpha1.RateLimitPolicy{
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					Rules: []avapigwv1alpha1.RateLimitRule{
						{
							Limit: avapigwv1alpha1.RateLimitValue{
								Requests: 100,
								Unit:     avapigwv1alpha1.RateLimitUnitSecond,
							},
						},
					},
				},
			},
			validate: func(t *testing.T, policy *avapigwv1alpha1.RateLimitPolicy) {
				require.NotNil(t, policy.Spec.Rules[0].Algorithm)
				assert.Equal(t, avapigwv1alpha1.RateLimitAlgorithmTokenBucket, *policy.Spec.Rules[0].Algorithm)
			},
		},
		{
			name:   "defaults response settings",
			policy: &avapigwv1alpha1.RateLimitPolicy{},
			validate: func(t *testing.T, policy *avapigwv1alpha1.RateLimitPolicy) {
				require.NotNil(t, policy.Spec.RateLimitResponse)
				require.NotNil(t, policy.Spec.RateLimitResponse.StatusCode)
				require.NotNil(t, policy.Spec.RateLimitResponse.IncludeRateLimitHeaders)
				assert.Equal(t, int32(429), *policy.Spec.RateLimitResponse.StatusCode)
				assert.True(t, *policy.Spec.RateLimitResponse.IncludeRateLimitHeaders)
			},
		},
		{
			name:   "defaults storage settings",
			policy: &avapigwv1alpha1.RateLimitPolicy{},
			validate: func(t *testing.T, policy *avapigwv1alpha1.RateLimitPolicy) {
				require.NotNil(t, policy.Spec.Storage)
				assert.Equal(t, avapigwv1alpha1.RateLimitStorageMemory, policy.Spec.Storage.Type)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewRateLimitPolicyDefaulter()
			d.Default(tt.policy)
			tt.validate(t, tt.policy)
		})
	}
}

func TestNewAuthPolicyDefaulter(t *testing.T) {
	d := NewAuthPolicyDefaulter()
	assert.NotNil(t, d)
}

func TestAuthPolicyDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		policy   *avapigwv1alpha1.AuthPolicy
		validate func(t *testing.T, policy *avapigwv1alpha1.AuthPolicy)
	}{
		{
			name:   "defaults authorization settings",
			policy: &avapigwv1alpha1.AuthPolicy{},
			validate: func(t *testing.T, policy *avapigwv1alpha1.AuthPolicy) {
				require.NotNil(t, policy.Spec.Authorization)
				require.NotNil(t, policy.Spec.Authorization.DefaultAction)
				assert.Equal(t, avapigwv1alpha1.AuthorizationActionDeny, *policy.Spec.Authorization.DefaultAction)
			},
		},
		{
			name: "defaults JWT token location",
			policy: &avapigwv1alpha1.AuthPolicy{
				Spec: avapigwv1alpha1.AuthPolicySpec{
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							Enabled: func() *bool { b := true; return &b }(),
						},
					},
				},
			},
			validate: func(t *testing.T, policy *avapigwv1alpha1.AuthPolicy) {
				require.NotNil(t, policy.Spec.Authentication.JWT.TokenLocation)
				require.NotNil(t, policy.Spec.Authentication.JWT.TokenLocation.Header)
				require.NotNil(t, policy.Spec.Authentication.JWT.TokenLocation.Prefix)
				assert.Equal(t, "Authorization", *policy.Spec.Authentication.JWT.TokenLocation.Header)
				assert.Equal(t, "Bearer ", *policy.Spec.Authentication.JWT.TokenLocation.Prefix)
			},
		},
		{
			name: "defaults CORS max age",
			policy: &avapigwv1alpha1.AuthPolicy{
				Spec: avapigwv1alpha1.AuthPolicySpec{
					SecurityHeaders: &avapigwv1alpha1.SecurityHeadersConfig{
						CORS: &avapigwv1alpha1.CORSConfig{
							AllowOrigins: []avapigwv1alpha1.CORSOrigin{
								{Exact: func() *string { s := "*"; return &s }()},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, policy *avapigwv1alpha1.AuthPolicy) {
				require.NotNil(t, policy.Spec.SecurityHeaders.CORS.MaxAge)
				assert.Equal(t, avapigwv1alpha1.Duration("86400s"), *policy.Spec.SecurityHeaders.CORS.MaxAge)
			},
		},
		{
			name: "defaults HSTS max age",
			policy: &avapigwv1alpha1.AuthPolicy{
				Spec: avapigwv1alpha1.AuthPolicySpec{
					SecurityHeaders: &avapigwv1alpha1.SecurityHeadersConfig{
						HSTS: &avapigwv1alpha1.HSTSConfig{},
					},
				},
			},
			validate: func(t *testing.T, policy *avapigwv1alpha1.AuthPolicy) {
				require.NotNil(t, policy.Spec.SecurityHeaders.HSTS.MaxAge)
				assert.Equal(t, int32(31536000), *policy.Spec.SecurityHeaders.HSTS.MaxAge)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewAuthPolicyDefaulter()
			d.Default(tt.policy)
			tt.validate(t, tt.policy)
		})
	}
}

func TestNewTLSConfigDefaulter(t *testing.T) {
	d := NewTLSConfigDefaulter()
	assert.NotNil(t, d)
}

func TestTLSConfigDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		config   *avapigwv1alpha1.TLSConfig
		validate func(t *testing.T, config *avapigwv1alpha1.TLSConfig)
	}{
		{
			name:   "defaults TLS versions",
			config: &avapigwv1alpha1.TLSConfig{},
			validate: func(t *testing.T, config *avapigwv1alpha1.TLSConfig) {
				require.NotNil(t, config.Spec.MinVersion)
				require.NotNil(t, config.Spec.MaxVersion)
				assert.Equal(t, avapigwv1alpha1.TLSVersion12, *config.Spec.MinVersion)
				assert.Equal(t, avapigwv1alpha1.TLSVersion13, *config.Spec.MaxVersion)
			},
		},
		{
			name:   "defaults cipher suites",
			config: &avapigwv1alpha1.TLSConfig{},
			validate: func(t *testing.T, config *avapigwv1alpha1.TLSConfig) {
				require.Len(t, config.Spec.CipherSuites, 3)
				assert.Contains(t, config.Spec.CipherSuites, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
				assert.Contains(t, config.Spec.CipherSuites, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
				assert.Contains(t, config.Spec.CipherSuites, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305")
			},
		},
		{
			name:   "defaults ALPN protocols",
			config: &avapigwv1alpha1.TLSConfig{},
			validate: func(t *testing.T, config *avapigwv1alpha1.TLSConfig) {
				require.Len(t, config.Spec.ALPNProtocols, 2)
				assert.Contains(t, config.Spec.ALPNProtocols, "h2")
				assert.Contains(t, config.Spec.ALPNProtocols, "http/1.1")
			},
		},
		{
			name:   "defaults rotation settings",
			config: &avapigwv1alpha1.TLSConfig{},
			validate: func(t *testing.T, config *avapigwv1alpha1.TLSConfig) {
				require.NotNil(t, config.Spec.Rotation)
				require.NotNil(t, config.Spec.Rotation.Enabled)
				require.NotNil(t, config.Spec.Rotation.CheckInterval)
				require.NotNil(t, config.Spec.Rotation.RenewBefore)
				assert.True(t, *config.Spec.Rotation.Enabled)
				assert.Equal(t, avapigwv1alpha1.Duration("1h"), *config.Spec.Rotation.CheckInterval)
				assert.Equal(t, "720h", *config.Spec.Rotation.RenewBefore)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewTLSConfigDefaulter()
			d.Default(tt.config)
			tt.validate(t, tt.config)
		})
	}
}

func TestNewVaultSecretDefaulter(t *testing.T) {
	d := NewVaultSecretDefaulter()
	assert.NotNil(t, d)
}

func TestVaultSecretDefaulter_Default(t *testing.T) {
	tests := []struct {
		name     string
		secret   *avapigwv1alpha1.VaultSecret
		validate func(t *testing.T, secret *avapigwv1alpha1.VaultSecret)
	}{
		{
			name:   "defaults mount point",
			secret: &avapigwv1alpha1.VaultSecret{},
			validate: func(t *testing.T, secret *avapigwv1alpha1.VaultSecret) {
				require.NotNil(t, secret.Spec.MountPoint)
				assert.Equal(t, "secret", *secret.Spec.MountPoint)
			},
		},
		{
			name:   "defaults refresh settings",
			secret: &avapigwv1alpha1.VaultSecret{},
			validate: func(t *testing.T, secret *avapigwv1alpha1.VaultSecret) {
				require.NotNil(t, secret.Spec.Refresh)
				require.NotNil(t, secret.Spec.Refresh.Enabled)
				require.NotNil(t, secret.Spec.Refresh.Interval)
				require.NotNil(t, secret.Spec.Refresh.JitterPercent)
				assert.True(t, *secret.Spec.Refresh.Enabled)
				assert.Equal(t, avapigwv1alpha1.Duration("5m"), *secret.Spec.Refresh.Interval)
				assert.Equal(t, int32(10), *secret.Spec.Refresh.JitterPercent)
			},
		},
		{
			name: "defaults target settings",
			secret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "my-secret",
					},
				},
			},
			validate: func(t *testing.T, secret *avapigwv1alpha1.VaultSecret) {
				require.NotNil(t, secret.Spec.Target.Type)
				require.NotNil(t, secret.Spec.Target.CreationPolicy)
				require.NotNil(t, secret.Spec.Target.DeletionPolicy)
				assert.Equal(t, "Opaque", *secret.Spec.Target.Type)
				assert.Equal(t, avapigwv1alpha1.SecretCreationPolicyOwner, *secret.Spec.Target.CreationPolicy)
				assert.Equal(t, avapigwv1alpha1.SecretDeletionPolicyDelete, *secret.Spec.Target.DeletionPolicy)
			},
		},
		{
			name: "defaults Kubernetes auth mount path",
			secret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "my-role",
							},
						},
					},
				},
			},
			validate: func(t *testing.T, secret *avapigwv1alpha1.VaultSecret) {
				require.NotNil(t, secret.Spec.VaultConnection.Auth.Kubernetes.MountPath)
				assert.Equal(t, "kubernetes", *secret.Spec.VaultConnection.Auth.Kubernetes.MountPath)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewVaultSecretDefaulter()
			d.Default(tt.secret)
			tt.validate(t, tt.secret)
		})
	}
}

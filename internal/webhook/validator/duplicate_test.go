// Package validator provides validation logic for CRD webhooks.
package validator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func setupDuplicateTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

func TestNewDuplicateChecker(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	checker := NewDuplicateChecker(client)
	require.NotNil(t, checker)
	assert.Equal(t, client, checker.Client)
}

func TestDuplicateChecker_CheckGatewayListenerDuplicates(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name            string
		existingGateway *avapigwv1alpha1.Gateway
		newGateway      *avapigwv1alpha1.Gateway
		expectError     bool
	}{
		{
			name:            "no existing gateways - no duplicates",
			existingGateway: nil,
			newGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "new-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			expectError: false,
		},
		{
			name: "duplicate port and hostname",
			existingGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			newGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "new-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			expectError: true,
		},
		{
			name: "different ports - no duplicates",
			existingGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			newGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "new-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
					},
				},
			},
			expectError: false,
		},
		{
			name: "same port different hostname - no duplicates",
			existingGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Hostname: func() *avapigwv1alpha1.Hostname { h := avapigwv1alpha1.Hostname("example.com"); return &h }(),
						},
					},
				},
			},
			newGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "new-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Hostname: func() *avapigwv1alpha1.Hostname { h := avapigwv1alpha1.Hostname("other.com"); return &h }(),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "update same gateway - no duplicates",
			existingGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			newGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
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
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingGateway != nil {
				builder = builder.WithObjects(tt.existingGateway)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckGatewayListenerDuplicates(ctx, tt.newGateway)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckHTTPRouteDuplicates(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	pathPrefix := avapigwv1alpha1.PathMatchPathPrefix
	getMethod := avapigwv1alpha1.HTTPMethod("GET")

	tests := []struct {
		name          string
		existingRoute *avapigwv1alpha1.HTTPRoute
		newRoute      *avapigwv1alpha1.HTTPRoute
		expectError   bool
	}{
		{
			name:          "no existing routes - no duplicates",
			existingRoute: nil,
			newRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  &pathPrefix,
										Value: func() *string { s := "/api"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "duplicate hostname, path, and method",
			existingRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  &pathPrefix,
										Value: func() *string { s := "/api"; return &s }(),
									},
									Method: &getMethod,
								},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  &pathPrefix,
										Value: func() *string { s := "/api"; return &s }(),
									},
									Method: &getMethod,
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "different hostnames - no duplicates",
			existingRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  &pathPrefix,
										Value: func() *string { s := "/api"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"other.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  &pathPrefix,
										Value: func() *string { s := "/api"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "update same route - no duplicates",
			existingRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  &pathPrefix,
										Value: func() *string { s := "/api"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  &pathPrefix,
										Value: func() *string { s := "/api"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingRoute != nil {
				builder = builder.WithObjects(tt.existingRoute)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckHTTPRouteDuplicates(ctx, tt.newRoute)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckGRPCRouteDuplicates(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name          string
		existingRoute *avapigwv1alpha1.GRPCRoute
		newRoute      *avapigwv1alpha1.GRPCRoute
		expectError   bool
	}{
		{
			name:          "no existing routes - no duplicates",
			existingRoute: nil,
			newRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: func() *string { s := "MyService"; return &s }(),
										Method:  func() *string { s := "MyMethod"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "duplicate hostname, service, and method",
			existingRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: func() *string { s := "MyService"; return &s }(),
										Method:  func() *string { s := "MyMethod"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: func() *string { s := "MyService"; return &s }(),
										Method:  func() *string { s := "MyMethod"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "different services - no duplicates",
			existingRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: func() *string { s := "ServiceA"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: func() *string { s := "ServiceB"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingRoute != nil {
				builder = builder.WithObjects(tt.existingRoute)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckGRPCRouteDuplicates(ctx, tt.newRoute)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckTCPRoutePortConflicts(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name          string
		existingRoute *avapigwv1alpha1.TCPRoute
		newRoute      *avapigwv1alpha1.TCPRoute
		expectError   bool
	}{
		{
			name:          "no existing routes - no conflicts",
			existingRoute: nil,
			newRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway", SectionName: func() *string { s := "tcp"; return &s }()},
					},
				},
			},
			expectError: false,
		},
		{
			name: "conflict on same gateway listener",
			existingRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway", SectionName: func() *string { s := "tcp"; return &s }()},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway", SectionName: func() *string { s := "tcp"; return &s }()},
					},
				},
			},
			expectError: true,
		},
		{
			name: "different gateway listeners - no conflicts",
			existingRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway", SectionName: func() *string { s := "tcp-1"; return &s }()},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway", SectionName: func() *string { s := "tcp-2"; return &s }()},
					},
				},
			},
			expectError: false,
		},
		{
			name: "update same route - no conflicts",
			existingRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway", SectionName: func() *string { s := "tcp"; return &s }()},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway", SectionName: func() *string { s := "tcp"; return &s }()},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingRoute != nil {
				builder = builder.WithObjects(tt.existingRoute)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckTCPRoutePortConflicts(ctx, tt.newRoute)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckTLSRouteHostnameDuplicates(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name          string
		existingRoute *avapigwv1alpha1.TLSRoute
		newRoute      *avapigwv1alpha1.TLSRoute
		expectError   bool
	}{
		{
			name:          "no existing routes - no duplicates",
			existingRoute: nil,
			newRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "duplicate hostname for same gateway",
			existingRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			expectError: true,
		},
		{
			name: "different hostnames - no duplicates",
			existingRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"other.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "my-gateway"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "same hostname different gateway - no duplicates",
			existingRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "gateway-1"},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{Name: "gateway-2"},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingRoute != nil {
				builder = builder.WithObjects(tt.existingRoute)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckTLSRouteHostnameDuplicates(ctx, tt.newRoute)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckPolicyTargetDuplicates(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name            string
		existingPolicy  interface{}
		targetRef       *avapigwv1alpha1.TargetRef
		policyNamespace string
		policyName      string
		policyKind      string
		expectError     bool
	}{
		{
			name:           "no existing policies - no duplicates",
			existingPolicy: nil,
			targetRef: &avapigwv1alpha1.TargetRef{
				Group: avapigwv1alpha1.GroupVersion.Group,
				Kind:  "Gateway",
				Name:  "my-gateway",
			},
			policyNamespace: "default",
			policyName:      "new-policy",
			policyKind:      "RateLimitPolicy",
			expectError:     false,
		},
		{
			name: "duplicate RateLimitPolicy target",
			existingPolicy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-policy", Namespace: "default"},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "Gateway",
						Name:  "my-gateway",
					},
				},
			},
			targetRef: &avapigwv1alpha1.TargetRef{
				Group: avapigwv1alpha1.GroupVersion.Group,
				Kind:  "Gateway",
				Name:  "my-gateway",
			},
			policyNamespace: "default",
			policyName:      "new-policy",
			policyKind:      "RateLimitPolicy",
			expectError:     true,
		},
		{
			name: "duplicate AuthPolicy target",
			existingPolicy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-policy", Namespace: "default"},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "HTTPRoute",
						Name:  "my-route",
					},
				},
			},
			targetRef: &avapigwv1alpha1.TargetRef{
				Group: avapigwv1alpha1.GroupVersion.Group,
				Kind:  "HTTPRoute",
				Name:  "my-route",
			},
			policyNamespace: "default",
			policyName:      "new-policy",
			policyKind:      "AuthPolicy",
			expectError:     true,
		},
		{
			name: "different targets - no duplicates",
			existingPolicy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-policy", Namespace: "default"},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "Gateway",
						Name:  "gateway-1",
					},
				},
			},
			targetRef: &avapigwv1alpha1.TargetRef{
				Group: avapigwv1alpha1.GroupVersion.Group,
				Kind:  "Gateway",
				Name:  "gateway-2",
			},
			policyNamespace: "default",
			policyName:      "new-policy",
			policyKind:      "RateLimitPolicy",
			expectError:     false,
		},
		{
			name: "update same policy - no duplicates",
			existingPolicy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "my-policy", Namespace: "default"},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: avapigwv1alpha1.GroupVersion.Group,
						Kind:  "Gateway",
						Name:  "my-gateway",
					},
				},
			},
			targetRef: &avapigwv1alpha1.TargetRef{
				Group: avapigwv1alpha1.GroupVersion.Group,
				Kind:  "Gateway",
				Name:  "my-gateway",
			},
			policyNamespace: "default",
			policyName:      "my-policy",
			policyKind:      "RateLimitPolicy",
			expectError:     false,
		},
		{
			name:           "unknown policy kind - no error",
			existingPolicy: nil,
			targetRef: &avapigwv1alpha1.TargetRef{
				Group: avapigwv1alpha1.GroupVersion.Group,
				Kind:  "Gateway",
				Name:  "my-gateway",
			},
			policyNamespace: "default",
			policyName:      "new-policy",
			policyKind:      "UnknownPolicy",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingPolicy != nil {
				switch p := tt.existingPolicy.(type) {
				case *avapigwv1alpha1.RateLimitPolicy:
					builder = builder.WithObjects(p)
				case *avapigwv1alpha1.AuthPolicy:
					builder = builder.WithObjects(p)
				}
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckPolicyTargetDuplicates(ctx, tt.targetRef, tt.policyNamespace, tt.policyName, tt.policyKind)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckPolicyTargetDuplicates_WithExplicitNamespace(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name            string
		existingPolicy  interface{}
		targetRef       *avapigwv1alpha1.TargetRef
		policyNamespace string
		policyName      string
		policyKind      string
		expectError     bool
	}{
		{
			name: "RateLimitPolicy with explicit namespace - duplicate",
			existingPolicy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-policy", Namespace: "policy-ns"},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group:     avapigwv1alpha1.GroupVersion.Group,
						Kind:      "Gateway",
						Name:      "my-gateway",
						Namespace: func() *string { s := "gateway-ns"; return &s }(),
					},
				},
			},
			targetRef: &avapigwv1alpha1.TargetRef{
				Group:     avapigwv1alpha1.GroupVersion.Group,
				Kind:      "Gateway",
				Name:      "my-gateway",
				Namespace: func() *string { s := "gateway-ns"; return &s }(),
			},
			policyNamespace: "other-policy-ns",
			policyName:      "new-policy",
			policyKind:      "RateLimitPolicy",
			expectError:     true,
		},
		{
			name: "AuthPolicy with explicit namespace - duplicate",
			existingPolicy: &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-policy", Namespace: "policy-ns"},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group:     avapigwv1alpha1.GroupVersion.Group,
						Kind:      "HTTPRoute",
						Name:      "my-route",
						Namespace: func() *string { s := "route-ns"; return &s }(),
					},
				},
			},
			targetRef: &avapigwv1alpha1.TargetRef{
				Group:     avapigwv1alpha1.GroupVersion.Group,
				Kind:      "HTTPRoute",
				Name:      "my-route",
				Namespace: func() *string { s := "route-ns"; return &s }(),
			},
			policyNamespace: "other-policy-ns",
			policyName:      "new-policy",
			policyKind:      "AuthPolicy",
			expectError:     true,
		},
		{
			name: "RateLimitPolicy with different explicit namespace - no duplicate",
			existingPolicy: &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-policy", Namespace: "policy-ns"},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group:     avapigwv1alpha1.GroupVersion.Group,
						Kind:      "Gateway",
						Name:      "my-gateway",
						Namespace: func() *string { s := "gateway-ns-1"; return &s }(),
					},
				},
			},
			targetRef: &avapigwv1alpha1.TargetRef{
				Group:     avapigwv1alpha1.GroupVersion.Group,
				Kind:      "Gateway",
				Name:      "my-gateway",
				Namespace: func() *string { s := "gateway-ns-2"; return &s }(),
			},
			policyNamespace: "other-policy-ns",
			policyName:      "new-policy",
			policyKind:      "RateLimitPolicy",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingPolicy != nil {
				switch p := tt.existingPolicy.(type) {
				case *avapigwv1alpha1.RateLimitPolicy:
					builder = builder.WithObjects(p)
				case *avapigwv1alpha1.AuthPolicy:
					builder = builder.WithObjects(p)
				}
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckPolicyTargetDuplicates(ctx, tt.targetRef, tt.policyNamespace, tt.policyName, tt.policyKind)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckTCPRoutePortConflicts_WithPort(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name          string
		existingRoute *avapigwv1alpha1.TCPRoute
		newRoute      *avapigwv1alpha1.TCPRoute
		expectError   bool
	}{
		{
			name: "conflict on same gateway listener with port",
			existingRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:        "my-gateway",
							SectionName: func() *string { s := "tcp"; return &s }(),
							Port:        func() *int32 { p := int32(8080); return &p }(),
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:        "my-gateway",
							SectionName: func() *string { s := "tcp"; return &s }(),
							Port:        func() *int32 { p := int32(8080); return &p }(),
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "different ports - no conflict",
			existingRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:        "my-gateway",
							SectionName: func() *string { s := "tcp"; return &s }(),
							Port:        func() *int32 { p := int32(8080); return &p }(),
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:        "my-gateway",
							SectionName: func() *string { s := "tcp"; return &s }(),
							Port:        func() *int32 { p := int32(9090); return &p }(),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "cross-namespace conflict with explicit namespace",
			existingRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "ns1"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:        "my-gateway",
							Namespace:   func() *string { s := "gateway-ns"; return &s }(),
							SectionName: func() *string { s := "tcp"; return &s }(),
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TCPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "ns2"},
				Spec: avapigwv1alpha1.TCPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:        "my-gateway",
							Namespace:   func() *string { s := "gateway-ns"; return &s }(),
							SectionName: func() *string { s := "tcp"; return &s }(),
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingRoute != nil {
				builder = builder.WithObjects(tt.existingRoute)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckTCPRoutePortConflicts(ctx, tt.newRoute)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckTLSRouteHostnameDuplicates_WithExplicitNamespace(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name          string
		existingRoute *avapigwv1alpha1.TLSRoute
		newRoute      *avapigwv1alpha1.TLSRoute
		expectError   bool
	}{
		{
			name: "cross-namespace duplicate with explicit namespace",
			existingRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "ns1"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:      "my-gateway",
							Namespace: func() *string { s := "gateway-ns"; return &s }(),
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "ns2"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:      "my-gateway",
							Namespace: func() *string { s := "gateway-ns"; return &s }(),
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "different gateway namespaces - no duplicate",
			existingRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "ns1"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:      "my-gateway",
							Namespace: func() *string { s := "gateway-ns-1"; return &s }(),
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "ns2"},
				Spec: avapigwv1alpha1.TLSRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name:      "my-gateway",
							Namespace: func() *string { s := "gateway-ns-2"; return &s }(),
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingRoute != nil {
				builder = builder.WithObjects(tt.existingRoute)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckTLSRouteHostnameDuplicates(ctx, tt.newRoute)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckGRPCRouteDuplicates_NilMethod(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name          string
		existingRoute *avapigwv1alpha1.GRPCRoute
		newRoute      *avapigwv1alpha1.GRPCRoute
		expectError   bool
	}{
		{
			name: "duplicate with nil method",
			existingRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{Method: nil},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{Method: nil},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "duplicate with partial method (only service)",
			existingRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: func() *string { s := "MyService"; return &s }(),
										Method:  nil,
									},
								},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: func() *string { s := "MyService"; return &s }(),
										Method:  nil,
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingRoute != nil {
				builder = builder.WithObjects(tt.existingRoute)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckGRPCRouteDuplicates(ctx, tt.newRoute)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckHTTPRouteDuplicates_NilPathAndMethod(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name          string
		existingRoute *avapigwv1alpha1.HTTPRoute
		newRoute      *avapigwv1alpha1.HTTPRoute
		expectError   bool
	}{
		{
			name: "duplicate with nil path (defaults to /)",
			existingRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{Path: nil, Method: nil},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{Path: nil, Method: nil},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "duplicate with path but nil value",
			existingRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  nil,
										Value: nil,
									},
								},
							},
						},
					},
				},
			},
			newRoute: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "new-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  nil,
										Value: nil,
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingRoute != nil {
				builder = builder.WithObjects(tt.existingRoute)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckHTTPRouteDuplicates(ctx, tt.newRoute)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckGatewayListenerDuplicates_WithHostname(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	tests := []struct {
		name            string
		existingGateway *avapigwv1alpha1.Gateway
		newGateway      *avapigwv1alpha1.Gateway
		expectError     bool
	}{
		{
			name: "duplicate port and hostname with explicit hostname",
			existingGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Hostname: func() *avapigwv1alpha1.Hostname { h := avapigwv1alpha1.Hostname("example.com"); return &h }(),
						},
					},
				},
			},
			newGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "new-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Hostname: func() *avapigwv1alpha1.Hostname { h := avapigwv1alpha1.Hostname("example.com"); return &h }(),
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "no duplicate - new gateway has nil hostname, existing has hostname",
			existingGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "existing-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Hostname: func() *avapigwv1alpha1.Hostname { h := avapigwv1alpha1.Hostname("example.com"); return &h }(),
						},
					},
				},
			},
			newGateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "new-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Hostname: nil,
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingGateway != nil {
				builder = builder.WithObjects(tt.existingGateway)
			}
			client := builder.Build()
			checker := NewDuplicateChecker(client)

			err := checker.CheckGatewayListenerDuplicates(ctx, tt.newGateway)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDuplicateChecker_CheckAuthPolicyDuplicates_UpdateSamePolicy(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	// Test updating the same AuthPolicy - should not report duplicate
	existingPolicy := &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "my-policy", Namespace: "default"},
		Spec: avapigwv1alpha1.AuthPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Group: avapigwv1alpha1.GroupVersion.Group,
				Kind:  "HTTPRoute",
				Name:  "my-route",
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingPolicy).Build()
	checker := NewDuplicateChecker(client)

	targetRef := &avapigwv1alpha1.TargetRef{
		Group: avapigwv1alpha1.GroupVersion.Group,
		Kind:  "HTTPRoute",
		Name:  "my-route",
	}

	err := checker.CheckPolicyTargetDuplicates(ctx, targetRef, "default", "my-policy", "AuthPolicy")
	assert.NoError(t, err)
}

func TestDuplicateChecker_CheckAuthPolicyDuplicates_DifferentTargets(t *testing.T) {
	scheme := setupDuplicateTestScheme()
	ctx := context.Background()

	// Test different targets - should not report duplicate
	existingPolicy := &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-policy", Namespace: "default"},
		Spec: avapigwv1alpha1.AuthPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Group: avapigwv1alpha1.GroupVersion.Group,
				Kind:  "HTTPRoute",
				Name:  "route-1",
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingPolicy).Build()
	checker := NewDuplicateChecker(client)

	targetRef := &avapigwv1alpha1.TargetRef{
		Group: avapigwv1alpha1.GroupVersion.Group,
		Kind:  "HTTPRoute",
		Name:  "route-2",
	}

	err := checker.CheckPolicyTargetDuplicates(ctx, targetRef, "default", "new-policy", "AuthPolicy")
	assert.NoError(t, err)
}

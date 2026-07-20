// Package controller provides Kubernetes controllers for the operator.
//
// This file verifies the reconcile-time spec normalization end-to-end: routes
// carrying deprecated field shapes (authorization.cache.sentinel, legacy
// CSP/HSTS header strings) must reach the gRPC configuration store in the
// exact JSON shape the gateway deserializes.
package controller

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// legacyAuthorization returns an authorization config using the deprecated
// cache sentinel shape.
func legacyAuthorization() *avapigwv1alpha1.AuthorizationConfig {
	return &avapigwv1alpha1.AuthorizationConfig{
		Enabled: true,
		RBAC: &avapigwv1alpha1.RBACConfig{
			Enabled:  true,
			Policies: []avapigwv1alpha1.RBACPolicyConfig{{Name: "p", Roles: []string{"admin"}}},
		},
		Cache: &avapigwv1alpha1.AuthzCacheConfig{
			Enabled: true,
			Type:    "redis",
			Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"s1:26379"},
			},
		},
	}
}

// legacySecurity returns a security config using the deprecated CSP/HSTS
// header-string fields.
func legacySecurity() *avapigwv1alpha1.SecurityConfig {
	return &avapigwv1alpha1.SecurityConfig{
		Enabled: true,
		Headers: &avapigwv1alpha1.SecurityHeadersConfig{
			Enabled:                 true,
			ContentSecurityPolicy:   "default-src 'self'",
			StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		},
	}
}

// assertGatewayShape verifies the serialized spec stored for the gateway
// carries authorization.cache.redis.sentinel (no legacy cache.sentinel key)
// and security.csp/security.hsts (no legacy header-string keys).
func assertGatewayShape(t *testing.T, specJSON []byte) {
	t.Helper()

	var spec struct {
		Authorization struct {
			Cache struct {
				Redis *struct {
					Sentinel *struct {
						MasterName string `json:"masterName"`
					} `json:"sentinel"`
				} `json:"redis"`
				Sentinel json.RawMessage `json:"sentinel"`
			} `json:"cache"`
		} `json:"authorization"`
		Security struct {
			Headers struct {
				ContentSecurityPolicy   string `json:"contentSecurityPolicy"`
				StrictTransportSecurity string `json:"strictTransportSecurity"`
			} `json:"headers"`
			CSP *struct {
				Enabled bool   `json:"enabled"`
				Policy  string `json:"policy"`
			} `json:"csp"`
			HSTS *struct {
				Enabled           bool `json:"enabled"`
				MaxAge            int  `json:"maxAge"`
				IncludeSubDomains bool `json:"includeSubDomains"`
			} `json:"hsts"`
		} `json:"security"`
	}
	require.NoError(t, json.Unmarshal(specJSON, &spec))

	require.NotNil(t, spec.Authorization.Cache.Redis, "authz cache must serialize under redis")
	require.NotNil(t, spec.Authorization.Cache.Redis.Sentinel)
	assert.Equal(t, "mymaster", spec.Authorization.Cache.Redis.Sentinel.MasterName)
	assert.Nil(t, spec.Authorization.Cache.Sentinel, "legacy sentinel key must be gone")

	require.NotNil(t, spec.Security.CSP, "legacy CSP header must become security.csp")
	assert.True(t, spec.Security.CSP.Enabled)
	assert.Equal(t, "default-src 'self'", spec.Security.CSP.Policy)

	require.NotNil(t, spec.Security.HSTS, "legacy HSTS header must become security.hsts")
	assert.Equal(t, 31536000, spec.Security.HSTS.MaxAge)
	assert.True(t, spec.Security.HSTS.IncludeSubDomains)

	assert.Empty(t, spec.Security.Headers.ContentSecurityPolicy, "legacy CSP header key must be cleared")
	assert.Empty(t, spec.Security.Headers.StrictTransportSecurity, "legacy HSTS header key must be cleared")
}

func TestReconcileAPIRoute_NormalizesLegacyFields(t *testing.T) {
	scheme := newTestScheme()
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-api-route", Namespace: "default"},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Authorization: legacyAuthorization(),
			Security:      legacySecurity(),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).WithObjects(route).WithStatusSubresource(route).Build()
	reconciler := newAPIRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	require.NoError(t, reconciler.reconcileAPIRoute(context.Background(), route))

	configs, err := reconciler.GRPCServer.GetAllConfigs()
	require.NoError(t, err)
	var all struct {
		APIRoutes map[string][]byte `json:"apiRoutes"`
	}
	require.NoError(t, json.Unmarshal(configs, &all))
	specJSON, ok := all.APIRoutes["default/legacy-api-route"]
	require.True(t, ok, "route must be stored in the gRPC configuration store")

	assertGatewayShape(t, specJSON)
}

func TestReconcileGRPCRoute_NormalizesLegacyFields(t *testing.T) {
	scheme := newTestScheme()
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-grpc-route", Namespace: "default"},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			Authorization: legacyAuthorization(),
			Security:      legacySecurity(),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).WithObjects(route).WithStatusSubresource(route).Build()
	reconciler := newGRPCRouteReconciler(t, fakeClient, scheme, newFakeRecorder())

	require.NoError(t, reconciler.reconcileGRPCRoute(context.Background(), route))

	configs, err := reconciler.GRPCServer.GetAllConfigs()
	require.NoError(t, err)
	var all struct {
		GRPCRoutes map[string][]byte `json:"grpcRoutes"`
	}
	require.NoError(t, json.Unmarshal(configs, &all))
	specJSON, ok := all.GRPCRoutes["default/legacy-grpc-route"]
	require.True(t, ok)

	assertGatewayShape(t, specJSON)
}

func TestReconcileGraphQLRoute_NormalizesLegacyFields(t *testing.T) {
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-graphql-route", Namespace: "default"},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Authorization: legacyAuthorization(),
			Security:      legacySecurity(),
		},
	}

	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).WithObjects(route).WithStatusSubresource(route).Build()
	reconciler := newGraphQLRouteReconciler(t, fakeClient, newFakeRecorder())

	require.NoError(t, reconciler.reconcileGraphQLRoute(context.Background(), route))

	configs, err := reconciler.GRPCServer.GetAllConfigs()
	require.NoError(t, err)
	var all struct {
		GraphQLRoutes map[string][]byte `json:"graphqlRoutes"`
	}
	require.NoError(t, json.Unmarshal(configs, &all))
	specJSON, ok := all.GraphQLRoutes["default/legacy-graphql-route"]
	require.True(t, ok)

	assertGatewayShape(t, specJSON)
}

// TestRecordLegacyFieldConversions verifies the metric recording helper
// increments the per-kind counter by exactly the recorded amount. The
// counter lives on the process-global registry (also fed by the reconcile
// tests above), so assertions are delta-based.
func TestRecordLegacyFieldConversions(t *testing.T) {
	metrics := GetControllerMetrics()

	tests := []struct {
		kind  string
		count int
	}{
		{kind: KindAPIRoute, count: 2},
		{kind: KindGRPCRoute, count: 1},
		{kind: KindGraphQLRoute, count: 3},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			counter := metrics.legacyFieldConversions.WithLabelValues(tt.kind)
			before := testutil.ToFloat64(counter)

			metrics.RecordLegacyFieldConversions(tt.kind, tt.count)

			after := testutil.ToFloat64(counter)
			assert.InDelta(t, float64(tt.count), after-before, 0.001,
				"counter for kind %s must grow by the recorded conversion count", tt.kind)
		})
	}
}

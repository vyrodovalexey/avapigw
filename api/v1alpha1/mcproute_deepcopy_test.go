// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
//
// This file covers the generated DeepCopy/DeepCopyInto/DeepCopyObject functions
// for the MCPRoute family (MCPRoute, MCPRouteList, MCPRouteSpec, MCPRouteMatch,
// MCPRouteStatus, MCPUpstreamRef) — the new weighted-routing CRD surface — using
// round-trip equality and deep-independence assertions mirroring
// graphql_status_deepcopy_test.go.
package v1alpha1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// fullyPopulatedMCPRouteSpec returns an MCPRouteSpec with every optional field
// set so DeepCopy exercises all slice/pointer/map branches.
func fullyPopulatedMCPRouteSpec() MCPRouteSpec {
	return MCPRouteSpec{
		Match: []MCPRouteMatch{
			{
				Path:   &StringMatch{Exact: "/mcp"},
				Method: "tools/call",
				Name:   &StringMatch{Prefix: "weather"},
				Headers: []HeaderMatch{
					{Name: "X-Tenant", Exact: "acme"},
				},
			},
		},
		Upstreams: []string{"legacy-a", "legacy-b"},
		WeightedUpstreams: []MCPUpstreamRef{
			{Name: "stable", Weight: 90},
			{Name: "canary", Weight: 10},
		},
		Timeout: Duration("30s"),
		Retries: &RetryPolicy{Attempts: 3, PerTryTimeout: Duration("10s"), RetryOn: "5xx"},
		Headers: &HeaderManipulation{
			Request: &HeaderOperation{Set: map[string]string{"X-Gateway": "avapigw"}},
		},
		RateLimit:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100},
		Cache:          &CacheConfig{Enabled: true, TTL: Duration("5m"), KeyComponents: []string{"path"}},
		CORS:           &CORSConfig{AllowOrigins: []string{"https://example.com"}},
		Security:       &SecurityConfig{Enabled: true},
		TLS:            &RouteTLSConfig{CertFile: "/certs/tls.crt", SNIHosts: []string{"mcp.example.com"}},
		Authentication: &AuthenticationConfig{Enabled: true},
		Authorization:  &AuthorizationConfig{Enabled: true, DefaultPolicy: "deny"},
		ScopeMap: map[string][]string{
			"tools/call": {"read", "write"},
			// A nil-valued scope entry exercises the map-value nil branch of the
			// generated MCPRouteSpec.DeepCopyInto.
			"tools/list": nil,
		},
	}
}

// ============================================================================
// MCPRouteSpec DeepCopy
// ============================================================================

func TestMCPRouteSpec_DeepCopy_FullyPopulated(t *testing.T) {
	original := fullyPopulatedMCPRouteSpec()

	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.True(t, reflect.DeepEqual(&original, copied), "round-trip must be deeply equal")

	// Mutating the copy's weighted upstream must not touch the original (deep,
	// not shallow, slice copy).
	copied.WeightedUpstreams[0].Weight = 1
	assert.Equal(t, 90, original.WeightedUpstreams[0].Weight)

	copied.WeightedUpstreams[0].Name = "modified"
	assert.Equal(t, "stable", original.WeightedUpstreams[0].Name)

	copied.Upstreams[0] = "modified"
	assert.Equal(t, "legacy-a", original.Upstreams[0])

	copied.ScopeMap["tools/call"][0] = "modified"
	assert.Equal(t, "read", original.ScopeMap["tools/call"][0])

	copied.Match[0].Headers[0].Name = "modified"
	assert.Equal(t, "X-Tenant", original.Match[0].Headers[0].Name)
}

func TestMCPRouteSpec_DeepCopy_NilAndEmpty(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var nilSpec *MCPRouteSpec
		assert.Nil(t, nilSpec.DeepCopy())
	})

	t.Run("empty spec", func(t *testing.T) {
		original := &MCPRouteSpec{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Match)
		assert.Nil(t, copied.Upstreams)
		assert.Nil(t, copied.WeightedUpstreams)
		assert.Nil(t, copied.Retries)
		assert.Nil(t, copied.ScopeMap)
	})
}

func TestMCPRouteSpec_DeepCopyInto(t *testing.T) {
	original := fullyPopulatedMCPRouteSpec()
	copied := &MCPRouteSpec{}
	original.DeepCopyInto(copied)

	assert.True(t, reflect.DeepEqual(&original, copied))

	copied.WeightedUpstreams[1].Weight = 99
	assert.Equal(t, 10, original.WeightedUpstreams[1].Weight)
}

// ============================================================================
// MCPUpstreamRef DeepCopy
// ============================================================================

func TestMCPUpstreamRef_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		original := &MCPUpstreamRef{Name: "canary", Weight: 25}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.NotSame(t, original, copied)
		assert.Equal(t, original.Name, copied.Name)
		assert.Equal(t, original.Weight, copied.Weight)

		copied.Name = "modified"
		copied.Weight = 1
		assert.Equal(t, "canary", original.Name)
		assert.Equal(t, 25, original.Weight)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilRef *MCPUpstreamRef
		assert.Nil(t, nilRef.DeepCopy())
	})
}

func TestMCPUpstreamRef_DeepCopyInto(t *testing.T) {
	original := &MCPUpstreamRef{Name: "stable", Weight: 75}
	copied := &MCPUpstreamRef{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Weight, copied.Weight)

	copied.Name = "modified"
	assert.Equal(t, "stable", original.Name)
}

// ============================================================================
// MCPRoute DeepCopy / DeepCopyObject / DeepCopyInto
// ============================================================================

func TestMCPRoute_DeepCopy(t *testing.T) {
	original := &MCPRoute{
		TypeMeta:   metav1.TypeMeta{APIVersion: "avapigw.io/v1alpha1", Kind: "MCPRoute"},
		ObjectMeta: metav1.ObjectMeta{Name: "mcp-route", Namespace: "default"},
		Spec:       fullyPopulatedMCPRouteSpec(),
		Status: MCPRouteStatus{
			Conditions: []Condition{
				{Type: ConditionReady, Status: metav1.ConditionTrue, Reason: ReasonReconciled, LastTransitionTime: metav1.Now()},
			},
			ObservedGeneration: 1,
			AppliedGateways: []AppliedGateway{
				{Name: "gateway-1", Namespace: "avapigw-system", LastApplied: metav1.Now()},
			},
		},
	}

	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.NotSame(t, original, copied)
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Spec.WeightedUpstreams, copied.Spec.WeightedUpstreams)

	// Deep independence.
	copied.Name = "modified"
	assert.Equal(t, "mcp-route", original.Name)

	copied.Spec.WeightedUpstreams[0].Weight = 1
	assert.Equal(t, 90, original.Spec.WeightedUpstreams[0].Weight)

	copied.Status.Conditions[0].Message = "modified"
	assert.Equal(t, "", original.Status.Conditions[0].Message)
}

func TestMCPRoute_DeepCopy_NilReceiver(t *testing.T) {
	var nilRoute *MCPRoute
	assert.Nil(t, nilRoute.DeepCopy())
}

func TestMCPRoute_DeepCopyObject(t *testing.T) {
	original := &MCPRoute{
		TypeMeta:   metav1.TypeMeta{APIVersion: "avapigw.io/v1alpha1", Kind: "MCPRoute"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-route"},
	}
	obj := original.DeepCopyObject()
	require.NotNil(t, obj)
	var _ runtime.Object = obj

	route, ok := obj.(*MCPRoute)
	require.True(t, ok)
	assert.Equal(t, "test-route", route.Name)

	var nilRoute *MCPRoute
	assert.Nil(t, nilRoute.DeepCopyObject())
}

func TestMCPRoute_DeepCopyInto(t *testing.T) {
	original := &MCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "original"},
		Spec:       fullyPopulatedMCPRouteSpec(),
	}
	copied := &MCPRoute{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Spec.WeightedUpstreams, copied.Spec.WeightedUpstreams)

	copied.Name = "modified"
	assert.Equal(t, "original", original.Name)
	copied.Spec.WeightedUpstreams[0].Name = "modified"
	assert.Equal(t, "stable", original.Spec.WeightedUpstreams[0].Name)
}

// ============================================================================
// MCPRouteList DeepCopy / DeepCopyObject / DeepCopyInto
// ============================================================================

func TestMCPRouteList_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		original := &MCPRouteList{
			TypeMeta: metav1.TypeMeta{APIVersion: "avapigw.io/v1alpha1", Kind: "MCPRouteList"},
			Items: []MCPRoute{
				{ObjectMeta: metav1.ObjectMeta{Name: "route-1"}, Spec: fullyPopulatedMCPRouteSpec()},
				{ObjectMeta: metav1.ObjectMeta{Name: "route-2"}},
			},
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Len(t, copied.Items, 2)
		assert.Equal(t, "route-1", copied.Items[0].Name)

		copied.Items[0].Name = "modified"
		assert.Equal(t, "route-1", original.Items[0].Name)
		copied.Items[0].Spec.WeightedUpstreams[0].Weight = 1
		assert.Equal(t, 90, original.Items[0].Spec.WeightedUpstreams[0].Weight)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilList *MCPRouteList
		assert.Nil(t, nilList.DeepCopy())
	})

	t.Run("empty items", func(t *testing.T) {
		original := &MCPRouteList{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Items)
	})
}

func TestMCPRouteList_DeepCopyObject(t *testing.T) {
	original := &MCPRouteList{Items: []MCPRoute{{ObjectMeta: metav1.ObjectMeta{Name: "route-1"}}}}
	obj := original.DeepCopyObject()
	require.NotNil(t, obj)
	var _ runtime.Object = obj

	list, ok := obj.(*MCPRouteList)
	require.True(t, ok)
	assert.Len(t, list.Items, 1)

	var nilList *MCPRouteList
	assert.Nil(t, nilList.DeepCopyObject())
}

func TestMCPRouteList_DeepCopyInto(t *testing.T) {
	original := &MCPRouteList{
		Items: []MCPRoute{{ObjectMeta: metav1.ObjectMeta{Name: "route-1"}}},
	}
	copied := &MCPRouteList{}
	original.DeepCopyInto(copied)

	assert.Len(t, copied.Items, 1)
	assert.Equal(t, "route-1", copied.Items[0].Name)

	copied.Items[0].Name = "modified"
	assert.Equal(t, "route-1", original.Items[0].Name)
}

// ============================================================================
// MCPRouteMatch DeepCopy / DeepCopyInto
// ============================================================================

func TestMCPRouteMatch_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		original := &MCPRouteMatch{
			Path:   &StringMatch{Exact: "/mcp"},
			Method: "tools/call",
			Name:   &StringMatch{Prefix: "weather"},
			Headers: []HeaderMatch{
				{Name: "X-Tenant", Exact: "acme"},
			},
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.True(t, reflect.DeepEqual(original, copied))
		assert.NotSame(t, original.Path, copied.Path)
		assert.NotSame(t, original.Name, copied.Name)

		copied.Path.Exact = "modified"
		assert.Equal(t, "/mcp", original.Path.Exact)
		copied.Headers[0].Name = "modified"
		assert.Equal(t, "X-Tenant", original.Headers[0].Name)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilMatch *MCPRouteMatch
		assert.Nil(t, nilMatch.DeepCopy())
	})

	t.Run("nil optional fields", func(t *testing.T) {
		original := &MCPRouteMatch{Method: "tools/list"}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Path)
		assert.Nil(t, copied.Name)
		assert.Nil(t, copied.Headers)
		assert.Equal(t, "tools/list", copied.Method)
	})
}

func TestMCPRouteMatch_DeepCopyInto(t *testing.T) {
	original := &MCPRouteMatch{
		Path:    &StringMatch{Exact: "/mcp"},
		Method:  "tools/call",
		Headers: []HeaderMatch{{Name: "X-Custom", Exact: "value"}},
	}
	copied := &MCPRouteMatch{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.Method, copied.Method)
	assert.Equal(t, original.Path.Exact, copied.Path.Exact)

	copied.Path.Exact = "modified"
	assert.Equal(t, "/mcp", original.Path.Exact)
}

// ============================================================================
// MCPRouteStatus DeepCopy / DeepCopyInto
// ============================================================================

func TestMCPRouteStatus_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		now := metav1.Now()
		original := &MCPRouteStatus{
			Conditions: []Condition{
				{Type: ConditionReady, Status: metav1.ConditionTrue, Reason: ReasonReconciled, Message: "ok", LastTransitionTime: now},
			},
			ObservedGeneration: 3,
			AppliedGateways: []AppliedGateway{
				{Name: "gateway-1", Namespace: "avapigw-system", LastApplied: now},
			},
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Equal(t, original.ObservedGeneration, copied.ObservedGeneration)
		assert.Len(t, copied.Conditions, 1)
		assert.Len(t, copied.AppliedGateways, 1)

		copied.Conditions[0].Message = "modified"
		assert.Equal(t, "ok", original.Conditions[0].Message)
		copied.AppliedGateways[0].Name = "modified"
		assert.Equal(t, "gateway-1", original.AppliedGateways[0].Name)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilStatus *MCPRouteStatus
		assert.Nil(t, nilStatus.DeepCopy())
	})

	t.Run("empty", func(t *testing.T) {
		original := &MCPRouteStatus{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Conditions)
		assert.Nil(t, copied.AppliedGateways)
	})
}

func TestMCPRouteStatus_DeepCopyInto(t *testing.T) {
	now := metav1.Now()
	original := &MCPRouteStatus{
		Conditions: []Condition{
			{Type: ConditionReady, Status: metav1.ConditionTrue, LastTransitionTime: now},
		},
		ObservedGeneration: 2,
		AppliedGateways: []AppliedGateway{
			{Name: "gateway-1", LastApplied: now},
		},
	}
	copied := &MCPRouteStatus{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.ObservedGeneration, copied.ObservedGeneration)
	copied.Conditions[0].Message = "modified"
	assert.Equal(t, "", original.Conditions[0].Message)
}

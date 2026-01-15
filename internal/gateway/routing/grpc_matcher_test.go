package routing

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// NewGRPCRouteMatcher Tests
// =============================================================================

func TestNewGRPCRouteMatcher(t *testing.T) {
	matcher := NewGRPCRouteMatcher()
	assert.NotNil(t, matcher)
	assert.NotNil(t, matcher.routes)
	assert.Empty(t, matcher.routes)
}

// =============================================================================
// GRPCRouteMatcher Match Tests
// =============================================================================

func TestGRPCRouteMatcher_Match(t *testing.T) {
	t.Run("match exact service and method", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "test-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-1", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "test-route", result.RouteName)
		assert.Len(t, result.BackendRefs, 1)
		assert.Equal(t, "backend-1", result.BackendRefs[0].Name)
	})

	t.Run("match with regex service and method", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "regex-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc\\.health\\..*",
						Method:    ".*",
						MatchType: "RegularExpression",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-regex", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "regex-route", result.RouteName)
	})

	t.Run("match with headers", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "header-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						Headers: []GRPCHeaderMatchConfig{
							{Name: "x-api-key", Value: "secret123", MatchType: "Exact"},
						},
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-header", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		// Should match with correct header
		headers := map[string]string{"x-api-key": "secret123"}
		result, found := matcher.Match("grpc.health.v1.Health", "Check", headers)
		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "header-route", result.RouteName)

		// Should not match with wrong header value
		headers = map[string]string{"x-api-key": "wrong"}
		result, found = matcher.Match("grpc.health.v1.Health", "Check", headers)
		assert.False(t, found)
		assert.Nil(t, result)

		// Should not match without header
		result, found = matcher.Match("grpc.health.v1.Health", "Check", nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with regex headers", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "regex-header-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						Headers: []GRPCHeaderMatchConfig{
							{Name: "authorization", Value: "^Bearer .+$", MatchType: "RegularExpression"},
						},
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-regex-header", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		// Should match with Bearer token
		headers := map[string]string{"authorization": "Bearer abc123token"}
		result, found := matcher.Match("grpc.health.v1.Health", "Check", headers)
		assert.True(t, found)
		assert.NotNil(t, result)

		// Should not match with Basic auth
		headers = map[string]string{"authorization": "Basic abc123"}
		result, found = matcher.Match("grpc.health.v1.Health", "Check", headers)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("no match returns nil", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "test-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("other.Service", "OtherMethod", nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("no match on empty matcher", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()

		result, found := matcher.Match("any.Service", "AnyMethod", nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with multiple rules - first rule matches", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "multi-rule-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-1", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Watch",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-2", Namespace: "default", Port: 8081, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.Equal(t, "backend-1", result.BackendRefs[0].Name)
	})

	t.Run("match with multiple rules - second rule matches", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "multi-rule-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-1", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Watch",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-2", Namespace: "default", Port: 8081, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("grpc.health.v1.Health", "Watch", nil)
		assert.True(t, found)
		assert.Equal(t, "backend-2", result.BackendRefs[0].Name)
	})

	t.Run("match with multiple routes", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:     "route-1",
				Priority: 100,
				Rules: []GRPCRuleConfig{
					{
						Service:   "service.v1.ServiceA",
						Method:    "MethodA",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-a", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
			{
				Name:     "route-2",
				Priority: 200,
				Rules: []GRPCRuleConfig{
					{
						Service:   "service.v1.ServiceB",
						Method:    "MethodB",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-b", Namespace: "default", Port: 8081, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("service.v1.ServiceB", "MethodB", nil)
		assert.True(t, found)
		assert.Equal(t, "route-2", result.RouteName)
	})

	t.Run("match with nil service matcher", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "wildcard-service-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-wildcard", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("any.Service", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with nil method matcher", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "wildcard-method-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-wildcard", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("grpc.health.v1.Health", "AnyMethod", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with multiple header matchers", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "multi-header-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						Headers: []GRPCHeaderMatchConfig{
							{Name: "x-api-key", Value: "secret123", MatchType: "Exact"},
							{Name: "x-tenant-id", Value: "tenant-1", MatchType: "Exact"},
						},
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-multi-header", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		// Should match with both headers
		headers := map[string]string{
			"x-api-key":   "secret123",
			"x-tenant-id": "tenant-1",
		}
		result, found := matcher.Match("grpc.health.v1.Health", "Check", headers)
		assert.True(t, found)
		assert.NotNil(t, result)

		// Should not match with only one header
		headers = map[string]string{"x-api-key": "secret123"}
		result, found = matcher.Match("grpc.health.v1.Health", "Check", headers)
		assert.False(t, found)
		assert.Nil(t, result)
	})
}

// =============================================================================
// GRPCRouteMatcher MatchWithHost Tests
// =============================================================================

func TestGRPCRouteMatcher_MatchWithHost(t *testing.T) {
	t.Run("match with exact hostname", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:      "host-route",
				Hostnames: []string{"api.example.com"},
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-host", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.MatchWithHost("api.example.com", "grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "host-route", result.RouteName)
	})

	t.Run("match with wildcard hostname", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:      "wildcard-host-route",
				Hostnames: []string{"*.example.com"},
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-wildcard-host", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.MatchWithHost("api.example.com", "grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)

		result, found = matcher.MatchWithHost("web.example.com", "grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("no match with wrong hostname", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:      "host-route",
				Hostnames: []string{"api.example.com"},
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-host", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.MatchWithHost("other.example.com", "grpc.health.v1.Health", "Check", nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with no hostnames specified", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:      "no-host-route",
				Hostnames: []string{},
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-no-host", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.MatchWithHost("any.hostname.com", "grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with wildcard * hostname", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:      "all-hosts-route",
				Hostnames: []string{"*"},
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-all-hosts", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.MatchWithHost("any.hostname.com", "grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with empty hostname in config", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:      "empty-host-route",
				Hostnames: []string{""},
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-empty-host", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.MatchWithHost("any.hostname.com", "grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with multiple hostnames", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:      "multi-host-route",
				Hostnames: []string{"api.example.com", "web.example.com"},
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-multi-host", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.MatchWithHost("api.example.com", "grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)

		result, found = matcher.MatchWithHost("web.example.com", "grpc.health.v1.Health", "Check", nil)
		assert.True(t, found)
		assert.NotNil(t, result)

		result, found = matcher.MatchWithHost("other.example.com", "grpc.health.v1.Health", "Check", nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with headers and hostname", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:      "host-header-route",
				Hostnames: []string{"api.example.com"},
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						Headers: []GRPCHeaderMatchConfig{
							{Name: "x-api-key", Value: "secret123", MatchType: "Exact"},
						},
						BackendRefs: []GRPCBackendRef{
							{Name: "backend-host-header", Namespace: "default", Port: 8080, Weight: 100},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		headers := map[string]string{"x-api-key": "secret123"}
		result, found := matcher.MatchWithHost("api.example.com", "grpc.health.v1.Health", "Check", headers)
		assert.True(t, found)
		assert.NotNil(t, result)

		// Wrong hostname
		result, found = matcher.MatchWithHost("other.example.com", "grpc.health.v1.Health", "Check", headers)
		assert.False(t, found)
		assert.Nil(t, result)

		// Wrong header
		headers = map[string]string{"x-api-key": "wrong"}
		result, found = matcher.MatchWithHost("api.example.com", "grpc.health.v1.Health", "Check", headers)
		assert.False(t, found)
		assert.Nil(t, result)
	})
}

// =============================================================================
// GRPCRouteMatcher Compile Tests
// =============================================================================

func TestGRPCRouteMatcher_Compile(t *testing.T) {
	t.Run("compile empty routes", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		err := matcher.Compile([]*GRPCRouteConfig{})
		assert.NoError(t, err)
		assert.Empty(t, matcher.routes)
	})

	t.Run("compile single route", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "test-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
					},
				},
			},
		}
		err := matcher.Compile(routes)
		assert.NoError(t, err)
		assert.Len(t, matcher.routes, 1)
		assert.Equal(t, "test-route", matcher.routes[0].Name)
	})

	t.Run("compile multiple routes", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:     "route-1",
				Priority: 100,
				Rules: []GRPCRuleConfig{
					{Service: "service.v1.A", Method: "MethodA", MatchType: "Exact"},
				},
			},
			{
				Name:     "route-2",
				Priority: 200,
				Rules: []GRPCRuleConfig{
					{Service: "service.v1.B", Method: "MethodB", MatchType: "Exact"},
				},
			},
		}
		err := matcher.Compile(routes)
		assert.NoError(t, err)
		assert.Len(t, matcher.routes, 2)
	})

	t.Run("compile with invalid regex service", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "invalid-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "[invalid",
						Method:    "Check",
						MatchType: "RegularExpression",
					},
				},
			},
		}
		err := matcher.Compile(routes)
		assert.Error(t, err)
	})

	t.Run("compile with invalid regex method", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "invalid-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "[invalid",
						MatchType: "RegularExpression",
					},
				},
			},
		}
		err := matcher.Compile(routes)
		assert.Error(t, err)
	})

	t.Run("compile with invalid regex header", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "invalid-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						Headers: []GRPCHeaderMatchConfig{
							{Name: "x-api-key", Value: "[invalid", MatchType: "RegularExpression"},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		assert.Error(t, err)
	})

	t.Run("compile replaces existing routes", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()

		// First compile
		routes1 := []*GRPCRouteConfig{
			{Name: "route-1", Rules: []GRPCRuleConfig{{Service: "service.A", Method: "MethodA", MatchType: "Exact"}}},
		}
		err := matcher.Compile(routes1)
		require.NoError(t, err)
		assert.Len(t, matcher.routes, 1)

		// Second compile replaces
		routes2 := []*GRPCRouteConfig{
			{Name: "route-2", Rules: []GRPCRuleConfig{{Service: "service.B", Method: "MethodB", MatchType: "Exact"}}},
			{Name: "route-3", Rules: []GRPCRuleConfig{{Service: "service.C", Method: "MethodC", MatchType: "Exact"}}},
		}
		err = matcher.Compile(routes2)
		require.NoError(t, err)
		assert.Len(t, matcher.routes, 2)
		assert.Equal(t, "route-2", matcher.routes[0].Name)
		assert.Equal(t, "route-3", matcher.routes[1].Name)
	})

	t.Run("compile with priority", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:     "route-1",
				Priority: 100,
				Rules: []GRPCRuleConfig{
					{Service: "service.A", Method: "MethodA", MatchType: "Exact", Priority: 50},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)
		assert.Equal(t, 100, matcher.routes[0].Priority)
		assert.Equal(t, 50, matcher.routes[0].Rules[0].Priority)
	})

	t.Run("compile with default priority", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "route-1",
				Rules: []GRPCRuleConfig{
					{Service: "service.A", Method: "MethodA", MatchType: "Exact"},
					{Service: "service.B", Method: "MethodB", MatchType: "Exact"},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)
		// Default priority should be set to index
		assert.Equal(t, 0, matcher.routes[0].Rules[0].Priority)
		assert.Equal(t, 1, matcher.routes[0].Rules[1].Priority)
	})
}

// =============================================================================
// GRPCRouteMatcher Concurrency Tests
// =============================================================================

func TestGRPCRouteMatcher_Concurrency(t *testing.T) {
	t.Run("concurrent reads", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "test-route",
				Rules: []GRPCRuleConfig{
					{Service: "grpc.health.v1.Health", Method: "Check", MatchType: "Exact"},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = matcher.Match("grpc.health.v1.Health", "Check", nil)
				_, _ = matcher.MatchWithHost("api.example.com", "grpc.health.v1.Health", "Check", nil)
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent compile and read", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()

		var wg sync.WaitGroup

		// Readers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					_, _ = matcher.Match("grpc.health.v1.Health", "Check", nil)
				}
			}()
		}

		// Writers
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				routes := []*GRPCRouteConfig{
					{
						Name: "route-" + string(rune('a'+idx)),
						Rules: []GRPCRuleConfig{
							{Service: "grpc.health.v1.Health", Method: "Check", MatchType: "Exact"},
						},
					},
				}
				_ = matcher.Compile(routes)
			}(i)
		}

		wg.Wait()
	})
}

// =============================================================================
// GRPCExactServiceMatcher Tests
// =============================================================================

func TestGRPCExactServiceMatcher(t *testing.T) {
	t.Run("exact match", func(t *testing.T) {
		matcher := NewGRPCExactServiceMatcher("grpc.health.v1.Health")
		assert.True(t, matcher.Match("grpc.health.v1.Health"))
		assert.False(t, matcher.Match("grpc.health.v2.Health"))
		assert.False(t, matcher.Match("other.Service"))
	})

	t.Run("wildcard match - empty string", func(t *testing.T) {
		matcher := NewGRPCExactServiceMatcher("")
		assert.True(t, matcher.Match("any.Service"))
		assert.True(t, matcher.Match(""))
	})

	t.Run("wildcard match - asterisk", func(t *testing.T) {
		matcher := NewGRPCExactServiceMatcher("*")
		assert.True(t, matcher.Match("any.Service"))
		assert.True(t, matcher.Match(""))
	})

	t.Run("case sensitive", func(t *testing.T) {
		matcher := NewGRPCExactServiceMatcher("grpc.health.v1.Health")
		assert.False(t, matcher.Match("GRPC.HEALTH.V1.HEALTH"))
		assert.False(t, matcher.Match("Grpc.Health.V1.Health"))
	})
}

// =============================================================================
// GRPCRegexServiceMatcher Tests
// =============================================================================

func TestGRPCRegexServiceMatcher(t *testing.T) {
	t.Run("valid regex match", func(t *testing.T) {
		matcher, err := NewGRPCRegexServiceMatcher("grpc\\.health\\..*")
		require.NoError(t, err)
		assert.True(t, matcher.Match("grpc.health.v1.Health"))
		assert.True(t, matcher.Match("grpc.health.v2.Health"))
		assert.False(t, matcher.Match("other.Service"))
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		matcher, err := NewGRPCRegexServiceMatcher("[invalid")
		assert.Error(t, err)
		assert.Nil(t, matcher)
	})

	t.Run("empty pattern matches all", func(t *testing.T) {
		matcher, err := NewGRPCRegexServiceMatcher("")
		require.NoError(t, err)
		assert.True(t, matcher.Match("any.Service"))
		assert.True(t, matcher.Match(""))
	})

	t.Run("asterisk pattern matches all", func(t *testing.T) {
		matcher, err := NewGRPCRegexServiceMatcher("*")
		require.NoError(t, err)
		assert.True(t, matcher.Match("any.Service"))
		assert.True(t, matcher.Match(""))
	})

	t.Run("complex regex pattern", func(t *testing.T) {
		matcher, err := NewGRPCRegexServiceMatcher("^(grpc|proto)\\..*\\.v[0-9]+\\..*$")
		require.NoError(t, err)
		assert.True(t, matcher.Match("grpc.health.v1.Health"))
		assert.True(t, matcher.Match("proto.api.v2.Service"))
		assert.False(t, matcher.Match("other.service"))
	})
}

// =============================================================================
// GRPCExactMethodMatcher Tests
// =============================================================================

func TestGRPCExactMethodMatcher(t *testing.T) {
	t.Run("exact match", func(t *testing.T) {
		matcher := NewGRPCExactMethodMatcher("Check")
		assert.True(t, matcher.Match("Check"))
		assert.False(t, matcher.Match("Watch"))
		assert.False(t, matcher.Match("check"))
	})

	t.Run("wildcard match - empty string", func(t *testing.T) {
		matcher := NewGRPCExactMethodMatcher("")
		assert.True(t, matcher.Match("AnyMethod"))
		assert.True(t, matcher.Match(""))
	})

	t.Run("wildcard match - asterisk", func(t *testing.T) {
		matcher := NewGRPCExactMethodMatcher("*")
		assert.True(t, matcher.Match("AnyMethod"))
		assert.True(t, matcher.Match(""))
	})

	t.Run("case sensitive", func(t *testing.T) {
		matcher := NewGRPCExactMethodMatcher("Check")
		assert.False(t, matcher.Match("CHECK"))
		assert.False(t, matcher.Match("check"))
	})
}

// =============================================================================
// GRPCRegexMethodMatcher Tests
// =============================================================================

func TestGRPCRegexMethodMatcher(t *testing.T) {
	t.Run("valid regex match", func(t *testing.T) {
		matcher, err := NewGRPCRegexMethodMatcher("^(Check|Watch)$")
		require.NoError(t, err)
		assert.True(t, matcher.Match("Check"))
		assert.True(t, matcher.Match("Watch"))
		assert.False(t, matcher.Match("Other"))
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		matcher, err := NewGRPCRegexMethodMatcher("[invalid")
		assert.Error(t, err)
		assert.Nil(t, matcher)
	})

	t.Run("empty pattern matches all", func(t *testing.T) {
		matcher, err := NewGRPCRegexMethodMatcher("")
		require.NoError(t, err)
		assert.True(t, matcher.Match("AnyMethod"))
		assert.True(t, matcher.Match(""))
	})

	t.Run("asterisk pattern matches all", func(t *testing.T) {
		matcher, err := NewGRPCRegexMethodMatcher("*")
		require.NoError(t, err)
		assert.True(t, matcher.Match("AnyMethod"))
		assert.True(t, matcher.Match(""))
	})

	t.Run("partial match", func(t *testing.T) {
		matcher, err := NewGRPCRegexMethodMatcher("Get.*")
		require.NoError(t, err)
		assert.True(t, matcher.Match("GetUser"))
		assert.True(t, matcher.Match("GetUsers"))
		assert.False(t, matcher.Match("ListUsers"))
	})
}

// =============================================================================
// GRPCExactHeaderMatcher Tests
// =============================================================================

func TestGRPCExactHeaderMatcher(t *testing.T) {
	t.Run("exact match", func(t *testing.T) {
		matcher := NewGRPCExactHeaderMatcher("x-api-key", "secret123")
		assert.Equal(t, "x-api-key", matcher.Name())
		assert.True(t, matcher.Match("secret123"))
		assert.False(t, matcher.Match("wrong"))
		assert.False(t, matcher.Match(""))
	})

	t.Run("header name is lowercased", func(t *testing.T) {
		matcher := NewGRPCExactHeaderMatcher("X-API-KEY", "secret123")
		assert.Equal(t, "x-api-key", matcher.Name())
	})

	t.Run("case sensitive value", func(t *testing.T) {
		matcher := NewGRPCExactHeaderMatcher("x-api-key", "Secret123")
		assert.False(t, matcher.Match("secret123"))
		assert.True(t, matcher.Match("Secret123"))
	})

	t.Run("empty value", func(t *testing.T) {
		matcher := NewGRPCExactHeaderMatcher("x-api-key", "")
		assert.True(t, matcher.Match(""))
		assert.False(t, matcher.Match("any"))
	})
}

// =============================================================================
// GRPCRegexHeaderMatcher Tests
// =============================================================================

func TestGRPCRegexHeaderMatcher(t *testing.T) {
	t.Run("valid regex match", func(t *testing.T) {
		matcher, err := NewGRPCRegexHeaderMatcher("authorization", "^Bearer .+$")
		require.NoError(t, err)
		assert.Equal(t, "authorization", matcher.Name())
		assert.True(t, matcher.Match("Bearer abc123"))
		assert.False(t, matcher.Match("Basic abc123"))
		assert.False(t, matcher.Match("Bearer "))
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		matcher, err := NewGRPCRegexHeaderMatcher("x-api-key", "[invalid")
		assert.Error(t, err)
		assert.Nil(t, matcher)
	})

	t.Run("header name is lowercased", func(t *testing.T) {
		matcher, err := NewGRPCRegexHeaderMatcher("X-API-KEY", ".*")
		require.NoError(t, err)
		assert.Equal(t, "x-api-key", matcher.Name())
	})

	t.Run("partial match", func(t *testing.T) {
		matcher, err := NewGRPCRegexHeaderMatcher("content-type", "json")
		require.NoError(t, err)
		assert.True(t, matcher.Match("application/json"))
		assert.True(t, matcher.Match("text/json"))
		assert.False(t, matcher.Match("text/xml"))
	})
}

// =============================================================================
// hostnameToRegex Tests
// =============================================================================

func TestHostnameToRegex(t *testing.T) {
	tests := []struct {
		name      string
		hostname  string
		testHost  string
		wantMatch bool
		wantNil   bool
	}{
		{
			name:      "exact hostname",
			hostname:  "api.example.com",
			testHost:  "api.example.com",
			wantMatch: true,
			wantNil:   false,
		},
		{
			name:      "exact hostname non-match",
			hostname:  "api.example.com",
			testHost:  "web.example.com",
			wantMatch: false,
			wantNil:   false,
		},
		{
			name:      "wildcard subdomain",
			hostname:  "*.example.com",
			testHost:  "api.example.com",
			wantMatch: true,
			wantNil:   false,
		},
		{
			name:      "wildcard subdomain different subdomain",
			hostname:  "*.example.com",
			testHost:  "web.example.com",
			wantMatch: true,
			wantNil:   false,
		},
		{
			name:      "wildcard subdomain non-match nested",
			hostname:  "*.example.com",
			testHost:  "api.v1.example.com",
			wantMatch: false,
			wantNil:   false,
		},
		{
			name:      "empty hostname returns nil",
			hostname:  "",
			testHost:  "any.host.com",
			wantMatch: false,
			wantNil:   true,
		},
		{
			name:      "asterisk only returns nil",
			hostname:  "*",
			testHost:  "any.host.com",
			wantMatch: false,
			wantNil:   true,
		},
		{
			name:      "hostname with special chars",
			hostname:  "api-v1.example.com",
			testHost:  "api-v1.example.com",
			wantMatch: true,
			wantNil:   false,
		},
		{
			name:      "hostname with dots escaped",
			hostname:  "api.v1.example.com",
			testHost:  "api.v1.example.com",
			wantMatch: true,
			wantNil:   false,
		},
		{
			name:      "hostname with dots escaped non-match",
			hostname:  "api.v1.example.com",
			testHost:  "apixv1xexample.com",
			wantMatch: false,
			wantNil:   false,
		},
		{
			name:      "wildcard in middle",
			hostname:  "api.*.example.com",
			testHost:  "api.v1.example.com",
			wantMatch: true,
			wantNil:   false,
		},
		{
			name:      "multiple wildcards",
			hostname:  "*.*.example.com",
			testHost:  "api.v1.example.com",
			wantMatch: true,
			wantNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex := hostnameToRegex(tt.hostname)
			if tt.wantNil {
				assert.Nil(t, regex)
			} else {
				assert.NotNil(t, regex)
				assert.Equal(t, tt.wantMatch, regex.MatchString(tt.testHost))
			}
		})
	}
}

// =============================================================================
// CompiledGRPCRoute and CompiledGRPCRule Tests
// =============================================================================

func TestCompiledGRPCRoute_Fields(t *testing.T) {
	route := &CompiledGRPCRoute{
		Name:        "test-route",
		HostRegexes: nil,
		Rules:       []*CompiledGRPCRule{},
		Priority:    100,
	}

	assert.Equal(t, "test-route", route.Name)
	assert.Nil(t, route.HostRegexes)
	assert.Empty(t, route.Rules)
	assert.Equal(t, 100, route.Priority)
}

func TestCompiledGRPCRule_Fields(t *testing.T) {
	rule := &CompiledGRPCRule{
		ServiceMatcher: NewGRPCExactServiceMatcher("grpc.health.v1.Health"),
		MethodMatcher:  NewGRPCExactMethodMatcher("Check"),
		HeaderMatchers: []GRPCHeaderMatcher{},
		Priority:       50,
		BackendRefs: []GRPCBackendRef{
			{Name: "backend-1", Namespace: "default", Port: 8080, Weight: 100},
		},
	}

	assert.NotNil(t, rule.ServiceMatcher)
	assert.NotNil(t, rule.MethodMatcher)
	assert.Empty(t, rule.HeaderMatchers)
	assert.Equal(t, 50, rule.Priority)
	assert.Len(t, rule.BackendRefs, 1)
}

func TestGRPCMatchResult_Fields(t *testing.T) {
	rule := &CompiledGRPCRule{
		BackendRefs: []GRPCBackendRef{
			{Name: "backend-1", Namespace: "default", Port: 8080, Weight: 100},
		},
	}
	result := &GRPCMatchResult{
		RouteName:   "test-route",
		Rule:        rule,
		BackendRefs: rule.BackendRefs,
	}

	assert.Equal(t, "test-route", result.RouteName)
	assert.Equal(t, rule, result.Rule)
	assert.Equal(t, rule.BackendRefs, result.BackendRefs)
}

func TestGRPCBackendRef_Fields(t *testing.T) {
	ref := GRPCBackendRef{
		Name:      "backend-1",
		Namespace: "default",
		Port:      8080,
		Weight:    100,
	}

	assert.Equal(t, "backend-1", ref.Name)
	assert.Equal(t, "default", ref.Namespace)
	assert.Equal(t, 8080, ref.Port)
	assert.Equal(t, 100, ref.Weight)
}

// =============================================================================
// GRPCRouteConfig and GRPCRuleConfig Tests
// =============================================================================

func TestGRPCRouteConfig_Fields(t *testing.T) {
	config := &GRPCRouteConfig{
		Name:      "test-route",
		Hostnames: []string{"api.example.com"},
		Rules: []GRPCRuleConfig{
			{Service: "grpc.health.v1.Health", Method: "Check", MatchType: "Exact"},
		},
		Priority: 100,
	}

	assert.Equal(t, "test-route", config.Name)
	assert.Equal(t, []string{"api.example.com"}, config.Hostnames)
	assert.Len(t, config.Rules, 1)
	assert.Equal(t, 100, config.Priority)
}

func TestGRPCRuleConfig_Fields(t *testing.T) {
	config := GRPCRuleConfig{
		Service:   "grpc.health.v1.Health",
		Method:    "Check",
		MatchType: "Exact",
		Headers: []GRPCHeaderMatchConfig{
			{Name: "x-api-key", Value: "secret123", MatchType: "Exact"},
		},
		BackendRefs: []GRPCBackendRef{
			{Name: "backend-1", Namespace: "default", Port: 8080, Weight: 100},
		},
		Priority: 50,
	}

	assert.Equal(t, "grpc.health.v1.Health", config.Service)
	assert.Equal(t, "Check", config.Method)
	assert.Equal(t, "Exact", config.MatchType)
	assert.Len(t, config.Headers, 1)
	assert.Len(t, config.BackendRefs, 1)
	assert.Equal(t, 50, config.Priority)
}

func TestGRPCHeaderMatchConfig_Fields(t *testing.T) {
	config := GRPCHeaderMatchConfig{
		Name:      "x-api-key",
		Value:     "secret123",
		MatchType: "Exact",
	}

	assert.Equal(t, "x-api-key", config.Name)
	assert.Equal(t, "secret123", config.Value)
	assert.Equal(t, "Exact", config.MatchType)
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestGRPCServiceMatcherInterface(t *testing.T) {
	var _ GRPCServiceMatcher = (*GRPCExactServiceMatcher)(nil)
	var _ GRPCServiceMatcher = (*GRPCRegexServiceMatcher)(nil)
}

func TestGRPCMethodMatcherInterface(t *testing.T) {
	var _ GRPCMethodMatcher = (*GRPCExactMethodMatcher)(nil)
	var _ GRPCMethodMatcher = (*GRPCRegexMethodMatcher)(nil)
}

func TestGRPCHeaderMatcherInterface(t *testing.T) {
	var _ GRPCHeaderMatcher = (*GRPCExactHeaderMatcher)(nil)
	var _ GRPCHeaderMatcher = (*GRPCRegexHeaderMatcher)(nil)
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestGRPCRouteMatcher_EdgeCases(t *testing.T) {
	t.Run("route with empty rules", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:  "empty-rules",
				Rules: []GRPCRuleConfig{},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("any.Service", "AnyMethod", nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("route with nil rules", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name:  "nil-rules",
				Rules: nil,
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("any.Service", "AnyMethod", nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with empty headers map", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "test-route",
				Rules: []GRPCRuleConfig{
					{Service: "grpc.health.v1.Health", Method: "Check", MatchType: "Exact"},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("grpc.health.v1.Health", "Check", map[string]string{})
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with empty service and method", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "wildcard-route",
				Rules: []GRPCRuleConfig{
					{Service: "", Method: "", MatchType: "Exact"},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		result, found := matcher.Match("", "", nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("header matching is case insensitive for name", func(t *testing.T) {
		matcher := NewGRPCRouteMatcher()
		routes := []*GRPCRouteConfig{
			{
				Name: "header-route",
				Rules: []GRPCRuleConfig{
					{
						Service:   "grpc.health.v1.Health",
						Method:    "Check",
						MatchType: "Exact",
						Headers: []GRPCHeaderMatchConfig{
							{Name: "X-API-KEY", Value: "secret123", MatchType: "Exact"},
						},
					},
				},
			},
		}
		err := matcher.Compile(routes)
		require.NoError(t, err)

		// Header name should be lowercased during matching
		headers := map[string]string{"x-api-key": "secret123"}
		result, found := matcher.Match("grpc.health.v1.Health", "Check", headers)
		assert.True(t, found)
		assert.NotNil(t, result)
	})
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkGRPCRouteMatcher_Match(b *testing.B) {
	matcher := NewGRPCRouteMatcher()
	routes := make([]*GRPCRouteConfig, 100)
	for i := 0; i < 100; i++ {
		routes[i] = &GRPCRouteConfig{
			Name:     "route-" + string(rune('a'+i%26)),
			Priority: i,
			Rules: []GRPCRuleConfig{
				{
					Service:   "service.v" + string(rune('0'+i%10)) + ".Service",
					Method:    "Method" + string(rune('A'+i%26)),
					MatchType: "Exact",
				},
			},
		}
	}
	_ = matcher.Compile(routes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("service.v5.Service", "MethodE", nil)
	}
}

func BenchmarkGRPCRouteMatcher_MatchWithHeaders(b *testing.B) {
	matcher := NewGRPCRouteMatcher()
	routes := []*GRPCRouteConfig{
		{
			Name: "header-route",
			Rules: []GRPCRuleConfig{
				{
					Service:   "grpc.health.v1.Health",
					Method:    "Check",
					MatchType: "Exact",
					Headers: []GRPCHeaderMatchConfig{
						{Name: "x-api-key", Value: "secret123", MatchType: "Exact"},
						{Name: "x-tenant-id", Value: "tenant-1", MatchType: "Exact"},
					},
				},
			},
		},
	}
	_ = matcher.Compile(routes)

	headers := map[string]string{
		"x-api-key":   "secret123",
		"x-tenant-id": "tenant-1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("grpc.health.v1.Health", "Check", headers)
	}
}

func BenchmarkGRPCRouteMatcher_MatchWithRegex(b *testing.B) {
	matcher := NewGRPCRouteMatcher()
	routes := []*GRPCRouteConfig{
		{
			Name: "regex-route",
			Rules: []GRPCRuleConfig{
				{
					Service:   "grpc\\.health\\.v[0-9]+\\.Health",
					Method:    ".*",
					MatchType: "RegularExpression",
				},
			},
		},
	}
	_ = matcher.Compile(routes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("grpc.health.v1.Health", "Check", nil)
	}
}

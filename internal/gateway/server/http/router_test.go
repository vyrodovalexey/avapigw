package http

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// =============================================================================
// NewRouter Tests
// =============================================================================

func TestNewRouter(t *testing.T) {
	logger := zap.NewNop()

	t.Run("creates empty router", func(t *testing.T) {
		router := NewRouter(logger)

		assert.NotNil(t, router)
		assert.NotNil(t, router.routes)
		assert.Empty(t, router.routes)
		assert.NotNil(t, router.matcher)
		assert.NotNil(t, router.logger)
	})

	t.Run("creates router with initialized matcher", func(t *testing.T) {
		router := NewRouter(logger)

		assert.NotNil(t, router.matcher)
		assert.Empty(t, router.matcher.compiledRoutes)
	})
}

// =============================================================================
// Router.AddRoute Tests
// =============================================================================

func TestRouter_AddRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("adds new route", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"example.com"},
			Priority:  100,
		}

		err := router.AddRoute(route)

		assert.NoError(t, err)
		assert.Len(t, router.routes, 1)
		assert.NotNil(t, router.routes["test-route"])
	})

	t.Run("returns error for duplicate route", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"example.com"},
		}

		err := router.AddRoute(route)
		require.NoError(t, err)

		// Try to add duplicate
		err = router.AddRoute(route)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("rebuilds matcher after adding route", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"example.com"},
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{
						{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}},
					},
				},
			},
		}

		err := router.AddRoute(route)

		assert.NoError(t, err)
		assert.Len(t, router.matcher.compiledRoutes, 1)
	})

	t.Run("adds multiple routes", func(t *testing.T) {
		router := NewRouter(logger)

		for i := 0; i < 5; i++ {
			route := &Route{
				Name:     "route-" + string(rune('a'+i)),
				Priority: i * 10,
			}
			err := router.AddRoute(route)
			require.NoError(t, err)
		}

		assert.Len(t, router.routes, 5)
		assert.Len(t, router.matcher.compiledRoutes, 5)
	})

	t.Run("adds route with all fields", func(t *testing.T) {
		router := NewRouter(logger)
		method := "GET"
		timeout := 30 * time.Second
		route := &Route{
			Name:      "full-route",
			Hostnames: []string{"example.com", "*.example.com"},
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{
						{
							Path:        &PathMatch{Type: PathMatchPrefix, Value: "/api"},
							Method:      &method,
							Headers:     []HeaderMatch{{Type: HeaderMatchExact, Name: "Content-Type", Value: "application/json"}},
							QueryParams: []QueryParamMatch{{Type: QueryParamMatchExact, Name: "version", Value: "v1"}},
						},
					},
					Filters: []RouteFilter{
						{Type: RouteFilterRequestHeaderModifier},
					},
					Timeouts: &RouteTimeouts{Request: &timeout},
				},
			},
			Backends: []BackendRef{
				{Name: "backend1", Namespace: "default", Port: 8080, Weight: 100},
			},
			Priority: 100,
		}

		err := router.AddRoute(route)

		assert.NoError(t, err)
		assert.NotNil(t, router.GetRoute("full-route"))
	})
}

// =============================================================================
// Router.RemoveRoute Tests
// =============================================================================

func TestRouter_RemoveRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("removes existing route", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{Name: "test-route"}
		err := router.AddRoute(route)
		require.NoError(t, err)

		err = router.RemoveRoute("test-route")

		assert.NoError(t, err)
		assert.Nil(t, router.GetRoute("test-route"))
		assert.Empty(t, router.routes)
	})

	t.Run("returns error for non-existent route", func(t *testing.T) {
		router := NewRouter(logger)

		err := router.RemoveRoute("non-existent")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("rebuilds matcher after removing route", func(t *testing.T) {
		router := NewRouter(logger)
		route1 := &Route{Name: "route1"}
		route2 := &Route{Name: "route2"}
		err := router.AddRoute(route1)
		require.NoError(t, err)
		err = router.AddRoute(route2)
		require.NoError(t, err)

		err = router.RemoveRoute("route1")

		assert.NoError(t, err)
		assert.Len(t, router.matcher.compiledRoutes, 1)
	})

	t.Run("removes middle route", func(t *testing.T) {
		router := NewRouter(logger)
		for i := 0; i < 3; i++ {
			route := &Route{Name: "route-" + string(rune('a'+i))}
			err := router.AddRoute(route)
			require.NoError(t, err)
		}

		err := router.RemoveRoute("route-b")

		assert.NoError(t, err)
		assert.Len(t, router.routes, 2)
		assert.NotNil(t, router.GetRoute("route-a"))
		assert.Nil(t, router.GetRoute("route-b"))
		assert.NotNil(t, router.GetRoute("route-c"))
	})
}

// =============================================================================
// Router.UpdateRoute Tests
// =============================================================================

func TestRouter_UpdateRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("updates existing route", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"example.com"},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		updatedRoute := &Route{
			Name:      "test-route",
			Hostnames: []string{"updated.example.com"},
		}
		err = router.UpdateRoute(updatedRoute)

		assert.NoError(t, err)
		storedRoute := router.GetRoute("test-route")
		assert.Contains(t, storedRoute.Hostnames, "updated.example.com")
	})

	t.Run("returns error for non-existent route", func(t *testing.T) {
		router := NewRouter(logger)

		route := &Route{Name: "non-existent"}
		err := router.UpdateRoute(route)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("rebuilds matcher after update", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:     "test-route",
			Priority: 100,
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		updatedRoute := &Route{
			Name:     "test-route",
			Priority: 200,
		}
		err = router.UpdateRoute(updatedRoute)

		assert.NoError(t, err)
		assert.Len(t, router.matcher.compiledRoutes, 1)
	})

	t.Run("updates route with new rules", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "test-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/old"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		updatedRoute := &Route{
			Name: "test-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/new"}}}},
			},
		}
		err = router.UpdateRoute(updatedRoute)

		assert.NoError(t, err)
		storedRoute := router.GetRoute("test-route")
		assert.Equal(t, "/new", storedRoute.Rules[0].Matches[0].Path.Value)
	})
}

// =============================================================================
// Router.GetRoute Tests
// =============================================================================

func TestRouter_GetRoute(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns route by name", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"example.com"},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		result := router.GetRoute("test-route")

		assert.NotNil(t, result)
		assert.Equal(t, "test-route", result.Name)
		assert.Contains(t, result.Hostnames, "example.com")
	})

	t.Run("returns nil for non-existent route", func(t *testing.T) {
		router := NewRouter(logger)

		result := router.GetRoute("non-existent")

		assert.Nil(t, result)
	})

	t.Run("returns nil for empty router", func(t *testing.T) {
		router := NewRouter(logger)

		result := router.GetRoute("any-route")

		assert.Nil(t, result)
	})
}

// =============================================================================
// Router.ListRoutes Tests
// =============================================================================

func TestRouter_ListRoutes(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns all route names", func(t *testing.T) {
		router := NewRouter(logger)
		for i := 0; i < 3; i++ {
			route := &Route{Name: "route-" + string(rune('a'+i))}
			err := router.AddRoute(route)
			require.NoError(t, err)
		}

		names := router.ListRoutes()

		assert.Len(t, names, 3)
		assert.Contains(t, names, "route-a")
		assert.Contains(t, names, "route-b")
		assert.Contains(t, names, "route-c")
	})

	t.Run("returns empty slice for empty router", func(t *testing.T) {
		router := NewRouter(logger)

		names := router.ListRoutes()

		assert.NotNil(t, names)
		assert.Empty(t, names)
	})

	t.Run("returns single name", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{Name: "only-route"}
		err := router.AddRoute(route)
		require.NoError(t, err)

		names := router.ListRoutes()

		assert.Len(t, names, 1)
		assert.Contains(t, names, "only-route")
	})
}

// =============================================================================
// Router.Match Tests
// =============================================================================

func TestRouter_Match(t *testing.T) {
	logger := zap.NewNop()

	t.Run("matches by hostname", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:      "host-route",
			Hostnames: []string{"api.example.com"},
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/test", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
		assert.Equal(t, "host-route", matchedRoute.Name)
	})

	t.Run("matches by path exact", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "exact-path-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchExact, Value: "/api/users"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
		assert.Equal(t, "exact-path-route", matchedRoute.Name)
	})

	t.Run("matches by path prefix", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "prefix-path-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/users/123", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
		assert.Equal(t, "prefix-path-route", matchedRoute.Name)
	})

	t.Run("matches by path regex", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "regex-path-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchRegularExpression, Value: "/api/v[0-9]+/users"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v2/users", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
		assert.Equal(t, "regex-path-route", matchedRoute.Name)
	})

	t.Run("matches by method", func(t *testing.T) {
		router := NewRouter(logger)
		method := "POST"
		route := &Route{
			Name: "method-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{
					Path:   &PathMatch{Type: PathMatchPrefix, Value: "/api"},
					Method: &method,
				}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		// Should match POST
		req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
		matchedRoute, _ := router.Match(req)
		assert.NotNil(t, matchedRoute)

		// Should not match GET
		req = httptest.NewRequest(http.MethodGet, "/api/test", nil)
		matchedRoute, _ = router.Match(req)
		assert.Nil(t, matchedRoute)
	})

	t.Run("matches by headers", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "header-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{
					Path:    &PathMatch{Type: PathMatchPrefix, Value: "/api"},
					Headers: []HeaderMatch{{Type: HeaderMatchExact, Name: "X-API-Key", Value: "secret"}},
				}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		// Should match with correct header
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("X-API-Key", "secret")
		matchedRoute, _ := router.Match(req)
		assert.NotNil(t, matchedRoute)

		// Should not match without header
		req = httptest.NewRequest(http.MethodGet, "/api/test", nil)
		matchedRoute, _ = router.Match(req)
		assert.Nil(t, matchedRoute)
	})

	t.Run("matches by query parameters", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "query-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{
					Path:        &PathMatch{Type: PathMatchPrefix, Value: "/api"},
					QueryParams: []QueryParamMatch{{Type: QueryParamMatchExact, Name: "version", Value: "v2"}},
				}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		// Should match with correct query param
		req := httptest.NewRequest(http.MethodGet, "/api/test?version=v2", nil)
		matchedRoute, _ := router.Match(req)
		assert.NotNil(t, matchedRoute)

		// Should not match without query param
		req = httptest.NewRequest(http.MethodGet, "/api/test", nil)
		matchedRoute, _ = router.Match(req)
		assert.Nil(t, matchedRoute)
	})

	t.Run("returns nil for no match", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "test-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchExact, Value: "/api"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/other", nil)
		matchedRoute, matchedRule := router.Match(req)

		assert.Nil(t, matchedRoute)
		assert.Nil(t, matchedRule)
	})

	t.Run("priority ordering", func(t *testing.T) {
		router := NewRouter(logger)

		// Add low priority route first
		lowPriorityRoute := &Route{
			Name:     "low-priority",
			Priority: 100,
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
		}
		err := router.AddRoute(lowPriorityRoute)
		require.NoError(t, err)

		// Add high priority route second
		highPriorityRoute := &Route{
			Name:     "high-priority",
			Priority: 200,
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
		}
		err = router.AddRoute(highPriorityRoute)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
		assert.Equal(t, "high-priority", matchedRoute.Name)
	})

	t.Run("strips port from host", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:      "host-route",
			Hostnames: []string{"api.example.com"},
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://api.example.com:8080/test", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
	})

	t.Run("returns matched rule", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "test-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		matchedRoute, matchedRule := router.Match(req)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
	})
}

// =============================================================================
// compileRoute Tests
// =============================================================================

func TestCompileRoute(t *testing.T) {
	t.Run("compiles hostnames to regex", func(t *testing.T) {
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"api.example.com", "*.example.com"},
		}

		compiled := compileRoute(route)

		assert.NotNil(t, compiled)
		assert.Equal(t, route, compiled.Route)
		assert.Len(t, compiled.HostRegexes, 2)
	})

	t.Run("compiles rules", func(t *testing.T) {
		route := &Route{
			Name: "test-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchExact, Value: "/health"}}}},
			},
		}

		compiled := compileRoute(route)

		assert.NotNil(t, compiled)
		assert.Len(t, compiled.Rules, 2)
	})

	t.Run("handles empty hostnames", func(t *testing.T) {
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{},
		}

		compiled := compileRoute(route)

		assert.NotNil(t, compiled)
		assert.Empty(t, compiled.HostRegexes)
	})

	t.Run("handles nil hostnames", func(t *testing.T) {
		route := &Route{
			Name:      "test-route",
			Hostnames: nil,
		}

		compiled := compileRoute(route)

		assert.NotNil(t, compiled)
		assert.Empty(t, compiled.HostRegexes)
	})

	t.Run("handles empty rules", func(t *testing.T) {
		route := &Route{
			Name:  "test-route",
			Rules: []RouteRule{},
		}

		compiled := compileRoute(route)

		assert.NotNil(t, compiled)
		assert.Empty(t, compiled.Rules)
	})

	t.Run("skips nil hostname regex", func(t *testing.T) {
		route := &Route{
			Name:      "test-route",
			Hostnames: []string{"*", "api.example.com"}, // * returns nil regex
		}

		compiled := compileRoute(route)

		assert.NotNil(t, compiled)
		assert.Len(t, compiled.HostRegexes, 1) // Only api.example.com compiled
	})
}

// =============================================================================
// compileRule Tests
// =============================================================================

func TestCompileRule(t *testing.T) {
	t.Run("compiles path matchers - exact", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Path: &PathMatch{Type: PathMatchExact, Value: "/api/users"}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Equal(t, "/api/users", compiled.PathExact)
		assert.Empty(t, compiled.PathPrefix)
		assert.Nil(t, compiled.PathRegex)
	})

	t.Run("compiles path matchers - prefix", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Equal(t, "/api", compiled.PathPrefix)
		assert.Empty(t, compiled.PathExact)
		assert.Nil(t, compiled.PathRegex)
	})

	t.Run("compiles path matchers - regex", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Path: &PathMatch{Type: PathMatchRegularExpression, Value: "/api/v[0-9]+"}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.NotNil(t, compiled.PathRegex)
		assert.True(t, compiled.PathRegex.MatchString("/api/v1"))
		assert.True(t, compiled.PathRegex.MatchString("/api/v99"))
	})

	t.Run("compiles method matcher", func(t *testing.T) {
		method := "POST"
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Method: &method},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.NotNil(t, compiled.MethodMatcher)
		assert.Equal(t, "POST", *compiled.MethodMatcher)
	})

	t.Run("compiles header matchers - exact", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Headers: []HeaderMatch{{Type: HeaderMatchExact, Name: "Content-Type", Value: "application/json"}}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Len(t, compiled.HeaderMatchers, 1)
		assert.Equal(t, "content-type", compiled.HeaderMatchers[0].Name) // Lowercased
		assert.Equal(t, "application/json", compiled.HeaderMatchers[0].Exact)
	})

	t.Run("compiles header matchers - regex", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Headers: []HeaderMatch{{Type: HeaderMatchRegularExpression, Name: "Authorization", Value: "^Bearer .+"}}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Len(t, compiled.HeaderMatchers, 1)
		assert.NotNil(t, compiled.HeaderMatchers[0].Regex)
		assert.True(t, compiled.HeaderMatchers[0].Regex.MatchString("Bearer token123"))
	})

	t.Run("compiles query matchers - exact", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{QueryParams: []QueryParamMatch{{Type: QueryParamMatchExact, Name: "version", Value: "v2"}}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Len(t, compiled.QueryMatchers, 1)
		assert.Equal(t, "version", compiled.QueryMatchers[0].Name)
		assert.Equal(t, "v2", compiled.QueryMatchers[0].Exact)
	})

	t.Run("compiles query matchers - regex", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{QueryParams: []QueryParamMatch{{Type: QueryParamMatchRegularExpression, Name: "page", Value: "^[0-9]+$"}}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Len(t, compiled.QueryMatchers, 1)
		assert.NotNil(t, compiled.QueryMatchers[0].Regex)
		assert.True(t, compiled.QueryMatchers[0].Regex.MatchString("123"))
	})

	t.Run("sets priority from index", func(t *testing.T) {
		rule := &RouteRule{}

		compiled := compileRule(rule, 5)

		assert.Equal(t, 5, compiled.Priority)
	})

	t.Run("handles invalid regex gracefully", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Path: &PathMatch{Type: PathMatchRegularExpression, Value: "[invalid"}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Nil(t, compiled.PathRegex) // Invalid regex should result in nil
	})

	t.Run("handles invalid header regex gracefully", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Headers: []HeaderMatch{{Type: HeaderMatchRegularExpression, Name: "X-Key", Value: "[invalid"}}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Len(t, compiled.HeaderMatchers, 1)
		assert.Nil(t, compiled.HeaderMatchers[0].Regex) // Invalid regex should result in nil
	})

	t.Run("handles invalid query regex gracefully", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{QueryParams: []QueryParamMatch{{Type: QueryParamMatchRegularExpression, Name: "param", Value: "[invalid"}}},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Len(t, compiled.QueryMatchers, 1)
		assert.Nil(t, compiled.QueryMatchers[0].Regex) // Invalid regex should result in nil
	})

	t.Run("handles nil path in match", func(t *testing.T) {
		rule := &RouteRule{
			Matches: []RouteMatch{
				{Path: nil},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Empty(t, compiled.PathExact)
		assert.Empty(t, compiled.PathPrefix)
		assert.Nil(t, compiled.PathRegex)
	})

	t.Run("handles multiple matches", func(t *testing.T) {
		method := "GET"
		rule := &RouteRule{
			Matches: []RouteMatch{
				{
					Path:        &PathMatch{Type: PathMatchPrefix, Value: "/api"},
					Method:      &method,
					Headers:     []HeaderMatch{{Type: HeaderMatchExact, Name: "X-Key", Value: "value"}},
					QueryParams: []QueryParamMatch{{Type: QueryParamMatchExact, Name: "q", Value: "test"}},
				},
			},
		}

		compiled := compileRule(rule, 0)

		assert.NotNil(t, compiled)
		assert.Equal(t, "/api", compiled.PathPrefix)
		assert.Equal(t, "GET", *compiled.MethodMatcher)
		assert.Len(t, compiled.HeaderMatchers, 1)
		assert.Len(t, compiled.QueryMatchers, 1)
	})
}

// =============================================================================
// hostnameToRegex Tests
// =============================================================================

func TestHostnameToRegex(t *testing.T) {
	t.Run("empty hostname returns nil", func(t *testing.T) {
		regex := hostnameToRegex("")

		assert.Nil(t, regex)
	})

	t.Run("wildcard returns nil", func(t *testing.T) {
		regex := hostnameToRegex("*")

		assert.Nil(t, regex)
	})

	t.Run("exact hostname", func(t *testing.T) {
		regex := hostnameToRegex("api.example.com")

		assert.NotNil(t, regex)
		assert.True(t, regex.MatchString("api.example.com"))
		assert.False(t, regex.MatchString("other.example.com"))
		assert.False(t, regex.MatchString("api.example.com.evil"))
	})

	t.Run("wildcard subdomain", func(t *testing.T) {
		regex := hostnameToRegex("*.example.com")

		assert.NotNil(t, regex)
		assert.True(t, regex.MatchString("api.example.com"))
		assert.True(t, regex.MatchString("web.example.com"))
		assert.True(t, regex.MatchString("anything.example.com"))
		assert.False(t, regex.MatchString("example.com"))
		assert.False(t, regex.MatchString("sub.api.example.com"))
	})

	t.Run("escapes special regex characters", func(t *testing.T) {
		regex := hostnameToRegex("api.example.com")

		assert.NotNil(t, regex)
		// The dot should be escaped, not match any character
		assert.False(t, regex.MatchString("apixexample.com"))
	})

	t.Run("anchors pattern", func(t *testing.T) {
		regex := hostnameToRegex("api.example.com")

		assert.NotNil(t, regex)
		assert.False(t, regex.MatchString("prefix.api.example.com"))
		assert.False(t, regex.MatchString("api.example.com.suffix"))
	})

	t.Run("handles multiple wildcards", func(t *testing.T) {
		regex := hostnameToRegex("*.*.example.com")

		assert.NotNil(t, regex)
		assert.True(t, regex.MatchString("api.v1.example.com"))
		assert.True(t, regex.MatchString("web.prod.example.com"))
		assert.False(t, regex.MatchString("example.com"))
	})

	t.Run("handles hostname with numbers", func(t *testing.T) {
		regex := hostnameToRegex("api123.example.com")

		assert.NotNil(t, regex)
		assert.True(t, regex.MatchString("api123.example.com"))
		assert.False(t, regex.MatchString("api124.example.com"))
	})

	t.Run("handles hostname with hyphens", func(t *testing.T) {
		regex := hostnameToRegex("my-api.example.com")

		assert.NotNil(t, regex)
		assert.True(t, regex.MatchString("my-api.example.com"))
		assert.False(t, regex.MatchString("myapi.example.com"))
	})
}

// =============================================================================
// RouteMatcher.Match Tests
// =============================================================================

func TestRouteMatcher_Match(t *testing.T) {
	t.Run("matches routes in priority order", func(t *testing.T) {
		matcher := &RouteMatcher{}

		lowPriorityRoute := &Route{
			Name:     "low-priority",
			Priority: 100,
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
		}
		highPriorityRoute := &Route{
			Name:     "high-priority",
			Priority: 200,
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
		}

		matcher.compiledRoutes = []*CompiledRoute{
			compileRoute(highPriorityRoute),
			compileRoute(lowPriorityRoute),
		}

		result, found := matcher.Match("", "/api/test", "GET", nil, nil)

		assert.True(t, found)
		assert.Equal(t, "high-priority", result.Route.Name)
	})

	t.Run("hostname matching", func(t *testing.T) {
		matcher := &RouteMatcher{}

		route := &Route{
			Name:      "host-route",
			Hostnames: []string{"api.example.com"},
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/"}}}},
			},
		}
		matcher.compiledRoutes = []*CompiledRoute{compileRoute(route)}

		// Should match
		result, found := matcher.Match("api.example.com", "/test", "GET", nil, nil)
		assert.True(t, found)
		assert.NotNil(t, result)

		// Should not match
		result, found = matcher.Match("other.example.com", "/test", "GET", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("rule matching", func(t *testing.T) {
		matcher := &RouteMatcher{}

		route := &Route{
			Name: "rule-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchExact, Value: "/api"}}}},
			},
		}
		matcher.compiledRoutes = []*CompiledRoute{compileRoute(route)}

		// Should match
		result, found := matcher.Match("", "/api", "GET", nil, nil)
		assert.True(t, found)
		assert.NotNil(t, result)

		// Should not match
		result, found = matcher.Match("", "/other", "GET", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("returns nil for empty matcher", func(t *testing.T) {
		matcher := &RouteMatcher{}

		result, found := matcher.Match("", "/api", "GET", nil, nil)

		assert.False(t, found)
		assert.Nil(t, result)
	})
}

// =============================================================================
// RouteMatcher.matchHostname Tests
// =============================================================================

func TestRouteMatcher_matchHostname(t *testing.T) {
	matcher := &RouteMatcher{}

	t.Run("no hostnames matches all", func(t *testing.T) {
		compiled := &CompiledRoute{
			Route:       &Route{Hostnames: nil},
			HostRegexes: nil,
		}

		result := matcher.matchHostname(compiled, "any.host.com")

		assert.True(t, result)
	})

	t.Run("empty hostnames matches all", func(t *testing.T) {
		compiled := &CompiledRoute{
			Route:       &Route{Hostnames: []string{}},
			HostRegexes: []*regexp.Regexp{},
		}

		result := matcher.matchHostname(compiled, "any.host.com")

		assert.True(t, result)
	})

	t.Run("wildcard matches all", func(t *testing.T) {
		compiled := &CompiledRoute{
			Route:       &Route{Hostnames: []string{"*"}},
			HostRegexes: nil,
		}

		result := matcher.matchHostname(compiled, "any.host.com")

		assert.True(t, result)
	})

	t.Run("regex matching", func(t *testing.T) {
		hostRegex := regexp.MustCompile("^api\\.example\\.com$")
		compiled := &CompiledRoute{
			Route:       &Route{Hostnames: []string{"api.example.com"}},
			HostRegexes: []*regexp.Regexp{hostRegex},
		}

		// Should match
		result := matcher.matchHostname(compiled, "api.example.com")
		assert.True(t, result)

		// Should not match
		result = matcher.matchHostname(compiled, "other.example.com")
		assert.False(t, result)
	})

	t.Run("multiple regex patterns", func(t *testing.T) {
		hostRegex1 := regexp.MustCompile("^api\\.example\\.com$")
		hostRegex2 := regexp.MustCompile("^web\\.example\\.com$")
		compiled := &CompiledRoute{
			Route:       &Route{Hostnames: []string{"api.example.com", "web.example.com"}},
			HostRegexes: []*regexp.Regexp{hostRegex1, hostRegex2},
		}

		// Should match first
		result := matcher.matchHostname(compiled, "api.example.com")
		assert.True(t, result)

		// Should match second
		result = matcher.matchHostname(compiled, "web.example.com")
		assert.True(t, result)

		// Should not match
		result = matcher.matchHostname(compiled, "other.example.com")
		assert.False(t, result)
	})
}

// =============================================================================
// RouteMatcher.matchRule Tests
// =============================================================================

func TestRouteMatcher_matchRule(t *testing.T) {
	matcher := &RouteMatcher{}

	t.Run("no matches defined matches all", func(t *testing.T) {
		rule := &CompiledRule{
			Rule: &RouteRule{Matches: nil},
		}

		result := matcher.matchRule(rule, "/any", "GET", nil, nil)

		assert.True(t, result)
	})

	t.Run("empty matches matches all", func(t *testing.T) {
		rule := &CompiledRule{
			Rule: &RouteRule{Matches: []RouteMatch{}},
		}

		result := matcher.matchRule(rule, "/any", "GET", nil, nil)

		assert.True(t, result)
	})

	t.Run("path matching", func(t *testing.T) {
		rule := &CompiledRule{
			Rule:       &RouteRule{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			PathPrefix: "/api",
		}

		// Should match
		result := matcher.matchRule(rule, "/api/test", "GET", nil, nil)
		assert.True(t, result)

		// Should not match
		result = matcher.matchRule(rule, "/other", "GET", nil, nil)
		assert.False(t, result)
	})

	t.Run("method matching", func(t *testing.T) {
		method := "POST"
		rule := &CompiledRule{
			Rule:          &RouteRule{Matches: []RouteMatch{{Method: &method}}},
			MethodMatcher: &method,
		}

		// Should match
		result := matcher.matchRule(rule, "/api", "POST", nil, nil)
		assert.True(t, result)

		// Should not match
		result = matcher.matchRule(rule, "/api", "GET", nil, nil)
		assert.False(t, result)
	})

	t.Run("header matching", func(t *testing.T) {
		rule := &CompiledRule{
			Rule: &RouteRule{Matches: []RouteMatch{{
				Headers: []HeaderMatch{{Type: HeaderMatchExact, Name: "x-key", Value: "value"}},
			}}},
			HeaderMatchers: []*CompiledHeaderMatcher{
				{Name: "x-key", Exact: "value"},
			},
		}

		// Should match
		headers := map[string]string{"x-key": "value"}
		result := matcher.matchRule(rule, "/api", "GET", headers, nil)
		assert.True(t, result)

		// Should not match - missing header
		result = matcher.matchRule(rule, "/api", "GET", nil, nil)
		assert.False(t, result)

		// Should not match - wrong value
		headers = map[string]string{"x-key": "wrong"}
		result = matcher.matchRule(rule, "/api", "GET", headers, nil)
		assert.False(t, result)
	})

	t.Run("header matching with regex", func(t *testing.T) {
		regex := regexp.MustCompile("^Bearer .+$")
		rule := &CompiledRule{
			Rule: &RouteRule{Matches: []RouteMatch{{
				Headers: []HeaderMatch{{Type: HeaderMatchRegularExpression, Name: "authorization", Value: "^Bearer .+$"}},
			}}},
			HeaderMatchers: []*CompiledHeaderMatcher{
				{Name: "authorization", Regex: regex},
			},
		}

		// Should match
		headers := map[string]string{"authorization": "Bearer token123"}
		result := matcher.matchRule(rule, "/api", "GET", headers, nil)
		assert.True(t, result)

		// Should not match
		headers = map[string]string{"authorization": "Basic abc"}
		result = matcher.matchRule(rule, "/api", "GET", headers, nil)
		assert.False(t, result)
	})

	t.Run("query matching", func(t *testing.T) {
		rule := &CompiledRule{
			Rule: &RouteRule{Matches: []RouteMatch{{
				QueryParams: []QueryParamMatch{{Type: QueryParamMatchExact, Name: "version", Value: "v2"}},
			}}},
			QueryMatchers: []*CompiledQueryMatcher{
				{Name: "version", Exact: "v2"},
			},
		}

		// Should match
		query := map[string]string{"version": "v2"}
		result := matcher.matchRule(rule, "/api", "GET", nil, query)
		assert.True(t, result)

		// Should not match - missing query
		result = matcher.matchRule(rule, "/api", "GET", nil, nil)
		assert.False(t, result)

		// Should not match - wrong value
		query = map[string]string{"version": "v1"}
		result = matcher.matchRule(rule, "/api", "GET", nil, query)
		assert.False(t, result)
	})

	t.Run("query matching with regex", func(t *testing.T) {
		regex := regexp.MustCompile("^[0-9]+$")
		rule := &CompiledRule{
			Rule: &RouteRule{Matches: []RouteMatch{{
				QueryParams: []QueryParamMatch{{Type: QueryParamMatchRegularExpression, Name: "page", Value: "^[0-9]+$"}},
			}}},
			QueryMatchers: []*CompiledQueryMatcher{
				{Name: "page", Regex: regex},
			},
		}

		// Should match
		query := map[string]string{"page": "123"}
		result := matcher.matchRule(rule, "/api", "GET", nil, query)
		assert.True(t, result)

		// Should not match
		query = map[string]string{"page": "abc"}
		result = matcher.matchRule(rule, "/api", "GET", nil, query)
		assert.False(t, result)
	})
}

// =============================================================================
// RouteMatcher.matchPath Tests
// =============================================================================

func TestRouteMatcher_matchPath(t *testing.T) {
	matcher := &RouteMatcher{}

	t.Run("exact match", func(t *testing.T) {
		rule := &CompiledRule{PathExact: "/api/users"}

		// Should match
		result := matcher.matchPath(rule, "/api/users")
		assert.True(t, result)

		// Should not match
		result = matcher.matchPath(rule, "/api/users/123")
		assert.False(t, result)

		result = matcher.matchPath(rule, "/api")
		assert.False(t, result)
	})

	t.Run("prefix match", func(t *testing.T) {
		rule := &CompiledRule{PathPrefix: "/api"}

		// Should match
		result := matcher.matchPath(rule, "/api")
		assert.True(t, result)

		result = matcher.matchPath(rule, "/api/users")
		assert.True(t, result)

		result = matcher.matchPath(rule, "/api/users/123")
		assert.True(t, result)

		// Should not match
		result = matcher.matchPath(rule, "/other")
		assert.False(t, result)
	})

	t.Run("regex match", func(t *testing.T) {
		regex := regexp.MustCompile("/api/v[0-9]+/users")
		rule := &CompiledRule{PathRegex: regex}

		// Should match
		result := matcher.matchPath(rule, "/api/v1/users")
		assert.True(t, result)

		result = matcher.matchPath(rule, "/api/v99/users")
		assert.True(t, result)

		// Should not match
		result = matcher.matchPath(rule, "/api/vX/users")
		assert.False(t, result)
	})

	t.Run("no criteria matches all", func(t *testing.T) {
		rule := &CompiledRule{}

		result := matcher.matchPath(rule, "/any/path")
		assert.True(t, result)

		result = matcher.matchPath(rule, "")
		assert.True(t, result)
	})
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestRouter_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()

	t.Run("concurrent reads", func(t *testing.T) {
		router := NewRouter(logger)
		for i := 0; i < 10; i++ {
			route := &Route{
				Name: "route-" + string(rune('a'+i)),
				Rules: []RouteRule{
					{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
				},
			}
			err := router.AddRoute(route)
			require.NoError(t, err)
		}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
				_, _ = router.Match(req)
				_ = router.ListRoutes()
				_ = router.GetRoute("route-a")
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent writes", func(t *testing.T) {
		router := NewRouter(logger)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &Route{
					Name:     "route-" + string(rune('a'+idx%26)) + string(rune('0'+idx/26)),
					Priority: idx,
				}
				_ = router.AddRoute(route)
			}(i)
		}
		wg.Wait()
	})

	t.Run("concurrent read and write", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "initial-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		var wg sync.WaitGroup

		// Readers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
					_, _ = router.Match(req)
				}
			}()
		}

		// Writers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &Route{
					Name:     "route-" + string(rune('a'+idx%26)),
					Priority: idx,
				}
				_ = router.AddRoute(route)
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent add and remove", func(t *testing.T) {
		router := NewRouter(logger)

		var wg sync.WaitGroup

		// Add routes
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &Route{
					Name:     "route-" + string(rune('a'+idx%26)),
					Priority: idx,
				}
				_ = router.AddRoute(route)
			}(i)
		}

		// Remove routes
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_ = router.RemoveRoute("route-" + string(rune('a'+idx%26)))
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent update", func(t *testing.T) {
		router := NewRouter(logger)
		for i := 0; i < 10; i++ {
			route := &Route{
				Name:     "route-" + string(rune('a'+i)),
				Priority: i * 10,
			}
			err := router.AddRoute(route)
			require.NoError(t, err)
		}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &Route{
					Name:     "route-" + string(rune('a'+idx%10)),
					Priority: idx * 100,
				}
				_ = router.UpdateRoute(route)
			}(i)
		}
		wg.Wait()
	})
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestRouter_EdgeCases(t *testing.T) {
	logger := zap.NewNop()

	t.Run("route with empty rules", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:  "empty-rules",
			Rules: []RouteRule{},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		matchedRoute, _ := router.Match(req)

		assert.Nil(t, matchedRoute)
	})

	t.Run("route with nil rules", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name:  "nil-rules",
			Rules: nil,
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		matchedRoute, _ := router.Match(req)

		assert.Nil(t, matchedRoute)
	})

	t.Run("match with empty path", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "empty-path-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchExact, Value: "/"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
	})

	t.Run("match with special characters in path", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "special-path-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api/v1"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users?name=test&id=123", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
	})

	t.Run("match with unicode in path", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "unicode-path-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/users/\u4e2d\u6587", nil)
		matchedRoute, _ := router.Match(req)

		assert.NotNil(t, matchedRoute)
	})

	t.Run("route with multiple backends", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "multi-backend-route",
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			},
			Backends: []BackendRef{
				{Name: "backend1", Namespace: "default", Port: 8080, Weight: 50},
				{Name: "backend2", Namespace: "default", Port: 8081, Weight: 50},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		storedRoute := router.GetRoute("multi-backend-route")
		assert.Len(t, storedRoute.Backends, 2)
	})

	t.Run("route with timeouts", func(t *testing.T) {
		router := NewRouter(logger)
		timeout := 30 * time.Second
		route := &Route{
			Name: "timeout-route",
			Rules: []RouteRule{
				{
					Matches:  []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}},
					Timeouts: &RouteTimeouts{Request: &timeout},
				},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		storedRoute := router.GetRoute("timeout-route")
		assert.NotNil(t, storedRoute.Rules[0].Timeouts)
	})

	t.Run("route with filters", func(t *testing.T) {
		router := NewRouter(logger)
		route := &Route{
			Name: "filter-route",
			Rules: []RouteRule{
				{
					Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}},
					Filters: []RouteFilter{
						{
							Type: RouteFilterRequestHeaderModifier,
							RequestHeaderModifier: &HeaderModifier{
								Set:    []HTTPHeader{{Name: "X-Custom", Value: "value"}},
								Add:    []HTTPHeader{{Name: "X-Added", Value: "added"}},
								Remove: []string{"X-Remove"},
							},
						},
					},
				},
			},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)

		storedRoute := router.GetRoute("filter-route")
		assert.Len(t, storedRoute.Rules[0].Filters, 1)
	})
}

// =============================================================================
// Type Tests
// =============================================================================

func TestPathMatchType(t *testing.T) {
	assert.Equal(t, PathMatchType("Exact"), PathMatchExact)
	assert.Equal(t, PathMatchType("PathPrefix"), PathMatchPrefix)
	assert.Equal(t, PathMatchType("RegularExpression"), PathMatchRegularExpression)
}

func TestHeaderMatchType(t *testing.T) {
	assert.Equal(t, HeaderMatchType("Exact"), HeaderMatchExact)
	assert.Equal(t, HeaderMatchType("RegularExpression"), HeaderMatchRegularExpression)
}

func TestQueryParamMatchType(t *testing.T) {
	assert.Equal(t, QueryParamMatchType("Exact"), QueryParamMatchExact)
	assert.Equal(t, QueryParamMatchType("RegularExpression"), QueryParamMatchRegularExpression)
}

func TestRouteFilterType(t *testing.T) {
	assert.Equal(t, RouteFilterType("RequestHeaderModifier"), RouteFilterRequestHeaderModifier)
	assert.Equal(t, RouteFilterType("ResponseHeaderModifier"), RouteFilterResponseHeaderModifier)
	assert.Equal(t, RouteFilterType("URLRewrite"), RouteFilterURLRewrite)
	assert.Equal(t, RouteFilterType("RequestRedirect"), RouteFilterRequestRedirect)
}

func TestPathModifierType(t *testing.T) {
	assert.Equal(t, PathModifierType("ReplaceFullPath"), PathModifierReplaceFullPath)
	assert.Equal(t, PathModifierType("ReplacePrefixMatch"), PathModifierReplacePrefixMatch)
}

// =============================================================================
// Struct Tests
// =============================================================================

func TestRoute_Fields(t *testing.T) {
	route := &Route{
		Name:      "test-route",
		Hostnames: []string{"example.com"},
		Rules: []RouteRule{
			{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
		},
		Backends: []BackendRef{
			{Name: "backend", Namespace: "default", Port: 8080, Weight: 100},
		},
		Priority: 100,
	}

	assert.Equal(t, "test-route", route.Name)
	assert.Len(t, route.Hostnames, 1)
	assert.Len(t, route.Rules, 1)
	assert.Len(t, route.Backends, 1)
	assert.Equal(t, 100, route.Priority)
}

func TestRouteRule_Fields(t *testing.T) {
	timeout := 30 * time.Second
	rule := RouteRule{
		Matches: []RouteMatch{
			{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}},
		},
		Filters: []RouteFilter{
			{Type: RouteFilterRequestHeaderModifier},
		},
		BackendRefs: []BackendRef{
			{Name: "backend", Port: 8080},
		},
		Timeouts: &RouteTimeouts{Request: &timeout},
	}

	assert.Len(t, rule.Matches, 1)
	assert.Len(t, rule.Filters, 1)
	assert.Len(t, rule.BackendRefs, 1)
	assert.NotNil(t, rule.Timeouts)
}

func TestRouteMatch_Fields(t *testing.T) {
	method := "GET"
	match := RouteMatch{
		Path:        &PathMatch{Type: PathMatchPrefix, Value: "/api"},
		Headers:     []HeaderMatch{{Type: HeaderMatchExact, Name: "X-Key", Value: "value"}},
		QueryParams: []QueryParamMatch{{Type: QueryParamMatchExact, Name: "version", Value: "v1"}},
		Method:      &method,
	}

	assert.NotNil(t, match.Path)
	assert.Len(t, match.Headers, 1)
	assert.Len(t, match.QueryParams, 1)
	assert.NotNil(t, match.Method)
}

func TestBackendRef_Fields(t *testing.T) {
	backend := BackendRef{
		Name:      "backend",
		Namespace: "default",
		Port:      8080,
		Weight:    100,
	}

	assert.Equal(t, "backend", backend.Name)
	assert.Equal(t, "default", backend.Namespace)
	assert.Equal(t, 8080, backend.Port)
	assert.Equal(t, 100, backend.Weight)
}

func TestRouteTimeouts_Fields(t *testing.T) {
	request := 30 * time.Second
	backend := 25 * time.Second
	idle := 60 * time.Second

	timeouts := RouteTimeouts{
		Request:        &request,
		BackendRequest: &backend,
		Idle:           &idle,
	}

	assert.Equal(t, 30*time.Second, *timeouts.Request)
	assert.Equal(t, 25*time.Second, *timeouts.BackendRequest)
	assert.Equal(t, 60*time.Second, *timeouts.Idle)
}

func TestHeaderModifier_Fields(t *testing.T) {
	modifier := HeaderModifier{
		Set:    []HTTPHeader{{Name: "X-Set", Value: "set-value"}},
		Add:    []HTTPHeader{{Name: "X-Add", Value: "add-value"}},
		Remove: []string{"X-Remove"},
	}

	assert.Len(t, modifier.Set, 1)
	assert.Len(t, modifier.Add, 1)
	assert.Len(t, modifier.Remove, 1)
}

func TestURLRewrite_Fields(t *testing.T) {
	hostname := "new.example.com"
	fullPath := "/new/path"
	rewrite := URLRewrite{
		Hostname: &hostname,
		Path: &PathModifier{
			Type:            PathModifierReplaceFullPath,
			ReplaceFullPath: &fullPath,
		},
	}

	assert.Equal(t, "new.example.com", *rewrite.Hostname)
	assert.NotNil(t, rewrite.Path)
	assert.Equal(t, "/new/path", *rewrite.Path.ReplaceFullPath)
}

func TestRequestRedirect_Fields(t *testing.T) {
	scheme := "https"
	hostname := "redirect.example.com"
	port := 443
	redirect := RequestRedirect{
		Scheme:     &scheme,
		Hostname:   &hostname,
		Port:       &port,
		StatusCode: 301,
	}

	assert.Equal(t, "https", *redirect.Scheme)
	assert.Equal(t, "redirect.example.com", *redirect.Hostname)
	assert.Equal(t, 443, *redirect.Port)
	assert.Equal(t, 301, redirect.StatusCode)
}

func TestCompiledRoute_Fields(t *testing.T) {
	hostRegex := regexp.MustCompile("^api\\.example\\.com$")
	compiled := &CompiledRoute{
		Route:       &Route{Name: "test-route"},
		HostRegexes: []*regexp.Regexp{hostRegex},
		Rules:       []*CompiledRule{{PathPrefix: "/api"}},
	}

	assert.NotNil(t, compiled.Route)
	assert.Len(t, compiled.HostRegexes, 1)
	assert.Len(t, compiled.Rules, 1)
}

func TestCompiledRule_Fields(t *testing.T) {
	method := "GET"
	pathRegex := regexp.MustCompile("/api/v[0-9]+")
	compiled := &CompiledRule{
		Rule:          &RouteRule{},
		PathRegex:     pathRegex,
		PathPrefix:    "/api",
		PathExact:     "/api/exact",
		MethodMatcher: &method,
		HeaderMatchers: []*CompiledHeaderMatcher{
			{Name: "x-key", Exact: "value"},
		},
		QueryMatchers: []*CompiledQueryMatcher{
			{Name: "version", Exact: "v1"},
		},
		Priority: 100,
	}

	assert.NotNil(t, compiled.Rule)
	assert.NotNil(t, compiled.PathRegex)
	assert.Equal(t, "/api", compiled.PathPrefix)
	assert.Equal(t, "/api/exact", compiled.PathExact)
	assert.Equal(t, "GET", *compiled.MethodMatcher)
	assert.Len(t, compiled.HeaderMatchers, 1)
	assert.Len(t, compiled.QueryMatchers, 1)
	assert.Equal(t, 100, compiled.Priority)
}

func TestMatchResult_Fields(t *testing.T) {
	result := &MatchResult{
		Route: &Route{Name: "test-route"},
		Rule:  &RouteRule{},
	}

	assert.NotNil(t, result.Route)
	assert.NotNil(t, result.Rule)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkRouter_Match(b *testing.B) {
	logger := zap.NewNop()
	router := NewRouter(logger)

	// Add 100 routes
	for i := 0; i < 100; i++ {
		route := &Route{
			Name:     "route-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Priority: i,
			Rules: []RouteRule{
				{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api/v" + string(rune('0'+i%10))}}}},
			},
		}
		_ = router.AddRoute(route)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v5/users", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.Match(req)
	}
}

func BenchmarkRouter_AddRoute(b *testing.B) {
	logger := zap.NewNop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router := NewRouter(logger)
		for j := 0; j < 100; j++ {
			route := &Route{
				Name:     "route-" + string(rune('a'+j%26)),
				Priority: j,
			}
			_ = router.AddRoute(route)
		}
	}
}

func BenchmarkHostnameToRegex(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostnameToRegex("*.example.com")
	}
}

func BenchmarkCompileRoute(b *testing.B) {
	route := &Route{
		Name:      "test-route",
		Hostnames: []string{"api.example.com", "*.example.com"},
		Rules: []RouteRule{
			{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchPrefix, Value: "/api"}}}},
			{Matches: []RouteMatch{{Path: &PathMatch{Type: PathMatchRegularExpression, Value: "/api/v[0-9]+"}}}},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compileRoute(route)
	}
}

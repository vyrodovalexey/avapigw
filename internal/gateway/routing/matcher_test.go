package routing

import (
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// NewRouteMatcher Tests
// =============================================================================

func TestNewRouteMatcher(t *testing.T) {
	matcher := NewRouteMatcher()
	assert.NotNil(t, matcher)
	assert.NotNil(t, matcher.routes)
	assert.Empty(t, matcher.routes)
	assert.Equal(t, 0, matcher.Count())
}

// =============================================================================
// AddRoute Tests
// =============================================================================

func TestRouteMatcher_AddRoute(t *testing.T) {
	t.Run("add single route", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name:     "test-route",
			Priority: 100,
		}

		matcher.AddRoute(route)

		assert.Equal(t, 1, matcher.Count())
		names := matcher.GetRouteNames()
		assert.Contains(t, names, "test-route")
	})

	t.Run("add multiple routes", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route1 := &CompiledRoute{Name: "route-1", Priority: 100}
		route2 := &CompiledRoute{Name: "route-2", Priority: 200}
		route3 := &CompiledRoute{Name: "route-3", Priority: 150}

		matcher.AddRoute(route1)
		matcher.AddRoute(route2)
		matcher.AddRoute(route3)

		assert.Equal(t, 3, matcher.Count())
		names := matcher.GetRouteNames()
		assert.Contains(t, names, "route-1")
		assert.Contains(t, names, "route-2")
		assert.Contains(t, names, "route-3")
	})

	t.Run("routes sorted by priority descending", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route1 := &CompiledRoute{Name: "low-priority", Priority: 100}
		route2 := &CompiledRoute{Name: "high-priority", Priority: 300}
		route3 := &CompiledRoute{Name: "medium-priority", Priority: 200}

		matcher.AddRoute(route1)
		matcher.AddRoute(route2)
		matcher.AddRoute(route3)

		names := matcher.GetRouteNames()
		// Routes should be sorted by priority (highest first)
		assert.Equal(t, "high-priority", names[0])
		assert.Equal(t, "medium-priority", names[1])
		assert.Equal(t, "low-priority", names[2])
	})

	t.Run("add route with same priority", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route1 := &CompiledRoute{Name: "route-1", Priority: 100}
		route2 := &CompiledRoute{Name: "route-2", Priority: 100}

		matcher.AddRoute(route1)
		matcher.AddRoute(route2)

		assert.Equal(t, 2, matcher.Count())
	})

	t.Run("add route with nil rules", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name:     "no-rules",
			Priority: 100,
			Rules:    nil,
		}

		matcher.AddRoute(route)
		assert.Equal(t, 1, matcher.Count())
	})
}

// =============================================================================
// RemoveRoute Tests
// =============================================================================

func TestRouteMatcher_RemoveRoute(t *testing.T) {
	t.Run("remove existing route", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{Name: "test-route", Priority: 100}
		matcher.AddRoute(route)

		removed := matcher.RemoveRoute("test-route")

		assert.True(t, removed)
		assert.Equal(t, 0, matcher.Count())
	})

	t.Run("remove non-existent route", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{Name: "test-route", Priority: 100}
		matcher.AddRoute(route)

		removed := matcher.RemoveRoute("non-existent")

		assert.False(t, removed)
		assert.Equal(t, 1, matcher.Count())
	})

	t.Run("remove from empty matcher", func(t *testing.T) {
		matcher := NewRouteMatcher()

		removed := matcher.RemoveRoute("any-route")

		assert.False(t, removed)
		assert.Equal(t, 0, matcher.Count())
	})

	t.Run("remove middle route", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-1", Priority: 100})
		matcher.AddRoute(&CompiledRoute{Name: "route-2", Priority: 200})
		matcher.AddRoute(&CompiledRoute{Name: "route-3", Priority: 300})

		removed := matcher.RemoveRoute("route-2")

		assert.True(t, removed)
		assert.Equal(t, 2, matcher.Count())
		names := matcher.GetRouteNames()
		assert.NotContains(t, names, "route-2")
		assert.Contains(t, names, "route-1")
		assert.Contains(t, names, "route-3")
	})

	t.Run("remove first route", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-1", Priority: 300})
		matcher.AddRoute(&CompiledRoute{Name: "route-2", Priority: 200})

		removed := matcher.RemoveRoute("route-1")

		assert.True(t, removed)
		assert.Equal(t, 1, matcher.Count())
		names := matcher.GetRouteNames()
		assert.Equal(t, []string{"route-2"}, names)
	})

	t.Run("remove last route", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-1", Priority: 300})
		matcher.AddRoute(&CompiledRoute{Name: "route-2", Priority: 200})

		removed := matcher.RemoveRoute("route-2")

		assert.True(t, removed)
		assert.Equal(t, 1, matcher.Count())
		names := matcher.GetRouteNames()
		assert.Equal(t, []string{"route-1"}, names)
	})
}

// =============================================================================
// UpdateRoute Tests
// =============================================================================

func TestRouteMatcher_UpdateRoute(t *testing.T) {
	t.Run("update existing route", func(t *testing.T) {
		matcher := NewRouteMatcher()
		originalRoute := &CompiledRoute{
			Name:     "test-route",
			Priority: 100,
			Metadata: map[string]interface{}{"version": "v1"},
		}
		matcher.AddRoute(originalRoute)

		updatedRoute := &CompiledRoute{
			Name:     "test-route",
			Priority: 200,
			Metadata: map[string]interface{}{"version": "v2"},
		}
		updated := matcher.UpdateRoute(updatedRoute)

		assert.True(t, updated)
		assert.Equal(t, 1, matcher.Count())
	})

	t.Run("update non-existent route", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "existing-route", Priority: 100})

		newRoute := &CompiledRoute{Name: "non-existent", Priority: 200}
		updated := matcher.UpdateRoute(newRoute)

		assert.False(t, updated)
		assert.Equal(t, 1, matcher.Count())
	})

	t.Run("update empty matcher", func(t *testing.T) {
		matcher := NewRouteMatcher()

		route := &CompiledRoute{Name: "test-route", Priority: 100}
		updated := matcher.UpdateRoute(route)

		assert.False(t, updated)
		assert.Equal(t, 0, matcher.Count())
	})

	t.Run("update route re-sorts by priority", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-1", Priority: 100})
		matcher.AddRoute(&CompiledRoute{Name: "route-2", Priority: 200})
		matcher.AddRoute(&CompiledRoute{Name: "route-3", Priority: 300})

		// Update route-1 to have highest priority
		updatedRoute := &CompiledRoute{Name: "route-1", Priority: 400}
		updated := matcher.UpdateRoute(updatedRoute)

		assert.True(t, updated)
		names := matcher.GetRouteNames()
		assert.Equal(t, "route-1", names[0])
	})
}

// =============================================================================
// Match Tests
// =============================================================================

func TestRouteMatcher_Match(t *testing.T) {
	t.Run("match by hostname - exact", func(t *testing.T) {
		matcher := NewRouteMatcher()
		hostRegex := regexp.MustCompile("^api\\.example\\.com$")
		route := &CompiledRoute{
			Name:        "api-route",
			HostRegexes: []*regexp.Regexp{hostRegex},
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("api.example.com", "/api", "GET", nil, nil)

		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "api-route", result.Route.Name)
	})

	t.Run("match by hostname - wildcard in hostnames", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name:      "wildcard-route",
			Hostnames: []string{"*"},
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("any.hostname.com", "/api", "GET", nil, nil)

		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "wildcard-route", result.Route.Name)
	})

	t.Run("match by hostname - empty hostname matches all", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name:      "empty-hostname-route",
			Hostnames: []string{""},
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("any.hostname.com", "/api", "GET", nil, nil)

		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match by hostname - no hostnames matches all", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "no-hostname-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("any.hostname.com", "/api", "GET", nil, nil)

		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match by path - exact", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "exact-path-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api/v1/users")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api/v1/users", "GET", nil, nil)

		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "exact-path-route", result.Route.Name)
	})

	t.Run("match by path - prefix", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "prefix-path-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewPrefixPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api/v1/users", "GET", nil, nil)

		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match by path - regex with captures", func(t *testing.T) {
		matcher := NewRouteMatcher()
		regexMatcher, _ := NewRegexPathMatcher("/api/v(?P<version>[0-9]+)/users/(?P<id>[0-9]+)")
		route := &CompiledRoute{
			Name: "regex-path-route",
			Rules: []*CompiledRule{
				{PathMatcher: regexMatcher},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api/v2/users/123", "GET", nil, nil)

		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "2", result.Captures["version"])
		assert.Equal(t, "123", result.Captures["id"])
	})

	t.Run("match by method", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "method-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:   NewExactPathMatcher("/api"),
					MethodMatcher: NewSimpleMethodMatcher("POST"),
				},
			},
		}
		matcher.AddRoute(route)

		// Should match POST
		result, found := matcher.Match("", "/api", "POST", nil, nil)
		assert.True(t, found)
		assert.NotNil(t, result)

		// Should not match GET
		result, found = matcher.Match("", "/api", "GET", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match by method - multi method", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "multi-method-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:   NewExactPathMatcher("/api"),
					MethodMatcher: NewMultiMethodMatcher([]string{"GET", "POST"}),
				},
			},
		}
		matcher.AddRoute(route)

		// Should match GET
		result, found := matcher.Match("", "/api", "GET", nil, nil)
		assert.True(t, found)

		// Should match POST
		result, found = matcher.Match("", "/api", "POST", nil, nil)
		assert.True(t, found)

		// Should not match DELETE
		result, found = matcher.Match("", "/api", "DELETE", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match by headers - exact", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "header-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:    NewExactPathMatcher("/api"),
					HeaderMatchers: []HeaderMatcher{NewExactHeaderMatcher("content-type", "application/json")},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with correct header
		headers := map[string]string{"content-type": "application/json"}
		result, found := matcher.Match("", "/api", "GET", headers, nil)
		assert.True(t, found)
		assert.NotNil(t, result)

		// Should not match with wrong header value
		headers = map[string]string{"content-type": "text/html"}
		result, found = matcher.Match("", "/api", "GET", headers, nil)
		assert.False(t, found)

		// Should not match without header
		result, found = matcher.Match("", "/api", "GET", nil, nil)
		assert.False(t, found)
	})

	t.Run("match by headers - regex", func(t *testing.T) {
		matcher := NewRouteMatcher()
		regexHeader, _ := NewRegexHeaderMatcher("authorization", "^Bearer .+$")
		route := &CompiledRoute{
			Name: "regex-header-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:    NewExactPathMatcher("/api"),
					HeaderMatchers: []HeaderMatcher{regexHeader},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with Bearer token
		headers := map[string]string{"authorization": "Bearer abc123"}
		result, found := matcher.Match("", "/api", "GET", headers, nil)
		assert.True(t, found)

		// Should not match with Basic auth
		headers = map[string]string{"authorization": "Basic abc123"}
		result, found = matcher.Match("", "/api", "GET", headers, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match by headers - present", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "present-header-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:    NewExactPathMatcher("/api"),
					HeaderMatchers: []HeaderMatcher{NewPresentHeaderMatcher("x-request-id")},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with header present
		headers := map[string]string{"x-request-id": "any-value"}
		result, found := matcher.Match("", "/api", "GET", headers, nil)
		assert.True(t, found)

		// Should not match without header
		result, found = matcher.Match("", "/api", "GET", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match by query parameters - exact", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "query-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:   NewExactPathMatcher("/api"),
					QueryMatchers: []QueryMatcher{NewExactQueryMatcher("version", "v2")},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with correct query param
		query := map[string]string{"version": "v2"}
		result, found := matcher.Match("", "/api", "GET", nil, query)
		assert.True(t, found)

		// Should not match with wrong value
		query = map[string]string{"version": "v1"}
		result, found = matcher.Match("", "/api", "GET", nil, query)
		assert.False(t, found)

		// Should not match without query param
		result, found = matcher.Match("", "/api", "GET", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match by query parameters - regex", func(t *testing.T) {
		matcher := NewRouteMatcher()
		regexQuery, _ := NewRegexQueryMatcher("page", "^[0-9]+$")
		route := &CompiledRoute{
			Name: "regex-query-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:   NewExactPathMatcher("/api"),
					QueryMatchers: []QueryMatcher{regexQuery},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with numeric page
		query := map[string]string{"page": "123"}
		result, found := matcher.Match("", "/api", "GET", nil, query)
		assert.True(t, found)

		// Should not match with non-numeric page
		query = map[string]string{"page": "abc"}
		result, found = matcher.Match("", "/api", "GET", nil, query)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match by query parameters - present", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "present-query-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:   NewExactPathMatcher("/api"),
					QueryMatchers: []QueryMatcher{NewPresentQueryMatcher("debug")},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with query param present
		query := map[string]string{"debug": "true"}
		result, found := matcher.Match("", "/api", "GET", nil, query)
		assert.True(t, found)

		// Should match with empty value
		query = map[string]string{"debug": ""}
		result, found = matcher.Match("", "/api", "GET", nil, query)
		assert.True(t, found)

		// Should not match without query param
		result, found = matcher.Match("", "/api", "GET", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match priority order", func(t *testing.T) {
		matcher := NewRouteMatcher()

		// Add low priority route first
		lowPriorityRoute := &CompiledRoute{
			Name:     "low-priority",
			Priority: 100,
			Rules: []*CompiledRule{
				{PathMatcher: NewPrefixPathMatcher("/api")},
			},
		}
		matcher.AddRoute(lowPriorityRoute)

		// Add high priority route second
		highPriorityRoute := &CompiledRoute{
			Name:     "high-priority",
			Priority: 200,
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api/v1")},
			},
		}
		matcher.AddRoute(highPriorityRoute)

		// Should match high priority route first
		result, found := matcher.Match("", "/api/v1", "GET", nil, nil)
		assert.True(t, found)
		assert.Equal(t, "high-priority", result.Route.Name)
	})

	t.Run("no match returns nil", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "test-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/other", "GET", nil, nil)

		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("no match on empty matcher", func(t *testing.T) {
		matcher := NewRouteMatcher()

		result, found := matcher.Match("", "/api", "GET", nil, nil)

		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with multiple rules - first rule matches", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "multi-rule-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api/v1")},
				{PathMatcher: NewExactPathMatcher("/api/v2")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api/v1", "GET", nil, nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with multiple rules - second rule matches", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "multi-rule-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api/v1")},
				{PathMatcher: NewExactPathMatcher("/api/v2")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api/v2", "GET", nil, nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with nil path matcher", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "nil-path-route",
			Rules: []*CompiledRule{
				{PathMatcher: nil, MethodMatcher: NewSimpleMethodMatcher("GET")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/any/path", "GET", nil, nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with nil method matcher", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "nil-method-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api"), MethodMatcher: nil},
			},
		}
		matcher.AddRoute(route)

		// Should match any method
		result, found := matcher.Match("", "/api", "GET", nil, nil)
		assert.True(t, found)

		result, found = matcher.Match("", "/api", "POST", nil, nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match hostname non-match", func(t *testing.T) {
		matcher := NewRouteMatcher()
		hostRegex := regexp.MustCompile("^api\\.example\\.com$")
		route := &CompiledRoute{
			Name:        "api-route",
			HostRegexes: []*regexp.Regexp{hostRegex},
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("other.example.com", "/api", "GET", nil, nil)

		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with multiple header matchers", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "multi-header-route",
			Rules: []*CompiledRule{
				{
					PathMatcher: NewExactPathMatcher("/api"),
					HeaderMatchers: []HeaderMatcher{
						NewExactHeaderMatcher("content-type", "application/json"),
						NewExactHeaderMatcher("accept", "application/json"),
					},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with both headers
		headers := map[string]string{
			"content-type": "application/json",
			"accept":       "application/json",
		}
		result, found := matcher.Match("", "/api", "GET", headers, nil)
		assert.True(t, found)

		// Should not match with only one header
		headers = map[string]string{"content-type": "application/json"}
		result, found = matcher.Match("", "/api", "GET", headers, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with multiple query matchers", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "multi-query-route",
			Rules: []*CompiledRule{
				{
					PathMatcher: NewExactPathMatcher("/api"),
					QueryMatchers: []QueryMatcher{
						NewExactQueryMatcher("page", "1"),
						NewExactQueryMatcher("limit", "10"),
					},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with both query params
		query := map[string]string{"page": "1", "limit": "10"}
		result, found := matcher.Match("", "/api", "GET", nil, query)
		assert.True(t, found)

		// Should not match with only one query param
		query = map[string]string{"page": "1"}
		result, found = matcher.Match("", "/api", "GET", nil, query)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match complex route with all matchers", func(t *testing.T) {
		matcher := NewRouteMatcher()
		hostRegex := regexp.MustCompile("^api\\.example\\.com$")
		regexPath, _ := NewRegexPathMatcher("/api/v(?P<version>[0-9]+)/users")
		regexHeader, _ := NewRegexHeaderMatcher("authorization", "^Bearer .+$")

		route := &CompiledRoute{
			Name:        "complex-route",
			HostRegexes: []*regexp.Regexp{hostRegex},
			Rules: []*CompiledRule{
				{
					PathMatcher:    regexPath,
					MethodMatcher:  NewMultiMethodMatcher([]string{"GET", "POST"}),
					HeaderMatchers: []HeaderMatcher{regexHeader},
					QueryMatchers:  []QueryMatcher{NewPresentQueryMatcher("api_key")},
				},
			},
		}
		matcher.AddRoute(route)

		// Should match with all conditions met
		headers := map[string]string{"authorization": "Bearer token123"}
		query := map[string]string{"api_key": "abc123"}
		result, found := matcher.Match("api.example.com", "/api/v2/users", "GET", headers, query)

		assert.True(t, found)
		assert.NotNil(t, result)
		assert.Equal(t, "2", result.Captures["version"])
	})
}

// =============================================================================
// Clear Tests
// =============================================================================

func TestRouteMatcher_Clear(t *testing.T) {
	t.Run("clear removes all routes", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-1", Priority: 100})
		matcher.AddRoute(&CompiledRoute{Name: "route-2", Priority: 200})
		matcher.AddRoute(&CompiledRoute{Name: "route-3", Priority: 300})

		assert.Equal(t, 3, matcher.Count())

		matcher.Clear()

		assert.Equal(t, 0, matcher.Count())
		assert.Empty(t, matcher.GetRouteNames())
	})

	t.Run("clear on empty matcher", func(t *testing.T) {
		matcher := NewRouteMatcher()

		matcher.Clear()

		assert.Equal(t, 0, matcher.Count())
	})

	t.Run("can add routes after clear", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-1", Priority: 100})
		matcher.Clear()

		matcher.AddRoute(&CompiledRoute{Name: "route-2", Priority: 200})

		assert.Equal(t, 1, matcher.Count())
		names := matcher.GetRouteNames()
		assert.Equal(t, []string{"route-2"}, names)
	})
}

// =============================================================================
// Count Tests
// =============================================================================

func TestRouteMatcher_Count(t *testing.T) {
	t.Run("count returns correct count", func(t *testing.T) {
		matcher := NewRouteMatcher()

		assert.Equal(t, 0, matcher.Count())

		matcher.AddRoute(&CompiledRoute{Name: "route-1"})
		assert.Equal(t, 1, matcher.Count())

		matcher.AddRoute(&CompiledRoute{Name: "route-2"})
		assert.Equal(t, 2, matcher.Count())

		matcher.AddRoute(&CompiledRoute{Name: "route-3"})
		assert.Equal(t, 3, matcher.Count())
	})

	t.Run("count after remove", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-1"})
		matcher.AddRoute(&CompiledRoute{Name: "route-2"})

		matcher.RemoveRoute("route-1")

		assert.Equal(t, 1, matcher.Count())
	})

	t.Run("count after clear", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-1"})
		matcher.AddRoute(&CompiledRoute{Name: "route-2"})

		matcher.Clear()

		assert.Equal(t, 0, matcher.Count())
	})
}

// =============================================================================
// GetRouteNames Tests
// =============================================================================

func TestRouteMatcher_GetRouteNames(t *testing.T) {
	t.Run("returns all route names", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "route-a", Priority: 100})
		matcher.AddRoute(&CompiledRoute{Name: "route-b", Priority: 200})
		matcher.AddRoute(&CompiledRoute{Name: "route-c", Priority: 150})

		names := matcher.GetRouteNames()

		assert.Len(t, names, 3)
		// Names should be in priority order (highest first)
		assert.Equal(t, "route-b", names[0])
		assert.Equal(t, "route-c", names[1])
		assert.Equal(t, "route-a", names[2])
	})

	t.Run("returns empty slice for empty matcher", func(t *testing.T) {
		matcher := NewRouteMatcher()

		names := matcher.GetRouteNames()

		assert.NotNil(t, names)
		assert.Empty(t, names)
	})

	t.Run("returns single name", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "only-route"})

		names := matcher.GetRouteNames()

		assert.Equal(t, []string{"only-route"}, names)
	})
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestRouteMatcher_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent reads", func(t *testing.T) {
		matcher := NewRouteMatcher()
		for i := 0; i < 10; i++ {
			matcher.AddRoute(&CompiledRoute{
				Name:     "route-" + string(rune('a'+i)),
				Priority: i * 10,
				Rules: []*CompiledRule{
					{PathMatcher: NewExactPathMatcher("/api")},
				},
			})
		}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = matcher.Match("", "/api", "GET", nil, nil)
				_ = matcher.Count()
				_ = matcher.GetRouteNames()
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent writes", func(t *testing.T) {
		matcher := NewRouteMatcher()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &CompiledRoute{
					Name:     "route-" + string(rune('a'+idx%26)),
					Priority: idx,
				}
				matcher.AddRoute(route)
			}(i)
		}
		wg.Wait()

		assert.Equal(t, 100, matcher.Count())
	})

	t.Run("concurrent read and write", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{
			Name: "initial-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		})

		var wg sync.WaitGroup

		// Readers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					_, _ = matcher.Match("", "/api", "GET", nil, nil)
					_ = matcher.Count()
				}
			}()
		}

		// Writers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &CompiledRoute{
					Name:     "route-" + string(rune('a'+idx%26)),
					Priority: idx,
					Rules: []*CompiledRule{
						{PathMatcher: NewExactPathMatcher("/api")},
					},
				}
				matcher.AddRoute(route)
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent add and remove", func(t *testing.T) {
		matcher := NewRouteMatcher()

		var wg sync.WaitGroup

		// Add routes
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &CompiledRoute{
					Name:     "route-" + string(rune('a'+idx%26)),
					Priority: idx,
				}
				matcher.AddRoute(route)
			}(i)
		}

		// Remove routes
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				matcher.RemoveRoute("route-" + string(rune('a'+idx%26)))
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent update", func(t *testing.T) {
		matcher := NewRouteMatcher()
		for i := 0; i < 10; i++ {
			matcher.AddRoute(&CompiledRoute{
				Name:     "route-" + string(rune('a'+i)),
				Priority: i * 10,
			})
		}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &CompiledRoute{
					Name:     "route-" + string(rune('a'+idx%10)),
					Priority: idx * 100,
				}
				matcher.UpdateRoute(route)
			}(i)
		}
		wg.Wait()

		assert.Equal(t, 10, matcher.Count())
	})

	t.Run("concurrent clear and add", func(t *testing.T) {
		matcher := NewRouteMatcher()

		var wg sync.WaitGroup

		// Clear operations
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				matcher.Clear()
			}()
		}

		// Add operations
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				route := &CompiledRoute{
					Name:     "route-" + string(rune('a'+idx%26)),
					Priority: idx,
				}
				matcher.AddRoute(route)
			}(i)
		}

		wg.Wait()
	})
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestRouteMatcher_EdgeCases(t *testing.T) {
	t.Run("route with empty rules", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name:  "empty-rules",
			Rules: []*CompiledRule{},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api", "GET", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("route with nil rules", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name:  "nil-rules",
			Rules: nil,
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api", "GET", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("match with empty headers map", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "test-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api", "GET", map[string]string{}, nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with empty query map", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "test-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api", "GET", nil, map[string]string{})
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with empty path", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "empty-path-route",
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "", "GET", nil, nil)
		assert.True(t, found)
		assert.NotNil(t, result)
	})

	t.Run("match with empty method", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "test-route",
			Rules: []*CompiledRule{
				{
					PathMatcher:   NewExactPathMatcher("/api"),
					MethodMatcher: NewSimpleMethodMatcher("GET"),
				},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api", "", nil, nil)
		assert.False(t, found)
		assert.Nil(t, result)
	})

	t.Run("duplicate route names", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route1 := &CompiledRoute{Name: "duplicate", Priority: 100}
		route2 := &CompiledRoute{Name: "duplicate", Priority: 200}

		matcher.AddRoute(route1)
		matcher.AddRoute(route2)

		// Both routes are added (no uniqueness constraint)
		assert.Equal(t, 2, matcher.Count())
	})

	t.Run("route with metadata", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name:     "metadata-route",
			Priority: 100,
			Metadata: map[string]interface{}{
				"backend": "service-a",
				"timeout": 30,
			},
			Rules: []*CompiledRule{
				{PathMatcher: NewExactPathMatcher("/api")},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api", "GET", nil, nil)
		assert.True(t, found)
		assert.Equal(t, "service-a", result.Route.Metadata["backend"])
		assert.Equal(t, 30, result.Route.Metadata["timeout"])
	})

	t.Run("rule with metadata", func(t *testing.T) {
		matcher := NewRouteMatcher()
		route := &CompiledRoute{
			Name: "rule-metadata-route",
			Rules: []*CompiledRule{
				{
					PathMatcher: NewExactPathMatcher("/api"),
					Metadata: map[string]interface{}{
						"rateLimit": 100,
					},
				},
			},
		}
		matcher.AddRoute(route)

		result, found := matcher.Match("", "/api", "GET", nil, nil)
		assert.True(t, found)
		assert.Equal(t, 100, result.Rule.Metadata["rateLimit"])
	})
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkRouteMatcher_Match(b *testing.B) {
	matcher := NewRouteMatcher()

	// Add 100 routes
	for i := 0; i < 100; i++ {
		route := &CompiledRoute{
			Name:     "route-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Priority: i,
			Rules: []*CompiledRule{
				{PathMatcher: NewPrefixPathMatcher("/api/v" + string(rune('0'+i%10)))},
			},
		}
		matcher.AddRoute(route)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("", "/api/v5/users", "GET", nil, nil)
	}
}

func BenchmarkRouteMatcher_AddRoute(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher := NewRouteMatcher()
		for j := 0; j < 100; j++ {
			route := &CompiledRoute{
				Name:     "route-" + string(rune('a'+j%26)),
				Priority: j,
			}
			matcher.AddRoute(route)
		}
	}
}

func BenchmarkRouteMatcher_MatchWithHeaders(b *testing.B) {
	matcher := NewRouteMatcher()
	route := &CompiledRoute{
		Name: "header-route",
		Rules: []*CompiledRule{
			{
				PathMatcher: NewExactPathMatcher("/api"),
				HeaderMatchers: []HeaderMatcher{
					NewExactHeaderMatcher("content-type", "application/json"),
					NewExactHeaderMatcher("authorization", "Bearer token"),
				},
			},
		},
	}
	matcher.AddRoute(route)

	headers := map[string]string{
		"content-type":  "application/json",
		"authorization": "Bearer token",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("", "/api", "GET", headers, nil)
	}
}

func BenchmarkRouteMatcher_MatchWithRegex(b *testing.B) {
	matcher := NewRouteMatcher()
	regexPath, _ := NewRegexPathMatcher("/api/v(?P<version>[0-9]+)/users/(?P<id>[0-9]+)")
	route := &CompiledRoute{
		Name: "regex-route",
		Rules: []*CompiledRule{
			{PathMatcher: regexPath},
		},
	}
	matcher.AddRoute(route)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match("", "/api/v2/users/12345", "GET", nil, nil)
	}
}

// =============================================================================
// CompiledRoute and CompiledRule Tests
// =============================================================================

func TestCompiledRoute_Fields(t *testing.T) {
	hostRegex := regexp.MustCompile("^api\\.example\\.com$")
	route := &CompiledRoute{
		Name:        "test-route",
		HostRegexes: []*regexp.Regexp{hostRegex},
		Hostnames:   []string{"api.example.com"},
		Rules: []*CompiledRule{
			{PathMatcher: NewExactPathMatcher("/api")},
		},
		Priority: 100,
		Metadata: map[string]interface{}{"key": "value"},
	}

	assert.Equal(t, "test-route", route.Name)
	assert.Len(t, route.HostRegexes, 1)
	assert.Equal(t, []string{"api.example.com"}, route.Hostnames)
	assert.Len(t, route.Rules, 1)
	assert.Equal(t, 100, route.Priority)
	assert.Equal(t, "value", route.Metadata["key"])
}

func TestCompiledRule_Fields(t *testing.T) {
	rule := &CompiledRule{
		PathMatcher:    NewExactPathMatcher("/api"),
		MethodMatcher:  NewSimpleMethodMatcher("GET"),
		HeaderMatchers: []HeaderMatcher{NewExactHeaderMatcher("content-type", "application/json")},
		QueryMatchers:  []QueryMatcher{NewExactQueryMatcher("page", "1")},
		Priority:       50,
		Metadata:       map[string]interface{}{"timeout": 30},
	}

	assert.NotNil(t, rule.PathMatcher)
	assert.NotNil(t, rule.MethodMatcher)
	assert.Len(t, rule.HeaderMatchers, 1)
	assert.Len(t, rule.QueryMatchers, 1)
	assert.Equal(t, 50, rule.Priority)
	assert.Equal(t, 30, rule.Metadata["timeout"])
}

func TestMatchResult_Fields(t *testing.T) {
	route := &CompiledRoute{Name: "test-route"}
	rule := &CompiledRule{PathMatcher: NewExactPathMatcher("/api")}
	captures := map[string]string{"id": "123"}

	result := &MatchResult{
		Route:    route,
		Rule:     rule,
		Captures: captures,
	}

	assert.Equal(t, route, result.Route)
	assert.Equal(t, rule, result.Rule)
	assert.Equal(t, captures, result.Captures)
}

// =============================================================================
// sortRoutes Tests
// =============================================================================

func TestRouteMatcher_sortRoutes(t *testing.T) {
	t.Run("sorts by priority descending", func(t *testing.T) {
		matcher := NewRouteMatcher()

		// Add routes in random priority order
		matcher.AddRoute(&CompiledRoute{Name: "medium", Priority: 50})
		matcher.AddRoute(&CompiledRoute{Name: "low", Priority: 10})
		matcher.AddRoute(&CompiledRoute{Name: "high", Priority: 100})
		matcher.AddRoute(&CompiledRoute{Name: "very-high", Priority: 200})

		names := matcher.GetRouteNames()

		assert.Equal(t, "very-high", names[0])
		assert.Equal(t, "high", names[1])
		assert.Equal(t, "medium", names[2])
		assert.Equal(t, "low", names[3])
	})

	t.Run("handles negative priorities", func(t *testing.T) {
		matcher := NewRouteMatcher()

		matcher.AddRoute(&CompiledRoute{Name: "negative", Priority: -10})
		matcher.AddRoute(&CompiledRoute{Name: "zero", Priority: 0})
		matcher.AddRoute(&CompiledRoute{Name: "positive", Priority: 10})

		names := matcher.GetRouteNames()

		assert.Equal(t, "positive", names[0])
		assert.Equal(t, "zero", names[1])
		assert.Equal(t, "negative", names[2])
	})

	t.Run("handles equal priorities", func(t *testing.T) {
		matcher := NewRouteMatcher()

		matcher.AddRoute(&CompiledRoute{Name: "first", Priority: 100})
		matcher.AddRoute(&CompiledRoute{Name: "second", Priority: 100})
		matcher.AddRoute(&CompiledRoute{Name: "third", Priority: 100})

		// All routes should be present
		assert.Equal(t, 3, matcher.Count())
	})

	t.Run("single route no sorting needed", func(t *testing.T) {
		matcher := NewRouteMatcher()
		matcher.AddRoute(&CompiledRoute{Name: "only", Priority: 100})

		names := matcher.GetRouteNames()
		assert.Equal(t, []string{"only"}, names)
	})

	t.Run("empty routes no sorting needed", func(t *testing.T) {
		matcher := NewRouteMatcher()
		names := matcher.GetRouteNames()
		assert.Empty(t, names)
	})
}

// =============================================================================
// matchHostname Tests
// =============================================================================

func TestRouteMatcher_matchHostname(t *testing.T) {
	matcher := NewRouteMatcher()

	t.Run("no hostnames or regexes matches all", func(t *testing.T) {
		route := &CompiledRoute{
			Name:        "no-host",
			HostRegexes: nil,
			Hostnames:   nil,
		}

		result := matcher.matchHostname(route, "any.host.com")
		assert.True(t, result)
	})

	t.Run("empty hostnames and regexes matches all", func(t *testing.T) {
		route := &CompiledRoute{
			Name:        "empty-host",
			HostRegexes: []*regexp.Regexp{},
			Hostnames:   []string{},
		}

		result := matcher.matchHostname(route, "any.host.com")
		assert.True(t, result)
	})

	t.Run("wildcard hostname matches all", func(t *testing.T) {
		route := &CompiledRoute{
			Name:      "wildcard-host",
			Hostnames: []string{"*"},
		}

		result := matcher.matchHostname(route, "any.host.com")
		assert.True(t, result)
	})

	t.Run("empty string hostname matches all", func(t *testing.T) {
		route := &CompiledRoute{
			Name:      "empty-string-host",
			Hostnames: []string{""},
		}

		result := matcher.matchHostname(route, "any.host.com")
		assert.True(t, result)
	})

	t.Run("regex hostname match", func(t *testing.T) {
		hostRegex := regexp.MustCompile("^api\\.example\\.com$")
		route := &CompiledRoute{
			Name:        "regex-host",
			HostRegexes: []*regexp.Regexp{hostRegex},
		}

		result := matcher.matchHostname(route, "api.example.com")
		assert.True(t, result)

		result = matcher.matchHostname(route, "other.example.com")
		assert.False(t, result)
	})

	t.Run("multiple regex hostnames", func(t *testing.T) {
		hostRegex1 := regexp.MustCompile("^api\\.example\\.com$")
		hostRegex2 := regexp.MustCompile("^web\\.example\\.com$")
		route := &CompiledRoute{
			Name:        "multi-regex-host",
			HostRegexes: []*regexp.Regexp{hostRegex1, hostRegex2},
		}

		result := matcher.matchHostname(route, "api.example.com")
		assert.True(t, result)

		result = matcher.matchHostname(route, "web.example.com")
		assert.True(t, result)

		result = matcher.matchHostname(route, "other.example.com")
		assert.False(t, result)
	})
}

// =============================================================================
// matchRule Tests
// =============================================================================

func TestRouteMatcher_matchRule(t *testing.T) {
	matcher := NewRouteMatcher()

	t.Run("nil path matcher matches any path", func(t *testing.T) {
		rule := &CompiledRule{PathMatcher: nil}
		captures := make(map[string]string)

		result := matcher.matchRule(rule, "/any/path", "GET", nil, nil, captures)
		assert.True(t, result)
	})

	t.Run("nil method matcher matches any method", func(t *testing.T) {
		rule := &CompiledRule{
			PathMatcher:   NewExactPathMatcher("/api"),
			MethodMatcher: nil,
		}
		captures := make(map[string]string)

		result := matcher.matchRule(rule, "/api", "ANY", nil, nil, captures)
		assert.True(t, result)
	})

	t.Run("path captures are added to captures map", func(t *testing.T) {
		regexPath, _ := NewRegexPathMatcher("/users/(?P<id>[0-9]+)")
		rule := &CompiledRule{PathMatcher: regexPath}
		captures := make(map[string]string)

		result := matcher.matchRule(rule, "/users/123", "GET", nil, nil, captures)
		assert.True(t, result)
		assert.Equal(t, "123", captures["id"])
	})

	t.Run("header matcher requires header presence", func(t *testing.T) {
		rule := &CompiledRule{
			PathMatcher:    NewExactPathMatcher("/api"),
			HeaderMatchers: []HeaderMatcher{NewExactHeaderMatcher("x-api-key", "secret")},
		}
		captures := make(map[string]string)

		// Without header
		result := matcher.matchRule(rule, "/api", "GET", nil, nil, captures)
		assert.False(t, result)

		// With wrong header
		headers := map[string]string{"x-api-key": "wrong"}
		result = matcher.matchRule(rule, "/api", "GET", headers, nil, captures)
		assert.False(t, result)

		// With correct header
		headers = map[string]string{"x-api-key": "secret"}
		result = matcher.matchRule(rule, "/api", "GET", headers, nil, captures)
		assert.True(t, result)
	})

	t.Run("query matcher requires query param presence", func(t *testing.T) {
		rule := &CompiledRule{
			PathMatcher:   NewExactPathMatcher("/api"),
			QueryMatchers: []QueryMatcher{NewExactQueryMatcher("version", "v2")},
		}
		captures := make(map[string]string)

		// Without query param
		result := matcher.matchRule(rule, "/api", "GET", nil, nil, captures)
		assert.False(t, result)

		// With wrong query param
		query := map[string]string{"version": "v1"}
		result = matcher.matchRule(rule, "/api", "GET", nil, query, captures)
		assert.False(t, result)

		// With correct query param
		query = map[string]string{"version": "v2"}
		result = matcher.matchRule(rule, "/api", "GET", nil, query, captures)
		assert.True(t, result)
	})

	t.Run("all matchers must pass", func(t *testing.T) {
		regexPath, _ := NewRegexPathMatcher("/api/v(?P<version>[0-9]+)")
		rule := &CompiledRule{
			PathMatcher:    regexPath,
			MethodMatcher:  NewSimpleMethodMatcher("POST"),
			HeaderMatchers: []HeaderMatcher{NewExactHeaderMatcher("content-type", "application/json")},
			QueryMatchers:  []QueryMatcher{NewExactQueryMatcher("debug", "true")},
		}
		captures := make(map[string]string)

		headers := map[string]string{"content-type": "application/json"}
		query := map[string]string{"debug": "true"}

		result := matcher.matchRule(rule, "/api/v2", "POST", headers, query, captures)
		assert.True(t, result)
		assert.Equal(t, "2", captures["version"])
	})
}

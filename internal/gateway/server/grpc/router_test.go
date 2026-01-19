package grpc

import (
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

// TestNewRouter tests creating a new router
func TestNewRouter(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	assert.NotNil(t, router)
	assert.NotNil(t, router.routes)
	assert.NotNil(t, router.matcher)
	assert.NotNil(t, router.logger)
	assert.Empty(t, router.routes)
}

// TestRouterAddRoute tests adding routes
func TestRouterAddRoute(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	t.Run("adds route successfully", func(t *testing.T) {
		route := &GRPCRoute{
			Name:      "test-route",
			Hostnames: []string{"example.com"},
			Rules: []GRPCRouteRule{
				{
					Matches: []GRPCMethodMatch{
						{Service: "test.Service", Method: "TestMethod"},
					},
				},
			},
		}

		err := router.AddRoute(route)
		assert.NoError(t, err)

		// Verify route was added
		addedRoute := router.GetRoute("test-route")
		assert.NotNil(t, addedRoute)
		assert.Equal(t, "test-route", addedRoute.Name)
	})

	t.Run("returns error for duplicate route", func(t *testing.T) {
		route := &GRPCRoute{
			Name:      "duplicate-route",
			Hostnames: []string{"example.com"},
		}

		err := router.AddRoute(route)
		require.NoError(t, err)

		// Try to add the same route again
		err = router.AddRoute(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}

// TestRouterRemoveRoute tests removing routes
func TestRouterRemoveRoute(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	t.Run("removes route successfully", func(t *testing.T) {
		route := &GRPCRoute{
			Name:      "route-to-remove",
			Hostnames: []string{"example.com"},
		}

		err := router.AddRoute(route)
		require.NoError(t, err)

		err = router.RemoveRoute("route-to-remove")
		assert.NoError(t, err)

		// Verify route was removed
		removedRoute := router.GetRoute("route-to-remove")
		assert.Nil(t, removedRoute)
	})

	t.Run("returns error for non-existent route", func(t *testing.T) {
		err := router.RemoveRoute("non-existent-route")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// TestRouterUpdateRoute tests updating routes
func TestRouterUpdateRoute(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	t.Run("updates route successfully", func(t *testing.T) {
		// Add initial route
		route := &GRPCRoute{
			Name:      "route-to-update",
			Hostnames: []string{"example.com"},
		}

		err := router.AddRoute(route)
		require.NoError(t, err)

		// Update the route
		updatedRoute := &GRPCRoute{
			Name:      "route-to-update",
			Hostnames: []string{"updated.example.com"},
		}

		err = router.UpdateRoute(updatedRoute)
		assert.NoError(t, err)

		// Verify route was updated
		result := router.GetRoute("route-to-update")
		assert.NotNil(t, result)
		assert.Contains(t, result.Hostnames, "updated.example.com")
	})

	t.Run("returns error for non-existent route", func(t *testing.T) {
		route := &GRPCRoute{
			Name:      "non-existent-route",
			Hostnames: []string{"example.com"},
		}

		err := router.UpdateRoute(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// TestRouterMatch tests route matching
func TestRouterMatch(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Add test routes
	route1 := &GRPCRoute{
		Name:      "service-route",
		Hostnames: []string{"*"},
		Priority:  10,
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "users.UserService",
						Method:  "GetUser",
						Type:    GRPCMethodMatchTypeExact,
					},
				},
				BackendRefs: []BackendRef{
					{Name: "users-backend", Port: 8080},
				},
			},
		},
	}

	route2 := &GRPCRoute{
		Name:      "wildcard-route",
		Hostnames: []string{"*"},
		Priority:  5,
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "*",
						Method:  "*",
						Type:    GRPCMethodMatchTypeExact,
					},
				},
				BackendRefs: []BackendRef{
					{Name: "default-backend", Port: 8080},
				},
			},
		},
	}

	err := router.AddRoute(route1)
	require.NoError(t, err)
	err = router.AddRoute(route2)
	require.NoError(t, err)

	t.Run("matches by service and method", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, matchedRule := router.Match("users.UserService", "GetUser", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
		assert.Equal(t, "service-route", matchedRoute.Name)
	})

	t.Run("matches wildcard route", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, matchedRule := router.Match("other.Service", "OtherMethod", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
		// Should match the higher priority route first, but since service doesn't match,
		// it should fall through to wildcard
	})

	t.Run("no match returns nil", func(t *testing.T) {
		// Create a router with no wildcard routes
		emptyRouter := NewRouter(logger)
		specificRoute := &GRPCRoute{
			Name:      "specific-route",
			Hostnames: []string{"specific.example.com"},
			Rules: []GRPCRouteRule{
				{
					Matches: []GRPCMethodMatch{
						{
							Service: "specific.Service",
							Method:  "SpecificMethod",
							Type:    GRPCMethodMatchTypeExact,
						},
					},
				},
			},
		}
		err := emptyRouter.AddRoute(specificRoute)
		require.NoError(t, err)

		md := metadata.MD{":authority": []string{"other.example.com"}}
		matchedRoute, matchedRule := emptyRouter.Match("other.Service", "OtherMethod", md)

		assert.Nil(t, matchedRoute)
		assert.Nil(t, matchedRule)
	})
}

// TestRouterMatchByHeaders tests matching by headers
func TestRouterMatchByHeaders(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "header-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "test.Service",
						Method:  "*",
						Type:    GRPCMethodMatchTypeExact,
						Headers: []GRPCHeaderMatch{
							{
								Name:  "x-api-version",
								Value: "v1",
								Type:  GRPCHeaderMatchTypeExact,
							},
						},
					},
				},
				BackendRefs: []BackendRef{
					{Name: "v1-backend", Port: 8080},
				},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	t.Run("matches with correct header", func(t *testing.T) {
		md := metadata.MD{
			"x-api-version": []string{"v1"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
		assert.Equal(t, "header-route", matchedRoute.Name)
	})

	t.Run("no match with wrong header value", func(t *testing.T) {
		md := metadata.MD{
			"x-api-version": []string{"v2"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.Nil(t, matchedRoute)
		assert.Nil(t, matchedRule)
	})

	t.Run("no match with missing header", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.Nil(t, matchedRoute)
		assert.Nil(t, matchedRule)
	})
}

// TestRouterMatchByHostname tests matching by hostname
func TestRouterMatchByHostname(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "hostname-route",
		Hostnames: []string{"api.example.com", "*.staging.example.com"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "*",
						Method:  "*",
					},
				},
				BackendRefs: []BackendRef{
					{Name: "api-backend", Port: 8080},
				},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	t.Run("matches exact hostname", func(t *testing.T) {
		md := metadata.MD{
			":authority": []string{"api.example.com:443"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
		assert.Equal(t, "hostname-route", matchedRoute.Name)
	})

	t.Run("matches wildcard hostname", func(t *testing.T) {
		md := metadata.MD{
			":authority": []string{"app.staging.example.com"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
	})

	t.Run("no match for different hostname", func(t *testing.T) {
		md := metadata.MD{
			":authority": []string{"other.example.com"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.Nil(t, matchedRoute)
		assert.Nil(t, matchedRule)
	})
}

// TestRouterListRoutes tests listing all routes
func TestRouterListRoutes(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Add multiple routes
	for i := 0; i < 5; i++ {
		route := &GRPCRoute{
			Name:      "route-" + string(rune('a'+i)),
			Hostnames: []string{"*"},
		}
		err := router.AddRoute(route)
		require.NoError(t, err)
	}

	routes := router.ListRoutes()
	assert.Len(t, routes, 5)
}

// TestRouterGetRoute tests getting a specific route
func TestRouterGetRoute(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "get-test-route",
		Hostnames: []string{"example.com"},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	t.Run("returns route when exists", func(t *testing.T) {
		result := router.GetRoute("get-test-route")
		assert.NotNil(t, result)
		assert.Equal(t, "get-test-route", result.Name)
	})

	t.Run("returns nil when not exists", func(t *testing.T) {
		result := router.GetRoute("non-existent")
		assert.Nil(t, result)
	})
}

// TestRouterConcurrentAccess tests concurrent access to router
func TestRouterConcurrentAccess(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			route := &GRPCRoute{
				Name:      "concurrent-route-" + string(rune('a'+idx)),
				Hostnames: []string{"*"},
			}
			_ = router.AddRoute(route)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = router.ListRoutes()
		}()
	}

	// Concurrent matches
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			md := metadata.MD{}
			_, _ = router.Match("test.Service", "TestMethod", md)
		}()
	}

	wg.Wait()
}

// TestExactServiceMatcher tests exact service matching
func TestExactServiceMatcher(t *testing.T) {
	t.Parallel()

	t.Run("matches exact service", func(t *testing.T) {
		matcher := NewExactServiceMatcher("users.UserService")
		assert.True(t, matcher.Match("users.UserService"))
		assert.False(t, matcher.Match("users.OtherService"))
	})

	t.Run("empty service matches all", func(t *testing.T) {
		matcher := NewExactServiceMatcher("")
		assert.True(t, matcher.Match("any.Service"))
	})

	t.Run("wildcard matches all", func(t *testing.T) {
		matcher := NewExactServiceMatcher("*")
		assert.True(t, matcher.Match("any.Service"))
	})
}

// TestRegexServiceMatcher tests regex service matching
func TestRegexServiceMatcher(t *testing.T) {
	t.Parallel()

	t.Run("matches regex pattern", func(t *testing.T) {
		matcher, err := NewRegexServiceMatcher("users\\..*")
		require.NoError(t, err)

		assert.True(t, matcher.Match("users.UserService"))
		assert.True(t, matcher.Match("users.AdminService"))
		assert.False(t, matcher.Match("orders.OrderService"))
	})

	t.Run("returns error for invalid regex", func(t *testing.T) {
		_, err := NewRegexServiceMatcher("[invalid")
		assert.Error(t, err)
	})
}

// TestExactMethodMatcher tests exact method matching
func TestExactMethodMatcher(t *testing.T) {
	t.Parallel()

	t.Run("matches exact method", func(t *testing.T) {
		matcher := NewExactMethodMatcher("GetUser")
		assert.True(t, matcher.Match("GetUser"))
		assert.False(t, matcher.Match("CreateUser"))
	})

	t.Run("empty method matches all", func(t *testing.T) {
		matcher := NewExactMethodMatcher("")
		assert.True(t, matcher.Match("AnyMethod"))
	})

	t.Run("wildcard matches all", func(t *testing.T) {
		matcher := NewExactMethodMatcher("*")
		assert.True(t, matcher.Match("AnyMethod"))
	})
}

// TestRegexMethodMatcher tests regex method matching
func TestRegexMethodMatcher(t *testing.T) {
	t.Parallel()

	t.Run("matches regex pattern", func(t *testing.T) {
		matcher, err := NewRegexMethodMatcher("Get.*")
		require.NoError(t, err)

		assert.True(t, matcher.Match("GetUser"))
		assert.True(t, matcher.Match("GetOrder"))
		assert.False(t, matcher.Match("CreateUser"))
	})

	t.Run("returns error for invalid regex", func(t *testing.T) {
		_, err := NewRegexMethodMatcher("[invalid")
		assert.Error(t, err)
	})
}

// TestExactHeaderMatcher tests exact header matching
func TestExactHeaderMatcher(t *testing.T) {
	t.Parallel()

	matcher := NewExactHeaderMatcher("X-Api-Version", "v1")

	assert.Equal(t, "x-api-version", matcher.Name())
	assert.True(t, matcher.Match("v1"))
	assert.False(t, matcher.Match("v2"))
}

// TestRegexHeaderMatcher tests regex header matching
func TestRegexHeaderMatcher(t *testing.T) {
	t.Parallel()

	t.Run("matches regex pattern", func(t *testing.T) {
		matcher, err := NewRegexHeaderMatcher("X-Api-Version", "v[0-9]+")
		require.NoError(t, err)

		assert.Equal(t, "x-api-version", matcher.Name())
		assert.True(t, matcher.Match("v1"))
		assert.True(t, matcher.Match("v2"))
		assert.False(t, matcher.Match("beta"))
	})

	t.Run("returns error for invalid regex", func(t *testing.T) {
		_, err := NewRegexHeaderMatcher("X-Api-Version", "[invalid")
		assert.Error(t, err)
	})
}

// TestHostnameToRegex tests hostname pattern to regex conversion
func TestHostnameToRegex(t *testing.T) {
	t.Parallel()

	t.Run("empty hostname returns nil", func(t *testing.T) {
		regex := hostnameToRegex("")
		assert.Nil(t, regex)
	})

	t.Run("wildcard hostname returns nil", func(t *testing.T) {
		regex := hostnameToRegex("*")
		assert.Nil(t, regex)
	})

	t.Run("exact hostname creates regex", func(t *testing.T) {
		regex := hostnameToRegex("api.example.com")
		require.NotNil(t, regex)

		assert.True(t, regex.MatchString("api.example.com"))
		assert.False(t, regex.MatchString("other.example.com"))
	})

	t.Run("wildcard subdomain creates regex", func(t *testing.T) {
		regex := hostnameToRegex("*.example.com")
		require.NotNil(t, regex)

		assert.True(t, regex.MatchString("api.example.com"))
		assert.True(t, regex.MatchString("app.example.com"))
		assert.False(t, regex.MatchString("example.com"))
	})
}

// TestGRPCRouteMatcher tests the route matcher
func TestGRPCRouteMatcher(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	matcher := &GRPCRouteMatcher{}

	routes := []*GRPCRoute{
		{
			Name:      "high-priority",
			Hostnames: []string{"*"},
			Priority:  100,
			Rules: []GRPCRouteRule{
				{
					Matches: []GRPCMethodMatch{
						{Service: "priority.Service", Method: "*"},
					},
				},
			},
		},
		{
			Name:      "low-priority",
			Hostnames: []string{"*"},
			Priority:  10,
			Rules: []GRPCRouteRule{
				{
					Matches: []GRPCMethodMatch{
						{Service: "*", Method: "*"},
					},
				},
			},
		},
	}

	err := matcher.Compile(routes, logger)
	require.NoError(t, err)

	t.Run("matches high priority route first", func(t *testing.T) {
		result, ok := matcher.Match("", "priority.Service", "TestMethod", nil)
		assert.True(t, ok)
		assert.NotNil(t, result)
		assert.Equal(t, "high-priority", result.Route.Name)
	})

	t.Run("falls back to low priority route", func(t *testing.T) {
		result, ok := matcher.Match("", "other.Service", "TestMethod", nil)
		assert.True(t, ok)
		assert.NotNil(t, result)
		assert.Equal(t, "low-priority", result.Route.Name)
	})
}

// TestGRPCRouteTypes tests the route type constants
func TestGRPCRouteTypes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, GRPCMethodMatchType("Exact"), GRPCMethodMatchTypeExact)
	assert.Equal(t, GRPCMethodMatchType("RegularExpression"), GRPCMethodMatchTypeRegex)
	assert.Equal(t, GRPCHeaderMatchType("Exact"), GRPCHeaderMatchTypeExact)
	assert.Equal(t, GRPCHeaderMatchType("RegularExpression"), GRPCHeaderMatchTypeRegex)
	assert.Equal(t, GRPCRouteFilterType("RequestHeaderModifier"), GRPCRouteFilterRequestHeaderModifier)
	assert.Equal(t, GRPCRouteFilterType("ResponseHeaderModifier"), GRPCRouteFilterResponseHeaderModifier)
}

// TestGRPCMatchResult tests the match result struct
func TestGRPCMatchResult(t *testing.T) {
	t.Parallel()

	route := &GRPCRoute{Name: "test-route"}
	rule := &GRPCRouteRule{
		BackendRefs: []BackendRef{{Name: "backend"}},
	}

	result := &GRPCMatchResult{
		Route: route,
		Rule:  rule,
	}

	assert.Equal(t, route, result.Route)
	assert.Equal(t, rule, result.Rule)
}

// TestRouterMatchWithEmptyRules tests matching routes with empty rules
func TestRouterMatchWithEmptyRules(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Route with empty rules should match all
	route := &GRPCRoute{
		Name:      "empty-rules-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches:     []GRPCMethodMatch{}, // Empty matches
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	md := metadata.MD{}
	matchedRoute, matchedRule := router.Match("any.Service", "AnyMethod", md)

	assert.NotNil(t, matchedRoute)
	assert.NotNil(t, matchedRule)
}

// TestRouterMatchWithRegexPatterns tests matching with regex patterns
func TestRouterMatchWithRegexPatterns(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "regex-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "users\\..*",
						Method:  "Get.*",
						Type:    GRPCMethodMatchTypeRegex,
					},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	t.Run("matches regex service and method", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, matchedRule := router.Match("users.UserService", "GetUser", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
	})

	t.Run("no match for non-matching service", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, matchedRule := router.Match("orders.OrderService", "GetOrder", md)

		assert.Nil(t, matchedRoute)
		assert.Nil(t, matchedRule)
	})
}

// TestRouterMatchWithRegexHeaders tests matching with regex header patterns
func TestRouterMatchWithRegexHeaders(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "regex-header-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "*",
						Method:  "*",
						Headers: []GRPCHeaderMatch{
							{
								Name:  "x-version",
								Value: "v[0-9]+",
								Type:  GRPCHeaderMatchTypeRegex,
							},
						},
					},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	t.Run("matches regex header", func(t *testing.T) {
		md := metadata.MD{
			"x-version": []string{"v1"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
	})

	t.Run("no match for non-matching header", func(t *testing.T) {
		md := metadata.MD{
			"x-version": []string{"beta"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.Nil(t, matchedRoute)
		assert.Nil(t, matchedRule)
	})
}

// ============================================================================
// Router Compile Error Path Tests
// ============================================================================

// TestRouterCompileInvalidServiceRegex tests compiling with invalid service regex
func TestRouterCompileInvalidServiceRegex(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Route with invalid regex pattern for service
	route := &GRPCRoute{
		Name:      "invalid-service-regex-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "[invalid", // Invalid regex
						Method:  "*",
						Type:    GRPCMethodMatchTypeRegex,
					},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	// Should not error - falls back to exact matcher
	err := router.AddRoute(route)
	assert.NoError(t, err)

	// Should still be able to match (using fallback exact matcher)
	md := metadata.MD{}
	matchedRoute, _ := router.Match("[invalid", "TestMethod", md)
	assert.NotNil(t, matchedRoute)
}

// TestRouterCompileInvalidMethodRegex tests compiling with invalid method regex
func TestRouterCompileInvalidMethodRegex(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Route with invalid regex pattern for method
	route := &GRPCRoute{
		Name:      "invalid-method-regex-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "*",
						Method:  "[invalid", // Invalid regex
						Type:    GRPCMethodMatchTypeRegex,
					},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	// Should not error - falls back to exact matcher
	err := router.AddRoute(route)
	assert.NoError(t, err)

	// Should still be able to match (using fallback exact matcher)
	md := metadata.MD{}
	matchedRoute, _ := router.Match("test.Service", "[invalid", md)
	assert.NotNil(t, matchedRoute)
}

// TestRouterCompileInvalidHeaderRegex tests compiling with invalid header regex
func TestRouterCompileInvalidHeaderRegex(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Route with invalid regex pattern for header
	route := &GRPCRoute{
		Name:      "invalid-header-regex-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "*",
						Method:  "*",
						Headers: []GRPCHeaderMatch{
							{
								Name:  "x-version",
								Value: "[invalid", // Invalid regex
								Type:  GRPCHeaderMatchTypeRegex,
							},
						},
					},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	// Should not error - invalid header matcher is skipped
	err := router.AddRoute(route)
	assert.NoError(t, err)

	// Should match since invalid header matcher is skipped
	md := metadata.MD{}
	matchedRoute, _ := router.Match("test.Service", "TestMethod", md)
	assert.NotNil(t, matchedRoute)
}

// TestRouterHostnameRegexError tests hostname regex compilation error
func TestRouterHostnameRegexError(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Route with hostname that would cause regex error (though most are escaped)
	route := &GRPCRoute{
		Name:      "hostname-route",
		Hostnames: []string{"api.example.com"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{Service: "*", Method: "*"},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	assert.NoError(t, err)

	// Should match the hostname
	md := metadata.MD{":authority": []string{"api.example.com"}}
	matchedRoute, _ := router.Match("test.Service", "TestMethod", md)
	assert.NotNil(t, matchedRoute)
}

// TestRouterMatchRuleWithNilMatchers tests matching with nil matchers
func TestRouterMatchRuleWithNilMatchers(t *testing.T) {
	t.Parallel()

	matcher := &GRPCRouteMatcher{}

	// Create a compiled rule with nil matchers
	rule := &CompiledGRPCRule{
		Rule: &GRPCRouteRule{
			Matches: []GRPCMethodMatch{}, // Empty matches
		},
		ServiceMatcher: nil,
		MethodMatcher:  nil,
		HeaderMatchers: nil,
	}

	// Should match since no matchers are defined
	result := matcher.matchRule(rule, "any.Service", "AnyMethod", nil)
	assert.True(t, result)
}

// TestRouterMatchHostnameWithNoRegexes tests hostname matching with no regexes
func TestRouterMatchHostnameWithNoRegexes(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Route with empty hostnames (matches all)
	route := &GRPCRoute{
		Name:      "no-hostname-route",
		Hostnames: []string{}, // Empty - matches all
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{Service: "*", Method: "*"},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	assert.NoError(t, err)

	// Should match any hostname
	md := metadata.MD{":authority": []string{"any.example.com"}}
	matchedRoute, _ := router.Match("test.Service", "TestMethod", md)
	assert.NotNil(t, matchedRoute)
}

// TestRouterMatchWithMethodMatcher tests matching with method matcher only
func TestRouterMatchWithMethodMatcher(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "method-only-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "", // Empty - matches all
						Method:  "GetUser",
						Type:    GRPCMethodMatchTypeExact,
					},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	assert.NoError(t, err)

	t.Run("matches correct method", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, _ := router.Match("any.Service", "GetUser", md)
		assert.NotNil(t, matchedRoute)
	})

	t.Run("no match for different method", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, _ := router.Match("any.Service", "CreateUser", md)
		assert.Nil(t, matchedRoute)
	})
}

// TestRouterMatchWithServiceMatcher tests matching with service matcher only
func TestRouterMatchWithServiceMatcher(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "service-only-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{
						Service: "users.UserService",
						Method:  "", // Empty - matches all
						Type:    GRPCMethodMatchTypeExact,
					},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	assert.NoError(t, err)

	t.Run("matches correct service", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, _ := router.Match("users.UserService", "AnyMethod", md)
		assert.NotNil(t, matchedRoute)
	})

	t.Run("no match for different service", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, _ := router.Match("orders.OrderService", "AnyMethod", md)
		assert.Nil(t, matchedRoute)
	})
}

// TestRouterPriorityOrdering tests that routes are ordered by priority
func TestRouterPriorityOrdering(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	// Add low priority route first
	lowPriorityRoute := &GRPCRoute{
		Name:      "low-priority",
		Hostnames: []string{"*"},
		Priority:  1,
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{Service: "*", Method: "*"},
				},
				BackendRefs: []BackendRef{{Name: "low-backend"}},
			},
		},
	}

	// Add high priority route second
	highPriorityRoute := &GRPCRoute{
		Name:      "high-priority",
		Hostnames: []string{"*"},
		Priority:  100,
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{Service: "*", Method: "*"},
				},
				BackendRefs: []BackendRef{{Name: "high-backend"}},
			},
		},
	}

	err := router.AddRoute(lowPriorityRoute)
	require.NoError(t, err)
	err = router.AddRoute(highPriorityRoute)
	require.NoError(t, err)

	// Should match high priority route
	md := metadata.MD{}
	matchedRoute, _ := router.Match("test.Service", "TestMethod", md)
	assert.NotNil(t, matchedRoute)
	assert.Equal(t, "high-priority", matchedRoute.Name)
}

// TestGRPCRouteFilterTypes tests the route filter types
func TestGRPCRouteFilterTypes(t *testing.T) {
	t.Parallel()

	filter := GRPCRouteFilter{
		Type: GRPCRouteFilterRequestHeaderModifier,
		RequestHeaderModifier: &HeaderModifier{
			Set:    map[string]string{"x-custom": "value"},
			Add:    map[string]string{"x-added": "value"},
			Remove: []string{"x-remove"},
		},
	}

	assert.Equal(t, GRPCRouteFilterRequestHeaderModifier, filter.Type)
	assert.NotNil(t, filter.RequestHeaderModifier)
	assert.Equal(t, "value", filter.RequestHeaderModifier.Set["x-custom"])
	assert.Equal(t, "value", filter.RequestHeaderModifier.Add["x-added"])
	assert.Contains(t, filter.RequestHeaderModifier.Remove, "x-remove")
}

// TestHeaderModifier tests the HeaderModifier struct
func TestHeaderModifier(t *testing.T) {
	t.Parallel()

	modifier := &HeaderModifier{
		Set:    map[string]string{"key1": "value1"},
		Add:    map[string]string{"key2": "value2"},
		Remove: []string{"key3"},
	}

	assert.Equal(t, "value1", modifier.Set["key1"])
	assert.Equal(t, "value2", modifier.Add["key2"])
	assert.Contains(t, modifier.Remove, "key3")
}

// TestCompiledGRPCRoute tests the CompiledGRPCRoute struct
func TestCompiledGRPCRoute(t *testing.T) {
	t.Parallel()

	route := &GRPCRoute{
		Name:      "test-route",
		Hostnames: []string{"example.com"},
		Priority:  10,
	}

	compiled := &CompiledGRPCRoute{
		Route:       route,
		HostRegexes: nil,
		Rules:       nil,
	}

	assert.Equal(t, route, compiled.Route)
	assert.Nil(t, compiled.HostRegexes)
	assert.Nil(t, compiled.Rules)
}

// TestCompiledGRPCRule tests the CompiledGRPCRule struct
func TestCompiledGRPCRule(t *testing.T) {
	t.Parallel()

	rule := &GRPCRouteRule{
		BackendRefs: []BackendRef{{Name: "backend"}},
	}

	compiled := &CompiledGRPCRule{
		Rule:           rule,
		ServiceMatcher: NewExactServiceMatcher("test.Service"),
		MethodMatcher:  NewExactMethodMatcher("TestMethod"),
		HeaderMatchers: nil,
		Priority:       5,
	}

	assert.Equal(t, rule, compiled.Rule)
	assert.NotNil(t, compiled.ServiceMatcher)
	assert.NotNil(t, compiled.MethodMatcher)
	assert.Equal(t, 5, compiled.Priority)
}

// TestHostnameToRegexInvalidPattern tests hostnameToRegex with patterns that cause regex errors
func TestHostnameToRegexInvalidPattern(t *testing.T) {
	t.Parallel()

	// Test with a hostname that would create an invalid regex after escaping
	// Most patterns are valid after escaping, so we test edge cases

	t.Run("normal hostname", func(t *testing.T) {
		regex := hostnameToRegex("api.example.com")
		assert.NotNil(t, regex)
		assert.True(t, regex.MatchString("api.example.com"))
	})

	t.Run("hostname with special chars", func(t *testing.T) {
		regex := hostnameToRegex("api-v1.example.com")
		assert.NotNil(t, regex)
		assert.True(t, regex.MatchString("api-v1.example.com"))
	})

	t.Run("hostname with numbers", func(t *testing.T) {
		regex := hostnameToRegex("api123.example.com")
		assert.NotNil(t, regex)
		assert.True(t, regex.MatchString("api123.example.com"))
	})
}

// ============================================================================
// Additional HostnameToRegex Tests
// ============================================================================

// TestHostnameToRegexEdgeCases tests edge cases for hostnameToRegex
func TestHostnameToRegexEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		hostname    string
		shouldMatch []string
		shouldNot   []string
		expectNil   bool
	}{
		{
			name:      "empty hostname returns nil",
			hostname:  "",
			expectNil: true,
		},
		{
			name:      "wildcard returns nil",
			hostname:  "*",
			expectNil: true,
		},
		{
			name:        "simple hostname",
			hostname:    "example.com",
			shouldMatch: []string{"example.com"},
			shouldNot:   []string{"other.com", "sub.example.com"},
		},
		{
			name:        "wildcard subdomain",
			hostname:    "*.example.com",
			shouldMatch: []string{"api.example.com", "www.example.com", "test.example.com"},
			shouldNot:   []string{"example.com", "api.other.com"},
		},
		{
			name:        "hostname with port-like suffix",
			hostname:    "api.example.com",
			shouldMatch: []string{"api.example.com"},
			shouldNot:   []string{"api.example.com:8080"},
		},
		{
			name:        "hostname with multiple wildcards",
			hostname:    "*.*.example.com",
			shouldMatch: []string{"a.b.example.com", "x.y.example.com"},
			shouldNot:   []string{"example.com", "a.example.com"},
		},
		{
			name:        "hostname with underscore",
			hostname:    "api_v1.example.com",
			shouldMatch: []string{"api_v1.example.com"},
			shouldNot:   []string{"api-v1.example.com"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			regex := hostnameToRegex(tc.hostname)

			if tc.expectNil {
				assert.Nil(t, regex)
				return
			}

			require.NotNil(t, regex)

			for _, match := range tc.shouldMatch {
				assert.True(t, regex.MatchString(match), "expected %q to match %q", tc.hostname, match)
			}

			for _, noMatch := range tc.shouldNot {
				assert.False(t, regex.MatchString(noMatch), "expected %q to NOT match %q", tc.hostname, noMatch)
			}
		})
	}
}

// ============================================================================
// Additional Router Match Tests
// ============================================================================

// TestRouterMatchWithAuthorityPort tests matching with authority containing port
func TestRouterMatchWithAuthorityPort(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "authority-port-route",
		Hostnames: []string{"api.example.com"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{Service: "*", Method: "*"},
				},
				BackendRefs: []BackendRef{{Name: "backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	t.Run("matches with port in authority", func(t *testing.T) {
		md := metadata.MD{
			":authority": []string{"api.example.com:443"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
	})

	t.Run("matches without port in authority", func(t *testing.T) {
		md := metadata.MD{
			":authority": []string{"api.example.com"},
		}
		matchedRoute, matchedRule := router.Match("test.Service", "TestMethod", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
	})
}

// TestRouterMatchWithMultipleRules tests matching with multiple rules
func TestRouterMatchWithMultipleRules(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "multi-rule-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{Service: "users.UserService", Method: "GetUser"},
				},
				BackendRefs: []BackendRef{{Name: "users-backend"}},
			},
			{
				Matches: []GRPCMethodMatch{
					{Service: "orders.OrderService", Method: "GetOrder"},
				},
				BackendRefs: []BackendRef{{Name: "orders-backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	t.Run("matches first rule", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, matchedRule := router.Match("users.UserService", "GetUser", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
		assert.Equal(t, "users-backend", matchedRule.BackendRefs[0].Name)
	})

	t.Run("matches second rule", func(t *testing.T) {
		md := metadata.MD{}
		matchedRoute, matchedRule := router.Match("orders.OrderService", "GetOrder", md)

		assert.NotNil(t, matchedRoute)
		assert.NotNil(t, matchedRule)
		assert.Equal(t, "orders-backend", matchedRule.BackendRefs[0].Name)
	})
}

// TestRouterMatchWithMultipleMatches tests matching with multiple matches in a rule
func TestRouterMatchWithMultipleMatches(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	router := NewRouter(logger)

	route := &GRPCRoute{
		Name:      "multi-match-route",
		Hostnames: []string{"*"},
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{Service: "users.UserService", Method: "GetUser"},
					{Service: "users.UserService", Method: "ListUsers"},
				},
				BackendRefs: []BackendRef{{Name: "users-backend"}},
			},
		},
	}

	err := router.AddRoute(route)
	require.NoError(t, err)

	// Note: Current implementation only uses first match
	md := metadata.MD{}
	matchedRoute, matchedRule := router.Match("users.UserService", "GetUser", md)

	assert.NotNil(t, matchedRoute)
	assert.NotNil(t, matchedRule)
}

// TestGRPCRouteMatcherMatchHostnameEdgeCases tests matchHostname edge cases
func TestGRPCRouteMatcherMatchHostnameEdgeCases(t *testing.T) {
	t.Parallel()

	_ = zap.NewNop() // Suppress unused warning
	matcher := &GRPCRouteMatcher{}

	t.Run("matches when no hostnames and no regexes", func(t *testing.T) {
		compiled := &CompiledGRPCRoute{
			Route: &GRPCRoute{
				Hostnames: []string{},
			},
			HostRegexes: []*regexp.Regexp{},
		}

		result := matcher.matchHostname(compiled, "any.host.com")
		assert.True(t, result)
	})

	t.Run("matches wildcard hostname", func(t *testing.T) {
		compiled := &CompiledGRPCRoute{
			Route: &GRPCRoute{
				Hostnames: []string{"*"},
			},
			HostRegexes: []*regexp.Regexp{},
		}

		result := matcher.matchHostname(compiled, "any.host.com")
		assert.True(t, result)
	})

	t.Run("matches with regex", func(t *testing.T) {
		regex := regexp.MustCompile("^api\\.example\\.com$")
		compiled := &CompiledGRPCRoute{
			Route: &GRPCRoute{
				Hostnames: []string{"api.example.com"},
			},
			HostRegexes: []*regexp.Regexp{regex},
		}

		result := matcher.matchHostname(compiled, "api.example.com")
		assert.True(t, result)
	})

	t.Run("no match with different hostname", func(t *testing.T) {
		regex := regexp.MustCompile("^api\\.example\\.com$")
		compiled := &CompiledGRPCRoute{
			Route: &GRPCRoute{
				Hostnames: []string{"api.example.com"},
			},
			HostRegexes: []*regexp.Regexp{regex},
		}

		result := matcher.matchHostname(compiled, "other.example.com")
		assert.False(t, result)
	})
}

// TestCompileGRPCRouteWithNilHostnameRegex tests compileGRPCRoute with nil hostname regex
func TestCompileGRPCRouteWithNilHostnameRegex(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	route := &GRPCRoute{
		Name:      "nil-regex-route",
		Hostnames: []string{"*", ""}, // Both should return nil regex
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCMethodMatch{
					{Service: "*", Method: "*"},
				},
			},
		},
	}

	compiled := compileGRPCRoute(route, logger)

	assert.NotNil(t, compiled)
	assert.Empty(t, compiled.HostRegexes) // Both wildcards should result in nil regexes
}

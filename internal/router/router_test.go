package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	r := New()
	assert.NotNil(t, r)
	assert.NotNil(t, r.routes)
	assert.NotNil(t, r.routeMap)
	assert.Empty(t, r.routes)
}

func TestRouter_AddRoute(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "test-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/api/"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	assert.Len(t, r.routes, 1)
	assert.Contains(t, r.routeMap, "test-route")
}

func TestRouter_AddRoute_Duplicate(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "test-route",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	err = r.AddRoute(route)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestRouter_AddRoute_InvalidRegex(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "test-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Regex: "[invalid"}},
		},
	}

	err := r.AddRoute(route)
	assert.Error(t, err)
}

func TestRouter_RemoveRoute(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "test-route",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	err = r.RemoveRoute("test-route")
	require.NoError(t, err)

	assert.Empty(t, r.routes)
	assert.NotContains(t, r.routeMap, "test-route")
}

func TestRouter_RemoveRoute_NotFound(t *testing.T) {
	t.Parallel()

	r := New()
	err := r.RemoveRoute("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRouter_Match(t *testing.T) {
	t.Parallel()

	r := New()

	// Add routes
	routes := []config.Route{
		{
			Name: "exact-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Exact: "/api/v1/users"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
		},
		{
			Name: "prefix-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
		},
	}

	for _, route := range routes {
		err := r.AddRoute(route)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		method        string
		path          string
		expectedRoute string
		expectError   bool
	}{
		{
			name:          "exact match",
			method:        "GET",
			path:          "/api/v1/users",
			expectedRoute: "exact-route",
		},
		{
			name:          "prefix match",
			method:        "GET",
			path:          "/api/v2/orders",
			expectedRoute: "prefix-route",
		},
		{
			name:        "no match",
			method:      "GET",
			path:        "/other/path",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			result, err := r.Match(req)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedRoute, result.Route.Name)
			}
		})
	}
}

func TestRouter_Match_WithMethods(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "get-only",
		Match: []config.RouteMatch{
			{
				URI:     &config.URIMatch{Prefix: "/api/"},
				Methods: []string{"GET"},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// GET should match
	req := httptest.NewRequest("GET", "/api/users", nil)
	result, err := r.Match(req)
	require.NoError(t, err)
	assert.Equal(t, "get-only", result.Route.Name)

	// POST should not match
	req = httptest.NewRequest("POST", "/api/users", nil)
	_, err = r.Match(req)
	assert.Error(t, err)
}

func TestRouter_Match_WithHeaders(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "header-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{Prefix: "/api/"},
				Headers: []config.HeaderMatch{
					{Name: "X-Custom", Exact: "value"},
				},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// With matching header
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("X-Custom", "value")
	result, err := r.Match(req)
	require.NoError(t, err)
	assert.Equal(t, "header-route", result.Route.Name)

	// Without matching header
	req = httptest.NewRequest("GET", "/api/users", nil)
	_, err = r.Match(req)
	assert.Error(t, err)
}

func TestRouter_Match_WithQueryParams(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "query-route",
		Match: []config.RouteMatch{
			{
				URI: &config.URIMatch{Prefix: "/api/"},
				QueryParams: []config.QueryParamMatch{
					{Name: "version", Exact: "v1"},
				},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// With matching query param
	req := httptest.NewRequest("GET", "/api/users?version=v1", nil)
	result, err := r.Match(req)
	require.NoError(t, err)
	assert.Equal(t, "query-route", result.Route.Name)

	// Without matching query param
	req = httptest.NewRequest("GET", "/api/users?version=v2", nil)
	_, err = r.Match(req)
	assert.Error(t, err)
}

func TestRouter_Match_WithPathParams(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "param-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Exact: "/users/{id}"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/users/123", nil)
	result, err := r.Match(req)
	require.NoError(t, err)
	assert.Equal(t, "param-route", result.Route.Name)
	assert.Equal(t, "123", result.PathParams["id"])
}

func TestRouter_Match_NoPathMatchers(t *testing.T) {
	t.Parallel()

	r := New()

	// Route with no path matchers matches all paths
	route := config.Route{
		Name: "catch-all",
		Match: []config.RouteMatch{
			{Methods: []string{"GET"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/any/path", nil)
	result, err := r.Match(req)
	require.NoError(t, err)
	assert.Equal(t, "catch-all", result.Route.Name)
}

func TestRouter_GetRoute(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "test-route",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Found
	result, exists := r.GetRoute("test-route")
	assert.True(t, exists)
	assert.Equal(t, "test-route", result.Name)

	// Not found
	_, exists = r.GetRoute("nonexistent")
	assert.False(t, exists)
}

func TestRouter_GetRoutes(t *testing.T) {
	t.Parallel()

	r := New()

	routes := []config.Route{
		{Name: "route1", Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend", Port: 8080}}}},
		{Name: "route2", Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend", Port: 8080}}}},
	}

	for _, route := range routes {
		err := r.AddRoute(route)
		require.NoError(t, err)
	}

	result := r.GetRoutes()
	assert.Len(t, result, 2)
}

func TestRouter_Clear(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "test-route",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	r.Clear()

	assert.Empty(t, r.routes)
	assert.Empty(t, r.routeMap)
}

func TestRouter_LoadRoutes(t *testing.T) {
	t.Parallel()

	r := New()

	// Add initial route
	err := r.AddRoute(config.Route{
		Name: "initial",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	})
	require.NoError(t, err)

	// Load new routes (should clear existing)
	routes := []config.Route{
		{Name: "route1", Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend", Port: 8080}}}},
		{Name: "route2", Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend", Port: 8080}}}},
	}

	err = r.LoadRoutes(routes)
	require.NoError(t, err)

	assert.Len(t, r.routes, 2)
	_, exists := r.GetRoute("initial")
	assert.False(t, exists)
}

func TestRouter_LoadRoutes_Error(t *testing.T) {
	t.Parallel()

	r := New()

	routes := []config.Route{
		{Name: "route1", Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend", Port: 8080}}}},
		{Name: "route1", Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend", Port: 8080}}}}, // Duplicate
	}

	err := r.LoadRoutes(routes)
	assert.Error(t, err)
}

func TestCalculatePriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		route   config.Route
		minPrio int
		maxPrio int
	}{
		{
			name: "exact match highest priority",
			route: config.Route{
				Match: []config.RouteMatch{
					{URI: &config.URIMatch{Exact: "/api/v1/users"}},
				},
			},
			minPrio: 1000,
		},
		{
			name: "prefix match medium priority",
			route: config.Route{
				Match: []config.RouteMatch{
					{URI: &config.URIMatch{Prefix: "/api/"}},
				},
			},
			minPrio: 500,
			maxPrio: 600,
		},
		{
			name: "regex match lower priority",
			route: config.Route{
				Match: []config.RouteMatch{
					{URI: &config.URIMatch{Regex: "^/api/.*"}},
				},
			},
			minPrio: 100,
			maxPrio: 200,
		},
		{
			name: "method restriction adds priority",
			route: config.Route{
				Match: []config.RouteMatch{
					{Methods: []string{"GET"}},
				},
			},
			minPrio: 50,
		},
		{
			name: "header restriction adds priority",
			route: config.Route{
				Match: []config.RouteMatch{
					{Headers: []config.HeaderMatch{{Name: "X-Custom"}}},
				},
			},
			minPrio: 10,
		},
		{
			name: "query restriction adds priority",
			route: config.Route{
				Match: []config.RouteMatch{
					{QueryParams: []config.QueryParamMatch{{Name: "id"}}},
				},
			},
			minPrio: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priority := calculatePriority(tt.route)
			assert.GreaterOrEqual(t, priority, tt.minPrio)
			if tt.maxPrio > 0 {
				assert.LessOrEqual(t, priority, tt.maxPrio)
			}
		})
	}
}

func TestRouter_RoutePriority(t *testing.T) {
	t.Parallel()

	r := New()

	// Add routes in reverse priority order
	routes := []config.Route{
		{
			Name: "prefix-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
		},
		{
			Name: "exact-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Exact: "/api/v1/users"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
		},
	}

	for _, route := range routes {
		err := r.AddRoute(route)
		require.NoError(t, err)
	}

	// Exact route should match first due to higher priority
	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	result, err := r.Match(req)
	require.NoError(t, err)
	assert.Equal(t, "exact-route", result.Route.Name)
}

func TestRouter_Concurrency(t *testing.T) {
	t.Parallel()

	r := New()

	// Add a route
	route := config.Route{
		Name: "test-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/api/"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}
	err := r.AddRoute(route)
	require.NoError(t, err)

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/api/users", nil)
			_, _ = r.Match(req)
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestRouter_CompileRoute_WithWildcard(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "wildcard-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/api/*"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1", nil)
	result, err := r.Match(req)
	require.NoError(t, err)
	assert.Equal(t, "wildcard-route", result.Route.Name)
}

func TestRouter_CompileRoute_InvalidHeaderMatcher(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "invalid-header-route",
		Match: []config.RouteMatch{
			{
				Headers: []config.HeaderMatch{
					{Name: "X-Custom", Regex: "[invalid"},
				},
			},
		},
	}

	err := r.AddRoute(route)
	assert.Error(t, err)
}

func TestRouter_CompileRoute_InvalidQueryMatcher(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.Route{
		Name: "invalid-query-route",
		Match: []config.RouteMatch{
			{
				QueryParams: []config.QueryParamMatch{
					{Name: "id", Regex: "[invalid"},
				},
			},
		},
	}

	err := r.AddRoute(route)
	assert.Error(t, err)
}

func BenchmarkRouter_Match(b *testing.B) {
	r := New()

	// Add multiple routes
	for i := 0; i < 100; i++ {
		route := config.Route{
			Name: "route-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v" + string(rune('0'+i%10)) + "/"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
		}
		_ = r.AddRoute(route)
	}

	req := httptest.NewRequest("GET", "/api/v5/users", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Match(req)
	}
}

func BenchmarkRouter_Match_ExactPath(b *testing.B) {
	r := New()

	route := config.Route{
		Name: "exact-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Exact: "/api/v1/users"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}
	_ = r.AddRoute(route)

	req := httptest.NewRequest("GET", "/api/v1/users", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Match(req)
	}
}

func createTestRequest(method, path string, headers http.Header) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		for _, val := range v {
			req.Header.Add(k, val)
		}
	}
	return req
}

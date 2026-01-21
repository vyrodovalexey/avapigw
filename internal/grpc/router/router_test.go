package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

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

	route := config.GRPCRoute{
		Name: "test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
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

	route := config.GRPCRoute{
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

	route := config.GRPCRoute{
		Name: "test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Regex: "[invalid"}},
		},
	}

	err := r.AddRoute(route)
	assert.Error(t, err)
}

func TestRouter_RemoveRoute(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
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

func TestRouter_Match_ExactService(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "exact-service",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.UserService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "exact-service", result.Route.Name)
	assert.Equal(t, "test.UserService", result.Service)
	assert.Equal(t, "GetUser", result.Method)

	// Should not match
	_, err = r.Match("/other.Service/GetUser", metadata.MD{})
	assert.Error(t, err)
}

func TestRouter_Match_PrefixService(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "prefix-service",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "prefix-service", result.Route.Name)

	result, err = r.Match("/test.OrderService/CreateOrder", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "prefix-service", result.Route.Name)

	// Should not match
	_, err = r.Match("/other.Service/GetUser", metadata.MD{})
	assert.Error(t, err)
}

func TestRouter_Match_RegexService(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "regex-service",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Regex: "^test\\..*Service$"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "regex-service", result.Route.Name)

	// Should not match
	_, err = r.Match("/test.UserController/GetUser", metadata.MD{})
	assert.Error(t, err)
}

func TestRouter_Match_ExactMethod(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "exact-method",
		Match: []config.GRPCRouteMatch{
			{
				Service: &config.StringMatch{Exact: "test.UserService"},
				Method:  &config.StringMatch{Exact: "GetUser"},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "exact-method", result.Route.Name)

	// Should not match different method
	_, err = r.Match("/test.UserService/CreateUser", metadata.MD{})
	assert.Error(t, err)
}

func TestRouter_Match_WildcardMethod(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "wildcard-method",
		Match: []config.GRPCRouteMatch{
			{
				Service: &config.StringMatch{Exact: "test.UserService"},
				Method:  &config.StringMatch{Exact: "*"},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match any method
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "wildcard-method", result.Route.Name)

	result, err = r.Match("/test.UserService/CreateUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "wildcard-method", result.Route.Name)
}

func TestRouter_Match_MetadataExact(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "metadata-exact",
		Match: []config.GRPCRouteMatch{
			{
				Service: &config.StringMatch{Prefix: "test."},
				Metadata: []config.MetadataMatch{
					{Name: "x-custom", Exact: "value"},
				},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match with correct metadata
	md := metadata.MD{"x-custom": []string{"value"}}
	result, err := r.Match("/test.UserService/GetUser", md)
	require.NoError(t, err)
	assert.Equal(t, "metadata-exact", result.Route.Name)

	// Should not match with wrong metadata value
	md = metadata.MD{"x-custom": []string{"wrong"}}
	_, err = r.Match("/test.UserService/GetUser", md)
	assert.Error(t, err)

	// Should not match without metadata
	_, err = r.Match("/test.UserService/GetUser", metadata.MD{})
	assert.Error(t, err)
}

func TestRouter_Match_MetadataPrefix(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "metadata-prefix",
		Match: []config.GRPCRouteMatch{
			{
				Service: &config.StringMatch{Prefix: "test."},
				Metadata: []config.MetadataMatch{
					{Name: "x-custom", Prefix: "val"},
				},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match with prefix
	md := metadata.MD{"x-custom": []string{"value123"}}
	result, err := r.Match("/test.UserService/GetUser", md)
	require.NoError(t, err)
	assert.Equal(t, "metadata-prefix", result.Route.Name)

	// Should not match without prefix
	md = metadata.MD{"x-custom": []string{"other"}}
	_, err = r.Match("/test.UserService/GetUser", md)
	assert.Error(t, err)
}

func TestRouter_Match_MetadataRegex(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "metadata-regex",
		Match: []config.GRPCRouteMatch{
			{
				Service: &config.StringMatch{Prefix: "test."},
				Metadata: []config.MetadataMatch{
					{Name: "x-custom", Regex: "^v[0-9]+$"},
				},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match with regex
	md := metadata.MD{"x-custom": []string{"v123"}}
	result, err := r.Match("/test.UserService/GetUser", md)
	require.NoError(t, err)
	assert.Equal(t, "metadata-regex", result.Route.Name)

	// Should not match without regex
	md = metadata.MD{"x-custom": []string{"version1"}}
	_, err = r.Match("/test.UserService/GetUser", md)
	assert.Error(t, err)
}

func TestRouter_Match_MetadataPresent(t *testing.T) {
	t.Parallel()

	r := New()

	present := true
	route := config.GRPCRoute{
		Name: "metadata-present",
		Match: []config.GRPCRouteMatch{
			{
				Service: &config.StringMatch{Prefix: "test."},
				Metadata: []config.MetadataMatch{
					{Name: "x-custom", Present: &present},
				},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match when header is present
	md := metadata.MD{"x-custom": []string{"any-value"}}
	result, err := r.Match("/test.UserService/GetUser", md)
	require.NoError(t, err)
	assert.Equal(t, "metadata-present", result.Route.Name)

	// Should not match when header is absent
	_, err = r.Match("/test.UserService/GetUser", metadata.MD{})
	assert.Error(t, err)
}

func TestRouter_Match_MetadataAbsent(t *testing.T) {
	t.Parallel()

	r := New()

	absent := true
	route := config.GRPCRoute{
		Name: "metadata-absent",
		Match: []config.GRPCRouteMatch{
			{
				Service: &config.StringMatch{Prefix: "test."},
				Metadata: []config.MetadataMatch{
					{Name: "x-internal", Absent: &absent},
				},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match when header is absent
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "metadata-absent", result.Route.Name)

	// Should not match when header is present
	md := metadata.MD{"x-internal": []string{"value"}}
	_, err = r.Match("/test.UserService/GetUser", md)
	assert.Error(t, err)
}

func TestRouter_Match_Authority(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "authority-match",
		Match: []config.GRPCRouteMatch{
			{
				Service:   &config.StringMatch{Prefix: "test."},
				Authority: &config.StringMatch{Exact: "api.example.com"},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match with correct authority
	md := metadata.MD{":authority": []string{"api.example.com"}}
	result, err := r.Match("/test.UserService/GetUser", md)
	require.NoError(t, err)
	assert.Equal(t, "authority-match", result.Route.Name)

	// Should not match with wrong authority
	md = metadata.MD{":authority": []string{"other.example.com"}}
	_, err = r.Match("/test.UserService/GetUser", md)
	assert.Error(t, err)
}

func TestRouter_Match_WithoutHeaders(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "without-headers",
		Match: []config.GRPCRouteMatch{
			{
				Service:        &config.StringMatch{Prefix: "test."},
				WithoutHeaders: []string{"x-internal"},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match when header is absent
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "without-headers", result.Route.Name)

	// Should not match when header is present
	md := metadata.MD{"x-internal": []string{"value"}}
	_, err = r.Match("/test.UserService/GetUser", md)
	assert.Error(t, err)
}

func TestRouter_Match_MultipleConditions_AND(t *testing.T) {
	t.Parallel()

	r := New()

	// Multiple conditions within a single match block use AND semantics
	route := config.GRPCRoute{
		Name: "and-conditions",
		Match: []config.GRPCRouteMatch{
			{
				Service: &config.StringMatch{Exact: "test.UserService"},
				Method:  &config.StringMatch{Exact: "GetUser"},
				Metadata: []config.MetadataMatch{
					{Name: "x-custom", Exact: "value"},
				},
			},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match when all conditions are met
	md := metadata.MD{"x-custom": []string{"value"}}
	result, err := r.Match("/test.UserService/GetUser", md)
	require.NoError(t, err)
	assert.Equal(t, "and-conditions", result.Route.Name)

	// Should not match when service doesn't match
	_, err = r.Match("/other.Service/GetUser", md)
	assert.Error(t, err)

	// Should not match when method doesn't match
	_, err = r.Match("/test.UserService/CreateUser", md)
	assert.Error(t, err)

	// Should not match when metadata doesn't match
	_, err = r.Match("/test.UserService/GetUser", metadata.MD{})
	assert.Error(t, err)
}

func TestRouter_Match_MultipleMatchBlocks_OR(t *testing.T) {
	t.Parallel()

	r := New()

	// Multiple match blocks use OR semantics
	route := config.GRPCRoute{
		Name: "or-conditions",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.UserService"}},
			{Service: &config.StringMatch{Exact: "test.OrderService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	// Should match first condition
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "or-conditions", result.Route.Name)

	// Should match second condition
	result, err = r.Match("/test.OrderService/CreateOrder", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "or-conditions", result.Route.Name)

	// Should not match neither condition
	_, err = r.Match("/test.ProductService/GetProduct", metadata.MD{})
	assert.Error(t, err)
}

func TestRouter_Match_NoMatchers(t *testing.T) {
	t.Parallel()

	r := New()

	// Route with no matchers matches everything
	route := config.GRPCRoute{
		Name: "catch-all",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	result, err := r.Match("/any.Service/AnyMethod", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "catch-all", result.Route.Name)
}

func TestRouter_Match_Priority(t *testing.T) {
	t.Parallel()

	r := New()

	// Add routes in reverse priority order
	routes := []config.GRPCRoute{
		{
			Name: "prefix-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Prefix: "test."}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
		},
		{
			Name: "exact-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.UserService"}},
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
	result, err := r.Match("/test.UserService/GetUser", metadata.MD{})
	require.NoError(t, err)
	assert.Equal(t, "exact-route", result.Route.Name)
}

func TestRouter_Match_NoMatchingRoute(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "specific-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.UserService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}

	err := r.AddRoute(route)
	require.NoError(t, err)

	_, err = r.Match("/other.Service/Method", metadata.MD{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no matching")
}

func TestRouter_GetRoute(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
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

	routes := []config.GRPCRoute{
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

	route := config.GRPCRoute{
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
	err := r.AddRoute(config.GRPCRoute{
		Name: "initial",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	})
	require.NoError(t, err)

	// Load new routes (should clear existing)
	routes := []config.GRPCRoute{
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

	routes := []config.GRPCRoute{
		{Name: "route1", Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend", Port: 8080}}}},
		{Name: "route1", Route: []config.RouteDestination{{Destination: config.Destination{Host: "backend", Port: 8080}}}}, // Duplicate
	}

	err := r.LoadRoutes(routes)
	assert.Error(t, err)
}

func TestRouter_RouteCount(t *testing.T) {
	t.Parallel()

	r := New()
	assert.Equal(t, 0, r.RouteCount())

	err := r.AddRoute(config.GRPCRoute{
		Name: "route1",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, r.RouteCount())

	err = r.AddRoute(config.GRPCRoute{
		Name: "route2",
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, r.RouteCount())
}

func TestCalculatePriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		route   config.GRPCRoute
		minPrio int
	}{
		{
			name: "exact service highest priority",
			route: config.GRPCRoute{
				Match: []config.GRPCRouteMatch{
					{Service: &config.StringMatch{Exact: "test.UserService"}},
				},
			},
			minPrio: 1000,
		},
		{
			name: "prefix service medium priority",
			route: config.GRPCRoute{
				Match: []config.GRPCRouteMatch{
					{Service: &config.StringMatch{Prefix: "test."}},
				},
			},
			minPrio: 500,
		},
		{
			name: "regex service lower priority",
			route: config.GRPCRoute{
				Match: []config.GRPCRouteMatch{
					{Service: &config.StringMatch{Regex: "^test\\..*"}},
				},
			},
			minPrio: 100,
		},
		{
			name: "exact method adds priority",
			route: config.GRPCRoute{
				Match: []config.GRPCRouteMatch{
					{Method: &config.StringMatch{Exact: "GetUser"}},
				},
			},
			minPrio: 500,
		},
		{
			name: "metadata adds priority",
			route: config.GRPCRoute{
				Match: []config.GRPCRouteMatch{
					{Metadata: []config.MetadataMatch{{Name: "x-custom"}}},
				},
			},
			minPrio: 10,
		},
		{
			name: "without headers adds priority",
			route: config.GRPCRoute{
				Match: []config.GRPCRouteMatch{
					{WithoutHeaders: []string{"x-internal"}},
				},
			},
			minPrio: 5,
		},
		{
			name: "authority adds priority",
			route: config.GRPCRoute{
				Match: []config.GRPCRouteMatch{
					{Authority: &config.StringMatch{Exact: "api.example.com"}},
				},
			},
			minPrio: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priority := calculatePriority(tt.route)
			assert.GreaterOrEqual(t, priority, tt.minPrio)
		})
	}
}

func TestRouter_Concurrency(t *testing.T) {
	t.Parallel()

	r := New()

	// Add a route
	route := config.GRPCRoute{
		Name: "test-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Prefix: "test."}},
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
			_, _ = r.Match("/test.UserService/GetUser", metadata.MD{})
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestRouter_CompileRoute_InvalidMetadataRegex(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "invalid-metadata-route",
		Match: []config.GRPCRouteMatch{
			{
				Metadata: []config.MetadataMatch{
					{Name: "x-custom", Regex: "[invalid"},
				},
			},
		},
	}

	err := r.AddRoute(route)
	assert.Error(t, err)
}

func TestRouter_CompileRoute_InvalidAuthorityRegex(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "invalid-authority-route",
		Match: []config.GRPCRouteMatch{
			{
				Authority: &config.StringMatch{Regex: "[invalid"},
			},
		},
	}

	err := r.AddRoute(route)
	assert.Error(t, err)
}

func TestRouter_CompileRoute_InvalidMethodRegex(t *testing.T) {
	t.Parallel()

	r := New()

	route := config.GRPCRoute{
		Name: "invalid-method-route",
		Match: []config.GRPCRouteMatch{
			{
				Method: &config.StringMatch{Regex: "[invalid"},
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
		route := config.GRPCRoute{
			Name: "route-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Prefix: "test.v" + string(rune('0'+i%10)) + "."}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend", Port: 8080}},
			},
		}
		_ = r.AddRoute(route)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Match("/test.v5.UserService/GetUser", metadata.MD{})
	}
}

func BenchmarkRouter_Match_ExactService(b *testing.B) {
	r := New()

	route := config.GRPCRoute{
		Name: "exact-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "test.UserService"}},
		},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: "backend", Port: 8080}},
		},
	}
	_ = r.AddRoute(route)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Match("/test.UserService/GetUser", metadata.MD{})
	}
}

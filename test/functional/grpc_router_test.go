//go:build functional
// +build functional

package functional

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
)

func TestFunctional_GRPCRouter_ServiceMatching(t *testing.T) {
	t.Parallel()

	t.Run("exact service match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "exact-service-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match exact service
		result, err := r.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "exact-service-route", result.Route.Name)
		assert.Equal(t, "api.v1.TestService", result.Service)
		assert.Equal(t, "Unary", result.Method)

		// Should not match different service
		_, err = r.Match("/api.v2.TestService/Unary", nil)
		require.Error(t, err)
	})

	t.Run("prefix service match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "prefix-service-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: "api.v1"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match services with prefix
		result, err := r.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "prefix-service-route", result.Route.Name)

		result, err = r.Match("/api.v1.UserService/GetUser", nil)
		require.NoError(t, err)
		assert.Equal(t, "prefix-service-route", result.Route.Name)

		// Should not match different prefix
		_, err = r.Match("/api.v2.TestService/Unary", nil)
		require.Error(t, err)
	})

	t.Run("regex service match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "regex-service-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Regex: `^api\.v[0-9]+\..*Service$`},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match regex pattern
		result, err := r.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "regex-service-route", result.Route.Name)

		result, err = r.Match("/api.v2.UserService/GetUser", nil)
		require.NoError(t, err)
		assert.Equal(t, "regex-service-route", result.Route.Name)

		// Should not match non-matching pattern
		_, err = r.Match("/api.v1.TestHandler/Handle", nil)
		require.Error(t, err)
	})

	t.Run("wildcard service match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "wildcard-service-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "*"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match any service
		result, err := r.Match("/any.Service/AnyMethod", nil)
		require.NoError(t, err)
		assert.Equal(t, "wildcard-service-route", result.Route.Name)
	})
}

func TestFunctional_GRPCRouter_MethodMatching(t *testing.T) {
	t.Parallel()

	t.Run("exact method match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "exact-method-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
					Method:  &config.StringMatch{Exact: "Unary"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match exact method
		result, err := r.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "exact-method-route", result.Route.Name)

		// Should not match different method
		_, err = r.Match("/api.v1.TestService/ServerStream", nil)
		require.Error(t, err)
	})

	t.Run("prefix method match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "prefix-method-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
					Method:  &config.StringMatch{Prefix: "Get"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match methods with prefix
		result, err := r.Match("/api.v1.TestService/GetUser", nil)
		require.NoError(t, err)
		assert.Equal(t, "prefix-method-route", result.Route.Name)

		result, err = r.Match("/api.v1.TestService/GetItems", nil)
		require.NoError(t, err)
		assert.Equal(t, "prefix-method-route", result.Route.Name)

		// Should not match different prefix
		_, err = r.Match("/api.v1.TestService/CreateUser", nil)
		require.Error(t, err)
	})

	t.Run("regex method match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "regex-method-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
					Method:  &config.StringMatch{Regex: `^(Get|List|Find).*$`},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match regex pattern
		methods := []string{"GetUser", "ListUsers", "FindByID"}
		for _, method := range methods {
			result, err := r.Match("/api.v1.TestService/"+method, nil)
			require.NoError(t, err, "Method %s should match", method)
			assert.Equal(t, "regex-method-route", result.Route.Name)
		}

		// Should not match non-matching pattern
		_, err = r.Match("/api.v1.TestService/CreateUser", nil)
		require.Error(t, err)
	})
}

func TestFunctional_GRPCRouter_MetadataMatching(t *testing.T) {
	t.Parallel()

	t.Run("exact metadata match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "metadata-exact-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: ""},
					Metadata: []config.MetadataMatch{
						{Name: "x-api-version", Exact: "v1"},
					},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match with correct metadata
		md := metadata.Pairs("x-api-version", "v1")
		result, err := r.Match("/api.v1.TestService/Unary", md)
		require.NoError(t, err)
		assert.Equal(t, "metadata-exact-route", result.Route.Name)

		// Should not match with wrong metadata value
		md = metadata.Pairs("x-api-version", "v2")
		_, err = r.Match("/api.v1.TestService/Unary", md)
		require.Error(t, err)

		// Should not match without metadata
		_, err = r.Match("/api.v1.TestService/Unary", nil)
		require.Error(t, err)
	})

	t.Run("prefix metadata match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "metadata-prefix-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: ""},
					Metadata: []config.MetadataMatch{
						{Name: "authorization", Prefix: "Bearer "},
					},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match with correct prefix
		md := metadata.Pairs("authorization", "Bearer token123")
		result, err := r.Match("/api.v1.TestService/Unary", md)
		require.NoError(t, err)
		assert.Equal(t, "metadata-prefix-route", result.Route.Name)

		// Should not match with wrong prefix
		md = metadata.Pairs("authorization", "Basic token123")
		_, err = r.Match("/api.v1.TestService/Unary", md)
		require.Error(t, err)
	})

	t.Run("present metadata match", func(t *testing.T) {
		t.Parallel()

		present := true
		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "metadata-present-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: ""},
					Metadata: []config.MetadataMatch{
						{Name: "x-request-id", Present: &present},
					},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match when metadata is present
		md := metadata.Pairs("x-request-id", "any-value")
		result, err := r.Match("/api.v1.TestService/Unary", md)
		require.NoError(t, err)
		assert.Equal(t, "metadata-present-route", result.Route.Name)

		// Should not match when metadata is absent
		_, err = r.Match("/api.v1.TestService/Unary", nil)
		require.Error(t, err)
	})

	t.Run("absent metadata match", func(t *testing.T) {
		t.Parallel()

		absent := true
		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "metadata-absent-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: ""},
					Metadata: []config.MetadataMatch{
						{Name: "x-internal-only", Absent: &absent},
					},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match when metadata is absent
		result, err := r.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "metadata-absent-route", result.Route.Name)

		// Should not match when metadata is present
		md := metadata.Pairs("x-internal-only", "true")
		_, err = r.Match("/api.v1.TestService/Unary", md)
		require.Error(t, err)
	})

	t.Run("multiple metadata conditions", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "multi-metadata-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: ""},
					Metadata: []config.MetadataMatch{
						{Name: "x-api-version", Exact: "v1"},
						{Name: "x-tenant-id", Prefix: "tenant-"},
					},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match when all metadata conditions are met
		md := metadata.Pairs(
			"x-api-version", "v1",
			"x-tenant-id", "tenant-123",
		)
		result, err := r.Match("/api.v1.TestService/Unary", md)
		require.NoError(t, err)
		assert.Equal(t, "multi-metadata-route", result.Route.Name)

		// Should not match when only some conditions are met
		md = metadata.Pairs("x-api-version", "v1")
		_, err = r.Match("/api.v1.TestService/Unary", md)
		require.Error(t, err)
	})
}

func TestFunctional_GRPCRouter_Priority(t *testing.T) {
	t.Parallel()

	t.Run("exact match has higher priority than prefix", func(t *testing.T) {
		t.Parallel()

		r := router.New()

		// Add prefix route first
		err := r.AddRoute(config.GRPCRoute{
			Name: "prefix-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: "api.v1"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Add exact route second
		err = r.AddRoute(config.GRPCRoute{
			Name: "exact-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		})
		require.NoError(t, err)

		// Exact route should match for exact service
		result, err := r.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "exact-route", result.Route.Name)

		// Prefix route should match for other services
		result, err = r.Match("/api.v1.UserService/GetUser", nil)
		require.NoError(t, err)
		assert.Equal(t, "prefix-route", result.Route.Name)
	})

	t.Run("more specific match has higher priority", func(t *testing.T) {
		t.Parallel()

		r := router.New()

		// Add service-only route
		err := r.AddRoute(config.GRPCRoute{
			Name: "service-only-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Add service+method route
		err = r.AddRoute(config.GRPCRoute{
			Name: "service-method-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
					Method:  &config.StringMatch{Exact: "Unary"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		})
		require.NoError(t, err)

		// More specific route should match
		result, err := r.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "service-method-route", result.Route.Name)

		// Less specific route should match for other methods
		result, err = r.Match("/api.v1.TestService/ServerStream", nil)
		require.NoError(t, err)
		assert.Equal(t, "service-only-route", result.Route.Name)
	})

	t.Run("metadata adds to priority", func(t *testing.T) {
		t.Parallel()

		r := router.New()

		// Add route without metadata
		err := r.AddRoute(config.GRPCRoute{
			Name: "no-metadata-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Add route with metadata
		err = r.AddRoute(config.GRPCRoute{
			Name: "with-metadata-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
					Metadata: []config.MetadataMatch{
						{Name: "x-api-version", Exact: "v1"},
					},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		})
		require.NoError(t, err)

		// Route with metadata should match when metadata is present
		md := metadata.Pairs("x-api-version", "v1")
		result, err := r.Match("/api.v1.TestService/Unary", md)
		require.NoError(t, err)
		assert.Equal(t, "with-metadata-route", result.Route.Name)

		// Route without metadata should match when metadata is absent
		result, err = r.Match("/api.v1.TestService/Unary", nil)
		require.NoError(t, err)
		assert.Equal(t, "no-metadata-route", result.Route.Name)
	})
}

func TestFunctional_GRPCRouter_NoMatch(t *testing.T) {
	t.Parallel()

	t.Run("no routes returns error", func(t *testing.T) {
		t.Parallel()

		r := router.New()

		_, err := r.Match("/api.v1.TestService/Unary", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no matching")
	})

	t.Run("no matching route returns error", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "specific-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.SpecificService"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		_, err = r.Match("/api.v1.OtherService/Method", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no matching")
	})

	t.Run("duplicate route name returns error", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "test-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: "api.v1"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Adding route with same name should fail
		err = r.AddRoute(config.GRPCRoute{
			Name: "test-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: "api.v2"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate")
	})

	t.Run("remove route", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "removable-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: "api.v1"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Route should exist
		route, exists := r.GetRoute("removable-route")
		require.True(t, exists)
		require.NotNil(t, route)

		// Remove route
		err = r.RemoveRoute("removable-route")
		require.NoError(t, err)

		// Route should not exist
		_, exists = r.GetRoute("removable-route")
		assert.False(t, exists)

		// Request should not match
		_, err = r.Match("/api.v1.TestService/Unary", nil)
		require.Error(t, err)
	})

	t.Run("clear routes", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.GRPCRoute{
			Name: "route1",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Prefix: "api.v1"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		err = r.AddRoute(config.GRPCRoute{
			Name: "route2",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Prefix: "api.v2"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		})
		require.NoError(t, err)

		// Should have 2 routes
		routes := r.GetRoutes()
		assert.Len(t, routes, 2)

		// Clear routes
		r.Clear()

		// Should have 0 routes
		routes = r.GetRoutes()
		assert.Len(t, routes, 0)
	})
}

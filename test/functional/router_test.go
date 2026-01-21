//go:build functional
// +build functional

package functional

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

func TestFunctional_Router_RouteMatching(t *testing.T) {
	t.Parallel()

	t.Run("exact match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "exact-route",
			Match: []config.RouteMatch{
				{
					URI: &config.URIMatch{Exact: "/api/v1/health"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match exact path
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "exact-route", result.Route.Name)

		// Should not match different path
		req = httptest.NewRequest(http.MethodGet, "/api/v1/health/check", nil)
		_, err = r.Match(req)
		require.Error(t, err)
	})

	t.Run("prefix match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "prefix-route",
			Match: []config.RouteMatch{
				{
					URI: &config.URIMatch{Prefix: "/api/v1/items"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match prefix
		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "prefix-route", result.Route.Name)

		// Should match path with suffix
		req = httptest.NewRequest(http.MethodGet, "/api/v1/items/123", nil)
		result, err = r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "prefix-route", result.Route.Name)

		// Should not match different prefix
		req = httptest.NewRequest(http.MethodGet, "/api/v2/items", nil)
		_, err = r.Match(req)
		require.Error(t, err)
	})

	t.Run("regex match", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "regex-route",
			Match: []config.RouteMatch{
				{
					URI: &config.URIMatch{Regex: `^/api/v[0-9]+/users/[0-9]+$`},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match regex
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/123", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "regex-route", result.Route.Name)

		// Should match different version
		req = httptest.NewRequest(http.MethodGet, "/api/v2/users/456", nil)
		result, err = r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "regex-route", result.Route.Name)

		// Should not match non-numeric user ID
		req = httptest.NewRequest(http.MethodGet, "/api/v1/users/abc", nil)
		_, err = r.Match(req)
		require.Error(t, err)
	})

	t.Run("method matching", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "get-only-route",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/readonly"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match GET
		req := httptest.NewRequest(http.MethodGet, "/api/readonly", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "get-only-route", result.Route.Name)

		// Should not match POST
		req = httptest.NewRequest(http.MethodPost, "/api/readonly", nil)
		_, err = r.Match(req)
		require.Error(t, err)
	})

	t.Run("multiple methods", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "crud-route",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/items"},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		methods := []string{"GET", "POST", "PUT", "DELETE"}
		for _, method := range methods {
			req := httptest.NewRequest(method, "/api/items", nil)
			result, err := r.Match(req)
			require.NoError(t, err, "Method %s should match", method)
			assert.Equal(t, "crud-route", result.Route.Name)
		}

		// PATCH should not match
		req := httptest.NewRequest(http.MethodPatch, "/api/items", nil)
		_, err = r.Match(req)
		require.Error(t, err)
	})

	t.Run("header matching - exact", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "header-route",
			Match: []config.RouteMatch{
				{
					URI: &config.URIMatch{Prefix: "/api"},
					Headers: []config.HeaderMatch{
						{Name: "X-API-Version", Exact: "v1"},
					},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match with correct header
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("X-API-Version", "v1")
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "header-route", result.Route.Name)

		// Should not match with wrong header value
		req = httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("X-API-Version", "v2")
		_, err = r.Match(req)
		require.Error(t, err)

		// Should not match without header
		req = httptest.NewRequest(http.MethodGet, "/api/test", nil)
		_, err = r.Match(req)
		require.Error(t, err)
	})

	t.Run("query parameter matching", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "query-route",
			Match: []config.RouteMatch{
				{
					URI: &config.URIMatch{Prefix: "/api/search"},
					QueryParams: []config.QueryParamMatch{
						{Name: "type", Exact: "advanced"},
					},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Should match with correct query param
		req := httptest.NewRequest(http.MethodGet, "/api/search?type=advanced", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "query-route", result.Route.Name)

		// Should not match with wrong query param value
		req = httptest.NewRequest(http.MethodGet, "/api/search?type=basic", nil)
		_, err = r.Match(req)
		require.Error(t, err)
	})

	t.Run("route priority - exact over prefix", func(t *testing.T) {
		t.Parallel()

		r := router.New()

		// Add prefix route first
		err := r.AddRoute(config.Route{
			Name: "prefix-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Add exact route second
		err = r.AddRoute(config.Route{
			Name: "exact-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Exact: "/api/v1/health"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		})
		require.NoError(t, err)

		// Exact route should match for exact path
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "exact-route", result.Route.Name)

		// Prefix route should match for other paths
		req = httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		result, err = r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "prefix-route", result.Route.Name)
	})

	t.Run("route priority - longer prefix over shorter", func(t *testing.T) {
		t.Parallel()

		r := router.New()

		// Add shorter prefix first
		err := r.AddRoute(config.Route{
			Name: "short-prefix",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Add longer prefix second
		err = r.AddRoute(config.Route{
			Name: "long-prefix",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1/items"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8081}},
			},
		})
		require.NoError(t, err)

		// Longer prefix should match
		req := httptest.NewRequest(http.MethodGet, "/api/v1/items/123", nil)
		result, err := r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "long-prefix", result.Route.Name)

		// Shorter prefix should match for other paths
		req = httptest.NewRequest(http.MethodGet, "/api/v2/users", nil)
		result, err = r.Match(req)
		require.NoError(t, err)
		assert.Equal(t, "short-prefix", result.Route.Name)
	})

	t.Run("duplicate route name error", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "test-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		// Adding route with same name should fail
		err = r.AddRoute(config.Route{
			Name: "test-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v2"}},
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
		err := r.AddRoute(config.Route{
			Name: "removable-route",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/removable"}},
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
		req := httptest.NewRequest(http.MethodGet, "/api/removable", nil)
		_, err = r.Match(req)
		require.Error(t, err)
	})

	t.Run("clear routes", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "route1",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v1"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		})
		require.NoError(t, err)

		err = r.AddRoute(config.Route{
			Name: "route2",
			Match: []config.RouteMatch{
				{URI: &config.URIMatch{Prefix: "/api/v2"}},
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

	t.Run("load routes from config", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		routes := []config.Route{
			{
				Name: "route1",
				Match: []config.RouteMatch{
					{URI: &config.URIMatch{Prefix: "/api/v1"}},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8080}},
				},
			},
			{
				Name: "route2",
				Match: []config.RouteMatch{
					{URI: &config.URIMatch{Prefix: "/api/v2"}},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "localhost", Port: 8081}},
				},
			},
		}

		err := r.LoadRoutes(routes)
		require.NoError(t, err)

		loadedRoutes := r.GetRoutes()
		assert.Len(t, loadedRoutes, 2)
	})
}

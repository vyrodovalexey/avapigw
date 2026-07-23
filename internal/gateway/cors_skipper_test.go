// Package gateway tests for the route-level CORS precedence skipper.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// newSkipperHTTPRouter loads one route with route-level CORS and one
// without.
func newSkipperHTTPRouter(t *testing.T) *router.Router {
	t.Helper()
	r := router.New()
	require.NoError(t, r.LoadRoutes([]config.Route{
		{
			Name: "with-cors",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/cors/"},
					Methods: []string{"GET", "OPTIONS"},
				},
			},
			CORS: &config.CORSConfig{AllowOrigins: []string{"https://a.example.com"}},
		},
		{
			Name: "without-cors",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/plain/"},
					Methods: []string{"GET", "OPTIONS"},
				},
			},
		},
	}))
	return r
}

func TestNewRouteCORSSkipper_HTTPMatrix(t *testing.T) {
	skip := NewRouteCORSSkipper(newSkipperHTTPRouter(t), nil, "/graphql")

	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{name: "route-CORS preflight skipped", method: http.MethodOptions, path: "/cors/items", want: true},
		{name: "route-CORS GET skipped", method: http.MethodGet, path: "/cors/items", want: true},
		{name: "plain route not skipped", method: http.MethodGet, path: "/plain/items", want: false},
		{name: "plain preflight not skipped", method: http.MethodOptions, path: "/plain/items", want: false},
		{name: "unmatched not skipped", method: http.MethodGet, path: "/none", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			assert.Equal(t, tt.want, skip(req))
		})
	}
}

func TestNewRouteCORSSkipper_NilRouters(t *testing.T) {
	skip := NewRouteCORSSkipper(nil, nil, "/graphql")
	req := httptest.NewRequest(http.MethodOptions, "/anything", nil)
	assert.False(t, skip(req), "nil routers must never skip (global CORS applies)")
}

func TestNewRouteCORSSkipper_GraphQLPath(t *testing.T) {
	gql := graphqlrouter.New()
	require.NoError(t, gql.LoadRoutes([]config.GraphQLRoute{
		{
			Name:  "gql-cors",
			Match: []config.GraphQLRouteMatch{{Path: &config.StringMatch{Exact: "/graphql"}}},
			Route: []config.RouteDestination{{Destination: config.Destination{Host: "b"}}},
			CORS:  &config.CORSConfig{AllowOrigins: []string{"https://gql.example.com"}},
		},
	}))

	skip := NewRouteCORSSkipper(newSkipperHTTPRouter(t), gql, "/graphql")

	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	assert.True(t, skip(req), "GraphQL route with CORS must be skipped")

	// The graphql path check must not shadow HTTP matching elsewhere.
	req = httptest.NewRequest(http.MethodGet, "/cors/x", nil)
	assert.True(t, skip(req))
}

func TestNewRouteCORSSkipper_GraphQLNoCORSOrNoMatch(t *testing.T) {
	gql := graphqlrouter.New()
	require.NoError(t, gql.LoadRoutes([]config.GraphQLRoute{
		{
			Name:  "gql-plain",
			Match: []config.GraphQLRouteMatch{{Path: &config.StringMatch{Exact: "/graphql"}}},
			Route: []config.RouteDestination{{Destination: config.Destination{Host: "b"}}},
		},
	}))

	skip := NewRouteCORSSkipper(nil, gql, "/graphql")

	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	assert.False(t, skip(req), "GraphQL route without CORS keeps global behavior")

	// Empty GraphQL router: no match -> not skipped.
	emptySkip := NewRouteCORSSkipper(nil, graphqlrouter.New(), "/graphql")
	assert.False(t, emptySkip(req))
}

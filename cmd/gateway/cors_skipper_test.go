// Package main tests for route-level CORS precedence over the global CORS
// middleware (newRouteCORSSkipper + buildMiddlewareChain wiring).
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// corsPrecedenceSpec builds a gateway spec with a global * CORS policy, a
// route WITH route-level CORS, and a route WITHOUT.
func corsPrecedenceSpec() *config.GatewaySpec {
	return &config.GatewaySpec{
		CORS: &config.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{"GET", "POST", "OPTIONS"},
			AllowHeaders: []string{"Content-Type"},
			MaxAge:       86400,
		},
		Routes: []config.Route{
			{
				Name: "route-with-cors",
				Match: []config.RouteMatch{
					{
						URI:     &config.URIMatch{Prefix: "/api/v1/cors/"},
						Methods: []string{"GET", "POST", "OPTIONS"},
					},
				},
				CORS: &config.CORSConfig{
					AllowOrigins: []string{"https://cors-test.example.com"},
					AllowMethods: []string{"GET", "POST", "OPTIONS"},
					AllowHeaders: []string{"Content-Type", "Authorization"},
					MaxAge:       3600,
				},
			},
			{
				Name: "route-without-cors",
				Match: []config.RouteMatch{
					{
						URI:     &config.URIMatch{Prefix: "/api/v1/plain/"},
						Methods: []string{"GET", "OPTIONS"},
					},
				},
			},
		},
	}
}

// newCORSPrecedenceHandler composes the production layering for the CORS
// path: the GLOBAL CORS middleware (with the route skipper) wrapping a
// route dispatcher that applies each matched route's middleware chain —
// exactly the global-chain -> reverse-proxy -> route-chain nesting of the
// real gateway.
func newCORSPrecedenceHandler(t *testing.T, spec *config.GatewaySpec) http.Handler {
	t.Helper()

	r := router.New()
	require.NoError(t, r.LoadRoutes(spec.Routes))

	mgr := gateway.NewRouteMiddlewareManager(spec, observability.NopLogger())

	// Terminal handler standing in for the proxied backend; emits its own
	// permissive CORS grant to prove authority-stripping still works.
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("X-Backend-Reached", "true")
		w.WriteHeader(http.StatusOK)
	})

	// Route dispatcher mirroring proxy.ServeHTTP's route-chain application.
	dispatcher := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		result, err := r.Match(req)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		mgr.ApplyMiddleware(terminal, &result.Route.Config).ServeHTTP(w, req)
	})

	// Same global CORS wrapping as buildMiddlewareChain (CORS section).
	skip := gateway.NewRouteCORSSkipper(r, nil, "/graphql")
	return middleware.CORSFromConfigWithSkipper(spec.CORS, skip)(dispatcher)
}

// preflightRequest builds an OPTIONS preflight for the given path/origin.
func preflightRequest(path, origin string) *http.Request {
	req := httptest.NewRequest(http.MethodOptions, path, nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	return req
}

// TestCORSPrecedence_Matrix is the route-vs-global precedence matrix
// through the production layering (fix for "route-level CORS shadowed by
// global * CORS on preflight").
func TestCORSPrecedence_Matrix(t *testing.T) {
	handler := newCORSPrecedenceHandler(t, corsPrecedenceSpec())

	t.Run("route CORS route: allowed origin preflight answered by ROUTE policy", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, preflightRequest("/api/v1/cors/items", "https://cors-test.example.com"))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://cors-test.example.com",
			rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "3600", rec.Header().Get("Access-Control-Max-Age"),
			"ROUTE maxAge must win over the global 86400")
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Authorization",
			"ROUTE header set must win")
		assert.Empty(t, rec.Header().Get("X-Backend-Reached"),
			"preflight must never reach the terminal handler")
	})

	t.Run("route CORS route: denied origin gets NO grant despite global *", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, preflightRequest("/api/v1/cors/items", "https://evil.example.org"))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"),
			"the global * layer must NOT answer preflight for a route with its own CORS policy")
	})

	t.Run("route CORS route: actual request carries route grant only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/cors/items", nil)
		req.Header.Set("Origin", "https://cors-test.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "true", rec.Header().Get("X-Backend-Reached"))
		assert.Equal(t, []string{"https://cors-test.example.com"},
			rec.Header().Values("Access-Control-Allow-Origin"),
			"single grant: backend * stripped, route grant applied, global layer silent")
	})

	t.Run("route CORS route: actual request denied origin gets no grant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/cors/items", nil)
		req.Header.Set("Origin", "https://evil.example.org")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"),
			"backend grant must be stripped; global * must not re-grant a route-denied origin")
	})

	t.Run("no-route-CORS route: global answers preflight (any origin)", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, preflightRequest("/api/v1/plain/items", "https://anywhere.example.net"))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://anywhere.example.net",
			rec.Header().Get("Access-Control-Allow-Origin"),
			"global * policy must keep answering preflight for routes without route CORS")
		assert.Equal(t, "86400", rec.Header().Get("Access-Control-Max-Age"))
	})

	t.Run("no-route-CORS route: actual request gets global grant with authority", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/plain/items", nil)
		req.Header.Set("Origin", "https://anywhere.example.net")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []string{"https://anywhere.example.net"},
			rec.Header().Values("Access-Control-Allow-Origin"),
			"authority semantics preserved: exactly one grant, backend headers stripped")
	})

	t.Run("unmatched path: global answers preflight", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, preflightRequest("/no-such-route", "https://anywhere.example.net"))

		assert.Equal(t, http.StatusNoContent, rec.Code,
			"unmatched preflight keeps the legacy global behavior")
		assert.Equal(t, "https://anywhere.example.net",
			rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

// TestNewRouteCORSSkipper_HTTPRoutes covers the skipper predicate directly.
func TestNewRouteCORSSkipper_HTTPRoutes(t *testing.T) {
	spec := corsPrecedenceSpec()
	r := router.New()
	require.NoError(t, r.LoadRoutes(spec.Routes))

	skip := gateway.NewRouteCORSSkipper(r, nil, "/graphql")

	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{name: "route with CORS preflight", method: http.MethodOptions, path: "/api/v1/cors/x", want: true},
		{name: "route with CORS GET", method: http.MethodGet, path: "/api/v1/cors/x", want: true},
		{name: "route without CORS", method: http.MethodGet, path: "/api/v1/plain/x", want: false},
		{name: "unmatched path", method: http.MethodGet, path: "/nope", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			assert.Equal(t, tt.want, skip(req))
		})
	}
}

// TestNewRouteCORSSkipper_NilRouter verifies nil-safety.
func TestNewRouteCORSSkipper_NilRouter(t *testing.T) {
	skip := gateway.NewRouteCORSSkipper(nil, nil, "/graphql")
	req := httptest.NewRequest(http.MethodGet, "/any", nil)
	assert.False(t, skip(req))
}

// TestNewRouteCORSSkipper_GraphQLRoutes verifies GraphQL endpoint requests
// consult the GraphQL router's route-level CORS.
func TestNewRouteCORSSkipper_GraphQLRoutes(t *testing.T) {
	gqlRouter := graphqlrouter.New()
	require.NoError(t, gqlRouter.LoadRoutes([]config.GraphQLRoute{
		{
			Name:  "gql-with-cors",
			Match: []config.GraphQLRouteMatch{{Path: &config.StringMatch{Exact: "/graphql"}}},
			Route: []config.RouteDestination{{Destination: config.Destination{Host: "gql-backend"}}},
			CORS: &config.CORSConfig{
				AllowOrigins: []string{"https://gql.example.com"},
			},
		},
	}))

	skip := gateway.NewRouteCORSSkipper(router.New(), gqlRouter, "/graphql")

	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	assert.True(t, skip(req), "GraphQL route with CORS must be skipped by the global layer")

	req = httptest.NewRequest(http.MethodGet, "/other", nil)
	assert.False(t, skip(req))
}

// TestNewRouteCORSSkipper_GraphQLWithoutCORS verifies GraphQL routes
// without route CORS keep the global behavior.
func TestNewRouteCORSSkipper_GraphQLWithoutCORS(t *testing.T) {
	gqlRouter := graphqlrouter.New()
	require.NoError(t, gqlRouter.LoadRoutes([]config.GraphQLRoute{
		{
			Name:  "gql-plain",
			Match: []config.GraphQLRouteMatch{{Path: &config.StringMatch{Exact: "/graphql"}}},
			Route: []config.RouteDestination{{Destination: config.Destination{Host: "gql-backend"}}},
		},
	}))

	skip := gateway.NewRouteCORSSkipper(router.New(), gqlRouter, "/graphql")

	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	assert.False(t, skip(req))
}

// TestNewRouteCORSSkipper_HotReload verifies the skipper follows route
// reloads on the same router instance (LoadRoutes swap).
func TestNewRouteCORSSkipper_HotReload(t *testing.T) {
	spec := corsPrecedenceSpec()
	r := router.New()
	require.NoError(t, r.LoadRoutes(spec.Routes))

	skip := gateway.NewRouteCORSSkipper(r, nil, "/graphql")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cors/x", nil)
	require.True(t, skip(req))

	// Reload: drop the route-level CORS block.
	spec.Routes[0].CORS = nil
	require.NoError(t, r.LoadRoutes(spec.Routes))
	assert.False(t, skip(req),
		"after reload without route CORS the global layer must apply again")
}

// Package gateway provides the core API Gateway functionality.
package gateway

import (
	"net/http"

	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// NewRouteCORSSkipper builds the predicate the GLOBAL CORS middleware uses
// to step aside for routes that define their own route-level CORS policy.
//
// Precedence contract: a route-level cors block fully overrides the global
// policy for that route — including preflight OPTIONS, which the global
// middleware would otherwise answer before the route chain runs. Routes
// without a route-level policy keep the global CORS behavior (the route
// chain's CORS middleware falls back to the global config, preserving the
// single-grant authority semantics).
//
// Matching notes:
//   - HTTP routes are matched with the live router (hot-reload safe: the
//     router instance is stable across LoadRoutes swaps). A preflight only
//     matches routes whose match includes OPTIONS — the same matching the
//     reverse proxy performs to run the route chain.
//   - GraphQL endpoint requests (graphqlPath) are matched on path/headers
//     only (mirroring GraphQLHandler.servePreflight): route-level CORS on
//     the first matching GraphQL route takes precedence for the endpoint.
//   - The extra match per request runs only when a global CORS policy is
//     configured; it reuses the same in-memory matchers as the proxy.
func NewRouteCORSSkipper(
	httpRouter *router.Router,
	gqlRouter *graphqlrouter.Router,
	graphqlPath string,
) func(*http.Request) bool {
	return func(r *http.Request) bool {
		if gqlRouter != nil && r.URL.Path == graphqlPath {
			return graphqlRouteHasCORS(gqlRouter, r)
		}
		return httpRouteHasCORS(httpRouter, r)
	}
}

// httpRouteHasCORS reports whether the request matches an HTTP route that
// declares a route-level CORS policy.
func httpRouteHasCORS(httpRouter *router.Router, r *http.Request) bool {
	if httpRouter == nil {
		return false
	}
	result, err := httpRouter.Match(r)
	if err != nil || result == nil || result.Route == nil {
		return false
	}
	return result.Route.Config.CORS != nil
}

// graphqlRouteHasCORS reports whether the GraphQL endpoint request matches
// (by path/headers) a GraphQL route that declares a route-level CORS policy.
func graphqlRouteHasCORS(gqlRouter *graphqlrouter.Router, r *http.Request) bool {
	match := gqlRouter.Match(r, &graphqlrouter.GraphQLRequest{})
	if match == nil || match.Route == nil {
		return false
	}
	return match.Route.CORS != nil
}

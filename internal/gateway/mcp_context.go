package gateway

import (
	"context"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpauthz "github.com/vyrodovalexey/avapigw/internal/mcp/authz"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// mcpRouteCtxKey is the context key under which the matched MCP route is
// stored so the terminal broker handler can read it after the route
// middleware chain runs.
type mcpRouteCtxKey struct{}

// withMCPRouteContext stores the matched MCP route in the request context and
// stamps the route name (namespaced with the MCP chain scope) so downstream
// middleware and the upstream metrics RouteHolder label by matched route.
func withMCPRouteContext(r *http.Request, route *config.MCPRoute) *http.Request {
	ctx := context.WithValue(r.Context(), mcpRouteCtxKey{}, route)
	if route != nil && route.Name != "" {
		ctx = util.ContextWithRoute(ctx, mcpChainScope+route.Name)
	}
	return r.WithContext(ctx)
}

// mcpRouteFromContext returns the matched MCP route stored in the request
// context, or nil when absent.
func mcpRouteFromContext(r *http.Request) *config.MCPRoute {
	route, _ := r.Context().Value(mcpRouteCtxKey{}).(*config.MCPRoute)
	return route
}

// mcpPrincipalCtxKey is the context key under which the authenticated MCP
// principal is stored so the terminal broker handler can enforce authorization
// on cache hits and label audit records after the route middleware chain runs.
type mcpPrincipalCtxKey struct{}

// withMCPPrincipal stores the authenticated principal (may be nil when
// authorization is not configured) in the request context.
func withMCPPrincipal(r *http.Request, principal *mcpauthz.Principal) *http.Request {
	if principal == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), mcpPrincipalCtxKey{}, principal))
}

// mcpPrincipalFromContext returns the authenticated principal stored in the
// request context, or nil when absent.
func mcpPrincipalFromContext(r *http.Request) *mcpauthz.Principal {
	p, _ := r.Context().Value(mcpPrincipalCtxKey{}).(*mcpauthz.Principal)
	return p
}

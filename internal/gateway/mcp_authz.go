package gateway

import (
	"errors"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpauthz "github.com/vyrodovalexey/avapigw/internal/mcp/authz"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// authorize authenticates and authorizes a request before any upstream call
// and before returning cached results (HUB-305/306/307/310). It resolves the
// principal from the validated bearer token, enforces the required scopes for
// (method, primitive) and consults the policy engine. When no authorizer is
// configured (or it is not enabled) authorization is skipped and (nil, true) is
// returned — the OAuth resource-server surface remains additive/opt-in.
//
// On failure it writes the appropriate 401/403 challenge, records the auth
// failure metric and returns ok=false.
func (h *MCPHandler) authorize(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, route *config.MCPRoute,
) (*mcpauthz.Principal, bool) {
	if h.authorizer == nil || !h.authorizer.Enabled() || !routeRequiresAuthz(route) {
		return nil, true
	}

	principal, ok := h.authenticate(w, r, mr)
	if !ok {
		return nil, false
	}
	if !h.enforceRequestScopes(w, r, mr, principal, route) {
		return nil, false
	}
	return principal, true
}

// authenticate validates the bearer token and returns the principal, writing a
// 401 challenge on failure.
func (h *MCPHandler) authenticate(
	w http.ResponseWriter, r *http.Request, mr *mcpReq,
) (*mcpauthz.Principal, bool) {
	token := mcpauthz.ExtractBearer(r)
	principal, err := h.authorizer.ValidateToken(r.Context(), token)
	if err != nil {
		h.metrics.RecordAuthFailure(mr.method(), authFailureClass(err))
		h.logger.Debug("mcp authz: token validation failed",
			observability.String("method", mr.method()), observability.Error(err))
		mcpauthz.WriteUnauthorized(w, h.authorizer.ResourceMetadataURL(), "", authDescription(err))
		return nil, false
	}
	return principal, true
}

// enforceRequestScopes enforces the required scopes and the policy engine for
// the request's (method, primitive), writing a 403 insufficient_scope challenge
// or a JSON-RPC policy-denied error on failure. The route's ScopeMap drives the
// per-primitive scope requirements (HUB-305/306).
func (h *MCPHandler) enforceRequestScopes(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, principal *mcpauthz.Principal, route *config.MCPRoute,
) bool {
	method := mr.method()
	primitive := primitiveName(mr.params)

	resolver := routeScopeResolver(route)
	required := resolver.Required(method, primitive)
	if err := h.authorizer.EnforceScopesWith(resolver, principal.Scopes, required); err != nil {
		h.metrics.RecordAuthFailure(method, mcpmetrics.AuthClassScope)
		mcpauthz.WriteInsufficientScope(w, h.authorizer.ResourceMetadataURL(), required)
		return false
	}

	// Policy engine is keyed on the owning upstream when the primitive is
	// namespaced; aggregation/list methods are checked per-primitive during
	// filtering, so only named-primitive requests are policy-checked here.
	if primitive == "" {
		return true
	}
	upstreamID, original, ok := h.mapper.Denamespace(primitive)
	if !ok {
		upstreamID, original = "", primitive
	}
	if err := h.authorizer.EnforcePolicy(r.Context(), principal.Subject, upstreamID, original, method); err != nil {
		h.metrics.RecordAuthFailure(method, mcpmetrics.AuthClassPolicy)
		h.writeJSONRPCError(w, mr.id(), http.StatusForbidden, protocol.InvalidRequest,
			"request denied by policy", nil)
		return false
	}
	return true
}

// permitsPrimitive reports whether the principal may see/invoke a namespaced
// primitive, used to filter list results (HUB-306). A nil principal (no authz
// configured) permits everything.
func (h *MCPHandler) permitsPrimitive(
	r *http.Request, principal *mcpauthz.Principal, resolver mcpauthz.ScopeResolver, method, nsName string,
) bool {
	if h.authorizer == nil || principal == nil {
		return true
	}
	upstreamID, original, ok := h.mapper.Denamespace(nsName)
	if !ok {
		original = nsName
	}
	return h.authorizer.PermitsPrimitive(r.Context(), resolver, principal, upstreamID, original, method)
}

// routeScopeResolver builds a per-request ScopeResolver from the matched
// route's ScopeMap (HUB-305/306). It is cheap to build and keeps scope
// requirements per-route rather than global.
func routeScopeResolver(route *config.MCPRoute) mcpauthz.ScopeResolver {
	if route == nil {
		return mcpauthz.NewMapScopeResolver(nil, nil)
	}
	return mcpauthz.NewMapScopeResolver(route.ScopeMap, nil)
}

// mcpauthzPrincipal is a local alias for the authenticated principal so the
// discovery/cache files can name it without repeating the import path.
type mcpauthzPrincipal = mcpauthz.Principal

// principalScopes returns the principal's granted scopes, or nil when the
// principal is absent (no authorization configured).
func principalScopes(p *mcpauthzPrincipal) []string {
	if p == nil {
		return nil
	}
	return p.Scopes
}

// authContextKey derives the cache auth-context component from the principal
// (HUB-183). An absent principal yields an empty component (public entries).
func authContextKey(p *mcpauthzPrincipal) string {
	if p == nil {
		return ""
	}
	return mcpcacheAuthContextKey(p.Subject, p.Scopes)
}

// authDescription returns a bounded, non-sensitive description for a token
// validation error suitable for a WWW-Authenticate challenge.
func authDescription(err error) string {
	switch {
	case errors.Is(err, mcpauthz.ErrNoToken):
		return "a bearer token is required"
	case errors.Is(err, mcpauthz.ErrAudienceMismatch):
		return "token audience is not this resource"
	default:
		return "the access token is invalid"
	}
}

// authFailureClass classifies a token-validation error into a bounded
// auth-failure metric class (HUB-505).
func authFailureClass(err error) string {
	switch {
	case errors.Is(err, mcpauthz.ErrNoToken):
		return mcpmetrics.AuthClassNoToken
	case errors.Is(err, mcpauthz.ErrAudienceMismatch):
		return mcpmetrics.AuthClassAudience
	default:
		return mcpmetrics.AuthClassInvalidToken
	}
}

// routeRequiresAuthz reports whether a matched route opts into MCP
// authorization: it must declare Authentication, Authorization or a ScopeMap.
// Routes with none of these skip enforcement (additive/opt-in).
func routeRequiresAuthz(route *config.MCPRoute) bool {
	if route == nil {
		return false
	}
	return route.Authentication != nil || route.Authorization != nil || len(route.ScopeMap) > 0
}

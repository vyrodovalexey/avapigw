package gateway

import (
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// MCPPathDispatcher routes downstream MCP endpoint requests (on the configured
// MCP path, default /mcp) to the MCP pipeline and everything else to the next
// handler (the HTTP reverse proxy or GraphQL dispatcher). Composing the
// dispatcher INSIDE the gateway's global middleware chain guarantees MCP
// traffic passes the same global middleware as proxied HTTP routes. The MCP
// handler itself enforces the modern method rules (405 on non-POST, HUB-103),
// so the dispatcher delegates all methods on the MCP path.
type MCPPathDispatcher struct {
	path          string
	wellKnownPath string
	mcp           http.Handler
	wellKnown     http.Handler
	next          http.Handler
}

// NewMCPPathDispatcher creates a dispatcher for the given MCP endpoint path. An
// empty path falls back to the default MCP path. A nil mcp handler disables
// dispatching (every request goes to next).
func NewMCPPathDispatcher(path string, mcp, next http.Handler) *MCPPathDispatcher {
	if path == "" {
		path = config.DefaultMCPPath
	}
	return &MCPPathDispatcher{
		path: path,
		mcp:  mcp,
		next: next,
	}
}

// WithWellKnown registers the OAuth 2.1 protected-resource metadata handler on
// the given path (RFC 9728, HUB-301). A nil handler leaves the well-known
// endpoint unregistered so behavior stays additive.
func (d *MCPPathDispatcher) WithWellKnown(path string, handler http.Handler) *MCPPathDispatcher {
	d.wellKnownPath = path
	d.wellKnown = handler
	return d
}

// MCPPathFromConfig resolves the configured MCP endpoint path, falling back to
// the default ("/mcp").
func MCPPathFromConfig(cfg *config.GatewayConfig) string {
	if cfg != nil && cfg.Spec.MCP != nil {
		return cfg.Spec.MCP.GetEffectivePath()
	}
	return config.DefaultMCPPath
}

// ServeHTTP implements http.Handler.
func (d *MCPPathDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d.wellKnown != nil && d.wellKnownPath != "" && r.URL.Path == d.wellKnownPath {
		d.wellKnown.ServeHTTP(w, r)
		return
	}
	if d.mcp != nil && r.URL.Path == d.path {
		d.mcp.ServeHTTP(w, r)
		return
	}
	d.next.ServeHTTP(w, r)
}

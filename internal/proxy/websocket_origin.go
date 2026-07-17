// Package proxy provides HTTP reverse proxy functionality.
package proxy

import (
	"net/http"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// wsPermissiveOriginWarning is logged once at proxy construction when no
// WebSocket origin allowlist is configured (cross-site WebSocket hijacking
// protection is disabled for backward compatibility).
const wsPermissiveOriginWarning = "WebSocket CheckOrigin permissive; set allowedOrigins to restrict"

// wsOriginPolicy decides whether the Origin of a WebSocket upgrade request
// is allowed. It is immutable after construction and therefore safe for
// concurrent use by all proxied connections.
type wsOriginPolicy struct {
	// allowAll is true when the allowlist is empty (backward-compatible
	// permissive default) or contains the "*" wildcard entry.
	allowAll bool

	// schemeHosts holds normalized "scheme://host[:port]" entries.
	schemeHosts map[string]struct{}

	// hosts holds normalized bare "host[:port]" entries matching any scheme.
	hosts map[string]struct{}
}

// newWSOriginPolicy builds an origin policy from gateway configuration.
//
// A nil config or an empty allowlist yields the permissive legacy behavior
// and emits a single startup warning (risk-R4 safe default). A "*" entry
// explicitly allows all origins without the warning. Malformed entries are
// skipped fail-closed with a warning; config validation rejects them at
// load time, so this only guards direct construction paths.
func newWSOriginPolicy(cfg *config.WebSocketConfig, logger observability.Logger) *wsOriginPolicy {
	policy := &wsOriginPolicy{
		schemeHosts: make(map[string]struct{}),
		hosts:       make(map[string]struct{}),
	}

	if cfg == nil || len(cfg.AllowedOrigins) == 0 {
		policy.allowAll = true
		logger.Warn(wsPermissiveOriginWarning)
		return policy
	}

	for _, entry := range cfg.AllowedOrigins {
		policy.addEntry(entry, logger)
	}
	return policy
}

// addEntry parses a single allowedOrigins entry into the policy.
func (p *wsOriginPolicy) addEntry(entry string, logger observability.Logger) {
	if strings.TrimSpace(entry) == config.WSOriginWildcard {
		p.allowAll = true
		return
	}

	scheme, host, err := config.ParseWSOrigin(entry)
	if err != nil {
		logger.Warn("ignoring invalid websocket allowed origin",
			observability.String("origin", entry),
			observability.Error(err),
		)
		return
	}

	if scheme == "" {
		p.hosts[host] = struct{}{}
		return
	}
	p.schemeHosts[scheme+"://"+host] = struct{}{}
}

// allow reports whether the request's Origin header is permitted.
//
// Requests without an Origin header are allowed (non-browser clients do
// not send one; this matches gorilla/websocket's default). When an
// allowlist is configured, an origin is accepted if it is same-origin
// with the request host, matches a "scheme://host" entry, or matches a
// bare-host entry. Unparseable origins are rejected fail-closed.
func (p *wsOriginPolicy) allow(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser clients omit the Origin header; keep them working
		// (matches gorilla/websocket's default policy).
		return true
	}
	if p.allowAll {
		return true
	}

	scheme, host, err := config.ParseWSOrigin(origin)
	if err != nil {
		return false
	}
	return p.matches(scheme, host, r.Host)
}

// matches checks a normalized origin against same-origin and the allowlist.
func (p *wsOriginPolicy) matches(scheme, host, requestHost string) bool {
	// Same-origin requests are always allowed when a list is configured.
	if strings.EqualFold(host, requestHost) {
		return true
	}
	if _, ok := p.schemeHosts[scheme+"://"+host]; ok {
		return true
	}
	_, ok := p.hosts[host]
	return ok
}

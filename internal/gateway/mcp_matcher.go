package gateway

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// matchMCPRoute returns the first MCPRoute whose Match conditions are
// satisfied by the request (path, MCP method, primitive name, headers). A
// route with no Match entries matches any request (catch-all). It returns nil
// when no route matches.
func matchMCPRoute(routes []config.MCPRoute, r *http.Request, method, name string) *config.MCPRoute {
	for i := range routes {
		if mcpRouteMatches(&routes[i], r, method, name) {
			return &routes[i]
		}
	}
	return nil
}

// mcpRouteMatches reports whether any of a route's match blocks is satisfied.
// An empty match slice is a catch-all.
func mcpRouteMatches(route *config.MCPRoute, r *http.Request, method, name string) bool {
	if len(route.Match) == 0 {
		return true
	}
	for i := range route.Match {
		if mcpMatchBlockMatches(&route.Match[i], r, method, name) {
			return true
		}
	}
	return false
}

// mcpMatchBlockMatches reports whether a single MCPRouteMatch block is
// satisfied. All configured conditions within the block must match (AND).
func mcpMatchBlockMatches(m *config.MCPRouteMatch, r *http.Request, method, name string) bool {
	if m.Method != "" && m.Method != method {
		return false
	}
	if !stringMatchMatches(m.Path, r.URL.Path) {
		return false
	}
	if !stringMatchMatches(m.Name, name) {
		return false
	}
	return headerMatchesAll(m.Headers, r.Header)
}

// stringMatchMatches reports whether value satisfies the StringMatch. A nil or
// empty match is treated as "no constraint" and always matches.
func stringMatchMatches(sm *config.StringMatch, value string) bool {
	if sm.IsEmpty() {
		return true
	}
	if sm.IsWildcard() {
		return true
	}
	switch sm.MatchType() {
	case "exact":
		return value == sm.Exact
	case "prefix":
		return strings.HasPrefix(value, sm.Prefix)
	case "regex":
		re, err := regexp.Compile(sm.Regex)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	default:
		return true
	}
}

// headerMatchesAll reports whether every configured header condition is
// satisfied by the request headers.
func headerMatchesAll(matches []config.HeaderMatchConfig, headers http.Header) bool {
	for i := range matches {
		if !headerMatchMatches(&matches[i], headers) {
			return false
		}
	}
	return true
}

// headerMatchMatches reports whether a single header condition is satisfied.
func headerMatchMatches(hm *config.HeaderMatchConfig, headers http.Header) bool {
	value := headers.Get(hm.Name)
	switch {
	case hm.Exact != "":
		return value == hm.Exact
	case hm.Prefix != "":
		return strings.HasPrefix(value, hm.Prefix)
	case hm.Regex != "":
		re, err := regexp.Compile(hm.Regex)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	default:
		// Name-only condition: header must be present.
		return value != ""
	}
}

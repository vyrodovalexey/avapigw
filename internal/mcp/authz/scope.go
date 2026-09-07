package authz

import (
	"sort"
	"strings"
	"sync"
)

// scopeHierarchySep is the separator that defines the scope hierarchy: a
// granted scope prefix (e.g. "mcp:tools") satisfies any required scope that is
// the prefix itself or a child of it (e.g. "mcp:tools:read"). This is the
// hierarchy rule enforced by MapScopeResolver.Sufficient (HUB-306).
const scopeHierarchySep = ":"

// ScopeResolver maps MCP methods/primitives to required scopes and decides
// whether granted scopes satisfy required scopes with hierarchy awareness.
type ScopeResolver interface {
	// Required returns the scopes required to invoke (method, primitive).
	Required(method, primitive string) []string
	// Sufficient reports whether the granted scopes satisfy every required
	// scope, accounting for scope hierarchies (HUB-306).
	Sufficient(granted, required []string) bool
}

// MapScopeResolver resolves required scopes from a configured map. Lookups are
// tried, in order, on the exact "method:primitive" key, then the method key,
// then the primitive key, unioning any matches. The hierarchy rule for
// sufficiency is: a granted scope G satisfies a required scope R when G == R or
// R is a hierarchical child of G (R has G + ":" as a prefix). This lets a
// broad grant such as "mcp:tools" satisfy "mcp:tools:read" while a narrow
// grant never satisfies a broader requirement.
type MapScopeResolver struct {
	mu sync.RWMutex
	// byMethodPrimitive maps "method|primitive" -> scopes.
	byMethodPrimitive map[string][]string
	// byKey maps a single method or primitive key -> scopes.
	byKey map[string][]string
}

// NewMapScopeResolver constructs a resolver from a route ScopeMap. The
// scopeMap keys are matched against "method", a primitive name, or the
// combined "method|primitive" key. defaultScopes, when non-empty, are required
// for every request in addition to any matched entry.
func NewMapScopeResolver(scopeMap map[string][]string, defaultScopes []string) *MapScopeResolver {
	r := &MapScopeResolver{
		byMethodPrimitive: make(map[string][]string),
		byKey:             make(map[string][]string),
	}
	for key, scopes := range scopeMap {
		if strings.Contains(key, "|") {
			r.byMethodPrimitive[key] = scopes
			continue
		}
		r.byKey[key] = scopes
	}
	if len(defaultScopes) > 0 {
		r.byKey["*"] = defaultScopes
	}
	return r
}

// Required returns the union of the scopes configured for the combined
// method|primitive key, the method key, the primitive key and the global "*"
// default, deduplicated and stably ordered.
func (r *MapScopeResolver) Required(method, primitive string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	set := make(map[string]struct{})
	addAll(set, r.byMethodPrimitive[method+"|"+primitive])
	addAll(set, r.byKey[method])
	if primitive != "" {
		addAll(set, r.byKey[primitive])
	}
	addAll(set, r.byKey["*"])

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Sufficient reports whether the granted scopes satisfy every required scope
// with hierarchy awareness (HUB-306).
func (r *MapScopeResolver) Sufficient(granted, required []string) bool {
	for _, req := range required {
		if !satisfiedBy(granted, req) {
			return false
		}
	}
	return true
}

// satisfiedBy reports whether any granted scope satisfies the required scope,
// exactly or as a hierarchical ancestor.
func satisfiedBy(granted []string, required string) bool {
	for _, g := range granted {
		if g == required {
			return true
		}
		if strings.HasPrefix(required, g+scopeHierarchySep) {
			return true
		}
	}
	return false
}

// addAll inserts every element of vals into set.
func addAll(set map[string]struct{}, vals []string) {
	for _, v := range vals {
		set[v] = struct{}{}
	}
}

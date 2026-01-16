// Package routing provides route matching functionality for the API Gateway.
package routing

import (
	"regexp"
	"strings"
	"sync"
)

// RouteMatcher performs efficient route matching.
type RouteMatcher struct {
	routes []*CompiledRoute
	mu     sync.RWMutex
}

// CompiledRoute is a pre-compiled route for efficient matching.
type CompiledRoute struct {
	Name        string
	HostRegexes []*regexp.Regexp
	Hostnames   []string
	Rules       []*CompiledRule
	Priority    int
	Metadata    map[string]interface{}
}

// CompiledRule is a pre-compiled rule for efficient matching.
type CompiledRule struct {
	PathMatcher    PathMatcher
	MethodMatcher  MethodMatcher
	HeaderMatchers []HeaderMatcher
	QueryMatchers  []QueryMatcher
	Priority       int
	Metadata       map[string]interface{}
}

// MatchResult contains the result of a route match.
type MatchResult struct {
	Route    *CompiledRoute
	Rule     *CompiledRule
	Captures map[string]string
}

// NewRouteMatcher creates a new route matcher.
func NewRouteMatcher() *RouteMatcher {
	return &RouteMatcher{
		routes: make([]*CompiledRoute, 0),
	}
}

// AddRoute adds a compiled route to the matcher.
func (m *RouteMatcher) AddRoute(route *CompiledRoute) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.routes = append(m.routes, route)
	m.sortRoutes()
}

// RemoveRoute removes a route by name.
func (m *RouteMatcher) RemoveRoute(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, route := range m.routes {
		if route.Name == name {
			m.routes = append(m.routes[:i], m.routes[i+1:]...)
			return true
		}
	}
	return false
}

// UpdateRoute updates an existing route.
func (m *RouteMatcher) UpdateRoute(route *CompiledRoute) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, r := range m.routes {
		if r.Name == route.Name {
			m.routes[i] = route
			m.sortRoutes()
			return true
		}
	}
	return false
}

// Match finds a matching route for the given request parameters.
func (m *RouteMatcher) Match(host, path, method string, headers, query map[string]string) (*MatchResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, route := range m.routes {
		// Check hostname match
		if !m.matchHostname(route, host) {
			continue
		}

		// Check rules
		for _, rule := range route.Rules {
			captures := make(map[string]string)
			if m.matchRule(rule, path, method, headers, query, captures) {
				return &MatchResult{
					Route:    route,
					Rule:     rule,
					Captures: captures,
				}, true
			}
		}
	}

	return nil, false
}

// matchHostname checks if the host matches the route's hostname patterns.
func (m *RouteMatcher) matchHostname(route *CompiledRoute, host string) bool {
	// If no hostnames specified, match all
	if len(route.HostRegexes) == 0 && len(route.Hostnames) == 0 {
		return true
	}

	// Check for wildcard hostname
	for _, hostname := range route.Hostnames {
		if hostname == "*" || hostname == "" {
			return true
		}
	}

	// Check regex patterns
	for _, regex := range route.HostRegexes {
		if regex.MatchString(host) {
			return true
		}
	}

	return false
}

// matchRule checks if the request matches the rule.
func (m *RouteMatcher) matchRule(
	rule *CompiledRule,
	path, method string,
	headers, query map[string]string,
	captures map[string]string,
) bool {
	// Check path
	if rule.PathMatcher != nil {
		matched, pathCaptures := rule.PathMatcher.Match(path)
		if !matched {
			return false
		}
		for k, v := range pathCaptures {
			captures[k] = v
		}
	}

	// Check method
	if rule.MethodMatcher != nil && !rule.MethodMatcher.Match(method) {
		return false
	}

	// Check headers
	for _, headerMatcher := range rule.HeaderMatchers {
		value, exists := headers[strings.ToLower(headerMatcher.Name())]
		if !exists {
			return false
		}
		if !headerMatcher.Match(value) {
			return false
		}
	}

	// Check query parameters
	for _, queryMatcher := range rule.QueryMatchers {
		value, exists := query[queryMatcher.Name()]
		if !exists {
			return false
		}
		if !queryMatcher.Match(value) {
			return false
		}
	}

	return true
}

// sortRoutes sorts routes by priority (higher priority first).
func (m *RouteMatcher) sortRoutes() {
	// Simple bubble sort for small number of routes
	for i := 0; i < len(m.routes)-1; i++ {
		for j := 0; j < len(m.routes)-i-1; j++ {
			if m.routes[j].Priority < m.routes[j+1].Priority {
				m.routes[j], m.routes[j+1] = m.routes[j+1], m.routes[j]
			}
		}
	}
}

// Clear removes all routes from the matcher.
func (m *RouteMatcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = make([]*CompiledRoute, 0)
}

// Count returns the number of routes.
func (m *RouteMatcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.routes)
}

// GetRouteNames returns all route names.
func (m *RouteMatcher) GetRouteNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, len(m.routes))
	for i, route := range m.routes {
		names[i] = route.Name
	}
	return names
}

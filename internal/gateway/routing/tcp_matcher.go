// Package routing provides route matching functionality for the API Gateway.
package routing

import (
	"sync"
)

// TCPRouteMatcher matches TCP connections to routes.
type TCPRouteMatcher struct {
	routes []*CompiledTCPRoute
	mu     sync.RWMutex
}

// CompiledTCPRoute is a pre-compiled TCP route for efficient matching.
type CompiledTCPRoute struct {
	Name        string
	Port        int
	BackendRefs []TCPBackendRef
	Priority    int
}

// TCPBackendRef references a backend service for TCP routing.
type TCPBackendRef struct {
	Name      string
	Namespace string
	Port      int
	Weight    int
}

// TCPMatchResult contains the result of a TCP route match.
type TCPMatchResult struct {
	Route       *CompiledTCPRoute
	BackendRefs []TCPBackendRef
}

// TCPRoute represents a TCP route configuration for compilation.
type TCPRoute struct {
	Name        string
	Port        int
	BackendRefs []TCPBackendRef
	Priority    int
}

// NewTCPRouteMatcher creates a new TCP route matcher.
func NewTCPRouteMatcher() *TCPRouteMatcher {
	return &TCPRouteMatcher{
		routes: make([]*CompiledTCPRoute, 0),
	}
}

// Match finds a matching route for the given port.
func (m *TCPRouteMatcher) Match(port int) (*TCPMatchResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, route := range m.routes {
		if route.Port == port || route.Port == 0 {
			return &TCPMatchResult{
				Route:       route,
				BackendRefs: route.BackendRefs,
			}, true
		}
	}

	return nil, false
}

// MatchByPort finds a matching route for the given port.
// This is an alias for Match for clarity.
func (m *TCPRouteMatcher) MatchByPort(port int) (*TCPMatchResult, bool) {
	return m.Match(port)
}

// Compile compiles a list of TCP routes for efficient matching.
func (m *TCPRouteMatcher) Compile(routes []*TCPRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	compiled := make([]*CompiledTCPRoute, 0, len(routes))

	for _, route := range routes {
		compiledRoute := &CompiledTCPRoute{
			Name:        route.Name,
			Port:        route.Port,
			BackendRefs: route.BackendRefs,
			Priority:    route.Priority,
		}
		compiled = append(compiled, compiledRoute)
	}

	// Sort by priority (higher priority first)
	sortTCPRoutes(compiled)

	m.routes = compiled
	return nil
}

// AddRoute adds a single route.
func (m *TCPRouteMatcher) AddRoute(route *TCPRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	compiledRoute := &CompiledTCPRoute{
		Name:        route.Name,
		Port:        route.Port,
		BackendRefs: route.BackendRefs,
		Priority:    route.Priority,
	}

	m.routes = append(m.routes, compiledRoute)
	sortTCPRoutes(m.routes)

	return nil
}

// RemoveRoute removes a route by name.
func (m *TCPRouteMatcher) RemoveRoute(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, route := range m.routes {
		if route.Name == name {
			m.routes = append(m.routes[:i], m.routes[i+1:]...)
			return nil
		}
	}

	return nil
}

// UpdateRoute updates an existing route.
func (m *TCPRouteMatcher) UpdateRoute(route *TCPRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.routes {
		if existing.Name == route.Name {
			m.routes[i] = &CompiledTCPRoute{
				Name:        route.Name,
				Port:        route.Port,
				BackendRefs: route.BackendRefs,
				Priority:    route.Priority,
			}
			sortTCPRoutes(m.routes)
			return nil
		}
	}

	// Route not found, add it
	return m.AddRoute(route)
}

// GetRoute returns a route by name.
func (m *TCPRouteMatcher) GetRoute(name string) *CompiledTCPRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, route := range m.routes {
		if route.Name == name {
			return route
		}
	}
	return nil
}

// ListRoutes returns all route names.
func (m *TCPRouteMatcher) ListRoutes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, len(m.routes))
	for i, route := range m.routes {
		names[i] = route.Name
	}
	return names
}

// Clear removes all routes.
func (m *TCPRouteMatcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = make([]*CompiledTCPRoute, 0)
}

// sortTCPRoutes sorts routes by priority (higher priority first).
func sortTCPRoutes(routes []*CompiledTCPRoute) {
	// Simple bubble sort for small number of routes
	for i := 0; i < len(routes)-1; i++ {
		for j := 0; j < len(routes)-i-1; j++ {
			if routes[j].Priority < routes[j+1].Priority {
				routes[j], routes[j+1] = routes[j+1], routes[j]
			}
		}
	}
}

// TLSRouteMatcher matches TLS connections to routes based on SNI.
type TLSRouteMatcher struct {
	routes        map[string]*CompiledTLSRoute // keyed by exact hostname
	wildcardIndex []*wildcardTLSRoute          // wildcard patterns
	mu            sync.RWMutex
}

// CompiledTLSRoute is a pre-compiled TLS route for efficient matching.
type CompiledTLSRoute struct {
	Name        string
	Hostnames   []string
	BackendRefs []TLSBackendRef
	Priority    int
}

// TLSBackendRef references a backend service for TLS routing.
type TLSBackendRef struct {
	Name      string
	Namespace string
	Port      int
	Weight    int
}

// wildcardTLSRoute holds a wildcard pattern and its route.
type wildcardTLSRoute struct {
	pattern string
	matcher *HostnameMatcher
	route   *CompiledTLSRoute
}

// TLSMatchResult contains the result of a TLS route match.
type TLSMatchResult struct {
	Route       *CompiledTLSRoute
	BackendRefs []TLSBackendRef
}

// TLSRoute represents a TLS route configuration for compilation.
type TLSRoute struct {
	Name        string
	Hostnames   []string
	BackendRefs []TLSBackendRef
	Priority    int
}

// NewTLSRouteMatcher creates a new TLS route matcher.
func NewTLSRouteMatcher() *TLSRouteMatcher {
	return &TLSRouteMatcher{
		routes:        make(map[string]*CompiledTLSRoute),
		wildcardIndex: make([]*wildcardTLSRoute, 0),
	}
}

// Match finds a matching route for the given SNI hostname.
func (m *TLSRouteMatcher) Match(sni string) (*TLSMatchResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Try exact match first
	if route, ok := m.routes[sni]; ok {
		return &TLSMatchResult{
			Route:       route,
			BackendRefs: route.BackendRefs,
		}, true
	}

	// Try wildcard matches
	for _, wr := range m.wildcardIndex {
		if wr.matcher.Match(sni) {
			return &TLSMatchResult{
				Route:       wr.route,
				BackendRefs: wr.route.BackendRefs,
			}, true
		}
	}

	return nil, false
}

// Compile compiles a list of TLS routes for efficient matching.
func (m *TLSRouteMatcher) Compile(routes []*TLSRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.routes = make(map[string]*CompiledTLSRoute)
	m.wildcardIndex = make([]*wildcardTLSRoute, 0)

	for _, route := range routes {
		compiledRoute := &CompiledTLSRoute{
			Name:        route.Name,
			Hostnames:   route.Hostnames,
			BackendRefs: route.BackendRefs,
			Priority:    route.Priority,
		}

		for _, hostname := range route.Hostnames {
			if hostname != "" && hostname[0] == '*' {
				// Wildcard hostname
				wr := &wildcardTLSRoute{
					pattern: hostname,
					matcher: NewHostnameMatcher(hostname),
					route:   compiledRoute,
				}
				m.wildcardIndex = append(m.wildcardIndex, wr)
			} else {
				// Exact hostname
				m.routes[hostname] = compiledRoute
			}
		}
	}

	// Sort wildcard routes by priority
	sortWildcardTLSRoutes(m.wildcardIndex)

	return nil
}

// AddRoute adds a single route.
func (m *TLSRouteMatcher) AddRoute(route *TLSRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	compiledRoute := &CompiledTLSRoute{
		Name:        route.Name,
		Hostnames:   route.Hostnames,
		BackendRefs: route.BackendRefs,
		Priority:    route.Priority,
	}

	for _, hostname := range route.Hostnames {
		if hostname != "" && hostname[0] == '*' {
			wr := &wildcardTLSRoute{
				pattern: hostname,
				matcher: NewHostnameMatcher(hostname),
				route:   compiledRoute,
			}
			m.wildcardIndex = append(m.wildcardIndex, wr)
		} else {
			m.routes[hostname] = compiledRoute
		}
	}

	sortWildcardTLSRoutes(m.wildcardIndex)

	return nil
}

// RemoveRoute removes a route by name.
func (m *TLSRouteMatcher) RemoveRoute(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from exact matches
	for hostname, route := range m.routes {
		if route.Name == name {
			delete(m.routes, hostname)
		}
	}

	// Remove from wildcard matches
	newWildcards := make([]*wildcardTLSRoute, 0, len(m.wildcardIndex))
	for _, wr := range m.wildcardIndex {
		if wr.route.Name != name {
			newWildcards = append(newWildcards, wr)
		}
	}
	m.wildcardIndex = newWildcards

	return nil
}

// Clear removes all routes.
func (m *TLSRouteMatcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = make(map[string]*CompiledTLSRoute)
	m.wildcardIndex = make([]*wildcardTLSRoute, 0)
}

// sortWildcardTLSRoutes sorts wildcard routes by priority.
func sortWildcardTLSRoutes(routes []*wildcardTLSRoute) {
	for i := 0; i < len(routes)-1; i++ {
		for j := 0; j < len(routes)-i-1; j++ {
			if routes[j].route.Priority < routes[j+1].route.Priority {
				routes[j], routes[j+1] = routes[j+1], routes[j]
			}
		}
	}
}

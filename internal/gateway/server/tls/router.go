// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Router manages TLS routes and performs SNI-based routing.
type Router struct {
	routes         map[string]*TLSRoute // keyed by route name
	hostnameIndex  map[string]*TLSRoute // keyed by hostname for fast lookup
	wildcardRoutes []*wildcardRoute     // wildcard routes for pattern matching
	mu             sync.RWMutex
	logger         *zap.Logger
}

// TLSRoute represents a TLS route configuration.
type TLSRoute struct {
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

// wildcardRoute holds a compiled wildcard pattern.
type wildcardRoute struct {
	pattern string
	regex   *regexp.Regexp
	route   *TLSRoute
}

// NewRouter creates a new TLS router.
func NewRouter(logger *zap.Logger) *Router {
	return &Router{
		routes:         make(map[string]*TLSRoute),
		hostnameIndex:  make(map[string]*TLSRoute),
		wildcardRoutes: make([]*wildcardRoute, 0),
		logger:         logger,
	}
}

// Match finds a matching route for the given SNI hostname.
func (r *Router) Match(sni string) (*TLSRoute, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if sni == "" {
		return nil, fmt.Errorf("empty SNI")
	}

	// Normalize hostname to lowercase
	sni = strings.ToLower(sni)

	// Try exact match first
	if route, ok := r.hostnameIndex[sni]; ok {
		r.logger.Debug("exact SNI match found",
			zap.String("sni", sni),
			zap.String("route", route.Name),
		)
		return route, nil
	}

	// Try wildcard matches
	for _, wr := range r.wildcardRoutes {
		if wr.regex != nil && wr.regex.MatchString(sni) {
			r.logger.Debug("wildcard SNI match found",
				zap.String("sni", sni),
				zap.String("pattern", wr.pattern),
				zap.String("route", wr.route.Name),
			)
			return wr.route, nil
		}
	}

	return nil, fmt.Errorf("no route found for SNI: %s", sni)
}

// AddRoute adds a new route.
func (r *Router) AddRoute(route *TLSRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.routes[route.Name]; exists {
		return fmt.Errorf("route %s already exists", route.Name)
	}

	r.routes[route.Name] = route

	// Index hostnames
	for _, hostname := range route.Hostnames {
		hostname = strings.ToLower(hostname)

		if strings.HasPrefix(hostname, "*.") {
			// Wildcard hostname
			wr := &wildcardRoute{
				pattern: hostname,
				regex:   compileWildcardPattern(hostname),
				route:   route,
			}
			r.wildcardRoutes = append(r.wildcardRoutes, wr)
		} else {
			// Exact hostname
			r.hostnameIndex[hostname] = route
		}
	}

	// Sort wildcard routes by specificity (more specific patterns first)
	r.sortWildcardRoutes()

	r.logger.Info("TLS route added",
		zap.String("name", route.Name),
		zap.Strings("hostnames", route.Hostnames),
		zap.Int("backends", len(route.BackendRefs)),
	)

	return nil
}

// RemoveRoute removes a route by name.
func (r *Router) RemoveRoute(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[name]
	if !exists {
		return fmt.Errorf("route %s not found", name)
	}

	// Remove from hostname index
	for _, hostname := range route.Hostnames {
		hostname = strings.ToLower(hostname)
		if !strings.HasPrefix(hostname, "*.") {
			delete(r.hostnameIndex, hostname)
		}
	}

	// Remove from wildcard routes
	newWildcardRoutes := make([]*wildcardRoute, 0, len(r.wildcardRoutes))
	for _, wr := range r.wildcardRoutes {
		if wr.route.Name != name {
			newWildcardRoutes = append(newWildcardRoutes, wr)
		}
	}
	r.wildcardRoutes = newWildcardRoutes

	delete(r.routes, name)

	r.logger.Info("TLS route removed", zap.String("name", name))

	return nil
}

// UpdateRoute updates an existing route.
func (r *Router) UpdateRoute(route *TLSRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	oldRoute, exists := r.routes[route.Name]
	if !exists {
		return fmt.Errorf("route %s not found", route.Name)
	}

	// Remove old hostname mappings
	for _, hostname := range oldRoute.Hostnames {
		hostname = strings.ToLower(hostname)
		if !strings.HasPrefix(hostname, "*.") {
			delete(r.hostnameIndex, hostname)
		}
	}

	// Remove old wildcard routes
	newWildcardRoutes := make([]*wildcardRoute, 0, len(r.wildcardRoutes))
	for _, wr := range r.wildcardRoutes {
		if wr.route.Name != route.Name {
			newWildcardRoutes = append(newWildcardRoutes, wr)
		}
	}
	r.wildcardRoutes = newWildcardRoutes

	// Add new route
	r.routes[route.Name] = route

	// Index new hostnames
	for _, hostname := range route.Hostnames {
		hostname = strings.ToLower(hostname)

		if strings.HasPrefix(hostname, "*.") {
			wr := &wildcardRoute{
				pattern: hostname,
				regex:   compileWildcardPattern(hostname),
				route:   route,
			}
			r.wildcardRoutes = append(r.wildcardRoutes, wr)
		} else {
			r.hostnameIndex[hostname] = route
		}
	}

	r.sortWildcardRoutes()

	r.logger.Info("TLS route updated",
		zap.String("name", route.Name),
		zap.Strings("hostnames", route.Hostnames),
	)

	return nil
}

// GetRoute returns a route by name.
func (r *Router) GetRoute(name string) *TLSRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.routes[name]
}

// ListRoutes returns all route names.
func (r *Router) ListRoutes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.routes))
	for name := range r.routes {
		names = append(names, name)
	}
	return names
}

// GetAllRoutes returns all routes.
func (r *Router) GetAllRoutes() []*TLSRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*TLSRoute, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	return routes
}

// compileWildcardPattern compiles a wildcard hostname pattern to a regex.
func compileWildcardPattern(pattern string) *regexp.Regexp {
	// Convert *.example.com to regex ^[^.]+\.example\.com$
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.Replace(escaped, `\*`, `[^.]+`, 1)
	regexPattern := "^" + escaped + "$"

	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil
	}
	return regex
}

// sortWildcardRoutes sorts wildcard routes by specificity.
// More specific patterns (more dots) come first.
func (r *Router) sortWildcardRoutes() {
	// Simple bubble sort for small number of routes
	for i := 0; i < len(r.wildcardRoutes)-1; i++ {
		for j := 0; j < len(r.wildcardRoutes)-i-1; j++ {
			// Count dots as a measure of specificity
			dots1 := strings.Count(r.wildcardRoutes[j].pattern, ".")
			dots2 := strings.Count(r.wildcardRoutes[j+1].pattern, ".")

			// Also consider priority
			priority1 := r.wildcardRoutes[j].route.Priority
			priority2 := r.wildcardRoutes[j+1].route.Priority

			// Sort by priority first, then by specificity
			if priority1 < priority2 || (priority1 == priority2 && dots1 < dots2) {
				r.wildcardRoutes[j], r.wildcardRoutes[j+1] = r.wildcardRoutes[j+1], r.wildcardRoutes[j]
			}
		}
	}
}

// Clear removes all routes.
func (r *Router) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes = make(map[string]*TLSRoute)
	r.hostnameIndex = make(map[string]*TLSRoute)
	r.wildcardRoutes = make([]*wildcardRoute, 0)

	r.logger.Info("all TLS routes cleared")
}

// GetRouteForHostname returns the route for a specific hostname.
func (r *Router) GetRouteForHostname(hostname string) *TLSRoute {
	route, _ := r.Match(hostname)
	return route
}

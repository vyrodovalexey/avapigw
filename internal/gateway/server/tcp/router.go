// Package tcp provides the TCP server implementation for the API Gateway.
package tcp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Router manages TCP routes and performs connection routing.
type Router struct {
	routes []*TCPRoute
	mu     sync.RWMutex
	logger *zap.Logger
}

// TCPRoute represents a TCP route configuration.
type TCPRoute struct {
	Name           string
	BackendRefs    []BackendRef
	IdleTimeout    time.Duration
	ConnectTimeout time.Duration
	Priority       int
}

// BackendRef references a backend service for TCP routing.
type BackendRef struct {
	Name      string
	Namespace string
	Port      int
	Weight    int
}

// NewRouter creates a new TCP router.
func NewRouter(logger *zap.Logger) *Router {
	return &Router{
		routes: make([]*TCPRoute, 0),
		logger: logger,
	}
}

// Match finds a matching route for the given connection.
// For TCP, routing is typically based on the listener port since there's no
// application-layer protocol information available without inspection.
func (r *Router) Match(conn net.Conn) (*TCPRoute, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.routes) == 0 {
		return nil, fmt.Errorf("no routes configured")
	}

	// For basic TCP routing, return the first (highest priority) route
	// More sophisticated routing could inspect the first bytes of the connection
	// or use connection metadata
	return r.routes[0], nil
}

// MatchByPort finds a matching route for the given port.
func (r *Router) MatchByPort(port int) (*TCPRoute, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// For now, return the first route
	// In a more complete implementation, routes could be associated with specific ports
	if len(r.routes) == 0 {
		return nil, fmt.Errorf("no routes configured for port %d", port)
	}

	return r.routes[0], nil
}

// AddRoute adds a new route.
func (r *Router) AddRoute(route *TCPRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate
	for _, existing := range r.routes {
		if existing.Name == route.Name {
			return fmt.Errorf("route %s already exists", route.Name)
		}
	}

	// Set default timeouts if not specified
	if route.IdleTimeout == 0 {
		route.IdleTimeout = 5 * time.Minute
	}
	if route.ConnectTimeout == 0 {
		route.ConnectTimeout = 30 * time.Second
	}

	r.routes = append(r.routes, route)
	r.sortRoutes()

	r.logger.Info("TCP route added",
		zap.String("name", route.Name),
		zap.Int("backends", len(route.BackendRefs)),
		zap.Duration("idleTimeout", route.IdleTimeout),
		zap.Duration("connectTimeout", route.ConnectTimeout),
	)

	return nil
}

// RemoveRoute removes a route by name.
func (r *Router) RemoveRoute(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, route := range r.routes {
		if route.Name == name {
			r.routes = append(r.routes[:i], r.routes[i+1:]...)
			r.logger.Info("TCP route removed", zap.String("name", name))
			return nil
		}
	}

	return fmt.Errorf("route %s not found", name)
}

// UpdateRoute updates an existing route.
func (r *Router) UpdateRoute(route *TCPRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, existing := range r.routes {
		if existing.Name != route.Name {
			continue
		}
		// Set default timeouts if not specified
		if route.IdleTimeout == 0 {
			route.IdleTimeout = 5 * time.Minute
		}
		if route.ConnectTimeout == 0 {
			route.ConnectTimeout = 30 * time.Second
		}

		r.routes[i] = route
		r.sortRoutes()

		r.logger.Info("TCP route updated",
			zap.String("name", route.Name),
			zap.Int("backends", len(route.BackendRefs)),
		)
		return nil
	}

	return fmt.Errorf("route %s not found", route.Name)
}

// GetRoute returns a route by name.
func (r *Router) GetRoute(name string) *TCPRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, route := range r.routes {
		if route.Name == name {
			return route
		}
	}
	return nil
}

// ListRoutes returns all route names.
func (r *Router) ListRoutes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.routes))
	for i, route := range r.routes {
		names[i] = route.Name
	}
	return names
}

// GetAllRoutes returns all routes.
func (r *Router) GetAllRoutes() []*TCPRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*TCPRoute, len(r.routes))
	copy(routes, r.routes)
	return routes
}

// sortRoutes sorts routes by priority (higher priority first).
func (r *Router) sortRoutes() {
	// Simple bubble sort for small number of routes
	for i := 0; i < len(r.routes)-1; i++ {
		for j := 0; j < len(r.routes)-i-1; j++ {
			if r.routes[j].Priority < r.routes[j+1].Priority {
				r.routes[j], r.routes[j+1] = r.routes[j+1], r.routes[j]
			}
		}
	}
}

// Clear removes all routes.
func (r *Router) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes = make([]*TCPRoute, 0)
	r.logger.Info("all TCP routes cleared")
}

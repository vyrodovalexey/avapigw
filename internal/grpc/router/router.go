package router

import (
	"fmt"
	"sort"
	"sync"

	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// Router is the gRPC routing engine.
type Router struct {
	routes   []*CompiledGRPCRoute
	routeMap map[string]*CompiledGRPCRoute
	mu       sync.RWMutex
}

// CompiledGRPCRoute is a pre-compiled gRPC route for efficient matching.
type CompiledGRPCRoute struct {
	Name     string
	Config   config.GRPCRoute
	Matchers []*CompiledGRPCMatch
	Priority int
}

// CompiledGRPCMatch is a pre-compiled match condition.
type CompiledGRPCMatch struct {
	ServiceMatcher   StringMatcher
	MethodMatcher    StringMatcher
	MetadataMatchers []MetadataMatcher
	AuthorityMatcher StringMatcher
	WithoutHeaders   []string
}

// MatchResult contains the result of a route match.
type MatchResult struct {
	Route   *CompiledGRPCRoute
	Service string
	Method  string
}

// New creates a new gRPC router.
func New() *Router {
	return &Router{
		routes:   make([]*CompiledGRPCRoute, 0),
		routeMap: make(map[string]*CompiledGRPCRoute),
	}
}

// AddRoute adds a route to the router.
func (r *Router) AddRoute(route config.GRPCRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate route names
	if _, exists := r.routeMap[route.Name]; exists {
		return fmt.Errorf("duplicate gRPC route name: %s", route.Name)
	}

	compiled, err := r.compileRoute(route)
	if err != nil {
		return fmt.Errorf("failed to compile gRPC route %s: %w", route.Name, err)
	}

	r.routes = append(r.routes, compiled)
	r.routeMap[route.Name] = compiled

	// Sort routes by priority (higher priority first)
	sort.Slice(r.routes, func(i, j int) bool {
		return r.routes[i].Priority > r.routes[j].Priority
	})

	return nil
}

// RemoveRoute removes a route from the router.
func (r *Router) RemoveRoute(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.routeMap[name]; !exists {
		return fmt.Errorf("gRPC route not found: %s", name)
	}

	delete(r.routeMap, name)

	// Remove from slice
	for i, route := range r.routes {
		if route.Name == name {
			r.routes = append(r.routes[:i], r.routes[i+1:]...)
			break
		}
	}

	return nil
}

// Match finds the first matching route for a gRPC request.
func (r *Router) Match(fullMethod string, md metadata.MD) (*MatchResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	service, method := ParseFullMethod(fullMethod)

	for _, route := range r.routes {
		if r.matchRoute(route, service, method, md) {
			return &MatchResult{
				Route:   route,
				Service: service,
				Method:  method,
			}, nil
		}
	}

	return nil, fmt.Errorf("no matching gRPC route for %s", fullMethod)
}

// matchRoute checks if a request matches a compiled route.
// Uses OR semantics between match blocks.
func (r *Router) matchRoute(route *CompiledGRPCRoute, service, method string, md metadata.MD) bool {
	// If no matchers, match everything
	if len(route.Matchers) == 0 {
		return true
	}

	// OR semantics: any match block can match
	for _, matcher := range route.Matchers {
		if r.matchCondition(matcher, service, method, md) {
			return true
		}
	}

	return false
}

// matchCondition checks if a request matches a single match condition.
// Uses AND semantics within a match block.
func (r *Router) matchCondition(matcher *CompiledGRPCMatch, service, method string, md metadata.MD) bool {
	// Check service
	if matcher.ServiceMatcher != nil && !matcher.ServiceMatcher.Match(service) {
		return false
	}

	// Check method
	if matcher.MethodMatcher != nil && !matcher.MethodMatcher.Match(method) {
		return false
	}

	// Check authority
	if matcher.AuthorityMatcher != nil {
		authority := ""
		if values := md.Get(":authority"); len(values) > 0 {
			authority = values[0]
		}
		if !matcher.AuthorityMatcher.Match(authority) {
			return false
		}
	}

	// Check metadata (AND semantics)
	for _, metaMatcher := range matcher.MetadataMatchers {
		if !metaMatcher.Match(md) {
			return false
		}
	}

	// Check without headers (must NOT be present)
	for _, header := range matcher.WithoutHeaders {
		if values := md.Get(header); len(values) > 0 {
			return false
		}
	}

	return true
}

// compileRoute compiles a route configuration into a CompiledGRPCRoute.
func (r *Router) compileRoute(route config.GRPCRoute) (*CompiledGRPCRoute, error) {
	compiled := &CompiledGRPCRoute{
		Name:     route.Name,
		Config:   route,
		Matchers: make([]*CompiledGRPCMatch, 0, len(route.Match)),
		Priority: calculatePriority(route),
	}

	for _, match := range route.Match {
		compiledMatch, err := r.compileMatch(match)
		if err != nil {
			return nil, err
		}
		compiled.Matchers = append(compiled.Matchers, compiledMatch)
	}

	return compiled, nil
}

// compileMatch compiles a single match condition.
func (r *Router) compileMatch(match config.GRPCRouteMatch) (*CompiledGRPCMatch, error) {
	compiled := &CompiledGRPCMatch{
		WithoutHeaders: match.WithoutHeaders,
	}

	// Compile service matcher
	if match.Service != nil {
		matcher, err := NewStringMatcher(match.Service)
		if err != nil {
			return nil, fmt.Errorf("failed to compile service matcher: %w", err)
		}
		compiled.ServiceMatcher = matcher
	}

	// Compile method matcher
	if match.Method != nil {
		matcher, err := NewStringMatcher(match.Method)
		if err != nil {
			return nil, fmt.Errorf("failed to compile method matcher: %w", err)
		}
		compiled.MethodMatcher = matcher
	}

	// Compile authority matcher
	if match.Authority != nil {
		matcher, err := NewStringMatcher(match.Authority)
		if err != nil {
			return nil, fmt.Errorf("failed to compile authority matcher: %w", err)
		}
		compiled.AuthorityMatcher = matcher
	}

	// Compile metadata matchers
	for _, meta := range match.Metadata {
		matcher, err := NewMetadataMatcher(meta)
		if err != nil {
			return nil, fmt.Errorf("failed to compile metadata matcher for %s: %w", meta.Name, err)
		}
		compiled.MetadataMatchers = append(compiled.MetadataMatchers, matcher)
	}

	return compiled, nil
}

// Match type constants.
const (
	matchTypeExact  = "exact"
	matchTypePrefix = "prefix"
	matchTypeRegex  = "regex"
)

// calculatePriority calculates the priority of a gRPC route.
// Higher priority routes are matched first.
func calculatePriority(route config.GRPCRoute) int {
	priority := 0

	for _, match := range route.Match {
		priority += calculateServicePriority(match.Service)
		priority += calculateMethodPriority(match.Method)
		priority += calculateAuthorityPriority(match.Authority)
		priority += len(match.Metadata) * 10
		priority += len(match.WithoutHeaders) * 5
	}

	return priority
}

// calculateServicePriority calculates priority contribution from service match.
func calculateServicePriority(service *config.StringMatch) int {
	if service == nil {
		return 0
	}

	switch service.MatchType() {
	case matchTypeExact:
		if service.Exact != "*" {
			return 1000
		}
	case matchTypePrefix:
		if service.Prefix != "*" {
			return 500 + len(service.Prefix)
		}
	case matchTypeRegex:
		return 100
	}
	return 0
}

// calculateMethodPriority calculates priority contribution from method match.
func calculateMethodPriority(method *config.StringMatch) int {
	if method == nil {
		return 0
	}

	switch method.MatchType() {
	case matchTypeExact:
		if method.Exact != "*" {
			return 500
		}
	case matchTypePrefix:
		if method.Prefix != "*" {
			return 250 + len(method.Prefix)
		}
	case matchTypeRegex:
		return 50
	}
	return 0
}

// calculateAuthorityPriority calculates priority contribution from authority match.
func calculateAuthorityPriority(authority *config.StringMatch) int {
	if authority != nil && !authority.IsEmpty() && !authority.IsWildcard() {
		return 100
	}
	return 0
}

// GetRoute returns a route by name.
func (r *Router) GetRoute(name string) (*CompiledGRPCRoute, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, exists := r.routeMap[name]
	return route, exists
}

// GetRoutes returns all routes.
func (r *Router) GetRoutes() []*CompiledGRPCRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*CompiledGRPCRoute, len(r.routes))
	copy(routes, r.routes)
	return routes
}

// Clear removes all routes.
func (r *Router) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes = make([]*CompiledGRPCRoute, 0)
	r.routeMap = make(map[string]*CompiledGRPCRoute)
}

// LoadRoutes loads routes from configuration.
func (r *Router) LoadRoutes(routes []config.GRPCRoute) error {
	r.Clear()

	for _, route := range routes {
		if err := r.AddRoute(route); err != nil {
			return err
		}
	}

	return nil
}

// RouteCount returns the number of routes.
func (r *Router) RouteCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.routes)
}

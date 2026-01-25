package router

import (
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// Route priority constants for calculating route matching order.
// Higher priority routes are matched first.
const (
	// priorityExactMatch is the base priority for exact path matches.
	priorityExactMatch = 1000

	// priorityPrefixMatch is the base priority for prefix path matches.
	// Longer prefixes receive additional priority based on their length.
	priorityPrefixMatch = 500

	// priorityRegexMatch is the base priority for regex path matches.
	priorityRegexMatch = 100

	// priorityMethodRestriction is the priority bonus for routes with method restrictions.
	priorityMethodRestriction = 50

	// priorityHeaderRestriction is the priority bonus per header restriction.
	priorityHeaderRestriction = 10

	// priorityQueryRestriction is the priority bonus per query parameter restriction.
	priorityQueryRestriction = 5
)

// Router is the main routing engine.
type Router struct {
	routes   []*CompiledRoute
	routeMap map[string]*CompiledRoute
	mu       sync.RWMutex
}

// CompiledRoute is a pre-compiled route for efficient matching.
type CompiledRoute struct {
	Name           string
	Config         config.Route
	PathMatchers   []PathMatcher
	MethodMatcher  *MethodMatcher
	HeaderMatchers []*HeaderMatcher
	QueryMatchers  []*QueryParamMatcher
	Priority       int
}

// MatchResult contains the result of a route match.
type MatchResult struct {
	Route      *CompiledRoute
	PathParams map[string]string
}

// New creates a new router.
func New() *Router {
	return &Router{
		routes:   make([]*CompiledRoute, 0),
		routeMap: make(map[string]*CompiledRoute),
	}
}

// AddRoute adds a route to the router.
func (r *Router) AddRoute(route config.Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate route names
	if _, exists := r.routeMap[route.Name]; exists {
		return fmt.Errorf("duplicate route name: %s", route.Name)
	}

	compiled, err := r.compileRoute(route)
	if err != nil {
		return fmt.Errorf("failed to compile route %s: %w", route.Name, err)
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
		return fmt.Errorf("route not found: %s", name)
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

// Match finds the first matching route for a request.
func (r *Router) Match(req *http.Request) (*MatchResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	path := req.URL.Path
	method := req.Method

	for _, route := range r.routes {
		if result := r.matchRoute(route, path, method, req); result != nil {
			return result, nil
		}
	}

	return nil, util.NewRouteNotFoundError(method, path)
}

// matchRoute checks if a request matches a compiled route.
func (r *Router) matchRoute(route *CompiledRoute, path, method string, req *http.Request) *MatchResult {
	// Check method first (fastest check)
	if route.MethodMatcher != nil && !route.MethodMatcher.Match(method) {
		return nil
	}

	// Check path
	var pathParams map[string]string
	pathMatched := false

	if len(route.PathMatchers) == 0 {
		// No path matchers means match all paths
		pathMatched = true
	} else {
		for _, matcher := range route.PathMatchers {
			if matched, params := matcher.Match(path); matched {
				pathMatched = true
				pathParams = params
				break
			}
		}
	}

	if !pathMatched {
		return nil
	}

	// Check headers
	for _, headerMatcher := range route.HeaderMatchers {
		if !headerMatcher.Match(req.Header) {
			return nil
		}
	}

	// Check query parameters
	query := req.URL.Query()
	for _, queryMatcher := range route.QueryMatchers {
		if !queryMatcher.Match(query) {
			return nil
		}
	}

	return &MatchResult{
		Route:      route,
		PathParams: pathParams,
	}
}

// compileRoute compiles a route configuration into a CompiledRoute.
func (r *Router) compileRoute(route config.Route) (*CompiledRoute, error) {
	compiled := &CompiledRoute{
		Name:     route.Name,
		Config:   route,
		Priority: calculatePriority(route),
	}

	for _, match := range route.Match {
		if err := r.compileMatchCondition(&match, compiled); err != nil {
			return nil, err
		}
	}

	return compiled, nil
}

// compileMatchCondition compiles a single match condition into the compiled route.
func (r *Router) compileMatchCondition(match *config.RouteMatch, compiled *CompiledRoute) error {
	if err := r.compilePathMatcher(match, compiled); err != nil {
		return err
	}

	if len(match.Methods) > 0 {
		compiled.MethodMatcher = NewMethodMatcher(match.Methods)
	}

	if err := r.compileHeaderMatchers(match, compiled); err != nil {
		return err
	}

	return r.compileQueryMatchers(match, compiled)
}

// compilePathMatcher compiles path matcher for a match condition.
func (r *Router) compilePathMatcher(match *config.RouteMatch, compiled *CompiledRoute) error {
	if match.URI == nil || match.URI.IsEmpty() {
		return nil
	}

	pathMatcher, err := r.createPathMatcher(match.URI)
	if err != nil {
		return fmt.Errorf("failed to create path matcher: %w", err)
	}
	if pathMatcher != nil {
		compiled.PathMatchers = append(compiled.PathMatchers, pathMatcher)
	}
	return nil
}

// compileHeaderMatchers compiles header matchers for a match condition.
func (r *Router) compileHeaderMatchers(match *config.RouteMatch, compiled *CompiledRoute) error {
	for _, headerCfg := range match.Headers {
		headerMatcher, err := NewHeaderMatcher(headerCfg)
		if err != nil {
			return fmt.Errorf("failed to create header matcher: %w", err)
		}
		compiled.HeaderMatchers = append(compiled.HeaderMatchers, headerMatcher)
	}
	return nil
}

// compileQueryMatchers compiles query matchers for a match condition.
func (r *Router) compileQueryMatchers(match *config.RouteMatch, compiled *CompiledRoute) error {
	for _, queryCfg := range match.QueryParams {
		queryMatcher, err := NewQueryParamMatcher(queryCfg)
		if err != nil {
			return fmt.Errorf("failed to create query matcher: %w", err)
		}
		compiled.QueryMatchers = append(compiled.QueryMatchers, queryMatcher)
	}
	return nil
}

// createPathMatcher creates a path matcher from URI configuration.
func (r *Router) createPathMatcher(uri *config.URIMatch) (PathMatcher, error) {
	if uri.Exact != "" {
		// Check if it has path parameters
		if HasPathParameters(uri.Exact) {
			return NewParameterMatcher(uri.Exact)
		}
		return NewExactMatcher(uri.Exact), nil
	}

	if uri.Prefix != "" {
		// Check if it has path parameters
		if HasPathParameters(uri.Prefix) {
			return NewParameterMatcher(uri.Prefix)
		}
		// Check if it has wildcards
		if HasWildcards(uri.Prefix) {
			return NewWildcardMatcher(uri.Prefix)
		}
		return NewPrefixMatcher(uri.Prefix), nil
	}

	if uri.Regex != "" {
		return NewRegexMatcher(uri.Regex)
	}

	return nil, nil
}

// calculatePriority calculates the priority of a route.
// Higher priority routes are matched first.
// Priority is determined by match specificity:
// - Exact path matches have the highest priority
// - Prefix matches have medium priority (longer prefixes rank higher)
// - Regex matches have lower priority
// - Additional restrictions (methods, headers, query params) increase priority
func calculatePriority(route config.Route) int {
	priority := 0

	for _, match := range route.Match {
		// Exact matches have highest priority
		if match.URI != nil && match.URI.Exact != "" {
			priority += priorityExactMatch
		}

		// Prefix matches have medium priority
		if match.URI != nil && match.URI.Prefix != "" {
			// Longer prefixes have higher priority
			priority += priorityPrefixMatch + len(match.URI.Prefix)
		}

		// Regex matches have lower priority
		if match.URI != nil && match.URI.Regex != "" {
			priority += priorityRegexMatch
		}

		// Method restrictions increase priority
		if len(match.Methods) > 0 {
			priority += priorityMethodRestriction
		}

		// Header restrictions increase priority
		priority += len(match.Headers) * priorityHeaderRestriction

		// Query restrictions increase priority
		priority += len(match.QueryParams) * priorityQueryRestriction
	}

	return priority
}

// GetRoute returns a route by name.
func (r *Router) GetRoute(name string) (*CompiledRoute, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, exists := r.routeMap[name]
	return route, exists
}

// GetRoutes returns all routes.
func (r *Router) GetRoutes() []*CompiledRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*CompiledRoute, len(r.routes))
	copy(routes, r.routes)
	return routes
}

// Clear removes all routes.
func (r *Router) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes = make([]*CompiledRoute, 0)
	r.routeMap = make(map[string]*CompiledRoute)
}

// LoadRoutes loads routes from configuration.
func (r *Router) LoadRoutes(routes []config.Route) error {
	r.Clear()

	for _, route := range routes {
		if err := r.AddRoute(route); err != nil {
			return err
		}
	}

	return nil
}

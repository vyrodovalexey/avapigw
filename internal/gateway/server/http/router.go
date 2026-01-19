package http

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Router manages HTTP routes and performs request matching.
type Router struct {
	routes  map[string]*Route
	mu      sync.RWMutex
	matcher *RouteMatcher
	logger  *zap.Logger
}

// Route represents an HTTP route configuration.
type Route struct {
	Name      string
	Hostnames []string
	Rules     []RouteRule
	Backends  []BackendRef
	Priority  int
}

// RouteRule defines a single routing rule with matches and filters.
type RouteRule struct {
	Matches     []RouteMatch
	Filters     []RouteFilter
	BackendRefs []BackendRef
	Timeouts    *RouteTimeouts
}

// RouteMatch defines conditions for matching a request.
type RouteMatch struct {
	Path        *PathMatch
	Headers     []HeaderMatch
	QueryParams []QueryParamMatch
	Method      *string
}

// PathMatch defines path matching criteria.
type PathMatch struct {
	Type  PathMatchType
	Value string
}

// PathMatchType defines the type of path matching.
type PathMatchType string

const (
	PathMatchExact             PathMatchType = "Exact"
	PathMatchPrefix            PathMatchType = "PathPrefix"
	PathMatchRegularExpression PathMatchType = "RegularExpression"
)

// HeaderMatch defines header matching criteria.
type HeaderMatch struct {
	Type  HeaderMatchType
	Name  string
	Value string
}

// HeaderMatchType defines the type of header matching.
type HeaderMatchType string

const (
	HeaderMatchExact             HeaderMatchType = "Exact"
	HeaderMatchRegularExpression HeaderMatchType = "RegularExpression"
)

// QueryParamMatch defines query parameter matching criteria.
type QueryParamMatch struct {
	Type  QueryParamMatchType
	Name  string
	Value string
}

// QueryParamMatchType defines the type of query parameter matching.
type QueryParamMatchType string

const (
	QueryParamMatchExact             QueryParamMatchType = "Exact"
	QueryParamMatchRegularExpression QueryParamMatchType = "RegularExpression"
)

// RouteFilter defines a filter to apply to requests/responses.
type RouteFilter struct {
	Type                   RouteFilterType
	RequestHeaderModifier  *HeaderModifier
	ResponseHeaderModifier *HeaderModifier
	URLRewrite             *URLRewrite
	RequestRedirect        *RequestRedirect
}

// RouteFilterType defines the type of route filter.
type RouteFilterType string

const (
	RouteFilterRequestHeaderModifier  RouteFilterType = "RequestHeaderModifier"
	RouteFilterResponseHeaderModifier RouteFilterType = "ResponseHeaderModifier"
	RouteFilterURLRewrite             RouteFilterType = "URLRewrite"
	RouteFilterRequestRedirect        RouteFilterType = "RequestRedirect"
)

// HeaderModifier defines header modification operations.
type HeaderModifier struct {
	Set    []HTTPHeader
	Add    []HTTPHeader
	Remove []string
}

// HTTPHeader represents an HTTP header.
type HTTPHeader struct {
	Name  string
	Value string
}

// URLRewrite defines URL rewrite configuration.
type URLRewrite struct {
	Hostname *string
	Path     *PathModifier
}

// PathModifier defines path modification.
type PathModifier struct {
	Type               PathModifierType
	ReplaceFullPath    *string
	ReplacePrefixMatch *string
}

// PathModifierType defines the type of path modification.
type PathModifierType string

const (
	PathModifierReplaceFullPath    PathModifierType = "ReplaceFullPath"
	PathModifierReplacePrefixMatch PathModifierType = "ReplacePrefixMatch"
)

// RequestRedirect defines redirect configuration.
type RequestRedirect struct {
	Scheme     *string
	Hostname   *string
	Port       *int
	StatusCode int
}

// RouteTimeouts defines timeout configuration for a route.
type RouteTimeouts struct {
	Request        *time.Duration
	BackendRequest *time.Duration
	Idle           *time.Duration
}

// BackendRef references a backend service.
type BackendRef struct {
	Name      string
	Namespace string
	Port      int
	Weight    int
}

// RouteMatcher performs route matching.
type RouteMatcher struct {
	compiledRoutes []*CompiledRoute
	mu             sync.RWMutex
}

// CompiledRoute is a pre-compiled route for efficient matching.
type CompiledRoute struct {
	Route       *Route
	HostRegexes []*regexp.Regexp
	Rules       []*CompiledRule
}

// CompiledRule is a pre-compiled rule for efficient matching.
type CompiledRule struct {
	Rule           *RouteRule
	PathRegex      *regexp.Regexp
	PathPrefix     string
	PathExact      string
	MethodMatcher  *string
	HeaderMatchers []*CompiledHeaderMatcher
	QueryMatchers  []*CompiledQueryMatcher
	Priority       int
}

// CompiledHeaderMatcher is a pre-compiled header matcher.
type CompiledHeaderMatcher struct {
	Name  string
	Regex *regexp.Regexp
	Exact string
}

// CompiledQueryMatcher is a pre-compiled query parameter matcher.
type CompiledQueryMatcher struct {
	Name  string
	Regex *regexp.Regexp
	Exact string
}

// MatchResult contains the result of a route match.
type MatchResult struct {
	Route *Route
	Rule  *RouteRule
}

// NewRouter creates a new router.
func NewRouter(logger *zap.Logger) *Router {
	return &Router{
		routes:  make(map[string]*Route),
		matcher: &RouteMatcher{},
		logger:  logger,
	}
}

// Match finds a matching route for the given request.
func (r *Router) Match(req *http.Request) (*Route, *RouteRule) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	host := req.Host
	// Remove port from host if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	path := req.URL.Path
	method := req.Method

	headers := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = values[0]
		}
	}

	query := make(map[string]string)
	for name, values := range req.URL.Query() {
		if len(values) > 0 {
			query[name] = values[0]
		}
	}

	result, ok := r.matcher.Match(host, path, method, headers, query)
	if !ok {
		return nil, nil
	}

	return result.Route, result.Rule
}

// AddRoute adds a new route.
func (r *Router) AddRoute(route *Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.routes[route.Name]; exists {
		return fmt.Errorf("route %s already exists", route.Name)
	}

	r.routes[route.Name] = route
	r.rebuildMatcher()

	r.logger.Info("route added",
		zap.String("name", route.Name),
		zap.Strings("hostnames", route.Hostnames),
	)

	return nil
}

// RemoveRoute removes a route by name.
func (r *Router) RemoveRoute(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.routes[name]; !exists {
		return fmt.Errorf("route %s not found", name)
	}

	delete(r.routes, name)
	r.rebuildMatcher()

	r.logger.Info("route removed", zap.String("name", name))

	return nil
}

// UpdateRoute updates an existing route.
func (r *Router) UpdateRoute(route *Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.routes[route.Name]; !exists {
		return fmt.Errorf("route %s not found", route.Name)
	}

	r.routes[route.Name] = route
	r.rebuildMatcher()

	r.logger.Info("route updated", zap.String("name", route.Name))

	return nil
}

// GetRoute returns a route by name.
func (r *Router) GetRoute(name string) *Route {
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

// rebuildMatcher rebuilds the route matcher (caller must hold lock).
func (r *Router) rebuildMatcher() {
	compiledRoutes := make([]*CompiledRoute, 0, len(r.routes))

	for _, route := range r.routes {
		compiled := compileRoute(route)
		compiledRoutes = append(compiledRoutes, compiled)
	}

	// Sort by priority (higher priority first)
	sort.Slice(compiledRoutes, func(i, j int) bool {
		return compiledRoutes[i].Route.Priority > compiledRoutes[j].Route.Priority
	})

	r.matcher.mu.Lock()
	r.matcher.compiledRoutes = compiledRoutes
	r.matcher.mu.Unlock()
}

// compileRoute compiles a route for efficient matching.
func compileRoute(route *Route) *CompiledRoute {
	compiled := &CompiledRoute{
		Route:       route,
		HostRegexes: make([]*regexp.Regexp, 0, len(route.Hostnames)),
		Rules:       make([]*CompiledRule, 0, len(route.Rules)),
	}

	// Compile hostname patterns
	for _, hostname := range route.Hostnames {
		regex := hostnameToRegex(hostname)
		if regex != nil {
			compiled.HostRegexes = append(compiled.HostRegexes, regex)
		}
	}

	// Compile rules
	for i := range route.Rules {
		compiledRule := compileRule(&route.Rules[i], i)
		compiled.Rules = append(compiled.Rules, compiledRule)
	}

	return compiled
}

// compileRule compiles a rule for efficient matching.
func compileRule(rule *RouteRule, index int) *CompiledRule {
	compiled := &CompiledRule{
		Rule:           rule,
		HeaderMatchers: make([]*CompiledHeaderMatcher, 0),
		QueryMatchers:  make([]*CompiledQueryMatcher, 0),
		Priority:       index,
	}

	for _, match := range rule.Matches {
		compilePathMatcher(compiled, match.Path)
		compileMethodMatcher(compiled, match.Method)
		compileHeaderMatchers(compiled, match.Headers)
		compileQueryMatchers(compiled, match.QueryParams)
	}

	return compiled
}

// compilePathMatcher compiles the path matcher for a route match.
func compilePathMatcher(compiled *CompiledRule, path *PathMatch) {
	if path == nil {
		return
	}

	switch path.Type {
	case PathMatchExact:
		compiled.PathExact = path.Value
	case PathMatchPrefix:
		compiled.PathPrefix = path.Value
	case PathMatchRegularExpression:
		if regex, err := regexp.Compile(path.Value); err == nil {
			compiled.PathRegex = regex
		}
	}
}

// compileMethodMatcher sets the method matcher for a route match.
func compileMethodMatcher(compiled *CompiledRule, method *string) {
	if method != nil {
		compiled.MethodMatcher = method
	}
}

// compileHeaderMatchers compiles header matchers for a route match.
func compileHeaderMatchers(compiled *CompiledRule, headers []HeaderMatch) {
	for _, header := range headers {
		headerMatcher := &CompiledHeaderMatcher{
			Name: strings.ToLower(header.Name),
		}
		switch header.Type {
		case HeaderMatchExact:
			headerMatcher.Exact = header.Value
		case HeaderMatchRegularExpression:
			if regex, err := regexp.Compile(header.Value); err == nil {
				headerMatcher.Regex = regex
			}
		}
		compiled.HeaderMatchers = append(compiled.HeaderMatchers, headerMatcher)
	}
}

// compileQueryMatchers compiles query parameter matchers for a route match.
func compileQueryMatchers(compiled *CompiledRule, queryParams []QueryParamMatch) {
	for _, query := range queryParams {
		queryMatcher := &CompiledQueryMatcher{
			Name: query.Name,
		}
		switch query.Type {
		case QueryParamMatchExact:
			queryMatcher.Exact = query.Value
		case QueryParamMatchRegularExpression:
			if regex, err := regexp.Compile(query.Value); err == nil {
				queryMatcher.Regex = regex
			}
		}
		compiled.QueryMatchers = append(compiled.QueryMatchers, queryMatcher)
	}
}

// hostnameToRegex converts a hostname pattern to a regex.
func hostnameToRegex(hostname string) *regexp.Regexp {
	if hostname == "" || hostname == "*" {
		return nil // Match all
	}

	// Escape special regex characters except *
	escaped := regexp.QuoteMeta(hostname)
	// Replace escaped \* with regex pattern for wildcard
	escaped = strings.ReplaceAll(escaped, `\*`, `[^.]+`)
	// Anchor the pattern
	pattern := "^" + escaped + "$"

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return regex
}

// Match finds a matching route for the given request parameters.
func (m *RouteMatcher) Match(host, path, method string, headers, query map[string]string) (*MatchResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, compiled := range m.compiledRoutes {
		// Check hostname match
		if !m.matchHostname(compiled, host) {
			continue
		}

		// Check rules
		for _, rule := range compiled.Rules {
			if m.matchRule(rule, path, method, headers, query) {
				return &MatchResult{
					Route: compiled.Route,
					Rule:  rule.Rule,
				}, true
			}
		}
	}

	return nil, false
}

// matchHostname checks if the host matches the route's hostname patterns.
func (m *RouteMatcher) matchHostname(compiled *CompiledRoute, host string) bool {
	// If no hostnames specified, match all
	if len(compiled.HostRegexes) == 0 && len(compiled.Route.Hostnames) == 0 {
		return true
	}

	// Check for wildcard hostname
	for _, hostname := range compiled.Route.Hostnames {
		if hostname == "*" {
			return true
		}
	}

	// Check regex patterns
	for _, regex := range compiled.HostRegexes {
		if regex.MatchString(host) {
			return true
		}
	}

	return false
}

// matchRule checks if the request matches the rule.
func (m *RouteMatcher) matchRule(rule *CompiledRule, path, method string, headers, query map[string]string) bool {
	if len(rule.Rule.Matches) == 0 {
		return true
	}

	if !m.matchPath(rule, path) {
		return false
	}

	if !m.matchMethod(rule, method) {
		return false
	}

	if !m.matchHeaders(rule.HeaderMatchers, headers) {
		return false
	}

	return m.matchQueryParams(rule.QueryMatchers, query)
}

// matchMethod checks if the method matches the rule's method criteria.
func (m *RouteMatcher) matchMethod(rule *CompiledRule, method string) bool {
	return rule.MethodMatcher == nil || *rule.MethodMatcher == method
}

// matchHeaders checks if all header matchers are satisfied.
func (m *RouteMatcher) matchHeaders(matchers []*CompiledHeaderMatcher, headers map[string]string) bool {
	for _, matcher := range matchers {
		if !m.matchSingleHeader(matcher, headers) {
			return false
		}
	}
	return true
}

// matchSingleHeader checks if a single header matcher is satisfied.
func (m *RouteMatcher) matchSingleHeader(matcher *CompiledHeaderMatcher, headers map[string]string) bool {
	value, exists := headers[matcher.Name]
	if !exists {
		return false
	}
	if matcher.Exact != "" && value != matcher.Exact {
		return false
	}
	if matcher.Regex != nil && !matcher.Regex.MatchString(value) {
		return false
	}
	return true
}

// matchQueryParams checks if all query parameter matchers are satisfied.
func (m *RouteMatcher) matchQueryParams(matchers []*CompiledQueryMatcher, query map[string]string) bool {
	for _, matcher := range matchers {
		if !m.matchSingleQueryParam(matcher, query) {
			return false
		}
	}
	return true
}

// matchSingleQueryParam checks if a single query parameter matcher is satisfied.
func (m *RouteMatcher) matchSingleQueryParam(matcher *CompiledQueryMatcher, query map[string]string) bool {
	value, exists := query[matcher.Name]
	if !exists {
		return false
	}
	if matcher.Exact != "" && value != matcher.Exact {
		return false
	}
	if matcher.Regex != nil && !matcher.Regex.MatchString(value) {
		return false
	}
	return true
}

// matchPath checks if the path matches the rule's path criteria.
func (m *RouteMatcher) matchPath(rule *CompiledRule, path string) bool {
	// Exact match
	if rule.PathExact != "" {
		return path == rule.PathExact
	}

	// Prefix match
	if rule.PathPrefix != "" {
		return strings.HasPrefix(path, rule.PathPrefix)
	}

	// Regex match
	if rule.PathRegex != nil {
		return rule.PathRegex.MatchString(path)
	}

	// No path criteria, match all
	return true
}

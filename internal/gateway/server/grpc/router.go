package grpc

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

// Router manages gRPC routes and performs request matching.
type Router struct {
	routes  map[string]*GRPCRoute
	mu      sync.RWMutex
	matcher *GRPCRouteMatcher
	logger  *zap.Logger
}

// GRPCRoute represents a gRPC route configuration.
type GRPCRoute struct {
	Name      string
	Hostnames []string
	Rules     []GRPCRouteRule
	Priority  int
}

// GRPCRouteRule defines a single routing rule with matches and filters.
type GRPCRouteRule struct {
	Matches     []GRPCMethodMatch
	Filters     []GRPCRouteFilter
	BackendRefs []BackendRef
}

// GRPCMethodMatch defines conditions for matching a gRPC request.
type GRPCMethodMatch struct {
	// Service is the gRPC service name (e.g., "users.UserService")
	Service string

	// Method is the gRPC method name (e.g., "GetUser" or "*" for all)
	Method string

	// Type is the match type: "Exact" or "RegularExpression"
	Type GRPCMethodMatchType

	// Headers are additional header matchers
	Headers []GRPCHeaderMatch
}

// GRPCMethodMatchType defines the type of method matching.
type GRPCMethodMatchType string

const (
	// GRPCMethodMatchTypeExact matches the service/method exactly.
	GRPCMethodMatchTypeExact GRPCMethodMatchType = "Exact"

	// GRPCMethodMatchTypeRegex matches using regular expressions.
	GRPCMethodMatchTypeRegex GRPCMethodMatchType = "RegularExpression"
)

// GRPCHeaderMatch defines header matching criteria.
type GRPCHeaderMatch struct {
	Name  string
	Value string
	Type  GRPCHeaderMatchType
}

// GRPCHeaderMatchType defines the type of header matching.
type GRPCHeaderMatchType string

const (
	// GRPCHeaderMatchTypeExact matches the header value exactly.
	GRPCHeaderMatchTypeExact GRPCHeaderMatchType = "Exact"

	// GRPCHeaderMatchTypeRegex matches using regular expressions.
	GRPCHeaderMatchTypeRegex GRPCHeaderMatchType = "RegularExpression"
)

// GRPCRouteFilter defines a filter to apply to requests/responses.
type GRPCRouteFilter struct {
	Type                   GRPCRouteFilterType
	RequestHeaderModifier  *HeaderModifier
	ResponseHeaderModifier *HeaderModifier
}

// GRPCRouteFilterType defines the type of route filter.
type GRPCRouteFilterType string

const (
	// GRPCRouteFilterRequestHeaderModifier modifies request headers.
	GRPCRouteFilterRequestHeaderModifier GRPCRouteFilterType = "RequestHeaderModifier"

	// GRPCRouteFilterResponseHeaderModifier modifies response headers.
	GRPCRouteFilterResponseHeaderModifier GRPCRouteFilterType = "ResponseHeaderModifier"
)

// HeaderModifier defines header modification operations.
type HeaderModifier struct {
	Set    map[string]string
	Add    map[string]string
	Remove []string
}

// BackendRef references a backend service.
type BackendRef struct {
	Name      string
	Namespace string
	Port      int
	Weight    int
}

// GRPCRouteMatcher performs route matching.
type GRPCRouteMatcher struct {
	compiledRoutes []*CompiledGRPCRoute
	mu             sync.RWMutex
}

// CompiledGRPCRoute is a pre-compiled route for efficient matching.
type CompiledGRPCRoute struct {
	Route       *GRPCRoute
	HostRegexes []*regexp.Regexp
	Rules       []*CompiledGRPCRule
}

// CompiledGRPCRule is a pre-compiled rule for efficient matching.
type CompiledGRPCRule struct {
	Rule           *GRPCRouteRule
	ServiceMatcher ServiceMatcher
	MethodMatcher  MethodMatcher
	HeaderMatchers []HeaderMatcher
	Priority       int
}

// ServiceMatcher defines the interface for service matching.
type ServiceMatcher interface {
	Match(service string) bool
}

// MethodMatcher defines the interface for method matching.
type MethodMatcher interface {
	Match(method string) bool
}

// HeaderMatcher defines the interface for header matching.
type HeaderMatcher interface {
	Name() string
	Match(value string) bool
}

// ExactServiceMatcher matches services exactly.
type ExactServiceMatcher struct {
	service string
}

// NewExactServiceMatcher creates a new exact service matcher.
func NewExactServiceMatcher(service string) *ExactServiceMatcher {
	return &ExactServiceMatcher{service: service}
}

// Match checks if the service matches exactly.
func (m *ExactServiceMatcher) Match(service string) bool {
	if m.service == "" || m.service == "*" {
		return true
	}
	return service == m.service
}

// RegexServiceMatcher matches services using regular expressions.
type RegexServiceMatcher struct {
	regex *regexp.Regexp
}

// NewRegexServiceMatcher creates a new regex service matcher.
func NewRegexServiceMatcher(pattern string) (*RegexServiceMatcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &RegexServiceMatcher{regex: regex}, nil
}

// Match checks if the service matches the regex.
func (m *RegexServiceMatcher) Match(service string) bool {
	return m.regex.MatchString(service)
}

// ExactMethodMatcher matches methods exactly.
type ExactMethodMatcher struct {
	method string
}

// NewExactMethodMatcher creates a new exact method matcher.
func NewExactMethodMatcher(method string) *ExactMethodMatcher {
	return &ExactMethodMatcher{method: method}
}

// Match checks if the method matches exactly.
func (m *ExactMethodMatcher) Match(method string) bool {
	if m.method == "" || m.method == "*" {
		return true
	}
	return method == m.method
}

// RegexMethodMatcher matches methods using regular expressions.
type RegexMethodMatcher struct {
	regex *regexp.Regexp
}

// NewRegexMethodMatcher creates a new regex method matcher.
func NewRegexMethodMatcher(pattern string) (*RegexMethodMatcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &RegexMethodMatcher{regex: regex}, nil
}

// Match checks if the method matches the regex.
func (m *RegexMethodMatcher) Match(method string) bool {
	return m.regex.MatchString(method)
}

// ExactHeaderMatcher matches headers exactly.
type ExactHeaderMatcher struct {
	name  string
	value string
}

// NewExactHeaderMatcher creates a new exact header matcher.
func NewExactHeaderMatcher(name, value string) *ExactHeaderMatcher {
	return &ExactHeaderMatcher{
		name:  strings.ToLower(name),
		value: value,
	}
}

// Name returns the header name.
func (m *ExactHeaderMatcher) Name() string {
	return m.name
}

// Match checks if the header value matches exactly.
func (m *ExactHeaderMatcher) Match(value string) bool {
	return value == m.value
}

// RegexHeaderMatcher matches headers using regular expressions.
type RegexHeaderMatcher struct {
	name  string
	regex *regexp.Regexp
}

// NewRegexHeaderMatcher creates a new regex header matcher.
func NewRegexHeaderMatcher(name, pattern string) (*RegexHeaderMatcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &RegexHeaderMatcher{
		name:  strings.ToLower(name),
		regex: regex,
	}, nil
}

// Name returns the header name.
func (m *RegexHeaderMatcher) Name() string {
	return m.name
}

// Match checks if the header value matches the regex.
func (m *RegexHeaderMatcher) Match(value string) bool {
	return m.regex.MatchString(value)
}

// GRPCMatchResult contains the result of a route match.
type GRPCMatchResult struct {
	Route *GRPCRoute
	Rule  *GRPCRouteRule
}

// NewRouter creates a new router.
func NewRouter(logger *zap.Logger) *Router {
	return &Router{
		routes:  make(map[string]*GRPCRoute),
		matcher: &GRPCRouteMatcher{},
		logger:  logger,
	}
}

// Match finds a matching route for the given gRPC request.
func (r *Router) Match(service, method string, md metadata.MD) (*GRPCRoute, *GRPCRouteRule) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Extract host from metadata
	host := ""
	if hosts := md.Get(":authority"); len(hosts) > 0 {
		host = hosts[0]
		// Remove port from host if present
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
	}

	// Convert metadata to headers map
	headers := make(map[string]string)
	for key, values := range md {
		if len(values) > 0 {
			headers[strings.ToLower(key)] = values[0]
		}
	}

	result, ok := r.matcher.Match(host, service, method, headers)
	if !ok {
		return nil, nil
	}

	return result.Route, result.Rule
}

// AddRoute adds a new route.
func (r *Router) AddRoute(route *GRPCRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.routes[route.Name]; exists {
		return fmt.Errorf("route %s already exists", route.Name)
	}

	r.routes[route.Name] = route
	r.rebuildMatcher()

	r.logger.Info("gRPC route added",
		zap.String("name", route.Name),
		zap.Strings("hostnames", route.Hostnames),
		zap.Int("rules", len(route.Rules)),
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

	r.logger.Info("gRPC route removed", zap.String("name", name))

	return nil
}

// UpdateRoute updates an existing route.
func (r *Router) UpdateRoute(route *GRPCRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.routes[route.Name]; !exists {
		return fmt.Errorf("route %s not found", route.Name)
	}

	r.routes[route.Name] = route
	r.rebuildMatcher()

	r.logger.Info("gRPC route updated", zap.String("name", route.Name))

	return nil
}

// GetRoute returns a route by name.
func (r *Router) GetRoute(name string) *GRPCRoute {
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
	compiledRoutes := make([]*CompiledGRPCRoute, 0, len(r.routes))

	for _, route := range r.routes {
		compiled := compileGRPCRoute(route, r.logger)
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

// compileGRPCRoute compiles a route for efficient matching.
func compileGRPCRoute(route *GRPCRoute, logger *zap.Logger) *CompiledGRPCRoute {
	compiled := &CompiledGRPCRoute{
		Route:       route,
		HostRegexes: make([]*regexp.Regexp, 0, len(route.Hostnames)),
		Rules:       make([]*CompiledGRPCRule, 0, len(route.Rules)),
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
		compiledRule := compileGRPCRule(&route.Rules[i], i, logger)
		compiled.Rules = append(compiled.Rules, compiledRule)
	}

	return compiled
}

// compileGRPCRule compiles a rule for efficient matching.
func compileGRPCRule(rule *GRPCRouteRule, index int, logger *zap.Logger) *CompiledGRPCRule {
	compiled := &CompiledGRPCRule{
		Rule:           rule,
		HeaderMatchers: make([]HeaderMatcher, 0),
		Priority:       index,
	}

	if len(rule.Matches) > 0 {
		match := rule.Matches[0]
		compiled.ServiceMatcher = compileServiceMatcher(match, logger)
		compiled.MethodMatcher = compileMethodMatcher(match, logger)
		compiled.HeaderMatchers = compileGRPCHeaderMatchers(match.Headers, logger)
	}

	return compiled
}

// compileServiceMatcher compiles the service matcher for a gRPC rule.
func compileServiceMatcher(match GRPCMethodMatch, logger *zap.Logger) ServiceMatcher {
	switch match.Type {
	case GRPCMethodMatchTypeRegex:
		if matcher, err := NewRegexServiceMatcher(match.Service); err == nil {
			return matcher
		}
		logger.Warn("failed to compile service regex",
			zap.String("pattern", match.Service),
			zap.Error(fmt.Errorf("regex compilation failed")),
		)
		return NewExactServiceMatcher(match.Service)
	default:
		return NewExactServiceMatcher(match.Service)
	}
}

// compileMethodMatcher compiles the method matcher for a gRPC rule.
func compileMethodMatcher(match GRPCMethodMatch, logger *zap.Logger) MethodMatcher {
	switch match.Type {
	case GRPCMethodMatchTypeRegex:
		if matcher, err := NewRegexMethodMatcher(match.Method); err == nil {
			return matcher
		}
		logger.Warn("failed to compile method regex",
			zap.String("pattern", match.Method),
			zap.Error(fmt.Errorf("regex compilation failed")),
		)
		return NewExactMethodMatcher(match.Method)
	default:
		return NewExactMethodMatcher(match.Method)
	}
}

// compileGRPCHeaderMatchers compiles header matchers for a gRPC rule.
func compileGRPCHeaderMatchers(headers []GRPCHeaderMatch, logger *zap.Logger) []HeaderMatcher {
	matchers := make([]HeaderMatcher, 0, len(headers))
	for _, header := range headers {
		matcher := compileGRPCHeaderMatcher(header, logger)
		if matcher != nil {
			matchers = append(matchers, matcher)
		}
	}
	return matchers
}

// compileGRPCHeaderMatcher compiles a single header matcher.
func compileGRPCHeaderMatcher(header GRPCHeaderMatch, logger *zap.Logger) HeaderMatcher {
	switch header.Type {
	case GRPCHeaderMatchTypeRegex:
		if matcher, err := NewRegexHeaderMatcher(header.Name, header.Value); err == nil {
			return matcher
		}
		logger.Warn("failed to compile header regex",
			zap.String("name", header.Name),
			zap.String("pattern", header.Value),
			zap.Error(fmt.Errorf("regex compilation failed")),
		)
		return nil
	default:
		return NewExactHeaderMatcher(header.Name, header.Value)
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
func (m *GRPCRouteMatcher) Match(host, service, method string, headers map[string]string) (*GRPCMatchResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, compiled := range m.compiledRoutes {
		// Check hostname match
		if !m.matchHostname(compiled, host) {
			continue
		}

		// Check rules
		for _, rule := range compiled.Rules {
			if m.matchRule(rule, service, method, headers) {
				return &GRPCMatchResult{
					Route: compiled.Route,
					Rule:  rule.Rule,
				}, true
			}
		}
	}

	return nil, false
}

// matchHostname checks if the host matches the route's hostname patterns.
func (m *GRPCRouteMatcher) matchHostname(compiled *CompiledGRPCRoute, host string) bool {
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
func (m *GRPCRouteMatcher) matchRule(rule *CompiledGRPCRule, service, method string, headers map[string]string) bool {
	// If no matches defined, match all
	if len(rule.Rule.Matches) == 0 {
		return true
	}

	// Check service
	if rule.ServiceMatcher != nil && !rule.ServiceMatcher.Match(service) {
		return false
	}

	// Check method
	if rule.MethodMatcher != nil && !rule.MethodMatcher.Match(method) {
		return false
	}

	// Check headers
	for _, headerMatcher := range rule.HeaderMatchers {
		value, exists := headers[headerMatcher.Name()]
		if !exists {
			return false
		}
		if !headerMatcher.Match(value) {
			return false
		}
	}

	return true
}

// Compile compiles the routes for efficient matching.
func (m *GRPCRouteMatcher) Compile(routes []*GRPCRoute, logger *zap.Logger) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	compiledRoutes := make([]*CompiledGRPCRoute, 0, len(routes))
	for _, route := range routes {
		compiled := compileGRPCRoute(route, logger)
		compiledRoutes = append(compiledRoutes, compiled)
	}

	// Sort by priority
	sort.Slice(compiledRoutes, func(i, j int) bool {
		return compiledRoutes[i].Route.Priority > compiledRoutes[j].Route.Priority
	})

	m.compiledRoutes = compiledRoutes
	return nil
}

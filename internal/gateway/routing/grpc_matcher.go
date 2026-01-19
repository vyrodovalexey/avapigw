package routing

import (
	"regexp"
	"strings"
	"sync"
)

// Match type constants
const (
	matchTypeRegularExpression = "RegularExpression"
)

// GRPCRouteMatcher performs gRPC route matching.
type GRPCRouteMatcher struct {
	routes []*CompiledGRPCRoute
	mu     sync.RWMutex
}

// CompiledGRPCRoute is a pre-compiled gRPC route for efficient matching.
type CompiledGRPCRoute struct {
	Name        string
	HostRegexes []*regexp.Regexp
	Rules       []*CompiledGRPCRule
	Priority    int
}

// CompiledGRPCRule is a pre-compiled gRPC rule for efficient matching.
type CompiledGRPCRule struct {
	ServiceMatcher GRPCServiceMatcher
	MethodMatcher  GRPCMethodMatcher
	HeaderMatchers []GRPCHeaderMatcher
	Priority       int
	BackendRefs    []GRPCBackendRef
}

// GRPCBackendRef references a backend for gRPC routing.
type GRPCBackendRef struct {
	Name      string
	Namespace string
	Port      int
	Weight    int
}

// GRPCServiceMatcher defines the interface for gRPC service matching.
type GRPCServiceMatcher interface {
	Match(service string) bool
}

// GRPCMethodMatcher defines the interface for gRPC method matching.
type GRPCMethodMatcher interface {
	Match(method string) bool
}

// GRPCHeaderMatcher defines the interface for gRPC header matching.
type GRPCHeaderMatcher interface {
	Name() string
	Match(value string) bool
}

// GRPCMatchResult contains the result of a gRPC route match.
type GRPCMatchResult struct {
	RouteName   string
	Rule        *CompiledGRPCRule
	BackendRefs []GRPCBackendRef
}

// NewGRPCRouteMatcher creates a new gRPC route matcher.
func NewGRPCRouteMatcher() *GRPCRouteMatcher {
	return &GRPCRouteMatcher{
		routes: make([]*CompiledGRPCRoute, 0),
	}
}

// Match finds a matching route for the given gRPC request.
func (m *GRPCRouteMatcher) Match(service, method string, headers map[string]string) (*GRPCMatchResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, route := range m.routes {
		for _, rule := range route.Rules {
			if m.matchRule(rule, service, method, headers) {
				return &GRPCMatchResult{
					RouteName:   route.Name,
					Rule:        rule,
					BackendRefs: rule.BackendRefs,
				}, true
			}
		}
	}

	return nil, false
}

// MatchWithHost finds a matching route considering the host.
func (m *GRPCRouteMatcher) MatchWithHost(
	host, service, method string,
	headers map[string]string,
) (*GRPCMatchResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, route := range m.routes {
		// Check hostname match
		if !m.matchHostname(route, host) {
			continue
		}

		for _, rule := range route.Rules {
			if m.matchRule(rule, service, method, headers) {
				return &GRPCMatchResult{
					RouteName:   route.Name,
					Rule:        rule,
					BackendRefs: rule.BackendRefs,
				}, true
			}
		}
	}

	return nil, false
}

// matchHostname checks if the host matches the route's hostname patterns.
func (m *GRPCRouteMatcher) matchHostname(route *CompiledGRPCRoute, host string) bool {
	// If no hostnames specified, match all
	if len(route.HostRegexes) == 0 {
		return true
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
func (m *GRPCRouteMatcher) matchRule(rule *CompiledGRPCRule, service, method string, headers map[string]string) bool {
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
		value, exists := headers[strings.ToLower(headerMatcher.Name())]
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
func (m *GRPCRouteMatcher) Compile(routes []*GRPCRouteConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	compiledRoutes := make([]*CompiledGRPCRoute, 0, len(routes))
	for _, route := range routes {
		compiled, err := compileGRPCRoute(route)
		if err != nil {
			return err
		}
		compiledRoutes = append(compiledRoutes, compiled)
	}

	m.routes = compiledRoutes
	return nil
}

// GRPCRouteConfig is the configuration for a gRPC route.
type GRPCRouteConfig struct {
	Name      string
	Hostnames []string
	Rules     []GRPCRuleConfig
	Priority  int
}

// GRPCRuleConfig is the configuration for a gRPC rule.
type GRPCRuleConfig struct {
	Service     string
	Method      string
	MatchType   string // "Exact" or "RegularExpression"
	Headers     []GRPCHeaderMatchConfig
	BackendRefs []GRPCBackendRef
	Priority    int
}

// GRPCHeaderMatchConfig is the configuration for a gRPC header match.
type GRPCHeaderMatchConfig struct {
	Name      string
	Value     string
	MatchType string // "Exact" or "RegularExpression"
}

// compileGRPCRoute compiles a gRPC route configuration.
func compileGRPCRoute(config *GRPCRouteConfig) (*CompiledGRPCRoute, error) {
	compiled := &CompiledGRPCRoute{
		Name:        config.Name,
		HostRegexes: make([]*regexp.Regexp, 0, len(config.Hostnames)),
		Rules:       make([]*CompiledGRPCRule, 0, len(config.Rules)),
		Priority:    config.Priority,
	}

	// Compile hostname patterns
	for _, hostname := range config.Hostnames {
		if hostname == "" || hostname == "*" {
			continue
		}
		regex := hostnameToRegex(hostname)
		if regex != nil {
			compiled.HostRegexes = append(compiled.HostRegexes, regex)
		}
	}

	// Compile rules
	for i, rule := range config.Rules {
		compiledRule, err := compileGRPCRule(&rule, i)
		if err != nil {
			return nil, err
		}
		compiled.Rules = append(compiled.Rules, compiledRule)
	}

	return compiled, nil
}

// compileGRPCRule compiles a gRPC rule configuration.
func compileGRPCRule(config *GRPCRuleConfig, index int) (*CompiledGRPCRule, error) {
	compiled := &CompiledGRPCRule{
		HeaderMatchers: make([]GRPCHeaderMatcher, 0, len(config.Headers)),
		Priority:       config.Priority,
		BackendRefs:    config.BackendRefs,
	}

	if compiled.Priority == 0 {
		compiled.Priority = index
	}

	// Compile service matcher
	switch config.MatchType {
	case matchTypeRegularExpression:
		matcher, err := NewGRPCRegexServiceMatcher(config.Service)
		if err != nil {
			return nil, err
		}
		compiled.ServiceMatcher = matcher
	default:
		compiled.ServiceMatcher = NewGRPCExactServiceMatcher(config.Service)
	}

	// Compile method matcher
	switch config.MatchType {
	case matchTypeRegularExpression:
		matcher, err := NewGRPCRegexMethodMatcher(config.Method)
		if err != nil {
			return nil, err
		}
		compiled.MethodMatcher = matcher
	default:
		compiled.MethodMatcher = NewGRPCExactMethodMatcher(config.Method)
	}

	// Compile header matchers
	for _, header := range config.Headers {
		var matcher GRPCHeaderMatcher
		var err error

		switch header.MatchType {
		case matchTypeRegularExpression:
			matcher, err = NewGRPCRegexHeaderMatcher(header.Name, header.Value)
			if err != nil {
				return nil, err
			}
		default:
			matcher = NewGRPCExactHeaderMatcher(header.Name, header.Value)
		}

		compiled.HeaderMatchers = append(compiled.HeaderMatchers, matcher)
	}

	return compiled, nil
}

// hostnameToRegex converts a hostname pattern to a regex.
func hostnameToRegex(hostname string) *regexp.Regexp {
	if hostname == "" || hostname == "*" {
		return nil
	}

	escaped := regexp.QuoteMeta(hostname)
	escaped = strings.ReplaceAll(escaped, `\*`, `[^.]+`)
	pattern := "^" + escaped + "$"

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return regex
}

// GRPCExactServiceMatcher matches services exactly.
type GRPCExactServiceMatcher struct {
	service string
}

// NewGRPCExactServiceMatcher creates a new exact service matcher.
func NewGRPCExactServiceMatcher(service string) *GRPCExactServiceMatcher {
	return &GRPCExactServiceMatcher{service: service}
}

// Match checks if the service matches exactly.
func (m *GRPCExactServiceMatcher) Match(service string) bool {
	if m.service == "" || m.service == "*" {
		return true
	}
	return service == m.service
}

// GRPCRegexServiceMatcher matches services using regular expressions.
type GRPCRegexServiceMatcher struct {
	regex *regexp.Regexp
}

// NewGRPCRegexServiceMatcher creates a new regex service matcher.
func NewGRPCRegexServiceMatcher(pattern string) (*GRPCRegexServiceMatcher, error) {
	if pattern == "" || pattern == "*" {
		return &GRPCRegexServiceMatcher{regex: nil}, nil
	}
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &GRPCRegexServiceMatcher{regex: regex}, nil
}

// Match checks if the service matches the regex.
func (m *GRPCRegexServiceMatcher) Match(service string) bool {
	if m.regex == nil {
		return true
	}
	return m.regex.MatchString(service)
}

// GRPCExactMethodMatcher matches methods exactly.
type GRPCExactMethodMatcher struct {
	method string
}

// NewGRPCExactMethodMatcher creates a new exact method matcher.
func NewGRPCExactMethodMatcher(method string) *GRPCExactMethodMatcher {
	return &GRPCExactMethodMatcher{method: method}
}

// Match checks if the method matches exactly.
func (m *GRPCExactMethodMatcher) Match(method string) bool {
	if m.method == "" || m.method == "*" {
		return true
	}
	return method == m.method
}

// GRPCRegexMethodMatcher matches methods using regular expressions.
type GRPCRegexMethodMatcher struct {
	regex *regexp.Regexp
}

// NewGRPCRegexMethodMatcher creates a new regex method matcher.
func NewGRPCRegexMethodMatcher(pattern string) (*GRPCRegexMethodMatcher, error) {
	if pattern == "" || pattern == "*" {
		return &GRPCRegexMethodMatcher{regex: nil}, nil
	}
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &GRPCRegexMethodMatcher{regex: regex}, nil
}

// Match checks if the method matches the regex.
func (m *GRPCRegexMethodMatcher) Match(method string) bool {
	if m.regex == nil {
		return true
	}
	return m.regex.MatchString(method)
}

// GRPCExactHeaderMatcher matches headers exactly.
type GRPCExactHeaderMatcher struct {
	name  string
	value string
}

// NewGRPCExactHeaderMatcher creates a new exact header matcher.
func NewGRPCExactHeaderMatcher(name, value string) *GRPCExactHeaderMatcher {
	return &GRPCExactHeaderMatcher{
		name:  strings.ToLower(name),
		value: value,
	}
}

// Name returns the header name.
func (m *GRPCExactHeaderMatcher) Name() string {
	return m.name
}

// Match checks if the header value matches exactly.
func (m *GRPCExactHeaderMatcher) Match(value string) bool {
	return value == m.value
}

// GRPCRegexHeaderMatcher matches headers using regular expressions.
type GRPCRegexHeaderMatcher struct {
	name  string
	regex *regexp.Regexp
}

// NewGRPCRegexHeaderMatcher creates a new regex header matcher.
func NewGRPCRegexHeaderMatcher(name, pattern string) (*GRPCRegexHeaderMatcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &GRPCRegexHeaderMatcher{
		name:  strings.ToLower(name),
		regex: regex,
	}, nil
}

// Name returns the header name.
func (m *GRPCRegexHeaderMatcher) Name() string {
	return m.name
}

// Match checks if the header value matches the regex.
func (m *GRPCRegexHeaderMatcher) Match(value string) bool {
	return m.regex.MatchString(value)
}

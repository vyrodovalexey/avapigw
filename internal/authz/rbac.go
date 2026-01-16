// Package authz provides authorization functionality for the API Gateway.
package authz

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// Common errors for authorization.
var (
	ErrAccessDenied     = errors.New("access denied")
	ErrNoMatchingRule   = errors.New("no matching rule")
	ErrInvalidRule      = errors.New("invalid rule")
	ErrMissingSubject   = errors.New("missing subject")
	ErrInvalidCondition = errors.New("invalid condition")
)

// Metrics for authorization.
var (
	authzDecisionTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_authz_decision_total",
			Help: "Total number of authorization decisions",
		},
		[]string{"decision", "rule"},
	)

	authzDecisionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "avapigw_authz_decision_duration_seconds",
			Help:    "Duration of authorization decisions in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"decision"},
	)
)

// Action represents an authorization action.
type Action string

const (
	// ActionAllow allows the request.
	ActionAllow Action = "ALLOW"
	// ActionDeny denies the request.
	ActionDeny Action = "DENY"
)

// Decision represents an authorization decision.
type Decision struct {
	// Allowed indicates whether the request is allowed.
	Allowed bool

	// Reason is the reason for the decision.
	Reason string

	// Rule is the name of the rule that matched.
	Rule string
}

// Subject represents the subject of an authorization request.
type Subject struct {
	// User is the username or user ID.
	User string

	// Groups is the list of groups the user belongs to.
	Groups []string

	// Roles is the list of roles assigned to the user.
	Roles []string

	// Scopes is the list of OAuth2 scopes.
	Scopes []string

	// Claims is a map of JWT claims.
	Claims map[string]interface{}

	// Metadata is additional metadata.
	Metadata map[string]string
}

// HasRole checks if the subject has the specified role.
func (s *Subject) HasRole(role string) bool {
	for _, r := range s.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the subject has any of the specified roles.
func (s *Subject) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if s.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the subject has all of the specified roles.
func (s *Subject) HasAllRoles(roles ...string) bool {
	for _, role := range roles {
		if !s.HasRole(role) {
			return false
		}
	}
	return true
}

// HasGroup checks if the subject belongs to the specified group.
func (s *Subject) HasGroup(group string) bool {
	for _, g := range s.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// HasScope checks if the subject has the specified scope.
func (s *Subject) HasScope(scope string) bool {
	for _, sc := range s.Scopes {
		if sc == scope {
			return true
		}
	}
	return false
}

// GetClaim returns a claim value.
func (s *Subject) GetClaim(name string) (interface{}, bool) {
	if s.Claims == nil {
		return nil, false
	}
	val, ok := s.Claims[name]
	return val, ok
}

// Resource represents the resource being accessed.
type Resource struct {
	// Path is the request path.
	Path string

	// Method is the HTTP method.
	Method string

	// Host is the request host.
	Host string

	// Port is the request port.
	Port int

	// Headers is the request headers.
	Headers http.Header

	// SourceIP is the source IP address.
	SourceIP string

	// Metadata is additional metadata.
	Metadata map[string]string
}

// NewResourceFromRequest creates a Resource from an HTTP request.
func NewResourceFromRequest(r *http.Request) *Resource {
	host := r.Host
	port := 0

	// Parse host and port
	if h, p, err := net.SplitHostPort(r.Host); err == nil {
		host = h
		if pn, err := strconv.Atoi(p); err == nil {
			port = pn
		}
	}

	// Get source IP
	sourceIP := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		sourceIP = h
	}

	// Check for X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			sourceIP = strings.TrimSpace(parts[0])
		}
	}

	return &Resource{
		Path:     r.URL.Path,
		Method:   r.Method,
		Host:     host,
		Port:     port,
		Headers:  r.Header,
		SourceIP: sourceIP,
	}
}

// Rule represents an authorization rule.
type Rule struct {
	// Name is the name of the rule.
	Name string

	// Priority is the priority of the rule (higher = evaluated first).
	Priority int

	// Conditions are the conditions that must be met for the rule to apply.
	Conditions []Condition

	// Targets are the resources this rule applies to.
	Targets []*Target

	// Action is the action to take when the rule matches.
	Action Action

	// Enabled indicates whether the rule is enabled.
	Enabled bool
}

// Matches checks if the rule matches the given subject and resource.
func (r *Rule) Matches(subject *Subject, resource *Resource) bool {
	if !r.Enabled {
		return false
	}

	// Check conditions
	for _, condition := range r.Conditions {
		if !condition.Evaluate(subject, resource) {
			return false
		}
	}

	// Check targets
	if len(r.Targets) == 0 {
		return true
	}

	for i := range r.Targets {
		if r.Targets[i].Matches(resource) {
			return true
		}
	}

	return false
}

// Condition represents a condition for authorization.
type Condition interface {
	// Evaluate evaluates the condition.
	Evaluate(subject *Subject, resource *Resource) bool
}

// ClaimCondition checks if a claim has a specific value.
type ClaimCondition struct {
	// Claim is the name of the claim.
	Claim string

	// Values is the list of allowed values.
	Values []string

	// MatchAny indicates whether any value should match (default: any).
	MatchAny bool
}

// Evaluate implements Condition.
func (c *ClaimCondition) Evaluate(subject *Subject, resource *Resource) bool {
	if subject == nil || subject.Claims == nil {
		return false
	}

	val, ok := subject.Claims[c.Claim]
	if !ok {
		return false
	}

	switch v := val.(type) {
	case string:
		return c.evaluateStringClaim(v)
	case []interface{}:
		return c.evaluateInterfaceSliceClaim(v)
	case []string:
		return c.evaluateStringSliceClaim(v)
	}

	return false
}

// evaluateStringClaim checks if a string claim matches any allowed value.
func (c *ClaimCondition) evaluateStringClaim(v string) bool {
	for _, allowed := range c.Values {
		if v == allowed {
			return true
		}
	}
	return false
}

// evaluateInterfaceSliceClaim checks if an interface slice claim matches allowed values.
func (c *ClaimCondition) evaluateInterfaceSliceClaim(v []interface{}) bool {
	if c.MatchAny {
		return c.matchAnyInterfaceSlice(v)
	}
	return c.matchAllInterfaceSlice(v)
}

// matchAnyInterfaceSlice returns true if any value in the slice matches an allowed value.
func (c *ClaimCondition) matchAnyInterfaceSlice(v []interface{}) bool {
	for _, item := range v {
		if str, ok := item.(string); ok {
			for _, allowed := range c.Values {
				if str == allowed {
					return true
				}
			}
		}
	}
	return false
}

// matchAllInterfaceSlice returns true if all allowed values are present in the slice.
func (c *ClaimCondition) matchAllInterfaceSlice(v []interface{}) bool {
	for _, allowed := range c.Values {
		found := false
		for _, item := range v {
			if str, ok := item.(string); ok && str == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// evaluateStringSliceClaim checks if a string slice claim matches allowed values.
func (c *ClaimCondition) evaluateStringSliceClaim(v []string) bool {
	if c.MatchAny {
		return c.matchAnyStringSlice(v)
	}
	return c.matchAllStringSlice(v)
}

// matchAnyStringSlice returns true if any value in the slice matches an allowed value.
func (c *ClaimCondition) matchAnyStringSlice(v []string) bool {
	for _, item := range v {
		for _, allowed := range c.Values {
			if item == allowed {
				return true
			}
		}
	}
	return false
}

// matchAllStringSlice returns true if all allowed values are present in the slice.
func (c *ClaimCondition) matchAllStringSlice(v []string) bool {
	for _, allowed := range c.Values {
		found := false
		for _, item := range v {
			if item == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// RoleCondition checks if the subject has specific roles.
type RoleCondition struct {
	// Roles is the list of required roles.
	Roles []string

	// MatchAll indicates whether all roles must match.
	MatchAll bool
}

// Evaluate implements Condition.
func (c *RoleCondition) Evaluate(subject *Subject, resource *Resource) bool {
	if subject == nil {
		return false
	}

	if c.MatchAll {
		return subject.HasAllRoles(c.Roles...)
	}
	return subject.HasAnyRole(c.Roles...)
}

// GroupCondition checks if the subject belongs to specific groups.
type GroupCondition struct {
	// Groups is the list of required groups.
	Groups []string

	// MatchAll indicates whether all groups must match.
	MatchAll bool
}

// Evaluate implements Condition.
func (c *GroupCondition) Evaluate(subject *Subject, resource *Resource) bool {
	if subject == nil {
		return false
	}

	if c.MatchAll {
		for _, group := range c.Groups {
			if !subject.HasGroup(group) {
				return false
			}
		}
		return true
	}

	for _, group := range c.Groups {
		if subject.HasGroup(group) {
			return true
		}
	}
	return false
}

// ScopeCondition checks if the subject has specific scopes.
type ScopeCondition struct {
	// Scopes is the list of required scopes.
	Scopes []string

	// MatchAll indicates whether all scopes must match.
	MatchAll bool
}

// Evaluate implements Condition.
func (c *ScopeCondition) Evaluate(subject *Subject, resource *Resource) bool {
	if subject == nil {
		return false
	}

	if c.MatchAll {
		for _, scope := range c.Scopes {
			if !subject.HasScope(scope) {
				return false
			}
		}
		return true
	}

	for _, scope := range c.Scopes {
		if subject.HasScope(scope) {
			return true
		}
	}
	return false
}

// SourceIPCondition checks if the source IP matches.
type SourceIPCondition struct {
	// CIDRs is the list of allowed CIDR ranges.
	CIDRs []string

	// NotCIDRs is the list of denied CIDR ranges.
	NotCIDRs []string

	// parsedCIDRs is the parsed CIDR networks.
	parsedCIDRs []*net.IPNet

	// parsedNotCIDRs is the parsed not CIDR networks.
	parsedNotCIDRs []*net.IPNet

	// once ensures parsing happens only once.
	once sync.Once
}

// Evaluate implements Condition.
func (c *SourceIPCondition) Evaluate(subject *Subject, resource *Resource) bool {
	if resource == nil || resource.SourceIP == "" {
		return false
	}

	// Parse CIDRs once
	c.once.Do(func() {
		for _, cidr := range c.CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil {
				c.parsedCIDRs = append(c.parsedCIDRs, network)
			}
		}
		for _, cidr := range c.NotCIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil {
				c.parsedNotCIDRs = append(c.parsedNotCIDRs, network)
			}
		}
	})

	ip := net.ParseIP(resource.SourceIP)
	if ip == nil {
		return false
	}

	// Check not CIDRs first
	for _, network := range c.parsedNotCIDRs {
		if network.Contains(ip) {
			return false
		}
	}

	// If no CIDRs specified, allow all (that aren't in NotCIDRs)
	if len(c.parsedCIDRs) == 0 {
		return true
	}

	// Check CIDRs
	for _, network := range c.parsedCIDRs {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// HeaderCondition checks if a header has a specific value.
type HeaderCondition struct {
	// Header is the name of the header.
	Header string

	// Values is the list of allowed values.
	Values []string

	// Regex is a regex pattern to match.
	Regex string

	// compiledRegex is the compiled regex.
	compiledRegex *regexp.Regexp

	// once ensures compilation happens only once.
	once sync.Once
}

// Evaluate implements Condition.
func (c *HeaderCondition) Evaluate(subject *Subject, resource *Resource) bool {
	if resource == nil || resource.Headers == nil {
		return false
	}

	value := resource.Headers.Get(c.Header)
	if value == "" {
		return false
	}

	// Check values
	if len(c.Values) > 0 {
		for _, allowed := range c.Values {
			if value == allowed {
				return true
			}
		}
		return false
	}

	// Check regex
	if c.Regex != "" {
		c.once.Do(func() {
			c.compiledRegex, _ = regexp.Compile(c.Regex)
		})
		if c.compiledRegex != nil {
			return c.compiledRegex.MatchString(value)
		}
	}

	return true
}

// Target represents a target resource.
type Target struct {
	// Methods is the list of HTTP methods.
	Methods []string

	// Paths is the list of path patterns.
	Paths []string

	// Hosts is the list of host patterns.
	Hosts []string

	// Ports is the list of ports.
	Ports []int

	// compiledPaths is the compiled path patterns.
	compiledPaths []*regexp.Regexp

	// compiledHosts is the compiled host patterns.
	compiledHosts []*regexp.Regexp

	// once ensures compilation happens only once.
	once sync.Once
}

// Matches checks if the target matches the resource.
func (t *Target) Matches(resource *Resource) bool {
	if resource == nil {
		return false
	}

	t.compilePatterns()

	if !t.matchesMethods(resource.Method) {
		return false
	}
	if !t.matchesPaths(resource.Path) {
		return false
	}
	if !t.matchesHosts(resource.Host) {
		return false
	}
	if !t.matchesPorts(resource.Port) {
		return false
	}

	return true
}

// compilePatterns compiles path and host patterns once.
func (t *Target) compilePatterns() {
	t.once.Do(func() {
		for _, path := range t.Paths {
			if re, err := compilePattern(path); err == nil {
				t.compiledPaths = append(t.compiledPaths, re)
			}
		}
		for _, host := range t.Hosts {
			if re, err := compilePattern(host); err == nil {
				t.compiledHosts = append(t.compiledHosts, re)
			}
		}
	})
}

// matchesMethods checks if the resource method matches any allowed method.
func (t *Target) matchesMethods(method string) bool {
	if len(t.Methods) == 0 {
		return true
	}
	for _, m := range t.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// matchesPaths checks if the resource path matches any compiled path pattern.
func (t *Target) matchesPaths(path string) bool {
	if len(t.compiledPaths) == 0 {
		return true
	}
	for _, re := range t.compiledPaths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// matchesHosts checks if the resource host matches any compiled host pattern.
func (t *Target) matchesHosts(host string) bool {
	if len(t.compiledHosts) == 0 {
		return true
	}
	for _, re := range t.compiledHosts {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// matchesPorts checks if the resource port matches any allowed port.
func (t *Target) matchesPorts(port int) bool {
	if len(t.Ports) == 0 || port <= 0 {
		return true
	}
	for _, p := range t.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// compilePattern compiles a pattern with wildcards to a regex.
func compilePattern(pattern string) (*regexp.Regexp, error) {
	// Escape special regex characters except *
	escaped := regexp.QuoteMeta(pattern)
	// Replace escaped * with .*
	escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
	// Anchor the pattern
	escaped = "^" + escaped + "$"
	return regexp.Compile(escaped)
}

// RBACAuthorizer is a role-based access control authorizer.
type RBACAuthorizer struct {
	rules         []*Rule
	defaultAction Action
	logger        *zap.Logger
	mu            sync.RWMutex
}

// RBACConfig holds configuration for the RBAC authorizer.
type RBACConfig struct {
	// Rules is the list of authorization rules.
	Rules []*Rule

	// DefaultAction is the default action when no rules match.
	DefaultAction Action

	// Logger is the logger to use.
	Logger *zap.Logger
}

// NewRBACAuthorizer creates a new RBAC authorizer.
func NewRBACAuthorizer(config *RBACConfig) *RBACAuthorizer {
	if config == nil {
		config = &RBACConfig{}
	}

	defaultAction := config.DefaultAction
	if defaultAction == "" {
		defaultAction = ActionDeny
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &RBACAuthorizer{
		rules:         config.Rules,
		defaultAction: defaultAction,
		logger:        logger,
	}
}

// Authorize authorizes a request.
func (a *RBACAuthorizer) Authorize(ctx context.Context, subject *Subject, resource *Resource) (*Decision, error) {
	start := time.Now()

	a.mu.RLock()
	rules := a.rules
	defaultAction := a.defaultAction
	a.mu.RUnlock()

	// Evaluate rules in priority order
	for _, rule := range rules {
		if !rule.Matches(subject, resource) {
			continue
		}
		decision := &Decision{
			Allowed: rule.Action == ActionAllow,
			Reason:  string(rule.Action),
			Rule:    rule.Name,
		}

		// Record metrics
		decisionStr := "deny"
		if decision.Allowed {
			decisionStr = "allow"
		}
		authzDecisionTotal.WithLabelValues(decisionStr, rule.Name).Inc()
		authzDecisionDuration.WithLabelValues(decisionStr).Observe(time.Since(start).Seconds())

		a.logger.Debug("authorization decision",
			zap.Bool("allowed", decision.Allowed),
			zap.String("rule", rule.Name),
			zap.String("path", resource.Path),
			zap.String("method", resource.Method),
		)

		return decision, nil
	}

	// No matching rule, use default action
	decision := &Decision{
		Allowed: defaultAction == ActionAllow,
		Reason:  "default action",
		Rule:    "",
	}

	decisionStr := "deny"
	if decision.Allowed {
		decisionStr = "allow"
	}
	authzDecisionTotal.WithLabelValues(decisionStr, "default").Inc()
	authzDecisionDuration.WithLabelValues(decisionStr).Observe(time.Since(start).Seconds())

	a.logger.Debug("authorization decision (default)",
		zap.Bool("allowed", decision.Allowed),
		zap.String("path", resource.Path),
		zap.String("method", resource.Method),
	)

	return decision, nil
}

// AddRule adds a rule to the authorizer.
func (a *RBACAuthorizer) AddRule(rule *Rule) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.rules = append(a.rules, rule)
	a.sortRules()
}

// RemoveRule removes a rule by name.
func (a *RBACAuthorizer) RemoveRule(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, rule := range a.rules {
		if rule.Name == name {
			a.rules = append(a.rules[:i], a.rules[i+1:]...)
			return
		}
	}
}

// SetRules sets all rules.
func (a *RBACAuthorizer) SetRules(rules []*Rule) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.rules = rules
	a.sortRules()
}

// SetDefaultAction sets the default action.
func (a *RBACAuthorizer) SetDefaultAction(action Action) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.defaultAction = action
}

// sortRules sorts rules by priority (descending).
func (a *RBACAuthorizer) sortRules() {
	// Simple bubble sort for small rule sets
	for i := 0; i < len(a.rules); i++ {
		for j := i + 1; j < len(a.rules); j++ {
			if a.rules[j].Priority > a.rules[i].Priority {
				a.rules[i], a.rules[j] = a.rules[j], a.rules[i]
			}
		}
	}
}

// Authorizer defines the interface for authorization.
type Authorizer interface {
	// Authorize authorizes a request.
	Authorize(ctx context.Context, subject *Subject, resource *Resource) (*Decision, error)
}

// SubjectContextKey is the context key for storing subject information.
type SubjectContextKey struct{}

// GetSubjectFromContext retrieves the subject from the context.
func GetSubjectFromContext(ctx context.Context) (*Subject, bool) {
	subject, ok := ctx.Value(SubjectContextKey{}).(*Subject)
	return subject, ok
}

// ContextWithSubject returns a new context with the subject.
func ContextWithSubject(ctx context.Context, subject *Subject) context.Context {
	return context.WithValue(ctx, SubjectContextKey{}, subject)
}

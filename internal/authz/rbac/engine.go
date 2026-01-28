package rbac

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Decision represents an authorization decision.
type Decision struct {
	// Allowed indicates if the request is allowed.
	Allowed bool

	// Reason is the reason for the decision.
	Reason string

	// Policy is the policy that made the decision.
	Policy string
}

// Request represents an authorization request.
type Request struct {
	// Subject is the subject (user/service) making the request.
	Subject string

	// Roles is the list of roles the subject has.
	Roles []string

	// Permissions is the list of permissions the subject has.
	Permissions []string

	// Groups is the list of groups the subject belongs to.
	Groups []string

	// Resource is the resource being accessed.
	Resource string

	// Action is the action being performed.
	Action string

	// Context contains additional context for the request.
	Context map[string]interface{}
}

// Engine is the RBAC authorization engine.
type Engine interface {
	// Authorize authorizes a request.
	Authorize(ctx context.Context, req *Request) (*Decision, error)

	// AddPolicy adds a policy to the engine.
	AddPolicy(policy Policy) error

	// RemovePolicy removes a policy from the engine.
	RemovePolicy(name string) error

	// GetPolicies returns all policies.
	GetPolicies() []Policy
}

// engine implements the Engine interface.
type engine struct {
	config  *Config
	logger  observability.Logger
	metrics *Metrics

	mu            sync.RWMutex
	policies      []Policy
	roleHierarchy map[string][]string
	compiledRegex map[string]*regexp.Regexp
}

// EngineOption is a functional option for the engine.
type EngineOption func(*engine)

// WithEngineLogger sets the logger.
func WithEngineLogger(logger observability.Logger) EngineOption {
	return func(e *engine) {
		e.logger = logger
	}
}

// WithEngineMetrics sets the metrics.
func WithEngineMetrics(metrics *Metrics) EngineOption {
	return func(e *engine) {
		e.metrics = metrics
	}
}

// NewEngine creates a new RBAC engine.
func NewEngine(config *Config, opts ...EngineOption) (Engine, error) {
	e := &engine{
		config:        config,
		logger:        observability.NopLogger(),
		policies:      make([]Policy, 0),
		roleHierarchy: make(map[string][]string),
		compiledRegex: make(map[string]*regexp.Regexp),
	}

	for _, opt := range opts {
		opt(e)
	}

	if e.metrics == nil {
		e.metrics = NewMetrics("gateway")
	}

	// Load policies from config
	if config != nil {
		for _, policy := range config.Policies {
			if err := e.AddPolicy(policy); err != nil {
				return nil, err
			}
		}

		// Load role hierarchy
		if config.RoleHierarchy != nil {
			e.roleHierarchy = config.RoleHierarchy
		}
	}

	return e, nil
}

// Authorize authorizes a request.
func (e *engine) Authorize(ctx context.Context, req *Request) (*Decision, error) {
	start := time.Now()

	e.mu.RLock()
	policies := e.policies
	e.mu.RUnlock()

	// Expand roles based on hierarchy
	expandedRoles := e.expandRoles(req.Roles)

	// Sort policies by priority (higher first)
	sortedPolicies := make([]Policy, len(policies))
	copy(sortedPolicies, policies)
	sort.Slice(sortedPolicies, func(i, j int) bool {
		return sortedPolicies[i].Priority > sortedPolicies[j].Priority
	})

	// Evaluate policies
	for _, policy := range sortedPolicies {
		if !e.matchesPolicy(req, &policy, expandedRoles) {
			continue
		}

		decision := &Decision{
			Allowed: policy.GetEffectiveEffect() == EffectAllow,
			Reason:  "matched policy: " + policy.Name,
			Policy:  policy.Name,
		}

		status := "denied"
		if decision.Allowed {
			status = "allowed"
		}

		e.metrics.RecordEvaluation(policy.Name, status, time.Since(start))
		e.logger.Debug("RBAC decision",
			observability.String("policy", policy.Name),
			observability.Bool("allowed", decision.Allowed),
			observability.String("resource", req.Resource),
			observability.String("action", req.Action),
		)

		return decision, nil
	}

	// No matching policy - use default
	defaultAllowed := false
	if e.config != nil && e.config.DefaultRole != "" {
		// Check if default role has access
		defaultReq := &Request{
			Subject:  req.Subject,
			Roles:    []string{e.config.DefaultRole},
			Resource: req.Resource,
			Action:   req.Action,
			Context:  req.Context,
		}
		for _, policy := range sortedPolicies {
			if e.matchesPolicy(defaultReq, &policy, []string{e.config.DefaultRole}) {
				defaultAllowed = policy.GetEffectiveEffect() == EffectAllow
				break
			}
		}
	}

	decision := &Decision{
		Allowed: defaultAllowed,
		Reason:  "no matching policy",
		Policy:  "",
	}

	status := "denied"
	if decision.Allowed {
		status = "allowed"
	}

	e.metrics.RecordEvaluation("default", status, time.Since(start))

	return decision, nil
}

// matchesPolicy checks if a request matches a policy.
func (e *engine) matchesPolicy(req *Request, policy *Policy, expandedRoles []string) bool {
	// Check roles
	if len(policy.Roles) > 0 {
		if !e.matchesAny(expandedRoles, policy.Roles) {
			return false
		}
	}

	// Check permissions
	if len(policy.Permissions) > 0 {
		if !e.matchesAny(req.Permissions, policy.Permissions) {
			return false
		}
	}

	// Check groups
	if len(policy.Groups) > 0 {
		if !e.matchesAny(req.Groups, policy.Groups) {
			return false
		}
	}

	// Check resource
	if !e.matchesResource(req.Resource, policy.Resources) {
		return false
	}

	// Check action
	if !e.matchesAction(req.Action, policy.Actions) {
		return false
	}

	// Check conditions
	if len(policy.Conditions) > 0 {
		if !e.matchesConditions(req, policy.Conditions) {
			return false
		}
	}

	return true
}

// matchesAny checks if any value in have matches any value in want.
func (e *engine) matchesAny(have, want []string) bool {
	for _, w := range want {
		if w == "*" {
			return true
		}
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

// matchesResource checks if a resource matches any of the patterns.
func (e *engine) matchesResource(resource string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}

		// Regex pattern (starts with ~)
		if strings.HasPrefix(pattern, "~") {
			regex := e.getCompiledRegex(pattern[1:])
			if regex != nil && regex.MatchString(resource) {
				return true
			}
			continue
		}

		// Prefix pattern (ends with *)
		if strings.HasSuffix(pattern, "*") {
			prefix := pattern[:len(pattern)-1]
			if strings.HasPrefix(resource, prefix) {
				return true
			}
			continue
		}

		// Exact match
		if resource == pattern {
			return true
		}
	}
	return false
}

// matchesAction checks if an action matches any of the patterns.
func (e *engine) matchesAction(action string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if strings.EqualFold(action, pattern) {
			return true
		}
	}
	return false
}

// matchesConditions checks if all conditions are met.
func (e *engine) matchesConditions(req *Request, conditions []Condition) bool {
	for _, condition := range conditions {
		if !e.matchesCondition(req, &condition) {
			return false
		}
	}
	return true
}

// matchesCondition checks if a single condition is met.
func (e *engine) matchesCondition(req *Request, condition *Condition) bool {
	// Get the value from context
	value, ok := req.Context[condition.Key]
	if !ok {
		return false
	}

	switch condition.Operator {
	case "eq", "==":
		return value == condition.Value
	case "ne", "!=":
		return value != condition.Value
	case "in":
		if values, ok := condition.Value.([]interface{}); ok {
			for _, v := range values {
				if value == v {
					return true
				}
			}
		}
		return false
	case "contains":
		if str, ok := value.(string); ok {
			if substr, ok := condition.Value.(string); ok {
				return strings.Contains(str, substr)
			}
		}
		return false
	default:
		return false
	}
}

// expandRoles expands roles based on the role hierarchy.
func (e *engine) expandRoles(roles []string) []string {
	if len(e.roleHierarchy) == 0 {
		return roles
	}

	expanded := make(map[string]bool)
	var expand func(role string)
	expand = func(role string) {
		if expanded[role] {
			return
		}
		expanded[role] = true
		for _, parent := range e.roleHierarchy[role] {
			expand(parent)
		}
	}

	for _, role := range roles {
		expand(role)
	}

	result := make([]string, 0, len(expanded))
	for role := range expanded {
		result = append(result, role)
	}
	return result
}

// getCompiledRegex returns a compiled regex, caching it for reuse.
func (e *engine) getCompiledRegex(pattern string) *regexp.Regexp {
	e.mu.RLock()
	regex, ok := e.compiledRegex[pattern]
	e.mu.RUnlock()

	if ok {
		return regex
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check after acquiring write lock
	if regex, ok := e.compiledRegex[pattern]; ok {
		return regex
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		e.logger.Warn("failed to compile regex pattern",
			observability.String("pattern", pattern),
			observability.Error(err),
		)
		return nil
	}

	e.compiledRegex[pattern] = compiled
	return compiled
}

// AddPolicy adds a policy to the engine.
func (e *engine) AddPolicy(policy Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Check for duplicate
	for i, p := range e.policies {
		if p.Name == policy.Name {
			e.policies[i] = policy
			return nil
		}
	}

	e.policies = append(e.policies, policy)
	return nil
}

// RemovePolicy removes a policy from the engine.
func (e *engine) RemovePolicy(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, p := range e.policies {
		if p.Name == name {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			return nil
		}
	}

	return nil
}

// GetPolicies returns all policies.
func (e *engine) GetPolicies() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]Policy, len(e.policies))
	copy(result, e.policies)
	return result
}

// Ensure engine implements Engine.
var _ Engine = (*engine)(nil)

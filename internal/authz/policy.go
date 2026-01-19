package authz

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Policy represents an authorization policy.
type Policy struct {
	// Name is the name of the policy.
	Name string

	// Description is a description of the policy.
	Description string

	// Rules is the list of rules in the policy.
	Rules []*Rule

	// DefaultAction is the default action when no rules match.
	DefaultAction Action

	// Enabled indicates whether the policy is enabled.
	Enabled bool

	// Priority is the priority of the policy (higher = evaluated first).
	Priority int

	// Targets defines which resources this policy applies to.
	Targets []*Target

	// CreatedAt is when the policy was created.
	CreatedAt time.Time

	// UpdatedAt is when the policy was last updated.
	UpdatedAt time.Time
}

// Matches checks if the policy applies to the given resource.
func (p *Policy) Matches(resource *Resource) bool {
	if !p.Enabled {
		return false
	}

	if len(p.Targets) == 0 {
		return true
	}

	for i := range p.Targets {
		if p.Targets[i].Matches(resource) {
			return true
		}
	}

	return false
}

// Evaluate evaluates the policy for the given subject and resource.
func (p *Policy) Evaluate(subject *Subject, resource *Resource) (*Decision, bool) {
	if !p.Enabled {
		return nil, false
	}

	// Check if policy applies to this resource
	if !p.Matches(resource) {
		return nil, false
	}

	// Evaluate rules
	for _, rule := range p.Rules {
		if rule.Matches(subject, resource) {
			return &Decision{
				Allowed: rule.Action == ActionAllow,
				Reason:  string(rule.Action),
				Rule:    rule.Name,
			}, true
		}
	}

	// No matching rule, use policy default action
	return &Decision{
		Allowed: p.DefaultAction == ActionAllow,
		Reason:  "policy default",
		Rule:    "",
	}, true
}

// PolicyEngine is a policy-based authorization engine.
type PolicyEngine struct {
	policies      []*Policy
	defaultAction Action
	logger        *zap.Logger
	mu            sync.RWMutex
}

// PolicyEngineConfig holds configuration for the policy engine.
type PolicyEngineConfig struct {
	// Policies is the list of policies.
	Policies []*Policy

	// DefaultAction is the default action when no policies match.
	DefaultAction Action

	// Logger is the logger to use.
	Logger *zap.Logger
}

// NewPolicyEngine creates a new policy engine.
func NewPolicyEngine(config *PolicyEngineConfig) *PolicyEngine {
	if config == nil {
		config = &PolicyEngineConfig{}
	}

	defaultAction := config.DefaultAction
	if defaultAction == "" {
		defaultAction = ActionDeny
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	engine := &PolicyEngine{
		policies:      config.Policies,
		defaultAction: defaultAction,
		logger:        logger,
	}

	engine.sortPolicies()

	return engine
}

// Authorize authorizes a request using the policy engine.
func (e *PolicyEngine) Authorize(ctx context.Context, subject *Subject, resource *Resource) (*Decision, error) {
	e.mu.RLock()
	policies := e.policies
	defaultAction := e.defaultAction
	e.mu.RUnlock()

	// Evaluate policies in priority order
	for _, policy := range policies {
		if decision, matched := policy.Evaluate(subject, resource); matched {
			e.logger.Debug("policy decision",
				zap.String("policy", policy.Name),
				zap.Bool("allowed", decision.Allowed),
				zap.String("rule", decision.Rule),
			)
			return decision, nil
		}
	}

	// No matching policy, use default action
	decision := &Decision{
		Allowed: defaultAction == ActionAllow,
		Reason:  "engine default",
		Rule:    "",
	}

	e.logger.Debug("policy decision (default)",
		zap.Bool("allowed", decision.Allowed),
	)

	return decision, nil
}

// AddPolicy adds a policy to the engine.
func (e *PolicyEngine) AddPolicy(policy *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = append(e.policies, policy)
	e.sortPolicies()
}

// RemovePolicy removes a policy by name.
func (e *PolicyEngine) RemovePolicy(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, policy := range e.policies {
		if policy.Name == name {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			return
		}
	}
}

// GetPolicy returns a policy by name.
func (e *PolicyEngine) GetPolicy(name string) (*Policy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, policy := range e.policies {
		if policy.Name == name {
			return policy, true
		}
	}
	return nil, false
}

// SetPolicies sets all policies.
func (e *PolicyEngine) SetPolicies(policies []*Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = policies
	e.sortPolicies()
}

// SetDefaultAction sets the default action.
func (e *PolicyEngine) SetDefaultAction(action Action) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.defaultAction = action
}

// sortPolicies sorts policies by priority (descending).
func (e *PolicyEngine) sortPolicies() {
	for i := 0; i < len(e.policies); i++ {
		for j := i + 1; j < len(e.policies); j++ {
			if e.policies[j].Priority > e.policies[i].Priority {
				e.policies[i], e.policies[j] = e.policies[j], e.policies[i]
			}
		}
	}
}

// PolicyBuilder helps build policies.
type PolicyBuilder struct {
	policy *Policy
}

// NewPolicyBuilder creates a new policy builder.
func NewPolicyBuilder(name string) *PolicyBuilder {
	return &PolicyBuilder{
		policy: &Policy{
			Name:          name,
			DefaultAction: ActionDeny,
			Enabled:       true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
	}
}

// WithDescription sets the policy description.
func (b *PolicyBuilder) WithDescription(description string) *PolicyBuilder {
	b.policy.Description = description
	return b
}

// WithDefaultAction sets the default action.
func (b *PolicyBuilder) WithDefaultAction(action Action) *PolicyBuilder {
	b.policy.DefaultAction = action
	return b
}

// WithPriority sets the policy priority.
func (b *PolicyBuilder) WithPriority(priority int) *PolicyBuilder {
	b.policy.Priority = priority
	return b
}

// WithEnabled sets whether the policy is enabled.
func (b *PolicyBuilder) WithEnabled(enabled bool) *PolicyBuilder {
	b.policy.Enabled = enabled
	return b
}

// WithTarget adds a target to the policy.
func (b *PolicyBuilder) WithTarget(target *Target) *PolicyBuilder {
	b.policy.Targets = append(b.policy.Targets, target)
	return b
}

// WithRule adds a rule to the policy.
func (b *PolicyBuilder) WithRule(rule *Rule) *PolicyBuilder {
	b.policy.Rules = append(b.policy.Rules, rule)
	return b
}

// Build builds the policy.
func (b *PolicyBuilder) Build() *Policy {
	return b.policy
}

// RuleBuilder helps build rules.
type RuleBuilder struct {
	rule *Rule
}

// NewRuleBuilder creates a new rule builder.
func NewRuleBuilder(name string) *RuleBuilder {
	return &RuleBuilder{
		rule: &Rule{
			Name:    name,
			Action:  ActionAllow,
			Enabled: true,
		},
	}
}

// WithPriority sets the rule priority.
func (b *RuleBuilder) WithPriority(priority int) *RuleBuilder {
	b.rule.Priority = priority
	return b
}

// WithAction sets the rule action.
func (b *RuleBuilder) WithAction(action Action) *RuleBuilder {
	b.rule.Action = action
	return b
}

// WithEnabled sets whether the rule is enabled.
func (b *RuleBuilder) WithEnabled(enabled bool) *RuleBuilder {
	b.rule.Enabled = enabled
	return b
}

// WithCondition adds a condition to the rule.
func (b *RuleBuilder) WithCondition(condition Condition) *RuleBuilder {
	b.rule.Conditions = append(b.rule.Conditions, condition)
	return b
}

// WithTarget adds a target to the rule.
func (b *RuleBuilder) WithTarget(target *Target) *RuleBuilder {
	b.rule.Targets = append(b.rule.Targets, target)
	return b
}

// RequireRole adds a role condition.
func (b *RuleBuilder) RequireRole(roles ...string) *RuleBuilder {
	b.rule.Conditions = append(b.rule.Conditions, &RoleCondition{
		Roles:    roles,
		MatchAll: false,
	})
	return b
}

// RequireAllRoles adds a role condition requiring all roles.
func (b *RuleBuilder) RequireAllRoles(roles ...string) *RuleBuilder {
	b.rule.Conditions = append(b.rule.Conditions, &RoleCondition{
		Roles:    roles,
		MatchAll: true,
	})
	return b
}

// RequireGroup adds a group condition.
func (b *RuleBuilder) RequireGroup(groups ...string) *RuleBuilder {
	b.rule.Conditions = append(b.rule.Conditions, &GroupCondition{
		Groups:   groups,
		MatchAll: false,
	})
	return b
}

// RequireScope adds a scope condition.
func (b *RuleBuilder) RequireScope(scopes ...string) *RuleBuilder {
	b.rule.Conditions = append(b.rule.Conditions, &ScopeCondition{
		Scopes:   scopes,
		MatchAll: false,
	})
	return b
}

// RequireClaim adds a claim condition.
func (b *RuleBuilder) RequireClaim(claim string, values ...string) *RuleBuilder {
	b.rule.Conditions = append(b.rule.Conditions, &ClaimCondition{
		Claim:    claim,
		Values:   values,
		MatchAny: true,
	})
	return b
}

// ForMethods adds a target for specific methods.
func (b *RuleBuilder) ForMethods(methods ...string) *RuleBuilder {
	if len(b.rule.Targets) == 0 {
		b.rule.Targets = append(b.rule.Targets, &Target{})
	}
	b.rule.Targets[len(b.rule.Targets)-1].Methods = methods
	return b
}

// ForPaths adds a target for specific paths.
func (b *RuleBuilder) ForPaths(paths ...string) *RuleBuilder {
	if len(b.rule.Targets) == 0 {
		b.rule.Targets = append(b.rule.Targets, &Target{})
	}
	b.rule.Targets[len(b.rule.Targets)-1].Paths = paths
	return b
}

// Build builds the rule.
func (b *RuleBuilder) Build() *Rule {
	return b.rule
}

// PathMatcher provides path matching utilities.
type PathMatcher struct {
	pattern  string
	regex    *regexp.Regexp
	segments []string
}

// NewPathMatcher creates a new path matcher.
func NewPathMatcher(pattern string) (*PathMatcher, error) {
	// Convert pattern to regex
	escaped := regexp.QuoteMeta(pattern)
	// Replace ** with match-all
	escaped = strings.ReplaceAll(escaped, `\*\*`, `.*`)
	// Replace * with single segment match
	escaped = strings.ReplaceAll(escaped, `\*`, `[^/]*`)
	// Handle path parameters like {id}
	escaped = regexp.MustCompile(`\\{[^}]+\\}`).ReplaceAllString(escaped, `[^/]+`)

	regex, err := regexp.Compile("^" + escaped + "$")
	if err != nil {
		return nil, err
	}

	return &PathMatcher{
		pattern:  pattern,
		regex:    regex,
		segments: strings.Split(pattern, "/"),
	}, nil
}

// Matches checks if the path matches the pattern.
func (m *PathMatcher) Matches(path string) bool {
	return m.regex.MatchString(path)
}

// ExtractParams extracts path parameters from a path.
func (m *PathMatcher) ExtractParams(path string) map[string]string {
	params := make(map[string]string)
	pathSegments := strings.Split(path, "/")

	if len(pathSegments) != len(m.segments) {
		return params
	}

	for i, segment := range m.segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			paramName := segment[1 : len(segment)-1]
			params[paramName] = pathSegments[i]
		}
	}

	return params
}

// CompositeAuthorizer combines multiple authorizers.
type CompositeAuthorizer struct {
	authorizers []Authorizer
	mode        CompositeMode
	logger      *zap.Logger
}

// CompositeMode defines how multiple authorizers are combined.
type CompositeMode int

const (
	// CompositeModeAll requires all authorizers to allow.
	CompositeModeAll CompositeMode = iota
	// CompositeModeAny requires at least one authorizer to allow.
	CompositeModeAny
	// CompositeModeFirst uses the first authorizer that makes a decision.
	CompositeModeFirst
)

// NewCompositeAuthorizer creates a new composite authorizer.
func NewCompositeAuthorizer(authorizers []Authorizer, mode CompositeMode, logger *zap.Logger) *CompositeAuthorizer {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &CompositeAuthorizer{
		authorizers: authorizers,
		mode:        mode,
		logger:      logger,
	}
}

// Authorize implements Authorizer.
func (a *CompositeAuthorizer) Authorize(ctx context.Context, subject *Subject, resource *Resource) (*Decision, error) {
	if len(a.authorizers) == 0 {
		return &Decision{Allowed: true, Reason: "no authorizers"}, nil
	}

	switch a.mode {
	case CompositeModeAll:
		return a.authorizeAll(ctx, subject, resource)
	case CompositeModeAny:
		return a.authorizeAny(ctx, subject, resource)
	case CompositeModeFirst:
		return a.authorizeFirst(ctx, subject, resource)
	default:
		return nil, errors.New("invalid composite mode")
	}
}

func (a *CompositeAuthorizer) authorizeAll(
	ctx context.Context,
	subject *Subject,
	resource *Resource,
) (*Decision, error) {
	for _, authorizer := range a.authorizers {
		decision, err := authorizer.Authorize(ctx, subject, resource)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}
	return &Decision{Allowed: true, Reason: "all authorizers allowed"}, nil
}

func (a *CompositeAuthorizer) authorizeAny(
	ctx context.Context,
	subject *Subject,
	resource *Resource,
) (*Decision, error) {
	var lastDecision *Decision
	for _, authorizer := range a.authorizers {
		decision, err := authorizer.Authorize(ctx, subject, resource)
		if err != nil {
			return nil, err
		}
		if decision.Allowed {
			return decision, nil
		}
		lastDecision = decision
	}
	if lastDecision != nil {
		return lastDecision, nil
	}
	return &Decision{Allowed: false, Reason: "no authorizer allowed"}, nil
}

func (a *CompositeAuthorizer) authorizeFirst(
	ctx context.Context,
	subject *Subject,
	resource *Resource,
) (*Decision, error) {
	if len(a.authorizers) > 0 {
		return a.authorizers[0].Authorize(ctx, subject, resource)
	}
	return &Decision{Allowed: true, Reason: "no authorizers"}, nil
}

// Add adds an authorizer.
func (a *CompositeAuthorizer) Add(authorizer Authorizer) {
	a.authorizers = append(a.authorizers, authorizer)
}

// NoopAuthorizer always allows requests.
type NoopAuthorizer struct{}

// Authorize implements Authorizer.
func (a *NoopAuthorizer) Authorize(ctx context.Context, subject *Subject, resource *Resource) (*Decision, error) {
	return &Decision{Allowed: true, Reason: "noop"}, nil
}

// DenyAllAuthorizer always denies requests.
type DenyAllAuthorizer struct{}

// Authorize implements Authorizer.
func (a *DenyAllAuthorizer) Authorize(ctx context.Context, subject *Subject, resource *Resource) (*Decision, error) {
	return &Decision{Allowed: false, Reason: "deny all"}, nil
}

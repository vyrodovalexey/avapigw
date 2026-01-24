package abac

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

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
	// Subject contains subject attributes.
	Subject map[string]interface{}

	// Resource is the resource being accessed.
	Resource string

	// Action is the action being performed.
	Action string

	// Request contains request attributes.
	RequestAttrs map[string]interface{}

	// Environment contains environment attributes.
	Environment map[string]interface{}
}

// Engine is the ABAC authorization engine.
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

// celEngine implements the Engine interface using CEL.
type celEngine struct {
	config  *Config
	logger  observability.Logger
	metrics *Metrics

	mu               sync.RWMutex
	policies         []Policy
	compiledPrograms map[string]cel.Program
	env              *cel.Env
}

// EngineOption is a functional option for the engine.
type EngineOption func(*celEngine)

// WithEngineLogger sets the logger.
func WithEngineLogger(logger observability.Logger) EngineOption {
	return func(e *celEngine) {
		e.logger = logger
	}
}

// WithEngineMetrics sets the metrics.
func WithEngineMetrics(metrics *Metrics) EngineOption {
	return func(e *celEngine) {
		e.metrics = metrics
	}
}

// NewEngine creates a new ABAC engine.
func NewEngine(config *Config, opts ...EngineOption) (Engine, error) {
	e := &celEngine{
		config:           config,
		logger:           observability.NopLogger(),
		policies:         make([]Policy, 0),
		compiledPrograms: make(map[string]cel.Program),
	}

	for _, opt := range opts {
		opt(e)
	}

	if e.metrics == nil {
		e.metrics = NewMetrics("gateway")
	}

	// Create CEL environment
	env, err := e.createCELEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}
	e.env = env

	// Load policies from config
	if config != nil {
		for _, policy := range config.Policies {
			if err := e.AddPolicy(policy); err != nil {
				return nil, err
			}
		}
	}

	return e, nil
}

// createCELEnvironment creates the CEL environment with standard variables and functions.
func (e *celEngine) createCELEnvironment() (*cel.Env, error) {
	return cel.NewEnv(
		// Subject attributes
		cel.Variable("subject", cel.MapType(cel.StringType, cel.DynType)),

		// Request attributes
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),

		// Resource
		cel.Variable("resource", cel.StringType),

		// Action
		cel.Variable("action", cel.StringType),

		// Environment attributes
		cel.Variable("environment", cel.MapType(cel.StringType, cel.DynType)),

		// Time functions
		cel.Variable("now", cel.TimestampType),

		// Add custom functions
		cel.Function("ip_in_range",
			cel.Overload("ip_in_range_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(ipInRangeBinding),
			),
		),
		cel.Function("has_role",
			cel.Overload("has_role_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(hasRoleBinding),
			),
		),
	)
}

// ipInRangeBinding checks if an IP is in a CIDR range (CEL binding).
func ipInRangeBinding(ip, cidr ref.Val) ref.Val {
	ipStr, ok := ip.Value().(string)
	if !ok {
		return types.False
	}
	cidrStr, ok := cidr.Value().(string)
	if !ok {
		return types.False
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return types.False
	}

	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return types.False
	}

	if network.Contains(parsedIP) {
		return types.True
	}
	return types.False
}

// hasRoleBinding is a placeholder for has_role function (CEL binding).
func hasRoleBinding(val ref.Val) ref.Val {
	// This is a placeholder - actual role checking would be done
	// by evaluating subject.roles in the CEL expression
	return types.False
}

// Authorize authorizes a request.
func (e *celEngine) Authorize(ctx context.Context, req *Request) (*Decision, error) {
	start := time.Now()

	e.mu.RLock()
	policies := e.policies
	programs := e.compiledPrograms
	e.mu.RUnlock()

	// Sort policies by priority (higher first)
	sortedPolicies := make([]Policy, len(policies))
	copy(sortedPolicies, policies)
	sort.Slice(sortedPolicies, func(i, j int) bool {
		return sortedPolicies[i].Priority > sortedPolicies[j].Priority
	})

	// Build evaluation context
	evalCtx := map[string]interface{}{
		"subject":     req.Subject,
		"request":     req.RequestAttrs,
		"resource":    req.Resource,
		"action":      req.Action,
		"environment": req.Environment,
		"now":         time.Now(),
	}

	// Evaluate policies
	for _, policy := range sortedPolicies {
		// Check if policy applies to this resource/action
		if !e.policyApplies(&policy, req.Resource, req.Action) {
			continue
		}

		program, ok := programs[policy.Name]
		if !ok {
			continue
		}

		result, _, err := program.Eval(evalCtx)
		if err != nil {
			e.logger.Warn("CEL evaluation error",
				observability.String("policy", policy.Name),
				observability.Error(err),
			)
			continue
		}

		// Check if the expression evaluated to true
		if boolResult, ok := result.Value().(bool); ok && boolResult {
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
			e.logger.Debug("ABAC decision",
				observability.String("policy", policy.Name),
				observability.Bool("allowed", decision.Allowed),
				observability.String("resource", req.Resource),
				observability.String("action", req.Action),
			)

			return decision, nil
		}
	}

	// No matching policy
	decision := &Decision{
		Allowed: false,
		Reason:  "no matching policy",
		Policy:  "",
	}

	e.metrics.RecordEvaluation("default", "denied", time.Since(start))

	return decision, nil
}

// policyApplies checks if a policy applies to a resource/action.
func (e *celEngine) policyApplies(policy *Policy, resource, action string) bool {
	// Check resources
	if len(policy.Resources) > 0 {
		matched := false
		for _, r := range policy.Resources {
			if r == "*" || r == resource || (strings.HasSuffix(r, "*") && strings.HasPrefix(resource, r[:len(r)-1])) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check actions
	if len(policy.Actions) > 0 {
		matched := false
		for _, a := range policy.Actions {
			if a == "*" || strings.EqualFold(a, action) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// AddPolicy adds a policy to the engine.
func (e *celEngine) AddPolicy(policy Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}

	// Compile the expression
	ast, issues := e.env.Compile(policy.Expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("failed to compile expression: %w", issues.Err())
	}

	program, err := e.env.Program(ast)
	if err != nil {
		return fmt.Errorf("failed to create program: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Check for duplicate
	for i, p := range e.policies {
		if p.Name == policy.Name {
			e.policies[i] = policy
			e.compiledPrograms[policy.Name] = program
			return nil
		}
	}

	e.policies = append(e.policies, policy)
	e.compiledPrograms[policy.Name] = program
	return nil
}

// RemovePolicy removes a policy from the engine.
func (e *celEngine) RemovePolicy(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, p := range e.policies {
		if p.Name == name {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			delete(e.compiledPrograms, name)
			return nil
		}
	}

	return nil
}

// GetPolicies returns all policies.
func (e *celEngine) GetPolicies() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]Policy, len(e.policies))
	copy(result, e.policies)
	return result
}

// Ensure celEngine implements Engine.
var _ Engine = (*celEngine)(nil)

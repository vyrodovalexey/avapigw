package abac

import (
	"errors"
	"fmt"
)

// Config represents ABAC configuration.
type Config struct {
	// Enabled enables ABAC.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Engine is the ABAC engine type (cel).
	Engine string `yaml:"engine,omitempty" json:"engine,omitempty"`

	// Policies is the list of ABAC policies.
	Policies []Policy `yaml:"policies,omitempty" json:"policies,omitempty"`
}

// Policy represents an ABAC policy.
type Policy struct {
	// Name is the policy name.
	Name string `yaml:"name" json:"name"`

	// Description is the policy description.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Expression is the CEL expression to evaluate.
	Expression string `yaml:"expression" json:"expression"`

	// Effect is the policy effect (allow or deny).
	Effect PolicyEffect `yaml:"effect,omitempty" json:"effect,omitempty"`

	// Priority is the policy priority (higher = evaluated first).
	Priority int `yaml:"priority,omitempty" json:"priority,omitempty"`

	// Resources is the list of resources this policy applies to.
	Resources []string `yaml:"resources,omitempty" json:"resources,omitempty"`

	// Actions is the list of actions this policy applies to.
	Actions []string `yaml:"actions,omitempty" json:"actions,omitempty"`
}

// PolicyEffect represents the effect of a policy.
type PolicyEffect string

// Policy effects.
const (
	EffectAllow PolicyEffect = "allow"
	EffectDeny  PolicyEffect = "deny"
)

// Validate validates the ABAC configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	// Validate engine
	if c.Engine != "" && c.Engine != "cel" {
		return fmt.Errorf("invalid engine: %s (only 'cel' is supported)", c.Engine)
	}

	// Validate policies
	for i, policy := range c.Policies {
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("policies[%d]: %w", i, err)
		}
	}

	return nil
}

// Validate validates a policy.
func (p *Policy) Validate() error {
	if p.Name == "" {
		return errors.New("name is required")
	}

	if p.Expression == "" {
		return errors.New("expression is required")
	}

	// Validate effect
	if p.Effect != "" && p.Effect != EffectAllow && p.Effect != EffectDeny {
		return fmt.Errorf("invalid effect: %s (must be 'allow' or 'deny')", p.Effect)
	}

	return nil
}

// DefaultConfig returns a default ABAC configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Engine:  "cel",
	}
}

// GetEffectiveEffect returns the effective effect for a policy.
func (p *Policy) GetEffectiveEffect() PolicyEffect {
	if p.Effect != "" {
		return p.Effect
	}
	return EffectAllow
}

// GetEffectiveEngine returns the effective engine.
func (c *Config) GetEffectiveEngine() string {
	if c.Engine != "" {
		return c.Engine
	}
	return "cel"
}

package rbac

import (
	"errors"
	"fmt"
)

// Config represents RBAC configuration.
type Config struct {
	// Enabled enables RBAC.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// ClaimMapping configures how roles are extracted from claims.
	ClaimMapping *ClaimMapping `yaml:"claimMapping,omitempty" json:"claimMapping,omitempty"`

	// Policies is the list of RBAC policies.
	Policies []Policy `yaml:"policies,omitempty" json:"policies,omitempty"`

	// RoleHierarchy defines role inheritance.
	RoleHierarchy map[string][]string `yaml:"roleHierarchy,omitempty" json:"roleHierarchy,omitempty"`

	// DefaultRole is the role assigned when no roles are found.
	DefaultRole string `yaml:"defaultRole,omitempty" json:"defaultRole,omitempty"`
}

// ClaimMapping configures how roles are extracted from claims.
type ClaimMapping struct {
	// Roles is the claim path for roles.
	Roles string `yaml:"roles,omitempty" json:"roles,omitempty"`

	// Permissions is the claim path for permissions.
	Permissions string `yaml:"permissions,omitempty" json:"permissions,omitempty"`

	// Groups is the claim path for groups.
	Groups string `yaml:"groups,omitempty" json:"groups,omitempty"`
}

// Policy represents an RBAC policy.
type Policy struct {
	// Name is the policy name.
	Name string `yaml:"name" json:"name"`

	// Description is the policy description.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Roles is the list of roles that this policy applies to.
	Roles []string `yaml:"roles,omitempty" json:"roles,omitempty"`

	// Permissions is the list of permissions that this policy applies to.
	Permissions []string `yaml:"permissions,omitempty" json:"permissions,omitempty"`

	// Groups is the list of groups that this policy applies to.
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`

	// Resources is the list of resources this policy applies to.
	// Supports exact match, prefix match (ending with *), and regex (starting with ~).
	Resources []string `yaml:"resources" json:"resources"`

	// Actions is the list of actions this policy allows.
	// For HTTP: GET, POST, PUT, DELETE, PATCH, etc.
	// For gRPC: method names or * for all.
	Actions []string `yaml:"actions" json:"actions"`

	// Effect is the policy effect (allow or deny).
	Effect PolicyEffect `yaml:"effect,omitempty" json:"effect,omitempty"`

	// Priority is the policy priority (higher = evaluated first).
	Priority int `yaml:"priority,omitempty" json:"priority,omitempty"`

	// Conditions are additional conditions for the policy.
	Conditions []Condition `yaml:"conditions,omitempty" json:"conditions,omitempty"`
}

// PolicyEffect represents the effect of a policy.
type PolicyEffect string

// Policy effects.
const (
	EffectAllow PolicyEffect = "allow"
	EffectDeny  PolicyEffect = "deny"
)

// Condition represents a policy condition.
type Condition struct {
	// Type is the condition type.
	Type string `yaml:"type" json:"type"`

	// Key is the condition key.
	Key string `yaml:"key" json:"key"`

	// Operator is the condition operator.
	Operator string `yaml:"operator" json:"operator"`

	// Value is the condition value.
	Value interface{} `yaml:"value" json:"value"`
}

// Validate validates the RBAC configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	// Validate policies
	for i, policy := range c.Policies {
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("policies[%d]: %w", i, err)
		}
	}

	// Validate role hierarchy (check for cycles)
	if len(c.RoleHierarchy) > 0 {
		if err := validateRoleHierarchy(c.RoleHierarchy); err != nil {
			return fmt.Errorf("roleHierarchy: %w", err)
		}
	}

	return nil
}

// Validate validates a policy.
func (p *Policy) Validate() error {
	if p.Name == "" {
		return errors.New("name is required")
	}

	if len(p.Roles) == 0 && len(p.Permissions) == 0 && len(p.Groups) == 0 {
		return errors.New("at least one of roles, permissions, or groups is required")
	}

	if len(p.Resources) == 0 {
		return errors.New("resources is required")
	}

	if len(p.Actions) == 0 {
		return errors.New("actions is required")
	}

	// Validate effect
	if p.Effect != "" && p.Effect != EffectAllow && p.Effect != EffectDeny {
		return fmt.Errorf("invalid effect: %s (must be 'allow' or 'deny')", p.Effect)
	}

	return nil
}

// validateRoleHierarchy validates the role hierarchy for cycles.
func validateRoleHierarchy(hierarchy map[string][]string) error {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var hasCycle func(role string) bool
	hasCycle = func(role string) bool {
		visited[role] = true
		recStack[role] = true

		for _, parent := range hierarchy[role] {
			if !visited[parent] {
				if hasCycle(parent) {
					return true
				}
			} else if recStack[parent] {
				return true
			}
		}

		recStack[role] = false
		return false
	}

	for role := range hierarchy {
		if !visited[role] {
			if hasCycle(role) {
				return fmt.Errorf("cycle detected in role hierarchy involving role: %s", role)
			}
		}
	}

	return nil
}

// DefaultConfig returns a default RBAC configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		ClaimMapping: &ClaimMapping{
			Roles:       "roles",
			Permissions: "permissions",
			Groups:      "groups",
		},
	}
}

// GetEffectiveEffect returns the effective effect for a policy.
func (p *Policy) GetEffectiveEffect() PolicyEffect {
	if p.Effect != "" {
		return p.Effect
	}
	return EffectAllow
}

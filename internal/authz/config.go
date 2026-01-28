package authz

import (
	"errors"
	"fmt"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
)

// Policy represents the default authorization policy.
type Policy string

// Authorization policies.
const (
	PolicyAllow Policy = "allow"
	PolicyDeny  Policy = "deny"
)

// Config represents the main authorization configuration.
type Config struct {
	// Enabled enables authorization.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// DefaultPolicy is the default policy when no rules match.
	DefaultPolicy Policy `yaml:"defaultPolicy,omitempty" json:"defaultPolicy,omitempty"`

	// RBAC configures role-based access control.
	RBAC *rbac.Config `yaml:"rbac,omitempty" json:"rbac,omitempty"`

	// ABAC configures attribute-based access control.
	ABAC *abac.Config `yaml:"abac,omitempty" json:"abac,omitempty"`

	// External configures external authorization.
	External *external.Config `yaml:"external,omitempty" json:"external,omitempty"`

	// SkipPaths is a list of paths to skip authorization.
	SkipPaths []string `yaml:"skipPaths,omitempty" json:"skipPaths,omitempty"`

	// Cache configures authorization decision caching.
	Cache *CacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`
}

// CacheConfig configures authorization decision caching.
type CacheConfig struct {
	// Enabled enables caching.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the cache TTL.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxSize is the maximum number of entries.
	MaxSize int `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`

	// Type is the cache type (memory, redis).
	Type string `yaml:"type,omitempty" json:"type,omitempty"`
}

// Validate validates the authorization configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if err := c.validateDefaultPolicy(); err != nil {
		return err
	}

	if !c.hasAnyAuthzMethod() {
		return errors.New("at least one authorization method must be configured when authorization is enabled")
	}

	return c.validateSubConfigs()
}

// validateDefaultPolicy validates the default policy.
func (c *Config) validateDefaultPolicy() error {
	if c.DefaultPolicy != "" && c.DefaultPolicy != PolicyAllow && c.DefaultPolicy != PolicyDeny {
		return fmt.Errorf("invalid default policy: %s (must be 'allow' or 'deny')", c.DefaultPolicy)
	}
	return nil
}

// validateSubConfigs validates sub-configurations.
func (c *Config) validateSubConfigs() error {
	if c.RBAC != nil && c.RBAC.Enabled {
		if err := c.RBAC.Validate(); err != nil {
			return fmt.Errorf("rbac config: %w", err)
		}
	}
	if c.ABAC != nil && c.ABAC.Enabled {
		if err := c.ABAC.Validate(); err != nil {
			return fmt.Errorf("abac config: %w", err)
		}
	}
	if c.External != nil && c.External.Enabled {
		if err := c.External.Validate(); err != nil {
			return fmt.Errorf("external config: %w", err)
		}
	}
	if c.Cache != nil && c.Cache.Enabled {
		if err := c.validateCache(); err != nil {
			return fmt.Errorf("cache config: %w", err)
		}
	}
	return nil
}

// hasAnyAuthzMethod checks if any authorization method is configured.
func (c *Config) hasAnyAuthzMethod() bool {
	if c.RBAC != nil && c.RBAC.Enabled {
		return true
	}
	if c.ABAC != nil && c.ABAC.Enabled {
		return true
	}
	if c.External != nil && c.External.Enabled {
		return true
	}
	return false
}

// validateCache validates cache configuration.
func (c *Config) validateCache() error {
	if c.Cache.TTL < 0 {
		return errors.New("ttl must be non-negative")
	}
	if c.Cache.MaxSize < 0 {
		return errors.New("maxSize must be non-negative")
	}
	validTypes := map[string]bool{
		"":       true,
		"memory": true,
		"redis":  true,
	}
	if !validTypes[c.Cache.Type] {
		return fmt.Errorf("invalid cache type: %s", c.Cache.Type)
	}
	return nil
}

// DefaultConfig returns a default authorization configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:       false,
		DefaultPolicy: PolicyDeny,
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 10000,
			Type:    "memory",
		},
	}
}

// IsRBACEnabled returns true if RBAC is enabled.
func (c *Config) IsRBACEnabled() bool {
	return c != nil && c.RBAC != nil && c.RBAC.Enabled
}

// IsABACEnabled returns true if ABAC is enabled.
func (c *Config) IsABACEnabled() bool {
	return c != nil && c.ABAC != nil && c.ABAC.Enabled
}

// IsExternalEnabled returns true if external authorization is enabled.
func (c *Config) IsExternalEnabled() bool {
	return c != nil && c.External != nil && c.External.Enabled
}

// GetEffectiveDefaultPolicy returns the effective default policy.
func (c *Config) GetEffectiveDefaultPolicy() Policy {
	if c.DefaultPolicy != "" {
		return c.DefaultPolicy
	}
	return PolicyDeny
}

// ShouldSkipPath checks if authorization should be skipped for a path.
func (c *Config) ShouldSkipPath(path string) bool {
	for _, skipPath := range c.SkipPaths {
		if matchPath(skipPath, path) {
			return true
		}
	}
	return false
}

// matchPath checks if a path matches a pattern.
func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	// Check for wildcard suffix
	if pattern != "" && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return false
}

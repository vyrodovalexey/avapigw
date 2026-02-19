package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// Config represents the main authentication configuration.
type Config struct {
	// Enabled enables authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// JWT configures JWT authentication.
	JWT *jwt.Config `yaml:"jwt,omitempty" json:"jwt,omitempty"`

	// APIKey configures API Key authentication.
	APIKey *apikey.Config `yaml:"apiKey,omitempty" json:"apiKey,omitempty"`

	// MTLS configures mTLS authentication.
	MTLS *mtls.Config `yaml:"mtls,omitempty" json:"mtls,omitempty"`

	// OIDC configures OIDC authentication.
	OIDC *oidc.Config `yaml:"oidc,omitempty" json:"oidc,omitempty"`

	// Extraction configures credential extraction.
	Extraction *ExtractionConfig `yaml:"extraction,omitempty" json:"extraction,omitempty"`

	// SkipPaths is a list of paths to skip authentication.
	SkipPaths []string `yaml:"skipPaths,omitempty" json:"skipPaths,omitempty"`

	// RequireAuthentication requires at least one authentication method to succeed.
	RequireAuthentication bool `yaml:"requireAuthentication,omitempty" json:"requireAuthentication,omitempty"`

	// AllowAnonymous allows anonymous access when no credentials are provided.
	AllowAnonymous bool `yaml:"allowAnonymous,omitempty" json:"allowAnonymous,omitempty"`

	// CacheConfig configures authentication result caching.
	Cache *AuthCacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`
}

// ExtractionConfig configures credential extraction.
type ExtractionConfig struct {
	// JWT configures JWT extraction.
	JWT []ExtractionSource `yaml:"jwt,omitempty" json:"jwt,omitempty"`

	// APIKey configures API Key extraction.
	APIKey []ExtractionSource `yaml:"apiKey,omitempty" json:"apiKey,omitempty"`
}

// ExtractionSource represents a source for credential extraction.
type ExtractionSource struct {
	// Type is the extraction type (header, cookie, query, metadata).
	Type ExtractionType `yaml:"type" json:"type"`

	// Name is the name of the header, cookie, query parameter, or metadata key.
	Name string `yaml:"name" json:"name"`

	// Prefix is the prefix to strip from the value (e.g., "Bearer ").
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
}

// ExtractionType represents the type of credential extraction.
type ExtractionType string

// Extraction types.
const (
	ExtractionTypeHeader   ExtractionType = "header"
	ExtractionTypeCookie   ExtractionType = "cookie"
	ExtractionTypeQuery    ExtractionType = "query"
	ExtractionTypeMetadata ExtractionType = "metadata"
)

// AuthCacheConfig configures authentication result caching.
type AuthCacheConfig struct {
	// Enabled enables caching.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the cache TTL.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxSize is the maximum number of entries.
	MaxSize int `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`

	// Type is the cache type (memory, redis).
	Type string `yaml:"type,omitempty" json:"type,omitempty"`
}

// Validate validates the authentication configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	// Validate at least one authentication method is configured
	if !c.hasAnyAuthMethod() {
		return errors.New("at least one authentication method must be configured when authentication is enabled")
	}

	// Validate all auth methods
	if err := c.validateAuthMethods(); err != nil {
		return err
	}

	// Validate extraction configuration
	if err := c.validateExtractionConfig(); err != nil {
		return err
	}

	// Validate cache configuration
	return c.validateCacheConfig()
}

// validateAuthMethods validates all authentication method configurations.
func (c *Config) validateAuthMethods() error {
	if c.JWT != nil && c.JWT.Enabled {
		if err := c.JWT.Validate(); err != nil {
			return fmt.Errorf("jwt config: %w", err)
		}
	}
	if c.APIKey != nil && c.APIKey.Enabled {
		if err := c.APIKey.Validate(); err != nil {
			return fmt.Errorf("apikey config: %w", err)
		}
	}
	if c.MTLS != nil && c.MTLS.Enabled {
		if err := c.MTLS.Validate(); err != nil {
			return fmt.Errorf("mtls config: %w", err)
		}
	}
	if c.OIDC != nil && c.OIDC.Enabled {
		if err := c.OIDC.Validate(); err != nil {
			return fmt.Errorf("oidc config: %w", err)
		}
	}
	return nil
}

// validateExtractionConfig validates the extraction configuration.
func (c *Config) validateExtractionConfig() error {
	if c.Extraction == nil {
		return nil
	}
	if err := c.validateExtraction(); err != nil {
		return fmt.Errorf("extraction config: %w", err)
	}
	return nil
}

// validateCacheConfig validates the cache configuration.
func (c *Config) validateCacheConfig() error {
	if c.Cache == nil || !c.Cache.Enabled {
		return nil
	}
	if err := c.validateCache(); err != nil {
		return fmt.Errorf("cache config: %w", err)
	}
	return nil
}

// hasAnyAuthMethod checks if any authentication method is configured.
func (c *Config) hasAnyAuthMethod() bool {
	if c.JWT != nil && c.JWT.Enabled {
		return true
	}
	if c.APIKey != nil && c.APIKey.Enabled {
		return true
	}
	if c.MTLS != nil && c.MTLS.Enabled {
		return true
	}
	if c.OIDC != nil && c.OIDC.Enabled {
		return true
	}
	return false
}

// validateExtraction validates extraction configuration.
func (c *Config) validateExtraction() error {
	for i, src := range c.Extraction.JWT {
		if err := validateExtractionSource(src); err != nil {
			return fmt.Errorf("jwt[%d]: %w", i, err)
		}
	}
	for i, src := range c.Extraction.APIKey {
		if err := validateExtractionSource(src); err != nil {
			return fmt.Errorf("apiKey[%d]: %w", i, err)
		}
	}
	return nil
}

// validateExtractionSource validates an extraction source.
func validateExtractionSource(src ExtractionSource) error {
	validTypes := map[ExtractionType]bool{
		ExtractionTypeHeader:   true,
		ExtractionTypeCookie:   true,
		ExtractionTypeQuery:    true,
		ExtractionTypeMetadata: true,
	}
	if !validTypes[src.Type] {
		return fmt.Errorf("invalid extraction type: %s", src.Type)
	}
	if src.Name == "" {
		return errors.New("name is required")
	}
	return nil
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

// DefaultConfig returns a default authentication configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{
					Type:   ExtractionTypeHeader,
					Name:   "Authorization",
					Prefix: "Bearer ",
				},
			},
			APIKey: []ExtractionSource{
				{
					Type: ExtractionTypeHeader,
					Name: "X-API-Key",
				},
			},
		},
		Cache: &AuthCacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 10000,
			Type:    "memory",
		},
	}
}

// IsJWTEnabled returns true if JWT authentication is enabled.
func (c *Config) IsJWTEnabled() bool {
	return c != nil && c.JWT != nil && c.JWT.Enabled
}

// IsAPIKeyEnabled returns true if API Key authentication is enabled.
func (c *Config) IsAPIKeyEnabled() bool {
	return c != nil && c.APIKey != nil && c.APIKey.Enabled
}

// IsMTLSEnabled returns true if mTLS authentication is enabled.
func (c *Config) IsMTLSEnabled() bool {
	return c != nil && c.MTLS != nil && c.MTLS.Enabled
}

// IsOIDCEnabled returns true if OIDC authentication is enabled.
func (c *Config) IsOIDCEnabled() bool {
	return c != nil && c.OIDC != nil && c.OIDC.Enabled
}

// ShouldSkipPath checks if authentication should be skipped for a path.
func (c *Config) ShouldSkipPath(path string) bool {
	for _, skipPath := range c.SkipPaths {
		if util.MatchPath(skipPath, path) {
			return true
		}
	}
	return false
}

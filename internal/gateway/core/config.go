package core

import (
	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
	"go.uber.org/zap"
)

// BaseConfig provides common configuration for all core components.
type BaseConfig struct {
	// Logger for logging events.
	Logger *zap.Logger

	// SkipPaths is a list of paths/identifiers to skip processing.
	SkipPaths []string

	// skipPathMap is the internal map for fast lookup.
	skipPathMap map[string]bool
}

// InitSkipPaths initializes the skip path map from the SkipPaths slice.
// This should be called after setting SkipPaths.
func (c *BaseConfig) InitSkipPaths() {
	c.skipPathMap = make(map[string]bool, len(c.SkipPaths))
	for _, path := range c.SkipPaths {
		c.skipPathMap[path] = true
	}
}

// ShouldSkip checks if the given path/identifier should be skipped.
func (c *BaseConfig) ShouldSkip(path string) bool {
	if c.skipPathMap == nil {
		return false
	}
	return c.skipPathMap[path]
}

// GetLogger returns the logger, or a noop logger if not set.
func (c *BaseConfig) GetLogger() *zap.Logger {
	if c.Logger == nil {
		return zap.NewNop()
	}
	return c.Logger
}

// RateLimitCoreConfig holds configuration for the rate limit core.
type RateLimitCoreConfig struct {
	BaseConfig

	// Limiter is the rate limiter to use.
	Limiter ratelimit.Limiter

	// KeyFunc extracts the rate limit key from an identifier.
	// If nil, the identifier is used as-is.
	KeyFunc func(identifier string) string

	// IncludeHeaders determines whether to include rate limit info in response.
	IncludeHeaders bool
}

// DefaultRateLimitCoreConfig returns a RateLimitCoreConfig with default values.
func DefaultRateLimitCoreConfig() *RateLimitCoreConfig {
	return &RateLimitCoreConfig{
		IncludeHeaders: true,
	}
}

// CircuitBreakerCoreConfig holds configuration for the circuit breaker core.
type CircuitBreakerCoreConfig struct {
	BaseConfig

	// Registry is the circuit breaker registry.
	Registry *circuitbreaker.Registry

	// NameFunc extracts the circuit breaker name from an identifier.
	// If nil, the identifier is used as-is.
	NameFunc func(identifier string) string
}

// DefaultCircuitBreakerCoreConfig returns a CircuitBreakerCoreConfig with default values.
func DefaultCircuitBreakerCoreConfig() *CircuitBreakerCoreConfig {
	return &CircuitBreakerCoreConfig{}
}

// AuthCoreConfig holds configuration for the auth core.
type AuthCoreConfig struct {
	BaseConfig

	// JWTEnabled indicates whether JWT authentication is enabled.
	JWTEnabled bool

	// APIKeyEnabled indicates whether API key authentication is enabled.
	APIKeyEnabled bool

	// BasicEnabled indicates whether basic authentication is enabled.
	BasicEnabled bool

	// RequireAuth indicates whether authentication is required.
	RequireAuth bool

	// AllowAnonymous indicates whether anonymous access is allowed.
	AllowAnonymous bool

	// AnonymousPaths is a list of paths that allow anonymous access.
	AnonymousPaths []string

	// anonymousPathMap is the internal map for fast lookup.
	anonymousPathMap map[string]bool
}

// DefaultAuthCoreConfig returns an AuthCoreConfig with default values.
func DefaultAuthCoreConfig() *AuthCoreConfig {
	return &AuthCoreConfig{
		RequireAuth:    true,
		AllowAnonymous: false,
	}
}

// InitAnonymousPaths initializes the anonymous path map from the AnonymousPaths slice.
func (c *AuthCoreConfig) InitAnonymousPaths() {
	c.anonymousPathMap = make(map[string]bool, len(c.AnonymousPaths))
	for _, path := range c.AnonymousPaths {
		c.anonymousPathMap[path] = true
	}
}

// IsAnonymousPath checks if the given path allows anonymous access.
func (c *AuthCoreConfig) IsAnonymousPath(path string) bool {
	if c.anonymousPathMap == nil {
		return false
	}
	return c.anonymousPathMap[path]
}

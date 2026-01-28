package config

import "time"

// RateLimitConfig represents rate limiting configuration.
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled" json:"enabled"`
	RequestsPerSecond int  `yaml:"requestsPerSecond" json:"requestsPerSecond"`
	Burst             int  `yaml:"burst" json:"burst"`
	PerClient         bool `yaml:"perClient,omitempty" json:"perClient,omitempty"`
}

// CircuitBreakerConfig represents circuit breaker configuration.
type CircuitBreakerConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	Threshold        int      `yaml:"threshold" json:"threshold"`
	Timeout          Duration `yaml:"timeout" json:"timeout"`
	HalfOpenRequests int      `yaml:"halfOpenRequests,omitempty" json:"halfOpenRequests,omitempty"`
}

// CORSConfig represents CORS configuration.
type CORSConfig struct {
	AllowOrigins     []string `yaml:"allowOrigins,omitempty" json:"allowOrigins,omitempty"`
	AllowMethods     []string `yaml:"allowMethods,omitempty" json:"allowMethods,omitempty"`
	AllowHeaders     []string `yaml:"allowHeaders,omitempty" json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `yaml:"exposeHeaders,omitempty" json:"exposeHeaders,omitempty"`
	MaxAge           int      `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`
	AllowCredentials bool     `yaml:"allowCredentials,omitempty" json:"allowCredentials,omitempty"`
}

// MaxSessionsConfig configures maximum concurrent sessions.
type MaxSessionsConfig struct {
	// Enabled enables max sessions limiting.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxConcurrent is the maximum number of concurrent sessions.
	MaxConcurrent int `yaml:"maxConcurrent" json:"maxConcurrent"`

	// QueueSize is the size of the waiting queue (0 = reject immediately).
	QueueSize int `yaml:"queueSize,omitempty" json:"queueSize,omitempty"`

	// QueueTimeout is the maximum time to wait in queue.
	QueueTimeout Duration `yaml:"queueTimeout,omitempty" json:"queueTimeout,omitempty"`
}

// GetEffectiveQueueTimeout returns the effective queue timeout.
func (c *MaxSessionsConfig) GetEffectiveQueueTimeout() time.Duration {
	if c == nil || c.QueueTimeout == 0 {
		return DefaultMaxSessionsQueueTimeout
	}
	return c.QueueTimeout.Duration()
}

// RequestLimitsConfig configures request size limits.
type RequestLimitsConfig struct {
	// MaxBodySize is the maximum allowed request body size in bytes.
	// Default is 10MB (10485760 bytes).
	MaxBodySize int64 `yaml:"maxBodySize,omitempty" json:"maxBodySize,omitempty"`

	// MaxHeaderSize is the maximum allowed total header size in bytes.
	// Default is 1MB (1048576 bytes).
	MaxHeaderSize int64 `yaml:"maxHeaderSize,omitempty" json:"maxHeaderSize,omitempty"`
}

// DefaultRequestLimits returns the default request limits configuration.
func DefaultRequestLimits() *RequestLimitsConfig {
	return &RequestLimitsConfig{
		MaxBodySize:   DefaultMaxBodySize,
		MaxHeaderSize: DefaultMaxHeaderSize,
	}
}

// GetEffectiveMaxBodySize returns the effective max body size.
func (c *RequestLimitsConfig) GetEffectiveMaxBodySize() int64 {
	if c == nil || c.MaxBodySize <= 0 {
		return DefaultMaxBodySize
	}
	return c.MaxBodySize
}

// GetEffectiveMaxHeaderSize returns the effective max header size.
func (c *RequestLimitsConfig) GetEffectiveMaxHeaderSize() int64 {
	if c == nil || c.MaxHeaderSize <= 0 {
		return DefaultMaxHeaderSize
	}
	return c.MaxHeaderSize
}

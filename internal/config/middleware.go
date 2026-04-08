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

// OpenAPIValidationConfig configures OpenAPI request validation.
type OpenAPIValidationConfig struct {
	// Enabled enables OpenAPI request validation.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// SpecFile is the path to the OpenAPI specification file.
	SpecFile string `yaml:"specFile,omitempty" json:"specFile,omitempty"`

	// SpecURL is the URL to fetch the OpenAPI specification from.
	SpecURL string `yaml:"specURL,omitempty" json:"specURL,omitempty"`

	// FailOnError rejects requests that fail validation (default: true).
	// When false, validation errors are logged but requests are allowed through.
	FailOnError *bool `yaml:"failOnError,omitempty" json:"failOnError,omitempty"`

	// ValidateRequestBody enables request body validation.
	ValidateRequestBody *bool `yaml:"validateRequestBody,omitempty" json:"validateRequestBody,omitempty"`

	// ValidateRequestParams enables request parameter validation (path, query, header).
	ValidateRequestParams *bool `yaml:"validateRequestParams,omitempty" json:"validateRequestParams,omitempty"`

	// ValidateRequestHeaders enables request header validation.
	ValidateRequestHeaders *bool `yaml:"validateRequestHeaders,omitempty" json:"validateRequestHeaders,omitempty"`

	// ValidateSecurity enables security requirement validation.
	ValidateSecurity *bool `yaml:"validateSecurity,omitempty" json:"validateSecurity,omitempty"`
}

// GetEffectiveFailOnError returns the effective failOnError value (default: true).
func (c *OpenAPIValidationConfig) GetEffectiveFailOnError() bool {
	if c == nil || c.FailOnError == nil {
		return true
	}
	return *c.FailOnError
}

// GetEffectiveValidateRequestBody returns the effective validateRequestBody value (default: true).
func (c *OpenAPIValidationConfig) GetEffectiveValidateRequestBody() bool {
	if c == nil || c.ValidateRequestBody == nil {
		return true
	}
	return *c.ValidateRequestBody
}

// GetEffectiveValidateRequestParams returns the effective validateRequestParams value (default: true).
func (c *OpenAPIValidationConfig) GetEffectiveValidateRequestParams() bool {
	if c == nil || c.ValidateRequestParams == nil {
		return true
	}
	return *c.ValidateRequestParams
}

// GetEffectiveValidateRequestHeaders returns the effective validateRequestHeaders value (default: false).
func (c *OpenAPIValidationConfig) GetEffectiveValidateRequestHeaders() bool {
	if c == nil || c.ValidateRequestHeaders == nil {
		return false
	}
	return *c.ValidateRequestHeaders
}

// GetEffectiveValidateSecurity returns the effective validateSecurity value (default: false).
func (c *OpenAPIValidationConfig) GetEffectiveValidateSecurity() bool {
	if c == nil || c.ValidateSecurity == nil {
		return false
	}
	return *c.ValidateSecurity
}

// ProtoValidationConfig configures proto descriptor-based request validation for gRPC.
type ProtoValidationConfig struct {
	// Enabled enables proto descriptor-based request validation.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// DescriptorFile is the path to the proto descriptor file.
	DescriptorFile string `yaml:"descriptorFile,omitempty" json:"descriptorFile,omitempty"`

	// FailOnError rejects requests that fail validation (default: true).
	// When false, validation errors are logged but requests are allowed through.
	FailOnError *bool `yaml:"failOnError,omitempty" json:"failOnError,omitempty"`

	// ValidateRequestMessage enables request message validation.
	ValidateRequestMessage *bool `yaml:"validateRequestMessage,omitempty" json:"validateRequestMessage,omitempty"`
}

// GetEffectiveFailOnError returns the effective failOnError value (default: true).
func (c *ProtoValidationConfig) GetEffectiveFailOnError() bool {
	if c == nil || c.FailOnError == nil {
		return true
	}
	return *c.FailOnError
}

// GetEffectiveValidateRequestMessage returns the effective validateRequestMessage value (default: true).
func (c *ProtoValidationConfig) GetEffectiveValidateRequestMessage() bool {
	if c == nil || c.ValidateRequestMessage == nil {
		return true
	}
	return *c.ValidateRequestMessage
}

// GraphQLSchemaValidationConfig configures GraphQL schema validation.
type GraphQLSchemaValidationConfig struct {
	// Enabled enables GraphQL schema validation.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// SchemaFile is the path to the GraphQL schema file.
	SchemaFile string `yaml:"schemaFile,omitempty" json:"schemaFile,omitempty"`

	// FailOnError rejects requests that fail validation (default: true).
	// When false, validation errors are logged but requests are allowed through.
	FailOnError *bool `yaml:"failOnError,omitempty" json:"failOnError,omitempty"`

	// ValidateVariables enables GraphQL variable validation.
	ValidateVariables *bool `yaml:"validateVariables,omitempty" json:"validateVariables,omitempty"`
}

// GetEffectiveFailOnError returns the effective failOnError value (default: true).
func (c *GraphQLSchemaValidationConfig) GetEffectiveFailOnError() bool {
	if c == nil || c.FailOnError == nil {
		return true
	}
	return *c.FailOnError
}

// GetEffectiveValidateVariables returns the effective validateVariables value (default: true).
func (c *GraphQLSchemaValidationConfig) GetEffectiveValidateVariables() bool {
	if c == nil || c.ValidateVariables == nil {
		return true
	}
	return *c.ValidateVariables
}

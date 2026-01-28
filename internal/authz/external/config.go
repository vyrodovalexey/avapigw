package external

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Config represents external authorization configuration.
type Config struct {
	// Enabled enables external authorization.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Type is the external authorizer type (opa, grpc, http).
	Type string `yaml:"type" json:"type"`

	// OPA configures OPA authorization.
	OPA *OPAConfig `yaml:"opa,omitempty" json:"opa,omitempty"`

	// GRPC configures gRPC external authorization.
	GRPC *GRPCConfig `yaml:"grpc,omitempty" json:"grpc,omitempty"`

	// HTTP configures HTTP external authorization.
	HTTP *HTTPConfig `yaml:"http,omitempty" json:"http,omitempty"`

	// Timeout is the timeout for external authorization requests.
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// FailOpen allows requests when external authorization fails.
	FailOpen bool `yaml:"failOpen,omitempty" json:"failOpen,omitempty"`

	// Cache configures decision caching.
	Cache *CacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`
}

// OPAConfig configures OPA authorization.
type OPAConfig struct {
	// URL is the OPA server URL.
	URL string `yaml:"url" json:"url"`

	// Policy is the policy path to query.
	Policy string `yaml:"policy,omitempty" json:"policy,omitempty"`

	// Query is the query to execute.
	Query string `yaml:"query,omitempty" json:"query,omitempty"`

	// Headers are additional headers to send.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// GRPCConfig configures gRPC external authorization.
type GRPCConfig struct {
	// Address is the gRPC server address.
	Address string `yaml:"address" json:"address"`

	// TLS configures TLS for the connection.
	TLS *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Metadata are additional metadata to send.
	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// HTTPConfig configures HTTP external authorization.
type HTTPConfig struct {
	// URL is the HTTP endpoint URL.
	URL string `yaml:"url" json:"url"`

	// Method is the HTTP method (GET, POST).
	Method string `yaml:"method,omitempty" json:"method,omitempty"`

	// Headers are additional headers to send.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// TLS configures TLS for the connection.
	TLS *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// TLSConfig configures TLS for external connections.
type TLSConfig struct {
	// Enabled enables TLS.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CAFile is the path to the CA certificate.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// CertFile is the path to the client certificate.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the client key.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// InsecureSkipVerify skips certificate verification.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`
}

// CacheConfig configures decision caching.
type CacheConfig struct {
	// Enabled enables caching.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the cache TTL.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxSize is the maximum number of entries.
	MaxSize int `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`
}

// Validate validates the external authorization configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if err := c.validateType(); err != nil {
		return err
	}
	if err := c.validateTypeConfig(); err != nil {
		return err
	}
	return c.validateOptions()
}

// validateType validates the authorization type.
func (c *Config) validateType() error {
	validTypes := map[string]bool{"opa": true, "grpc": true, "http": true}
	if !validTypes[c.Type] {
		return fmt.Errorf("invalid type: %s (must be 'opa', 'grpc', or 'http')", c.Type)
	}
	return nil
}

// validateTypeConfig validates type-specific configuration.
func (c *Config) validateTypeConfig() error {
	switch c.Type {
	case "opa":
		if c.OPA == nil {
			return errors.New("opa configuration is required when type is 'opa'")
		}
		return c.OPA.Validate()
	case "grpc":
		if c.GRPC == nil {
			return errors.New("grpc configuration is required when type is 'grpc'")
		}
		return c.GRPC.Validate()
	case "http":
		if c.HTTP == nil {
			return errors.New("http configuration is required when type is 'http'")
		}
		return c.HTTP.Validate()
	}
	return nil
}

// validateOptions validates timeout and cache options.
func (c *Config) validateOptions() error {
	if c.Timeout < 0 {
		return errors.New("timeout must be non-negative")
	}
	if c.Cache != nil && c.Cache.Enabled {
		if c.Cache.TTL < 0 {
			return errors.New("cache.ttl must be non-negative")
		}
		if c.Cache.MaxSize < 0 {
			return errors.New("cache.maxSize must be non-negative")
		}
	}
	return nil
}

// Validate validates the OPA configuration.
func (c *OPAConfig) Validate() error {
	if c.URL == "" {
		return errors.New("url is required")
	}
	return nil
}

// Validate validates the gRPC configuration.
func (c *GRPCConfig) Validate() error {
	if c.Address == "" {
		return errors.New("address is required")
	}
	return nil
}

// Validate validates the HTTP configuration.
func (c *HTTPConfig) Validate() error {
	if c.URL == "" {
		return errors.New("url is required")
	}
	if c.Method != "" && c.Method != http.MethodGet && c.Method != http.MethodPost {
		return fmt.Errorf("invalid method: %s (must be 'GET' or 'POST')", c.Method)
	}
	return nil
}

// DefaultConfig returns a default external authorization configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:  false,
		Type:     "opa",
		Timeout:  100 * time.Millisecond,
		FailOpen: false,
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 10000,
		},
	}
}

// GetEffectiveTimeout returns the effective timeout.
func (c *Config) GetEffectiveTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 100 * time.Millisecond
}

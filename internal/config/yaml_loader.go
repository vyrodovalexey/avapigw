// Package config provides configuration management for the API Gateway.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadYAMLConfig loads and parses a YAML configuration file from the specified path.
// It returns the parsed LocalConfig or an error if the file cannot be read or parsed.
func LoadYAMLConfig(path string) (*LocalConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("config file path is empty")
	}

	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file does not exist: %s", path)
		}
		return nil, fmt.Errorf("failed to stat config file: %w", err)
	}

	// Check if it's a regular file
	if info.IsDir() {
		return nil, fmt.Errorf("config path is a directory, not a file: %s", path)
	}

	// Read file contents
	// G304: path is validated above via os.Stat and comes from trusted configuration
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var cfg LocalConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return &cfg, nil
}

// ValidateLocalConfig validates the LocalConfig and returns an error if invalid.
// This is a convenience function that calls the Validate method on LocalConfig.
func ValidateLocalConfig(cfg *LocalConfig) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	return cfg.Validate()
}

// MergeConfigs merges a LocalConfig into a base Config.
// The LocalConfig values take precedence over the base Config values.
// This function modifies the base Config in place and returns it.
func MergeConfigs(base *Config, local *LocalConfig) *Config {
	if base == nil {
		base = DefaultConfig()
	}

	if local == nil {
		return base
	}

	// Merge gateway configuration
	if local.Gateway.Name != "" {
		// Gateway name can be used for service identification
		if base.ServiceName == "" || base.ServiceName == "avapigw" {
			base.ServiceName = local.Gateway.Name
		}
	}

	// Merge listener configurations
	for _, listener := range local.Gateway.Listeners {
		switch listener.Protocol {
		case "HTTP", "http":
			if listener.Port > 0 {
				base.HTTPPort = listener.Port
			}
		case "HTTPS", "https":
			if listener.Port > 0 {
				base.HTTPPort = listener.Port
				base.TLSEnabled = true
			}
			if listener.TLS != nil {
				mergeTLSConfig(base, listener.TLS)
			}
		case "GRPC", "grpc":
			if listener.Port > 0 {
				base.GRPCPort = listener.Port
				base.GRPCEnabled = true
			}
		case "GRPCS", "grpcs":
			if listener.Port > 0 {
				base.GRPCPort = listener.Port
				base.GRPCEnabled = true
				base.TLSEnabled = true
			}
		case "TCP", "tcp":
			if listener.Port > 0 {
				base.TCPPort = listener.Port
				base.TCPEnabled = true
			}
		case "TLS", "tls":
			if listener.Port > 0 {
				base.TLSPassthroughPort = listener.Port
				base.TLSPassthroughEnabled = true
			}
		}
	}

	// Merge rate limit configurations from the first rate limit policy
	// (global rate limiting settings)
	if len(local.RateLimits) > 0 {
		firstRateLimit := local.RateLimits[0]
		base.RateLimitEnabled = true
		base.RateLimitAlgorithm = firstRateLimit.Algorithm
		base.RateLimitRequests = firstRateLimit.Requests
		base.RateLimitWindow = firstRateLimit.Window
		if firstRateLimit.Burst > 0 {
			base.RateLimitBurst = firstRateLimit.Burst
		}
	}

	// Merge auth policy configurations from the first auth policy
	// (global auth settings)
	if len(local.AuthPolicies) > 0 {
		firstAuthPolicy := local.AuthPolicies[0]

		if firstAuthPolicy.JWT != nil {
			base.JWTEnabled = true
			if firstAuthPolicy.JWT.Issuer != "" {
				base.JWTIssuer = firstAuthPolicy.JWT.Issuer
			}
			if firstAuthPolicy.JWT.JWKSURL != "" {
				base.JWKSURL = firstAuthPolicy.JWT.JWKSURL
			}
			if len(firstAuthPolicy.JWT.Audiences) > 0 {
				base.JWTAudiences = firstAuthPolicy.JWT.Audiences
			}
			if len(firstAuthPolicy.JWT.Algorithms) > 0 {
				base.JWTAlgorithms = firstAuthPolicy.JWT.Algorithms
			}
			if firstAuthPolicy.JWT.TokenSource != nil {
				if firstAuthPolicy.JWT.TokenSource.Header != "" {
					base.JWTTokenHeader = firstAuthPolicy.JWT.TokenSource.Header
				}
				if firstAuthPolicy.JWT.TokenSource.Prefix != "" {
					base.JWTTokenPrefix = firstAuthPolicy.JWT.TokenSource.Prefix
				}
				if firstAuthPolicy.JWT.TokenSource.Cookie != "" {
					base.JWTTokenCookie = firstAuthPolicy.JWT.TokenSource.Cookie
				}
				if firstAuthPolicy.JWT.TokenSource.Query != "" {
					base.JWTTokenQuery = firstAuthPolicy.JWT.TokenSource.Query
				}
			}
		}

		if firstAuthPolicy.APIKey != nil {
			base.APIKeyEnabled = true
			if firstAuthPolicy.APIKey.Header != "" {
				base.APIKeyHeader = firstAuthPolicy.APIKey.Header
			}
			if firstAuthPolicy.APIKey.Query != "" {
				base.APIKeyQueryParam = firstAuthPolicy.APIKey.Query
			}
		}

		if firstAuthPolicy.BasicAuth != nil {
			base.BasicAuthEnabled = true
			if firstAuthPolicy.BasicAuth.Realm != "" {
				base.BasicAuthRealm = firstAuthPolicy.BasicAuth.Realm
			}
		}

		if firstAuthPolicy.OAuth2 != nil {
			base.OAuth2Enabled = true
			if firstAuthPolicy.OAuth2.TokenEndpoint != "" {
				base.OAuth2TokenEndpoint = firstAuthPolicy.OAuth2.TokenEndpoint
			}
			if firstAuthPolicy.OAuth2.ClientID != "" {
				base.OAuth2ClientID = firstAuthPolicy.OAuth2.ClientID
			}
			if len(firstAuthPolicy.OAuth2.Scopes) > 0 {
				base.OAuth2Scopes = firstAuthPolicy.OAuth2.Scopes
			}
		}
	}

	// Merge backend configurations
	// Extract common settings from the first backend
	if len(local.Backends) > 0 {
		firstBackend := local.Backends[0]

		if firstBackend.HealthCheck != nil {
			base.HealthCheckInterval = firstBackend.HealthCheck.Interval
			base.HealthCheckTimeout = firstBackend.HealthCheck.Timeout
		}

		if firstBackend.CircuitBreaker != nil {
			base.CircuitBreakerEnabled = true
			if firstBackend.CircuitBreaker.ConsecutiveErrors > 0 {
				base.CircuitBreakerMaxFailures = firstBackend.CircuitBreaker.ConsecutiveErrors
			}
			if firstBackend.CircuitBreaker.Interval > 0 {
				base.CircuitBreakerTimeout = firstBackend.CircuitBreaker.Interval
			}
		}

		if firstBackend.ConnectionPool != nil {
			if firstBackend.ConnectionPool.HTTP != nil {
				if firstBackend.ConnectionPool.HTTP.IdleTimeout > 0 {
					base.IdleConnTimeout = firstBackend.ConnectionPool.HTTP.IdleTimeout
				}
			}
			if firstBackend.ConnectionPool.TCP != nil {
				if firstBackend.ConnectionPool.TCP.MaxConnections > 0 {
					base.MaxConnsPerHost = firstBackend.ConnectionPool.TCP.MaxConnections
				}
			}
		}
	}

	return base
}

// mergeTLSConfig merges TLS configuration from listener to base config.
func mergeTLSConfig(base *Config, tlsCfg *ListenerTLSConfig) {
	if tlsCfg == nil {
		return
	}

	if tlsCfg.Mode == "passthrough" {
		base.TLSPassthroughEnabled = true
	}

	// Certificate references would typically be resolved by the controller
	// For local config, we might store the reference for later resolution
	// Note: tlsCfg.CertificateRef is intentionally not processed here
}

// LoadAndValidateYAMLConfig loads a YAML config file and validates it.
// This is a convenience function that combines LoadYAMLConfig and ValidateLocalConfig.
func LoadAndValidateYAMLConfig(path string) (*LocalConfig, error) {
	cfg, err := LoadYAMLConfig(path)
	if err != nil {
		return nil, err
	}

	if err := ValidateLocalConfig(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// SaveYAMLConfig saves a LocalConfig to a YAML file.
// This is useful for generating sample configurations or exporting current config.
func SaveYAMLConfig(cfg *LocalConfig, path string) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	if path == "" {
		return fmt.Errorf("path is empty")
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	// G306: Config files need to be readable by other processes, 0o644 is intentional
	if err := os.WriteFile(filepath.Clean(path), data, 0o644); err != nil { //nolint:gosec // config files need broader read permissions
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DefaultLocalConfig returns a LocalConfig with sensible defaults.
func DefaultLocalConfig() *LocalConfig {
	return &LocalConfig{
		Gateway: GatewayConfig{
			Name: "default-gateway",
			Listeners: []ListenerConfig{
				{
					Name:     "http",
					Port:     8080,
					Protocol: "HTTP",
				},
			},
		},
		Routes:       []LocalRoute{},
		Backends:     []LocalBackend{},
		RateLimits:   []LocalRateLimit{},
		AuthPolicies: []LocalAuthPolicy{},
	}
}

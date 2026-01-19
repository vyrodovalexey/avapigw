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

	mergeGatewayConfig(base, local)
	mergeListenerConfigs(base, local)
	mergeRateLimitConfigs(base, local)
	mergeAuthPolicyConfigs(base, local)
	mergeBackendConfigs(base, local)

	return base
}

// mergeGatewayConfig merges gateway configuration from local config.
func mergeGatewayConfig(base *Config, local *LocalConfig) {
	if local.Gateway.Name != "" {
		// Gateway name can be used for service identification
		if base.ServiceName == "" || base.ServiceName == "avapigw" {
			base.ServiceName = local.Gateway.Name
		}
	}
}

// mergeListenerConfigs merges listener configurations from local config.
func mergeListenerConfigs(base *Config, local *LocalConfig) {
	for _, listener := range local.Gateway.Listeners {
		mergeListenerConfig(base, &listener)
	}
}

// mergeListenerConfig merges a single listener configuration.
func mergeListenerConfig(base *Config, listener *ListenerConfig) {
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
			mergeListenerTLSConfig(base, listener.TLS)
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

// mergeListenerTLSConfig merges TLS configuration from listener to base config.
func mergeListenerTLSConfig(base *Config, tlsCfg *ListenerTLSConfig) {
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

// mergeRateLimitConfigs merges rate limit configurations from local config.
// Uses the first rate limit policy for global rate limiting settings.
func mergeRateLimitConfigs(base *Config, local *LocalConfig) {
	if len(local.RateLimits) == 0 {
		return
	}
	firstRateLimit := local.RateLimits[0]
	base.RateLimitEnabled = true
	base.RateLimitAlgorithm = firstRateLimit.Algorithm
	base.RateLimitRequests = firstRateLimit.Requests
	base.RateLimitWindow = firstRateLimit.Window
	if firstRateLimit.Burst > 0 {
		base.RateLimitBurst = firstRateLimit.Burst
	}
}

// mergeAuthPolicyConfigs merges auth policy configurations from local config.
// Uses the first auth policy for global auth settings.
func mergeAuthPolicyConfigs(base *Config, local *LocalConfig) {
	if len(local.AuthPolicies) == 0 {
		return
	}
	firstAuthPolicy := local.AuthPolicies[0]

	mergeJWTAuthConfig(base, firstAuthPolicy.JWT)
	mergeAPIKeyAuthConfig(base, firstAuthPolicy.APIKey)
	mergeBasicAuthConfig(base, firstAuthPolicy.BasicAuth)
	mergeOAuth2AuthConfig(base, firstAuthPolicy.OAuth2)
}

// mergeJWTAuthConfig merges JWT authentication configuration.
func mergeJWTAuthConfig(base *Config, jwt *JWTAuthConfig) {
	if jwt == nil {
		return
	}
	base.JWTEnabled = true
	if jwt.Issuer != "" {
		base.JWTIssuer = jwt.Issuer
	}
	if jwt.JWKSURL != "" {
		base.JWKSURL = jwt.JWKSURL
	}
	if len(jwt.Audiences) > 0 {
		base.JWTAudiences = jwt.Audiences
	}
	if len(jwt.Algorithms) > 0 {
		base.JWTAlgorithms = jwt.Algorithms
	}
	mergeJWTTokenSourceConfig(base, jwt.TokenSource)
}

// mergeJWTTokenSourceConfig merges JWT token source configuration.
func mergeJWTTokenSourceConfig(base *Config, tokenSource *TokenSourceConfig) {
	if tokenSource == nil {
		return
	}
	if tokenSource.Header != "" {
		base.JWTTokenHeader = tokenSource.Header
	}
	if tokenSource.Prefix != "" {
		base.JWTTokenPrefix = tokenSource.Prefix
	}
	if tokenSource.Cookie != "" {
		base.JWTTokenCookie = tokenSource.Cookie
	}
	if tokenSource.Query != "" {
		base.JWTTokenQuery = tokenSource.Query
	}
}

// mergeAPIKeyAuthConfig merges API key authentication configuration.
func mergeAPIKeyAuthConfig(base *Config, apiKey *APIKeyAuthConfig) {
	if apiKey == nil {
		return
	}
	base.APIKeyEnabled = true
	if apiKey.Header != "" {
		base.APIKeyHeader = apiKey.Header
	}
	if apiKey.Query != "" {
		base.APIKeyQueryParam = apiKey.Query
	}
}

// mergeBasicAuthConfig merges basic authentication configuration.
func mergeBasicAuthConfig(base *Config, basicAuth *BasicAuthConfig) {
	if basicAuth == nil {
		return
	}
	base.BasicAuthEnabled = true
	if basicAuth.Realm != "" {
		base.BasicAuthRealm = basicAuth.Realm
	}
}

// mergeOAuth2AuthConfig merges OAuth2 authentication configuration.
func mergeOAuth2AuthConfig(base *Config, oauth2 *OAuth2AuthConfig) {
	if oauth2 == nil {
		return
	}
	base.OAuth2Enabled = true
	if oauth2.TokenEndpoint != "" {
		base.OAuth2TokenEndpoint = oauth2.TokenEndpoint
	}
	if oauth2.ClientID != "" {
		base.OAuth2ClientID = oauth2.ClientID
	}
	if len(oauth2.Scopes) > 0 {
		base.OAuth2Scopes = oauth2.Scopes
	}
}

// mergeBackendConfigs merges backend configurations from local config.
// Extracts common settings from the first backend.
func mergeBackendConfigs(base *Config, local *LocalConfig) {
	if len(local.Backends) == 0 {
		return
	}
	firstBackend := local.Backends[0]

	mergeBackendHealthCheckConfig(base, firstBackend.HealthCheck)
	mergeBackendCircuitBreakerConfig(base, firstBackend.CircuitBreaker)
	mergeBackendConnectionPoolConfig(base, firstBackend.ConnectionPool)
}

// mergeBackendHealthCheckConfig merges backend health check configuration.
func mergeBackendHealthCheckConfig(base *Config, healthCheck *HealthCheckConfig) {
	if healthCheck == nil {
		return
	}
	base.HealthCheckInterval = healthCheck.Interval
	base.HealthCheckTimeout = healthCheck.Timeout
}

// mergeBackendCircuitBreakerConfig merges backend circuit breaker configuration.
func mergeBackendCircuitBreakerConfig(base *Config, cb *CircuitBreakerConfig) {
	if cb == nil {
		return
	}
	base.CircuitBreakerEnabled = true
	if cb.ConsecutiveErrors > 0 {
		base.CircuitBreakerMaxFailures = cb.ConsecutiveErrors
	}
	if cb.Interval > 0 {
		base.CircuitBreakerTimeout = cb.Interval
	}
}

// mergeBackendConnectionPoolConfig merges backend connection pool configuration.
func mergeBackendConnectionPoolConfig(base *Config, pool *ConnectionPoolConfig) {
	if pool == nil {
		return
	}
	if pool.HTTP != nil && pool.HTTP.IdleTimeout > 0 {
		base.IdleConnTimeout = pool.HTTP.IdleTimeout
	}
	if pool.TCP != nil && pool.TCP.MaxConnections > 0 {
		base.MaxConnsPerHost = pool.TCP.MaxConnections
	}
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
	//nolint:gosec // config files need broader read permissions
	if err := os.WriteFile(filepath.Clean(path), data, 0o644); err != nil {
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

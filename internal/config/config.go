// Package config provides configuration types and loading for the API Gateway.
package config

// GatewayConfig represents the root configuration for the API Gateway.
type GatewayConfig struct {
	APIVersion string      `yaml:"apiVersion" json:"apiVersion"`
	Kind       string      `yaml:"kind" json:"kind"`
	Metadata   Metadata    `yaml:"metadata" json:"metadata"`
	Spec       GatewaySpec `yaml:"spec" json:"spec"`
}

// Metadata contains metadata about the gateway configuration.
type Metadata struct {
	Name        string            `yaml:"name" json:"name"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

// GatewaySpec contains the main gateway specification.
type GatewaySpec struct {
	Listeners      []Listener            `yaml:"listeners" json:"listeners"`
	Routes         []Route               `yaml:"routes,omitempty" json:"routes,omitempty"`
	Backends       []Backend             `yaml:"backends,omitempty" json:"backends,omitempty"`
	GRPCRoutes     []GRPCRoute           `yaml:"grpcRoutes,omitempty" json:"grpcRoutes,omitempty"`
	GRPCBackends   []GRPCBackend         `yaml:"grpcBackends,omitempty" json:"grpcBackends,omitempty"`
	RateLimit      *RateLimitConfig      `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`
	CORS           *CORSConfig           `yaml:"cors,omitempty" json:"cors,omitempty"`
	Observability  *ObservabilityConfig  `yaml:"observability,omitempty" json:"observability,omitempty"`
	Authentication *AuthenticationConfig `yaml:"authentication,omitempty" json:"authentication,omitempty"`
	Authorization  *AuthorizationConfig  `yaml:"authorization,omitempty" json:"authorization,omitempty"`
	Security       *SecurityConfig       `yaml:"security,omitempty" json:"security,omitempty"`
	Audit          *AuditConfig          `yaml:"audit,omitempty" json:"audit,omitempty"`
	// RequestLimits configures request size limits.
	RequestLimits *RequestLimitsConfig `yaml:"requestLimits,omitempty" json:"requestLimits,omitempty"`
	// MaxSessions configures maximum concurrent sessions at the gateway level.
	MaxSessions *MaxSessionsConfig `yaml:"maxSessions,omitempty" json:"maxSessions,omitempty"`
	// TrustedProxies is a list of trusted proxy CIDRs for X-Forwarded-For validation.
	// When configured, only requests from these CIDRs will have their
	// X-Forwarded-For headers trusted for client IP extraction.
	// When empty, only RemoteAddr is used (secure default).
	TrustedProxies []string `yaml:"trustedProxies,omitempty" json:"trustedProxies,omitempty"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *GatewayConfig {
	return &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: Metadata{
			Name: "default-gateway",
		},
		Spec: GatewaySpec{
			Listeners: []Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: "HTTP",
					Hosts:    []string{"*"},
					Bind:     "0.0.0.0",
				},
			},
			Observability: &ObservabilityConfig{
				Metrics: &MetricsConfig{
					Enabled: true,
					Path:    "/metrics",
				},
				Logging: &LoggingConfig{
					Level:  "info",
					Format: "json",
				},
			},
		},
	}
}

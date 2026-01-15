// Package config provides configuration management for the API Gateway.
// It supports loading configuration from environment variables and command-line flags,
// with environment variables taking precedence over flags.
package config

import (
	"fmt"
	"time"
)

// Config holds all configuration settings for the API Gateway.
type Config struct {
	// Server settings
	HTTPPort    int `json:"httpPort" yaml:"httpPort"`
	GRPCPort    int `json:"grpcPort" yaml:"grpcPort"`
	MetricsPort int `json:"metricsPort" yaml:"metricsPort"`
	HealthPort  int `json:"healthPort" yaml:"healthPort"`

	// Server timeouts
	ReadTimeout     time.Duration `json:"readTimeout" yaml:"readTimeout"`
	WriteTimeout    time.Duration `json:"writeTimeout" yaml:"writeTimeout"`
	IdleTimeout     time.Duration `json:"idleTimeout" yaml:"idleTimeout"`
	ShutdownTimeout time.Duration `json:"shutdownTimeout" yaml:"shutdownTimeout"`

	// TLS settings
	TLSEnabled  bool   `json:"tlsEnabled" yaml:"tlsEnabled"`
	TLSCertFile string `json:"tlsCertFile" yaml:"tlsCertFile"`
	TLSKeyFile  string `json:"tlsKeyFile" yaml:"tlsKeyFile"`
	TLSCAFile   string `json:"tlsCAFile" yaml:"tlsCAFile"`

	// Vault settings
	VaultEnabled          bool          `json:"vaultEnabled" yaml:"vaultEnabled"`
	VaultAddress          string        `json:"vaultAddress" yaml:"vaultAddress"`
	VaultNamespace        string        `json:"vaultNamespace" yaml:"vaultNamespace"`
	VaultAuthMethod       string        `json:"vaultAuthMethod" yaml:"vaultAuthMethod"` // kubernetes, token, approle
	VaultRole             string        `json:"vaultRole" yaml:"vaultRole"`
	VaultMountPath        string        `json:"vaultMountPath" yaml:"vaultMountPath"`
	VaultSecretMountPoint string        `json:"vaultSecretMountPoint" yaml:"vaultSecretMountPoint"`
	VaultTLSSkipVerify    bool          `json:"vaultTLSSkipVerify" yaml:"vaultTLSSkipVerify"`
	VaultCACert           string        `json:"vaultCACert" yaml:"vaultCACert"`
	VaultClientCert       string        `json:"vaultClientCert" yaml:"vaultClientCert"`
	VaultClientKey        string        `json:"vaultClientKey" yaml:"vaultClientKey"`
	VaultTimeout          time.Duration `json:"vaultTimeout" yaml:"vaultTimeout"`
	VaultMaxRetries       int           `json:"vaultMaxRetries" yaml:"vaultMaxRetries"`
	VaultRetryWaitMin     time.Duration `json:"vaultRetryWaitMin" yaml:"vaultRetryWaitMin"`
	VaultRetryWaitMax     time.Duration `json:"vaultRetryWaitMax" yaml:"vaultRetryWaitMax"`
	VaultCacheEnabled     bool          `json:"vaultCacheEnabled" yaml:"vaultCacheEnabled"`
	VaultCacheTTL         time.Duration `json:"vaultCacheTTL" yaml:"vaultCacheTTL"`
	VaultTokenRenewal     bool          `json:"vaultTokenRenewal" yaml:"vaultTokenRenewal"`
	VaultTokenRenewalTime time.Duration `json:"vaultTokenRenewalTime" yaml:"vaultTokenRenewalTime"`

	// Secrets Provider settings
	SecretsProvider  string `json:"secretsProvider" yaml:"secretsProvider"`   // kubernetes, vault, local, env
	SecretsLocalPath string `json:"secretsLocalPath" yaml:"secretsLocalPath"` // base path for local provider
	SecretsEnvPrefix string `json:"secretsEnvPrefix" yaml:"secretsEnvPrefix"` // prefix for env provider

	// Observability - Logging
	LogLevel         string `json:"logLevel" yaml:"logLevel"`
	LogFormat        string `json:"logFormat" yaml:"logFormat"`
	LogOutput        string `json:"logOutput" yaml:"logOutput"`
	AccessLogEnabled bool   `json:"accessLogEnabled" yaml:"accessLogEnabled"`

	// Observability - Tracing
	TracingEnabled    bool    `json:"tracingEnabled" yaml:"tracingEnabled"`
	TracingExporter   string  `json:"tracingExporter" yaml:"tracingExporter"` // otlp-grpc, otlp-http
	OTLPEndpoint      string  `json:"otlpEndpoint" yaml:"otlpEndpoint"`
	TracingSampleRate float64 `json:"tracingSampleRate" yaml:"tracingSampleRate"`
	ServiceName       string  `json:"serviceName" yaml:"serviceName"`
	ServiceVersion    string  `json:"serviceVersion" yaml:"serviceVersion"`
	TracingInsecure   bool    `json:"tracingInsecure" yaml:"tracingInsecure"`

	// Observability - Metrics
	MetricsEnabled bool   `json:"metricsEnabled" yaml:"metricsEnabled"`
	MetricsPath    string `json:"metricsPath" yaml:"metricsPath"`

	// Rate limiting
	RateLimitEnabled   bool          `json:"rateLimitEnabled" yaml:"rateLimitEnabled"`
	RateLimitAlgorithm string        `json:"rateLimitAlgorithm" yaml:"rateLimitAlgorithm"` // token_bucket, sliding_window, fixed_window
	RateLimitRequests  int           `json:"rateLimitRequests" yaml:"rateLimitRequests"`
	RateLimitWindow    time.Duration `json:"rateLimitWindow" yaml:"rateLimitWindow"`
	RateLimitBurst     int           `json:"rateLimitBurst" yaml:"rateLimitBurst"`
	RateLimitStoreType string        `json:"rateLimitStoreType" yaml:"rateLimitStoreType"` // memory, redis
	RedisAddress       string        `json:"redisAddress" yaml:"redisAddress"`
	RedisPassword      string        `json:"redisPassword" yaml:"redisPassword"`
	RedisDB            int           `json:"redisDB" yaml:"redisDB"`

	// Circuit Breaker
	CircuitBreakerEnabled          bool          `json:"circuitBreakerEnabled" yaml:"circuitBreakerEnabled"`
	CircuitBreakerMaxFailures      int           `json:"circuitBreakerMaxFailures" yaml:"circuitBreakerMaxFailures"`
	CircuitBreakerTimeout          time.Duration `json:"circuitBreakerTimeout" yaml:"circuitBreakerTimeout"`
	CircuitBreakerHalfOpenMax      int           `json:"circuitBreakerHalfOpenMax" yaml:"circuitBreakerHalfOpenMax"`
	CircuitBreakerSuccessThreshold int           `json:"circuitBreakerSuccessThreshold" yaml:"circuitBreakerSuccessThreshold"`

	// Retry
	RetryEnabled        bool          `json:"retryEnabled" yaml:"retryEnabled"`
	RetryMaxAttempts    int           `json:"retryMaxAttempts" yaml:"retryMaxAttempts"`
	RetryInitialBackoff time.Duration `json:"retryInitialBackoff" yaml:"retryInitialBackoff"`
	RetryMaxBackoff     time.Duration `json:"retryMaxBackoff" yaml:"retryMaxBackoff"`
	RetryBackoffFactor  float64       `json:"retryBackoffFactor" yaml:"retryBackoffFactor"`

	// Backend settings
	MaxIdleConns        int           `json:"maxIdleConns" yaml:"maxIdleConns"`
	MaxIdleConnsPerHost int           `json:"maxIdleConnsPerHost" yaml:"maxIdleConnsPerHost"`
	MaxConnsPerHost     int           `json:"maxConnsPerHost" yaml:"maxConnsPerHost"`
	IdleConnTimeout     time.Duration `json:"idleConnTimeout" yaml:"idleConnTimeout"`

	// Health check settings
	HealthCheckInterval time.Duration `json:"healthCheckInterval" yaml:"healthCheckInterval"`
	HealthCheckTimeout  time.Duration `json:"healthCheckTimeout" yaml:"healthCheckTimeout"`

	// Health server timeouts
	HealthServerReadTimeout     time.Duration `json:"healthServerReadTimeout" yaml:"healthServerReadTimeout"`
	HealthServerWriteTimeout    time.Duration `json:"healthServerWriteTimeout" yaml:"healthServerWriteTimeout"`
	HealthServerShutdownTimeout time.Duration `json:"healthServerShutdownTimeout" yaml:"healthServerShutdownTimeout"`

	// Metrics server timeouts
	MetricsServerReadTimeout     time.Duration `json:"metricsServerReadTimeout" yaml:"metricsServerReadTimeout"`
	MetricsServerWriteTimeout    time.Duration `json:"metricsServerWriteTimeout" yaml:"metricsServerWriteTimeout"`
	MetricsServerShutdownTimeout time.Duration `json:"metricsServerShutdownTimeout" yaml:"metricsServerShutdownTimeout"`

	// Readiness/Liveness probe timeouts
	ReadinessProbeTimeout time.Duration `json:"readinessProbeTimeout" yaml:"readinessProbeTimeout"`
	LivenessProbeTimeout  time.Duration `json:"livenessProbeTimeout" yaml:"livenessProbeTimeout"`

	// gRPC settings
	GRPCEnabled              bool `json:"grpcEnabled" yaml:"grpcEnabled"`
	GRPCMaxRecvMsgSize       int  `json:"grpcMaxRecvMsgSize" yaml:"grpcMaxRecvMsgSize"`
	GRPCMaxSendMsgSize       int  `json:"grpcMaxSendMsgSize" yaml:"grpcMaxSendMsgSize"`
	GRPCMaxConcurrentStreams int  `json:"grpcMaxConcurrentStreams" yaml:"grpcMaxConcurrentStreams"`
	GRPCEnableReflection     bool `json:"grpcEnableReflection" yaml:"grpcEnableReflection"`
	GRPCEnableHealthCheck    bool `json:"grpcEnableHealthCheck" yaml:"grpcEnableHealthCheck"`

	// TCP settings
	TCPEnabled        bool          `json:"tcpEnabled" yaml:"tcpEnabled"`
	TCPPort           int           `json:"tcpPort" yaml:"tcpPort"`
	TCPReadTimeout    time.Duration `json:"tcpReadTimeout" yaml:"tcpReadTimeout"`
	TCPWriteTimeout   time.Duration `json:"tcpWriteTimeout" yaml:"tcpWriteTimeout"`
	TCPIdleTimeout    time.Duration `json:"tcpIdleTimeout" yaml:"tcpIdleTimeout"`
	TCPMaxConnections int           `json:"tcpMaxConnections" yaml:"tcpMaxConnections"`

	// TLS Passthrough settings
	TLSPassthroughEnabled bool `json:"tlsPassthroughEnabled" yaml:"tlsPassthroughEnabled"`
	TLSPassthroughPort    int  `json:"tlsPassthroughPort" yaml:"tlsPassthroughPort"`

	// Authentication - JWT
	JWTEnabled     bool          `json:"jwtEnabled" yaml:"jwtEnabled"`
	JWTIssuer      string        `json:"jwtIssuer" yaml:"jwtIssuer"`
	JWTAudiences   []string      `json:"jwtAudiences" yaml:"jwtAudiences"`
	JWKSURL        string        `json:"jwksUrl" yaml:"jwksUrl"`
	JWKSCacheTTL   time.Duration `json:"jwksCacheTtl" yaml:"jwksCacheTtl"`
	JWTClockSkew   time.Duration `json:"jwtClockSkew" yaml:"jwtClockSkew"`
	JWTAlgorithms  []string      `json:"jwtAlgorithms" yaml:"jwtAlgorithms"`
	JWTTokenHeader string        `json:"jwtTokenHeader" yaml:"jwtTokenHeader"`
	JWTTokenPrefix string        `json:"jwtTokenPrefix" yaml:"jwtTokenPrefix"`
	JWTTokenCookie string        `json:"jwtTokenCookie" yaml:"jwtTokenCookie"`
	JWTTokenQuery  string        `json:"jwtTokenQuery" yaml:"jwtTokenQuery"`

	// Authentication - API Key
	APIKeyEnabled    bool   `json:"apiKeyEnabled" yaml:"apiKeyEnabled"`
	APIKeyHeader     string `json:"apiKeyHeader" yaml:"apiKeyHeader"`
	APIKeyQueryParam string `json:"apiKeyQueryParam" yaml:"apiKeyQueryParam"`

	// Authentication - Basic Auth
	BasicAuthEnabled bool   `json:"basicAuthEnabled" yaml:"basicAuthEnabled"`
	BasicAuthRealm   string `json:"basicAuthRealm" yaml:"basicAuthRealm"`

	// Authentication - OAuth2 Client Credentials
	OAuth2Enabled       bool          `json:"oauth2Enabled" yaml:"oauth2Enabled"`
	OAuth2TokenEndpoint string        `json:"oauth2TokenEndpoint" yaml:"oauth2TokenEndpoint"`
	OAuth2ClientID      string        `json:"oauth2ClientId" yaml:"oauth2ClientId"`
	OAuth2Scopes        []string      `json:"oauth2Scopes" yaml:"oauth2Scopes"`
	OAuth2Timeout       time.Duration `json:"oauth2Timeout" yaml:"oauth2Timeout"`

	// Authorization
	AuthzEnabled      bool `json:"authzEnabled" yaml:"authzEnabled"`
	AuthzDefaultAllow bool `json:"authzDefaultAllow" yaml:"authzDefaultAllow"`

	// Security Headers
	SecurityHeadersEnabled bool   `json:"securityHeadersEnabled" yaml:"securityHeadersEnabled"`
	HSTSEnabled            bool   `json:"hstsEnabled" yaml:"hstsEnabled"`
	HSTSMaxAge             int    `json:"hstsMaxAge" yaml:"hstsMaxAge"`
	HSTSIncludeSubDomains  bool   `json:"hstsIncludeSubDomains" yaml:"hstsIncludeSubDomains"`
	HSTSPreload            bool   `json:"hstsPreload" yaml:"hstsPreload"`
	CSPPolicy              string `json:"cspPolicy" yaml:"cspPolicy"`
	XFrameOptions          string `json:"xFrameOptions" yaml:"xFrameOptions"`
	XContentTypeOptions    string `json:"xContentTypeOptions" yaml:"xContentTypeOptions"`
	ReferrerPolicy         string `json:"referrerPolicy" yaml:"referrerPolicy"`

	// Webhook Certificate Settings
	WebhookSelfSignedCert       bool          `json:"webhookSelfSignedCert" yaml:"webhookSelfSignedCert"`
	WebhookCertDir              string        `json:"webhookCertDir" yaml:"webhookCertDir"`
	WebhookCertValidity         time.Duration `json:"webhookCertValidity" yaml:"webhookCertValidity"`
	WebhookCertRotation         time.Duration `json:"webhookCertRotation" yaml:"webhookCertRotation"`
	WebhookCertSecretName       string        `json:"webhookCertSecretName" yaml:"webhookCertSecretName"`
	WebhookServiceName          string        `json:"webhookServiceName" yaml:"webhookServiceName"`
	WebhookServiceNamespace     string        `json:"webhookServiceNamespace" yaml:"webhookServiceNamespace"`
	WebhookValidatingConfigName string        `json:"webhookValidatingConfigName" yaml:"webhookValidatingConfigName"`
	WebhookMutatingConfigName   string        `json:"webhookMutatingConfigName" yaml:"webhookMutatingConfigName"`
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		// Server settings
		HTTPPort:    8080,
		GRPCPort:    9090,
		MetricsPort: 9091,
		HealthPort:  8081,

		// Server timeouts
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 30 * time.Second,

		// TLS settings
		TLSEnabled:  false,
		TLSCertFile: "",
		TLSKeyFile:  "",
		TLSCAFile:   "",

		// Vault settings
		VaultEnabled:          false,
		VaultAddress:          "http://localhost:8200",
		VaultNamespace:        "",
		VaultAuthMethod:       "kubernetes",
		VaultRole:             "avapigw",
		VaultMountPath:        "kubernetes",
		VaultSecretMountPoint: "secret",
		VaultTLSSkipVerify:    false,
		VaultCACert:           "",
		VaultClientCert:       "",
		VaultClientKey:        "",
		VaultTimeout:          30 * time.Second,
		VaultMaxRetries:       3,
		VaultRetryWaitMin:     500 * time.Millisecond,
		VaultRetryWaitMax:     5 * time.Second,
		VaultCacheEnabled:     true,
		VaultCacheTTL:         5 * time.Minute,
		VaultTokenRenewal:     true,
		VaultTokenRenewalTime: 5 * time.Minute,

		// Secrets Provider settings
		SecretsProvider:  "",                     // empty means auto-detect (vault if enabled, otherwise kubernetes)
		SecretsLocalPath: "/etc/avapigw/secrets", // default path for local secrets
		SecretsEnvPrefix: "AVAPIGW_SECRET_",      // default prefix for env secrets

		// Observability - Logging
		LogLevel:         "info",
		LogFormat:        "json",
		LogOutput:        "stdout",
		AccessLogEnabled: true,

		// Observability - Tracing
		TracingEnabled:    false,
		TracingExporter:   "otlp-grpc",
		OTLPEndpoint:      "localhost:4317",
		TracingSampleRate: 1.0,
		ServiceName:       "avapigw",
		ServiceVersion:    "1.0.0",
		TracingInsecure:   true,

		// Observability - Metrics
		MetricsEnabled: true,
		MetricsPath:    "/metrics",

		// Rate limiting
		RateLimitEnabled:   false,
		RateLimitAlgorithm: "token_bucket",
		RateLimitRequests:  100,
		RateLimitWindow:    time.Minute,
		RateLimitBurst:     10,
		RateLimitStoreType: "memory",
		RedisAddress:       "localhost:6379",
		RedisPassword:      "",
		RedisDB:            0,

		// Circuit Breaker
		CircuitBreakerEnabled:          false,
		CircuitBreakerMaxFailures:      5,
		CircuitBreakerTimeout:          30 * time.Second,
		CircuitBreakerHalfOpenMax:      3,
		CircuitBreakerSuccessThreshold: 2,

		// Retry
		RetryEnabled:        false,
		RetryMaxAttempts:    3,
		RetryInitialBackoff: 100 * time.Millisecond,
		RetryMaxBackoff:     10 * time.Second,
		RetryBackoffFactor:  2.0,

		// Backend settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,

		// Health check settings
		HealthCheckInterval: 10 * time.Second,
		HealthCheckTimeout:  5 * time.Second,

		// Health server timeouts - used for the dedicated health check server
		HealthServerReadTimeout:     5 * time.Second,
		HealthServerWriteTimeout:    5 * time.Second,
		HealthServerShutdownTimeout: 5 * time.Second,

		// Metrics server timeouts - used for the Prometheus metrics server
		MetricsServerReadTimeout:     5 * time.Second,
		MetricsServerWriteTimeout:    10 * time.Second,
		MetricsServerShutdownTimeout: 5 * time.Second,

		// Readiness/Liveness probe timeouts - context timeout for health check execution
		ReadinessProbeTimeout: 5 * time.Second,
		LivenessProbeTimeout:  10 * time.Second,

		// gRPC settings
		GRPCEnabled:              true,
		GRPCMaxRecvMsgSize:       4 * 1024 * 1024, // 4 MB
		GRPCMaxSendMsgSize:       4 * 1024 * 1024, // 4 MB
		GRPCMaxConcurrentStreams: 1000,
		GRPCEnableReflection:     false,
		GRPCEnableHealthCheck:    true,

		// TCP settings
		TCPEnabled:        false,
		TCPPort:           8443,
		TCPReadTimeout:    30 * time.Second,
		TCPWriteTimeout:   30 * time.Second,
		TCPIdleTimeout:    5 * time.Minute,
		TCPMaxConnections: 10000,

		// TLS Passthrough settings
		TLSPassthroughEnabled: false,
		TLSPassthroughPort:    8444,

		// Authentication - JWT
		JWTEnabled:     false,
		JWTIssuer:      "",
		JWTAudiences:   nil,
		JWKSURL:        "",
		JWKSCacheTTL:   time.Hour,
		JWTClockSkew:   time.Minute,
		JWTAlgorithms:  []string{"RS256", "RS384", "RS512"},
		JWTTokenHeader: "Authorization",
		JWTTokenPrefix: "Bearer ",
		JWTTokenCookie: "",
		JWTTokenQuery:  "",

		// Authentication - API Key
		APIKeyEnabled:    false,
		APIKeyHeader:     "X-API-Key",
		APIKeyQueryParam: "api_key",

		// Authentication - Basic Auth
		BasicAuthEnabled: false,
		BasicAuthRealm:   "Restricted",

		// Authentication - OAuth2 Client Credentials
		OAuth2Enabled:       false,
		OAuth2TokenEndpoint: "",
		OAuth2ClientID:      "",
		OAuth2Scopes:        nil,
		OAuth2Timeout:       30 * time.Second,

		// Authorization
		AuthzEnabled:      false,
		AuthzDefaultAllow: false,

		// Security Headers
		SecurityHeadersEnabled: true,
		HSTSEnabled:            true,
		HSTSMaxAge:             31536000, // 1 year
		HSTSIncludeSubDomains:  true,
		HSTSPreload:            false,
		CSPPolicy:              "",
		XFrameOptions:          "DENY",
		XContentTypeOptions:    "nosniff",
		ReferrerPolicy:         "strict-origin-when-cross-origin",

		// Webhook Certificate Settings
		WebhookSelfSignedCert:       false,
		WebhookCertDir:              "/tmp/k8s-webhook-server/serving-certs",
		WebhookCertValidity:         365 * 24 * time.Hour, // 1 year
		WebhookCertRotation:         30 * 24 * time.Hour,  // 30 days before expiry
		WebhookCertSecretName:       "avapigw-webhook-certs",
		WebhookServiceName:          "avapigw-webhook-service",
		WebhookServiceNamespace:     "avapigw-system",
		WebhookValidatingConfigName: "avapigw-validating-webhook-configuration",
		WebhookMutatingConfigName:   "avapigw-mutating-webhook-configuration",
	}
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	// Validate ports
	if err := validatePort(c.HTTPPort, "HTTPPort"); err != nil {
		return err
	}
	if err := validatePort(c.GRPCPort, "GRPCPort"); err != nil {
		return err
	}
	if err := validatePort(c.MetricsPort, "MetricsPort"); err != nil {
		return err
	}
	if err := validatePort(c.HealthPort, "HealthPort"); err != nil {
		return err
	}

	// Validate TLS settings
	if c.TLSEnabled {
		if c.TLSCertFile == "" {
			return fmt.Errorf("TLSCertFile is required when TLS is enabled")
		}
		if c.TLSKeyFile == "" {
			return fmt.Errorf("TLSKeyFile is required when TLS is enabled")
		}
	}

	// Validate Vault settings
	if c.VaultEnabled {
		if c.VaultAddress == "" {
			return fmt.Errorf("VaultAddress is required when Vault is enabled")
		}
		validAuthMethods := map[string]bool{
			"kubernetes": true,
			"token":      true,
			"approle":    true,
		}
		if !validAuthMethods[c.VaultAuthMethod] {
			return fmt.Errorf("invalid VaultAuthMethod: %s, must be one of: kubernetes, token, approle", c.VaultAuthMethod)
		}
		if c.VaultAuthMethod == "kubernetes" && c.VaultRole == "" {
			return fmt.Errorf("VaultRole is required when using Kubernetes auth")
		}
		if c.VaultTimeout <= 0 {
			return fmt.Errorf("VaultTimeout must be positive")
		}
		if c.VaultMaxRetries < 0 {
			return fmt.Errorf("VaultMaxRetries must be non-negative")
		}
	}

	// Validate secrets provider
	if c.SecretsProvider != "" {
		validProviders := map[string]bool{
			"kubernetes": true,
			"vault":      true,
			"local":      true,
			"env":        true,
		}
		if !validProviders[c.SecretsProvider] {
			return fmt.Errorf("invalid SecretsProvider: %s, must be one of: kubernetes, vault, local, env", c.SecretsProvider)
		}

		// Validate provider-specific settings
		if c.SecretsProvider == "vault" && !c.VaultEnabled {
			return fmt.Errorf("VaultEnabled must be true when SecretsProvider is vault")
		}
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid LogLevel: %s, must be one of: debug, info, warn, error", c.LogLevel)
	}

	// Validate log format
	validLogFormats := map[string]bool{
		"json":    true,
		"console": true,
	}
	if !validLogFormats[c.LogFormat] {
		return fmt.Errorf("invalid LogFormat: %s, must be one of: json, console", c.LogFormat)
	}

	// Validate log output
	validLogOutputs := map[string]bool{
		"stdout": true,
		"stderr": true,
	}
	if c.LogOutput != "" && !validLogOutputs[c.LogOutput] {
		// Allow file paths as well
		if c.LogOutput[0] != '/' && c.LogOutput[0] != '.' {
			return fmt.Errorf("invalid LogOutput: %s, must be stdout, stderr, or a file path", c.LogOutput)
		}
	}

	// Validate tracing settings
	if c.TracingEnabled {
		if c.OTLPEndpoint == "" {
			return fmt.Errorf("OTLPEndpoint is required when tracing is enabled")
		}
		validExporters := map[string]bool{
			"otlp-grpc": true,
			"otlp-http": true,
		}
		if !validExporters[c.TracingExporter] {
			return fmt.Errorf("invalid TracingExporter: %s, must be one of: otlp-grpc, otlp-http", c.TracingExporter)
		}
		if c.TracingSampleRate < 0 || c.TracingSampleRate > 1 {
			return fmt.Errorf("TracingSampleRate must be between 0.0 and 1.0")
		}
	}

	// Validate rate limiting settings
	if c.RateLimitEnabled {
		validAlgorithms := map[string]bool{
			"token_bucket":   true,
			"sliding_window": true,
			"fixed_window":   true,
		}
		if !validAlgorithms[c.RateLimitAlgorithm] {
			return fmt.Errorf("invalid RateLimitAlgorithm: %s, must be one of: token_bucket, sliding_window, fixed_window", c.RateLimitAlgorithm)
		}

		validStoreTypes := map[string]bool{
			"memory": true,
			"redis":  true,
		}
		if !validStoreTypes[c.RateLimitStoreType] {
			return fmt.Errorf("invalid RateLimitStoreType: %s, must be one of: memory, redis", c.RateLimitStoreType)
		}

		if c.RateLimitStoreType == "redis" && c.RedisAddress == "" {
			return fmt.Errorf("RedisAddress is required when rate limit store type is redis")
		}

		if c.RateLimitRequests <= 0 {
			return fmt.Errorf("RateLimitRequests must be positive")
		}
		if c.RateLimitWindow <= 0 {
			return fmt.Errorf("RateLimitWindow must be positive")
		}
		if c.RateLimitBurst <= 0 {
			return fmt.Errorf("RateLimitBurst must be positive")
		}
	}

	// Validate circuit breaker settings
	if c.CircuitBreakerEnabled {
		if c.CircuitBreakerMaxFailures <= 0 {
			return fmt.Errorf("CircuitBreakerMaxFailures must be positive")
		}
		if c.CircuitBreakerTimeout <= 0 {
			return fmt.Errorf("CircuitBreakerTimeout must be positive")
		}
		if c.CircuitBreakerHalfOpenMax <= 0 {
			return fmt.Errorf("CircuitBreakerHalfOpenMax must be positive")
		}
		if c.CircuitBreakerSuccessThreshold <= 0 {
			return fmt.Errorf("CircuitBreakerSuccessThreshold must be positive")
		}
	}

	// Validate retry settings
	if c.RetryEnabled {
		if c.RetryMaxAttempts < 0 {
			return fmt.Errorf("RetryMaxAttempts must be non-negative")
		}
		if c.RetryInitialBackoff <= 0 {
			return fmt.Errorf("RetryInitialBackoff must be positive")
		}
		if c.RetryMaxBackoff <= 0 {
			return fmt.Errorf("RetryMaxBackoff must be positive")
		}
		if c.RetryBackoffFactor <= 0 {
			return fmt.Errorf("RetryBackoffFactor must be positive")
		}
	}

	// Validate timeouts
	if c.ReadTimeout <= 0 {
		return fmt.Errorf("ReadTimeout must be positive")
	}
	if c.WriteTimeout <= 0 {
		return fmt.Errorf("WriteTimeout must be positive")
	}
	if c.IdleTimeout <= 0 {
		return fmt.Errorf("IdleTimeout must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("ShutdownTimeout must be positive")
	}

	// Validate health server timeouts
	if c.HealthServerReadTimeout <= 0 {
		return fmt.Errorf("HealthServerReadTimeout must be positive")
	}
	if c.HealthServerWriteTimeout <= 0 {
		return fmt.Errorf("HealthServerWriteTimeout must be positive")
	}
	if c.HealthServerShutdownTimeout <= 0 {
		return fmt.Errorf("HealthServerShutdownTimeout must be positive")
	}

	// Validate metrics server timeouts
	if c.MetricsServerReadTimeout <= 0 {
		return fmt.Errorf("MetricsServerReadTimeout must be positive")
	}
	if c.MetricsServerWriteTimeout <= 0 {
		return fmt.Errorf("MetricsServerWriteTimeout must be positive")
	}
	if c.MetricsServerShutdownTimeout <= 0 {
		return fmt.Errorf("MetricsServerShutdownTimeout must be positive")
	}

	// Validate probe timeouts
	if c.ReadinessProbeTimeout <= 0 {
		return fmt.Errorf("ReadinessProbeTimeout must be positive")
	}
	if c.LivenessProbeTimeout <= 0 {
		return fmt.Errorf("LivenessProbeTimeout must be positive")
	}

	// Validate backend settings
	if c.MaxIdleConns <= 0 {
		return fmt.Errorf("MaxIdleConns must be positive")
	}
	if c.MaxIdleConnsPerHost <= 0 {
		return fmt.Errorf("MaxIdleConnsPerHost must be positive")
	}
	if c.MaxConnsPerHost <= 0 {
		return fmt.Errorf("MaxConnsPerHost must be positive")
	}

	// Validate TCP settings
	if c.TCPEnabled {
		if err := validatePort(c.TCPPort, "TCPPort"); err != nil {
			return err
		}
		if c.TCPReadTimeout <= 0 {
			return fmt.Errorf("TCPReadTimeout must be positive")
		}
		if c.TCPWriteTimeout <= 0 {
			return fmt.Errorf("TCPWriteTimeout must be positive")
		}
		if c.TCPIdleTimeout <= 0 {
			return fmt.Errorf("TCPIdleTimeout must be positive")
		}
		if c.TCPMaxConnections <= 0 {
			return fmt.Errorf("TCPMaxConnections must be positive")
		}
	}

	// Validate TLS Passthrough settings
	if c.TLSPassthroughEnabled {
		if err := validatePort(c.TLSPassthroughPort, "TLSPassthroughPort"); err != nil {
			return err
		}
	}

	// Validate JWT settings
	if c.JWTEnabled {
		if c.JWKSURL == "" && c.JWTIssuer == "" {
			return fmt.Errorf("either JWKSURL or JWTIssuer is required when JWT is enabled")
		}
		if c.JWKSCacheTTL <= 0 {
			return fmt.Errorf("JWKSCacheTTL must be positive")
		}
		if c.JWTClockSkew < 0 {
			return fmt.Errorf("JWTClockSkew must be non-negative")
		}
	}

	// Validate OAuth2 settings
	if c.OAuth2Enabled {
		if c.OAuth2TokenEndpoint == "" {
			return fmt.Errorf("OAuth2TokenEndpoint is required when OAuth2 is enabled")
		}
		if c.OAuth2ClientID == "" {
			return fmt.Errorf("OAuth2ClientID is required when OAuth2 is enabled")
		}
		if c.OAuth2Timeout <= 0 {
			return fmt.Errorf("OAuth2Timeout must be positive")
		}
	}

	// Validate Security Headers settings
	if c.SecurityHeadersEnabled {
		if c.HSTSEnabled && c.HSTSMaxAge < 0 {
			return fmt.Errorf("HSTSMaxAge must be non-negative")
		}
		validXFrameOptions := map[string]bool{
			"":           true,
			"DENY":       true,
			"SAMEORIGIN": true,
		}
		if !validXFrameOptions[c.XFrameOptions] {
			return fmt.Errorf("invalid XFrameOptions: %s, must be one of: DENY, SAMEORIGIN", c.XFrameOptions)
		}
	}

	// Validate Webhook Certificate settings
	if c.WebhookSelfSignedCert {
		if c.WebhookCertDir == "" {
			return fmt.Errorf("WebhookCertDir is required when self-signed certificates are enabled")
		}
		if c.WebhookCertValidity <= 0 {
			return fmt.Errorf("WebhookCertValidity must be positive")
		}
		if c.WebhookCertRotation <= 0 {
			return fmt.Errorf("WebhookCertRotation must be positive")
		}
		if c.WebhookCertRotation >= c.WebhookCertValidity {
			return fmt.Errorf("WebhookCertRotation must be less than WebhookCertValidity")
		}
		if c.WebhookCertSecretName == "" {
			return fmt.Errorf("WebhookCertSecretName is required when self-signed certificates are enabled")
		}
		if c.WebhookServiceName == "" {
			return fmt.Errorf("WebhookServiceName is required when self-signed certificates are enabled")
		}
		if c.WebhookServiceNamespace == "" {
			return fmt.Errorf("WebhookServiceNamespace is required when self-signed certificates are enabled")
		}
	}

	return nil
}

// validatePort validates that a port number is within valid range.
func validatePort(port int, name string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s must be between 1 and 65535, got %d", name, port)
	}
	return nil
}

// String returns a string representation of the config (without sensitive data).
func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{HTTPPort: %d, GRPCPort: %d, MetricsPort: %d, HealthPort: %d, TLSEnabled: %t, VaultEnabled: %t, LogLevel: %s, TracingEnabled: %t, TCPEnabled: %t, TCPPort: %d, TLSPassthroughEnabled: %t, TLSPassthroughPort: %d}",
		c.HTTPPort, c.GRPCPort, c.MetricsPort, c.HealthPort, c.TLSEnabled, c.VaultEnabled, c.LogLevel, c.TracingEnabled, c.TCPEnabled, c.TCPPort, c.TLSPassthroughEnabled, c.TLSPassthroughPort,
	)
}

// Package config provides configuration management for the API Gateway.
// It supports loading configuration from environment variables and command-line flags,
// with environment variables taking precedence over flags.
package config

import (
	"fmt"
	"time"
)

// Vault authentication methods.
const (
	// VaultAuthMethodKubernetes is the Kubernetes authentication method for Vault.
	VaultAuthMethodKubernetes = "kubernetes"
	// VaultAuthMethodToken is the token authentication method for Vault.
	VaultAuthMethodToken = "token"
	// VaultAuthMethodAppRole is the AppRole authentication method for Vault.
	VaultAuthMethodAppRole = "approle"
)

// Secrets provider types.
const (
	// SecretsProviderKubernetes uses Kubernetes secrets as the secrets provider.
	SecretsProviderKubernetes = "kubernetes"
	// SecretsProviderVault uses HashiCorp Vault as the secrets provider.
	SecretsProviderVault = "vault"
	// SecretsProviderLocal uses local filesystem as the secrets provider.
	SecretsProviderLocal = "local"
	// SecretsProviderEnv uses environment variables as the secrets provider.
	SecretsProviderEnv = "env"
)

// Configuration constants for default values.
const (
	// DefaultVaultRole is the default Vault role name.
	DefaultVaultRole = "avapigw"
	// DefaultVaultAuthMethod is the default Vault authentication method.
	DefaultVaultAuthMethod = VaultAuthMethodKubernetes
	// DefaultServiceName is the default service name for observability.
	DefaultServiceName = "avapigw"
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
	RateLimitEnabled bool `json:"rateLimitEnabled" yaml:"rateLimitEnabled"`
	// RateLimitAlgorithm: token_bucket, sliding_window, fixed_window
	RateLimitAlgorithm string        `json:"rateLimitAlgorithm" yaml:"rateLimitAlgorithm"`
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
	CircuitBreakerSuccessThreshold int           `json:"circuitBreakerSuccessThreshold" yaml:"circuitBreakerSuccessThreshold"` //nolint:lll // long struct tag for JSON/YAML serialization

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
// It assembles defaults from domain-specific helper functions.
func DefaultConfig() *Config {
	cfg := &Config{}
	applyDefaultServerConfig(cfg)
	applyDefaultTLSConfig(cfg)
	applyDefaultVaultConfig(cfg)
	applyDefaultSecretsProviderConfig(cfg)
	applyDefaultObservabilityConfig(cfg)
	applyDefaultRateLimitConfig(cfg)
	applyDefaultResilienceConfig(cfg)
	applyDefaultBackendConfig(cfg)
	applyDefaultHealthConfig(cfg)
	applyDefaultGRPCConfig(cfg)
	applyDefaultTCPConfig(cfg)
	applyDefaultAuthConfig(cfg)
	applyDefaultSecurityConfig(cfg)
	applyDefaultWebhookConfig(cfg)
	return cfg
}

// applyDefaultServerConfig sets default server settings.
func applyDefaultServerConfig(cfg *Config) {
	cfg.HTTPPort = 8080
	cfg.GRPCPort = 9090
	cfg.MetricsPort = 9091
	cfg.HealthPort = 8081
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	cfg.IdleTimeout = 120 * time.Second
	cfg.ShutdownTimeout = 30 * time.Second
}

// applyDefaultTLSConfig sets default TLS settings.
func applyDefaultTLSConfig(cfg *Config) {
	cfg.TLSEnabled = false
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""
	cfg.TLSCAFile = ""
	cfg.TLSPassthroughEnabled = false
	cfg.TLSPassthroughPort = 8444
}

// applyDefaultVaultConfig sets default Vault settings.
func applyDefaultVaultConfig(cfg *Config) {
	cfg.VaultEnabled = false
	cfg.VaultAddress = "http://localhost:8200"
	cfg.VaultNamespace = ""
	cfg.VaultAuthMethod = DefaultVaultAuthMethod
	cfg.VaultRole = DefaultVaultRole
	cfg.VaultMountPath = DefaultVaultAuthMethod
	cfg.VaultSecretMountPoint = "secret"
	cfg.VaultTLSSkipVerify = false
	cfg.VaultCACert = ""
	cfg.VaultClientCert = ""
	cfg.VaultClientKey = ""
	cfg.VaultTimeout = 30 * time.Second
	cfg.VaultMaxRetries = 3
	cfg.VaultRetryWaitMin = 500 * time.Millisecond
	cfg.VaultRetryWaitMax = 5 * time.Second
	cfg.VaultCacheEnabled = true
	cfg.VaultCacheTTL = 5 * time.Minute
	cfg.VaultTokenRenewal = true
	cfg.VaultTokenRenewalTime = 5 * time.Minute
}

// applyDefaultSecretsProviderConfig sets default secrets provider settings.
func applyDefaultSecretsProviderConfig(cfg *Config) {
	cfg.SecretsProvider = ""                      // empty means auto-detect (vault if enabled, otherwise kubernetes)
	cfg.SecretsLocalPath = "/etc/avapigw/secrets" // default path for local secrets
	cfg.SecretsEnvPrefix = "AVAPIGW_SECRET_"      // default prefix for env secrets
}

// applyDefaultObservabilityConfig sets default observability settings (logging, tracing, metrics).
func applyDefaultObservabilityConfig(cfg *Config) {
	// Logging
	cfg.LogLevel = "info"
	cfg.LogFormat = "json"
	cfg.LogOutput = "stdout"
	cfg.AccessLogEnabled = true

	// Tracing
	cfg.TracingEnabled = false
	cfg.TracingExporter = "otlp-grpc"
	cfg.OTLPEndpoint = "localhost:4317"
	cfg.TracingSampleRate = 1.0
	cfg.ServiceName = DefaultServiceName
	cfg.ServiceVersion = "1.0.0"
	cfg.TracingInsecure = true

	// Metrics
	cfg.MetricsEnabled = true
	cfg.MetricsPath = "/metrics"
}

// applyDefaultRateLimitConfig sets default rate limiting settings.
func applyDefaultRateLimitConfig(cfg *Config) {
	cfg.RateLimitEnabled = false
	cfg.RateLimitAlgorithm = "token_bucket"
	cfg.RateLimitRequests = 100
	cfg.RateLimitWindow = time.Minute
	cfg.RateLimitBurst = 10
	cfg.RateLimitStoreType = "memory"
	cfg.RedisAddress = "localhost:6379"
	cfg.RedisPassword = ""
	cfg.RedisDB = 0
}

// applyDefaultResilienceConfig sets default circuit breaker and retry settings.
func applyDefaultResilienceConfig(cfg *Config) {
	// Circuit Breaker
	cfg.CircuitBreakerEnabled = false
	cfg.CircuitBreakerMaxFailures = 5
	cfg.CircuitBreakerTimeout = 30 * time.Second
	cfg.CircuitBreakerHalfOpenMax = 3
	cfg.CircuitBreakerSuccessThreshold = 2

	// Retry
	cfg.RetryEnabled = false
	cfg.RetryMaxAttempts = 3
	cfg.RetryInitialBackoff = 100 * time.Millisecond
	cfg.RetryMaxBackoff = 10 * time.Second
	cfg.RetryBackoffFactor = 2.0
}

// applyDefaultBackendConfig sets default backend connection pool settings.
func applyDefaultBackendConfig(cfg *Config) {
	cfg.MaxIdleConns = 100
	cfg.MaxIdleConnsPerHost = 10
	cfg.MaxConnsPerHost = 100
	cfg.IdleConnTimeout = 90 * time.Second
}

// applyDefaultHealthConfig sets default health check and server timeout settings.
func applyDefaultHealthConfig(cfg *Config) {
	// Health check settings
	cfg.HealthCheckInterval = 10 * time.Second
	cfg.HealthCheckTimeout = 5 * time.Second

	// Health server timeouts - used for the dedicated health check server
	cfg.HealthServerReadTimeout = 5 * time.Second
	cfg.HealthServerWriteTimeout = 5 * time.Second
	cfg.HealthServerShutdownTimeout = 5 * time.Second

	// Metrics server timeouts - used for the Prometheus metrics server
	cfg.MetricsServerReadTimeout = 5 * time.Second
	cfg.MetricsServerWriteTimeout = 10 * time.Second
	cfg.MetricsServerShutdownTimeout = 5 * time.Second

	// Readiness/Liveness probe timeouts - context timeout for health check execution
	cfg.ReadinessProbeTimeout = 5 * time.Second
	cfg.LivenessProbeTimeout = 10 * time.Second
}

// applyDefaultGRPCConfig sets default gRPC server settings.
func applyDefaultGRPCConfig(cfg *Config) {
	cfg.GRPCEnabled = true
	cfg.GRPCMaxRecvMsgSize = 4 * 1024 * 1024 // 4 MB
	cfg.GRPCMaxSendMsgSize = 4 * 1024 * 1024 // 4 MB
	cfg.GRPCMaxConcurrentStreams = 1000
	cfg.GRPCEnableReflection = false
	cfg.GRPCEnableHealthCheck = true
}

// applyDefaultTCPConfig sets default TCP server settings.
func applyDefaultTCPConfig(cfg *Config) {
	cfg.TCPEnabled = false
	cfg.TCPPort = 8443
	cfg.TCPReadTimeout = 30 * time.Second
	cfg.TCPWriteTimeout = 30 * time.Second
	cfg.TCPIdleTimeout = 5 * time.Minute
	cfg.TCPMaxConnections = 10000
}

// applyDefaultAuthConfig sets default authentication settings.
func applyDefaultAuthConfig(cfg *Config) {
	// JWT
	cfg.JWTEnabled = false
	cfg.JWTIssuer = ""
	cfg.JWTAudiences = nil
	cfg.JWKSURL = ""
	cfg.JWKSCacheTTL = time.Hour
	cfg.JWTClockSkew = time.Minute
	cfg.JWTAlgorithms = []string{"RS256", "RS384", "RS512"}
	cfg.JWTTokenHeader = "Authorization"
	cfg.JWTTokenPrefix = "Bearer "
	cfg.JWTTokenCookie = ""
	cfg.JWTTokenQuery = ""

	// API Key
	cfg.APIKeyEnabled = false
	cfg.APIKeyHeader = "X-API-Key"
	cfg.APIKeyQueryParam = "api_key"

	// Basic Auth
	cfg.BasicAuthEnabled = false
	cfg.BasicAuthRealm = "Restricted"

	// OAuth2 Client Credentials
	cfg.OAuth2Enabled = false
	cfg.OAuth2TokenEndpoint = ""
	cfg.OAuth2ClientID = ""
	cfg.OAuth2Scopes = nil
	cfg.OAuth2Timeout = 30 * time.Second

	// Authorization
	cfg.AuthzEnabled = false
	cfg.AuthzDefaultAllow = false
}

// applyDefaultSecurityConfig sets default security header settings.
func applyDefaultSecurityConfig(cfg *Config) {
	cfg.SecurityHeadersEnabled = true
	cfg.HSTSEnabled = true
	cfg.HSTSMaxAge = 31536000 // 1 year
	cfg.HSTSIncludeSubDomains = true
	cfg.HSTSPreload = false
	cfg.CSPPolicy = ""
	cfg.XFrameOptions = "DENY"
	cfg.XContentTypeOptions = "nosniff"
	cfg.ReferrerPolicy = "strict-origin-when-cross-origin"
}

// applyDefaultWebhookConfig sets default webhook certificate settings.
func applyDefaultWebhookConfig(cfg *Config) {
	cfg.WebhookSelfSignedCert = false
	cfg.WebhookCertDir = "/tmp/k8s-webhook-server/serving-certs"
	cfg.WebhookCertValidity = 365 * 24 * time.Hour      // 1 year
	cfg.WebhookCertRotation = 30 * 24 * time.Hour       // 30 days before expiry
	cfg.WebhookCertSecretName = "avapigw-webhook-certs" // NOSONAR this is not real seacret
	cfg.WebhookServiceName = "avapigw-webhook-service"
	cfg.WebhookServiceNamespace = "avapigw-system"
	cfg.WebhookValidatingConfigName = "avapigw-validating-webhook-configuration"
	cfg.WebhookMutatingConfigName = "avapigw-mutating-webhook-configuration"
}

// Validate validates the configuration and returns an error if invalid.
// It delegates to domain-specific validators for each configuration section.
func (c *Config) Validate() error {
	if err := c.validateServerConfig(); err != nil {
		return err
	}
	if err := c.validateTLSConfig(); err != nil {
		return err
	}
	if err := c.validateVaultConfig(); err != nil {
		return err
	}
	if err := c.validateSecretsProviderConfig(); err != nil {
		return err
	}
	if err := c.validateObservabilityConfig(); err != nil {
		return err
	}
	if err := c.validateRateLimitConfig(); err != nil {
		return err
	}
	if err := c.validateResilienceConfig(); err != nil {
		return err
	}
	if err := c.validateBackendConfig(); err != nil {
		return err
	}
	if err := c.validateHealthConfig(); err != nil {
		return err
	}
	if err := c.validateTCPConfig(); err != nil {
		return err
	}
	if err := c.validateAuthConfig(); err != nil {
		return err
	}
	if err := c.validateSecurityConfig(); err != nil {
		return err
	}
	if err := c.validateWebhookConfig(); err != nil {
		return err
	}
	return nil
}

// validateServerConfig validates server-related settings.
func (c *Config) validateServerConfig() error {
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
	return nil
}

// validateTLSConfig validates TLS-related settings.
func (c *Config) validateTLSConfig() error {
	if c.TLSEnabled {
		if c.TLSCertFile == "" {
			return fmt.Errorf("TLSCertFile is required when TLS is enabled")
		}
		if c.TLSKeyFile == "" {
			return fmt.Errorf("TLSKeyFile is required when TLS is enabled")
		}
	}
	if c.TLSPassthroughEnabled {
		if err := validatePort(c.TLSPassthroughPort, "TLSPassthroughPort"); err != nil {
			return err
		}
	}
	return nil
}

// validateVaultConfig validates Vault-related settings.
func (c *Config) validateVaultConfig() error {
	if !c.VaultEnabled {
		return nil
	}
	if c.VaultAddress == "" {
		return fmt.Errorf("VaultAddress is required when Vault is enabled")
	}
	validAuthMethods := map[string]bool{
		VaultAuthMethodKubernetes: true,
		VaultAuthMethodToken:      true,
		VaultAuthMethodAppRole:    true,
	}
	if !validAuthMethods[c.VaultAuthMethod] {
		return fmt.Errorf("invalid VaultAuthMethod: %s, must be one of: kubernetes, token, approle", c.VaultAuthMethod)
	}
	if c.VaultAuthMethod == DefaultVaultAuthMethod && c.VaultRole == "" {
		return fmt.Errorf("VaultRole is required when using Kubernetes auth")
	}
	if c.VaultTimeout <= 0 {
		return fmt.Errorf("VaultTimeout must be positive")
	}
	if c.VaultMaxRetries < 0 {
		return fmt.Errorf("VaultMaxRetries must be non-negative")
	}
	return nil
}

// validateSecretsProviderConfig validates secrets provider settings.
func (c *Config) validateSecretsProviderConfig() error {
	if c.SecretsProvider == "" {
		return nil
	}
	validProviders := map[string]bool{
		SecretsProviderKubernetes: true,
		SecretsProviderVault:      true,
		SecretsProviderLocal:      true,
		SecretsProviderEnv:        true,
	}
	if !validProviders[c.SecretsProvider] {
		return fmt.Errorf(
			"invalid SecretsProvider: %s, must be one of: kubernetes, vault, local, env", c.SecretsProvider)
	}
	if c.SecretsProvider == SecretsProviderVault && !c.VaultEnabled {
		return fmt.Errorf("VaultEnabled must be true when SecretsProvider is vault")
	}
	return nil
}

// validateObservabilityConfig validates observability settings (logging, tracing, metrics).
func (c *Config) validateObservabilityConfig() error {
	if err := c.validateLoggingConfig(); err != nil {
		return err
	}
	if err := c.validateTracingConfig(); err != nil {
		return err
	}
	return nil
}

// validateLoggingConfig validates logging settings.
func (c *Config) validateLoggingConfig() error {
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid LogLevel: %s, must be one of: debug, info, warn, error", c.LogLevel)
	}
	validLogFormats := map[string]bool{
		"json":    true,
		"console": true,
	}
	if !validLogFormats[c.LogFormat] {
		return fmt.Errorf("invalid LogFormat: %s, must be one of: json, console", c.LogFormat)
	}
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
	return nil
}

// validateTracingConfig validates tracing settings.
func (c *Config) validateTracingConfig() error {
	if !c.TracingEnabled {
		return nil
	}
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
	return nil
}

// validateRateLimitConfig validates rate limiting settings.
func (c *Config) validateRateLimitConfig() error {
	if !c.RateLimitEnabled {
		return nil
	}
	validAlgorithms := map[string]bool{
		"token_bucket":   true,
		"sliding_window": true,
		"fixed_window":   true,
	}
	if !validAlgorithms[c.RateLimitAlgorithm] {
		return fmt.Errorf("invalid RateLimitAlgorithm: %s, must be one of: "+
			"token_bucket, sliding_window, fixed_window", c.RateLimitAlgorithm)
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
	return nil
}

// validateResilienceConfig validates circuit breaker and retry settings.
func (c *Config) validateResilienceConfig() error {
	if err := c.validateCircuitBreakerConfig(); err != nil {
		return err
	}
	if err := c.validateRetryConfig(); err != nil {
		return err
	}
	return nil
}

// validateCircuitBreakerConfig validates circuit breaker settings.
func (c *Config) validateCircuitBreakerConfig() error {
	if !c.CircuitBreakerEnabled {
		return nil
	}
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
	return nil
}

// validateRetryConfig validates retry settings.
func (c *Config) validateRetryConfig() error {
	if !c.RetryEnabled {
		return nil
	}
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
	return nil
}

// validateBackendConfig validates backend connection pool settings.
func (c *Config) validateBackendConfig() error {
	if c.MaxIdleConns <= 0 {
		return fmt.Errorf("MaxIdleConns must be positive")
	}
	if c.MaxIdleConnsPerHost <= 0 {
		return fmt.Errorf("MaxIdleConnsPerHost must be positive")
	}
	if c.MaxConnsPerHost <= 0 {
		return fmt.Errorf("MaxConnsPerHost must be positive")
	}
	return nil
}

// validateHealthConfig validates health check and server timeout settings.
func (c *Config) validateHealthConfig() error {
	// Health server timeouts
	if c.HealthServerReadTimeout <= 0 {
		return fmt.Errorf("HealthServerReadTimeout must be positive")
	}
	if c.HealthServerWriteTimeout <= 0 {
		return fmt.Errorf("HealthServerWriteTimeout must be positive")
	}
	if c.HealthServerShutdownTimeout <= 0 {
		return fmt.Errorf("HealthServerShutdownTimeout must be positive")
	}
	// Metrics server timeouts
	if c.MetricsServerReadTimeout <= 0 {
		return fmt.Errorf("MetricsServerReadTimeout must be positive")
	}
	if c.MetricsServerWriteTimeout <= 0 {
		return fmt.Errorf("MetricsServerWriteTimeout must be positive")
	}
	if c.MetricsServerShutdownTimeout <= 0 {
		return fmt.Errorf("MetricsServerShutdownTimeout must be positive")
	}
	// Probe timeouts
	if c.ReadinessProbeTimeout <= 0 {
		return fmt.Errorf("ReadinessProbeTimeout must be positive")
	}
	if c.LivenessProbeTimeout <= 0 {
		return fmt.Errorf("LivenessProbeTimeout must be positive")
	}
	return nil
}

// validateTCPConfig validates TCP server settings.
func (c *Config) validateTCPConfig() error {
	if !c.TCPEnabled {
		return nil
	}
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
	return nil
}

// validateAuthConfig validates authentication settings (JWT, OAuth2).
func (c *Config) validateAuthConfig() error {
	if err := c.validateJWTConfig(); err != nil {
		return err
	}
	if err := c.validateOAuth2Config(); err != nil {
		return err
	}
	return nil
}

// validateJWTConfig validates JWT authentication settings.
func (c *Config) validateJWTConfig() error {
	if !c.JWTEnabled {
		return nil
	}
	if c.JWKSURL == "" && c.JWTIssuer == "" {
		return fmt.Errorf("either JWKSURL or JWTIssuer is required when JWT is enabled")
	}
	if c.JWKSCacheTTL <= 0 {
		return fmt.Errorf("JWKSCacheTTL must be positive")
	}
	if c.JWTClockSkew < 0 {
		return fmt.Errorf("JWTClockSkew must be non-negative")
	}
	return nil
}

// validateOAuth2Config validates OAuth2 authentication settings.
func (c *Config) validateOAuth2Config() error {
	if !c.OAuth2Enabled {
		return nil
	}
	if c.OAuth2TokenEndpoint == "" {
		return fmt.Errorf("OAuth2TokenEndpoint is required when OAuth2 is enabled")
	}
	if c.OAuth2ClientID == "" {
		return fmt.Errorf("OAuth2ClientID is required when OAuth2 is enabled")
	}
	if c.OAuth2Timeout <= 0 {
		return fmt.Errorf("OAuth2Timeout must be positive")
	}
	return nil
}

// validateSecurityConfig validates security header settings.
func (c *Config) validateSecurityConfig() error {
	if !c.SecurityHeadersEnabled {
		return nil
	}
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
	return nil
}

// validateWebhookConfig validates webhook certificate settings.
func (c *Config) validateWebhookConfig() error {
	if !c.WebhookSelfSignedCert {
		return nil
	}
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
		"Config{HTTPPort: %d, GRPCPort: %d, MetricsPort: %d, HealthPort: %d, "+
			"TLSEnabled: %t, VaultEnabled: %t, LogLevel: %s, TracingEnabled: %t, "+
			"TCPEnabled: %t, TCPPort: %d, TLSPassthroughEnabled: %t, TLSPassthroughPort: %d}",
		c.HTTPPort, c.GRPCPort, c.MetricsPort, c.HealthPort,
		c.TLSEnabled, c.VaultEnabled, c.LogLevel, c.TracingEnabled,
		c.TCPEnabled, c.TCPPort, c.TLSPassthroughEnabled, c.TLSPassthroughPort,
	)
}

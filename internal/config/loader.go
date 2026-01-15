package config

import (
	"flag"
	"os"
	"strconv"
	"time"
)

// Loader handles loading configuration from various sources.
type Loader struct {
	config     *Config
	flags      *flag.FlagSet
	configFile string

	// localConfig holds the parsed YAML configuration
	localConfig *LocalConfig
}

// NewLoader creates a new configuration loader.
func NewLoader() *Loader {
	return &Loader{
		config: DefaultConfig(),
		flags:  flag.NewFlagSet("avapigw", flag.ContinueOnError),
	}
}

// Load loads configuration from environment variables and command-line flags.
// Priority: YAML file > Environment variables > Command-line flags > Defaults
func Load() (*Config, error) {
	loader := NewLoader()
	return loader.LoadConfig(os.Args[1:])
}

// LoadWithLocalConfig loads configuration and returns both the Config and LocalConfig.
// This is useful when you need access to the full YAML configuration including
// routes, backends, rate limits, and auth policies.
// Priority: YAML file > Environment variables > Command-line flags > Defaults
func LoadWithLocalConfig() (*Config, *LocalConfig, error) {
	loader := NewLoader()
	cfg, err := loader.LoadConfig(os.Args[1:])
	if err != nil {
		return nil, nil, err
	}
	return cfg, loader.localConfig, nil
}

// LoadConfig loads configuration from the provided arguments.
// Priority: YAML file > Environment variables > Command-line flags > Defaults
func (l *Loader) LoadConfig(args []string) (*Config, error) {
	// Define flags (including --config-file)
	l.defineFlags()

	// Parse flags first to get the config file path
	if err := l.flags.Parse(args); err != nil {
		return nil, err
	}

	// Check for config file from environment variable (ENV has higher priority than flag)
	if v := os.Getenv("AVAPIGW_CONFIG_FILE"); v != "" {
		l.configFile = v
	}

	// Load YAML configuration if specified (highest priority for settings it defines)
	if l.configFile != "" {
		localCfg, err := LoadAndValidateYAMLConfig(l.configFile)
		if err != nil {
			return nil, err
		}
		l.localConfig = localCfg

		// Merge YAML config into base config
		// YAML settings override defaults and flags
		l.config = MergeConfigs(l.config, localCfg)
	}

	// Override with environment variables (ENV has higher priority than YAML for base config)
	l.loadFromEnv()

	// Validate configuration
	if err := l.config.Validate(); err != nil {
		return nil, err
	}

	return l.config, nil
}

// GetLocalConfig returns the parsed LocalConfig from the YAML file.
// Returns nil if no YAML config file was loaded.
func (l *Loader) GetLocalConfig() *LocalConfig {
	return l.localConfig
}

// GetConfigFilePath returns the path to the config file that was loaded.
// Returns empty string if no config file was specified.
func (l *Loader) GetConfigFilePath() string {
	return l.configFile
}

// defineFlags defines all command-line flags.
func (l *Loader) defineFlags() {
	// Config file flag
	l.flags.StringVar(&l.configFile, "config-file", "", "Path to YAML configuration file")

	// Server settings
	l.flags.IntVar(&l.config.HTTPPort, "http-port", l.config.HTTPPort, "HTTP server port")
	l.flags.IntVar(&l.config.GRPCPort, "grpc-port", l.config.GRPCPort, "gRPC server port")
	l.flags.IntVar(&l.config.MetricsPort, "metrics-port", l.config.MetricsPort, "Metrics server port")
	l.flags.IntVar(&l.config.HealthPort, "health-port", l.config.HealthPort, "Health check server port")

	// Server timeouts
	l.flags.DurationVar(&l.config.ReadTimeout, "read-timeout", l.config.ReadTimeout, "HTTP read timeout")
	l.flags.DurationVar(&l.config.WriteTimeout, "write-timeout", l.config.WriteTimeout, "HTTP write timeout")
	l.flags.DurationVar(&l.config.IdleTimeout, "idle-timeout", l.config.IdleTimeout, "HTTP idle timeout")
	l.flags.DurationVar(&l.config.ShutdownTimeout, "shutdown-timeout", l.config.ShutdownTimeout, "Graceful shutdown timeout")

	// TLS settings
	l.flags.BoolVar(&l.config.TLSEnabled, "tls-enabled", l.config.TLSEnabled, "Enable TLS")
	l.flags.StringVar(&l.config.TLSCertFile, "tls-cert-file", l.config.TLSCertFile, "TLS certificate file path")
	l.flags.StringVar(&l.config.TLSKeyFile, "tls-key-file", l.config.TLSKeyFile, "TLS key file path")
	l.flags.StringVar(&l.config.TLSCAFile, "tls-ca-file", l.config.TLSCAFile, "TLS CA certificate file path")

	// Vault settings
	l.flags.BoolVar(&l.config.VaultEnabled, "vault-enabled", l.config.VaultEnabled, "Enable Vault integration")
	l.flags.StringVar(&l.config.VaultAddress, "vault-address", l.config.VaultAddress, "Vault server address")
	l.flags.StringVar(&l.config.VaultNamespace, "vault-namespace", l.config.VaultNamespace, "Vault namespace")
	l.flags.StringVar(&l.config.VaultAuthMethod, "vault-auth-method", l.config.VaultAuthMethod, "Vault auth method (kubernetes, token, approle)")
	l.flags.StringVar(&l.config.VaultRole, "vault-role", l.config.VaultRole, "Vault Kubernetes auth role")
	l.flags.StringVar(&l.config.VaultMountPath, "vault-mount-path", l.config.VaultMountPath, "Vault auth mount path")
	l.flags.StringVar(&l.config.VaultSecretMountPoint, "vault-secret-mount-point", l.config.VaultSecretMountPoint, "Vault KV secrets mount point")
	l.flags.BoolVar(&l.config.VaultTLSSkipVerify, "vault-tls-skip-verify", l.config.VaultTLSSkipVerify, "Skip Vault TLS verification")
	l.flags.StringVar(&l.config.VaultCACert, "vault-ca-cert", l.config.VaultCACert, "Vault CA certificate path")
	l.flags.StringVar(&l.config.VaultClientCert, "vault-client-cert", l.config.VaultClientCert, "Vault client certificate path")
	l.flags.StringVar(&l.config.VaultClientKey, "vault-client-key", l.config.VaultClientKey, "Vault client key path")
	l.flags.DurationVar(&l.config.VaultTimeout, "vault-timeout", l.config.VaultTimeout, "Vault request timeout")
	l.flags.IntVar(&l.config.VaultMaxRetries, "vault-max-retries", l.config.VaultMaxRetries, "Vault max retries")
	l.flags.DurationVar(&l.config.VaultRetryWaitMin, "vault-retry-wait-min", l.config.VaultRetryWaitMin, "Vault minimum retry wait time")
	l.flags.DurationVar(&l.config.VaultRetryWaitMax, "vault-retry-wait-max", l.config.VaultRetryWaitMax, "Vault maximum retry wait time")
	l.flags.BoolVar(&l.config.VaultCacheEnabled, "vault-cache-enabled", l.config.VaultCacheEnabled, "Enable Vault secret caching")
	l.flags.DurationVar(&l.config.VaultCacheTTL, "vault-cache-ttl", l.config.VaultCacheTTL, "Vault cache TTL")
	l.flags.BoolVar(&l.config.VaultTokenRenewal, "vault-token-renewal", l.config.VaultTokenRenewal, "Enable Vault token renewal")
	l.flags.DurationVar(&l.config.VaultTokenRenewalTime, "vault-token-renewal-time", l.config.VaultTokenRenewalTime, "Vault token renewal interval")

	// Secrets Provider settings
	l.flags.StringVar(&l.config.SecretsProvider, "secrets-provider", l.config.SecretsProvider, "Secrets provider (kubernetes, vault, local, env)")
	l.flags.StringVar(&l.config.SecretsLocalPath, "secrets-local-path", l.config.SecretsLocalPath, "Base path for local secrets provider")
	l.flags.StringVar(&l.config.SecretsEnvPrefix, "secrets-env-prefix", l.config.SecretsEnvPrefix, "Prefix for environment variable secrets")

	// Observability - Logging
	l.flags.StringVar(&l.config.LogLevel, "log-level", l.config.LogLevel, "Log level (debug, info, warn, error)")
	l.flags.StringVar(&l.config.LogFormat, "log-format", l.config.LogFormat, "Log format (json, console)")
	l.flags.StringVar(&l.config.LogOutput, "log-output", l.config.LogOutput, "Log output (stdout, stderr, or file path)")
	l.flags.BoolVar(&l.config.AccessLogEnabled, "access-log-enabled", l.config.AccessLogEnabled, "Enable access logging")

	// Observability - Tracing
	l.flags.BoolVar(&l.config.TracingEnabled, "tracing-enabled", l.config.TracingEnabled, "Enable OpenTelemetry tracing")
	l.flags.StringVar(&l.config.TracingExporter, "tracing-exporter", l.config.TracingExporter, "Tracing exporter (otlp-grpc, otlp-http)")
	l.flags.StringVar(&l.config.OTLPEndpoint, "otlp-endpoint", l.config.OTLPEndpoint, "OTLP exporter endpoint")
	l.flags.Float64Var(&l.config.TracingSampleRate, "tracing-sample-rate", l.config.TracingSampleRate, "Tracing sample rate (0.0 to 1.0)")
	l.flags.StringVar(&l.config.ServiceName, "service-name", l.config.ServiceName, "Service name for tracing")
	l.flags.StringVar(&l.config.ServiceVersion, "service-version", l.config.ServiceVersion, "Service version for tracing")
	l.flags.BoolVar(&l.config.TracingInsecure, "tracing-insecure", l.config.TracingInsecure, "Use insecure connection for tracing")

	// Observability - Metrics
	l.flags.BoolVar(&l.config.MetricsEnabled, "metrics-enabled", l.config.MetricsEnabled, "Enable Prometheus metrics")
	l.flags.StringVar(&l.config.MetricsPath, "metrics-path", l.config.MetricsPath, "Metrics endpoint path")

	// Rate limiting
	l.flags.BoolVar(&l.config.RateLimitEnabled, "rate-limit-enabled", l.config.RateLimitEnabled, "Enable rate limiting")
	l.flags.StringVar(&l.config.RateLimitAlgorithm, "rate-limit-algorithm", l.config.RateLimitAlgorithm, "Rate limit algorithm (token_bucket, sliding_window, fixed_window)")
	l.flags.IntVar(&l.config.RateLimitRequests, "rate-limit-requests", l.config.RateLimitRequests, "Rate limit requests per window")
	l.flags.DurationVar(&l.config.RateLimitWindow, "rate-limit-window", l.config.RateLimitWindow, "Rate limit window duration")
	l.flags.IntVar(&l.config.RateLimitBurst, "rate-limit-burst", l.config.RateLimitBurst, "Rate limit burst size")
	l.flags.StringVar(&l.config.RateLimitStoreType, "rate-limit-store-type", l.config.RateLimitStoreType, "Rate limit store type (memory, redis)")
	l.flags.StringVar(&l.config.RedisAddress, "redis-address", l.config.RedisAddress, "Redis server address")
	l.flags.StringVar(&l.config.RedisPassword, "redis-password", l.config.RedisPassword, "Redis password")
	l.flags.IntVar(&l.config.RedisDB, "redis-db", l.config.RedisDB, "Redis database number")

	// Circuit Breaker
	l.flags.BoolVar(&l.config.CircuitBreakerEnabled, "circuit-breaker-enabled", l.config.CircuitBreakerEnabled, "Enable circuit breaker")
	l.flags.IntVar(&l.config.CircuitBreakerMaxFailures, "circuit-breaker-max-failures", l.config.CircuitBreakerMaxFailures, "Circuit breaker max failures before opening")
	l.flags.DurationVar(&l.config.CircuitBreakerTimeout, "circuit-breaker-timeout", l.config.CircuitBreakerTimeout, "Circuit breaker timeout in open state")
	l.flags.IntVar(&l.config.CircuitBreakerHalfOpenMax, "circuit-breaker-half-open-max", l.config.CircuitBreakerHalfOpenMax, "Circuit breaker max requests in half-open state")
	l.flags.IntVar(&l.config.CircuitBreakerSuccessThreshold, "circuit-breaker-success-threshold", l.config.CircuitBreakerSuccessThreshold, "Circuit breaker successes needed to close")

	// Retry
	l.flags.BoolVar(&l.config.RetryEnabled, "retry-enabled", l.config.RetryEnabled, "Enable retry")
	l.flags.IntVar(&l.config.RetryMaxAttempts, "retry-max-attempts", l.config.RetryMaxAttempts, "Retry max attempts")
	l.flags.DurationVar(&l.config.RetryInitialBackoff, "retry-initial-backoff", l.config.RetryInitialBackoff, "Retry initial backoff duration")
	l.flags.DurationVar(&l.config.RetryMaxBackoff, "retry-max-backoff", l.config.RetryMaxBackoff, "Retry max backoff duration")
	l.flags.Float64Var(&l.config.RetryBackoffFactor, "retry-backoff-factor", l.config.RetryBackoffFactor, "Retry backoff factor")

	// Backend settings
	l.flags.IntVar(&l.config.MaxIdleConns, "max-idle-conns", l.config.MaxIdleConns, "Maximum idle connections")
	l.flags.IntVar(&l.config.MaxIdleConnsPerHost, "max-idle-conns-per-host", l.config.MaxIdleConnsPerHost, "Maximum idle connections per host")
	l.flags.IntVar(&l.config.MaxConnsPerHost, "max-conns-per-host", l.config.MaxConnsPerHost, "Maximum connections per host")
	l.flags.DurationVar(&l.config.IdleConnTimeout, "idle-conn-timeout", l.config.IdleConnTimeout, "Idle connection timeout")

	// Health check settings
	l.flags.DurationVar(&l.config.HealthCheckInterval, "health-check-interval", l.config.HealthCheckInterval, "Health check interval")
	l.flags.DurationVar(&l.config.HealthCheckTimeout, "health-check-timeout", l.config.HealthCheckTimeout, "Health check timeout")

	// Health server timeouts
	l.flags.DurationVar(&l.config.HealthServerReadTimeout, "health-server-read-timeout", l.config.HealthServerReadTimeout, "Health server read timeout")
	l.flags.DurationVar(&l.config.HealthServerWriteTimeout, "health-server-write-timeout", l.config.HealthServerWriteTimeout, "Health server write timeout")
	l.flags.DurationVar(&l.config.HealthServerShutdownTimeout, "health-server-shutdown-timeout", l.config.HealthServerShutdownTimeout, "Health server shutdown timeout")

	// Metrics server timeouts
	l.flags.DurationVar(&l.config.MetricsServerReadTimeout, "metrics-server-read-timeout", l.config.MetricsServerReadTimeout, "Metrics server read timeout")
	l.flags.DurationVar(&l.config.MetricsServerWriteTimeout, "metrics-server-write-timeout", l.config.MetricsServerWriteTimeout, "Metrics server write timeout")
	l.flags.DurationVar(&l.config.MetricsServerShutdownTimeout, "metrics-server-shutdown-timeout", l.config.MetricsServerShutdownTimeout, "Metrics server shutdown timeout")

	// Probe timeouts
	l.flags.DurationVar(&l.config.ReadinessProbeTimeout, "readiness-probe-timeout", l.config.ReadinessProbeTimeout, "Readiness probe timeout")
	l.flags.DurationVar(&l.config.LivenessProbeTimeout, "liveness-probe-timeout", l.config.LivenessProbeTimeout, "Liveness probe timeout")

	// gRPC settings
	l.flags.BoolVar(&l.config.GRPCEnabled, "grpc-enabled", l.config.GRPCEnabled, "Enable gRPC server")
	l.flags.IntVar(&l.config.GRPCMaxRecvMsgSize, "grpc-max-recv-msg-size", l.config.GRPCMaxRecvMsgSize, "gRPC maximum receive message size")
	l.flags.IntVar(&l.config.GRPCMaxSendMsgSize, "grpc-max-send-msg-size", l.config.GRPCMaxSendMsgSize, "gRPC maximum send message size")
	l.flags.IntVar(&l.config.GRPCMaxConcurrentStreams, "grpc-max-concurrent-streams", l.config.GRPCMaxConcurrentStreams, "gRPC maximum concurrent streams")
	l.flags.BoolVar(&l.config.GRPCEnableReflection, "grpc-enable-reflection", l.config.GRPCEnableReflection, "Enable gRPC reflection")
	l.flags.BoolVar(&l.config.GRPCEnableHealthCheck, "grpc-enable-health-check", l.config.GRPCEnableHealthCheck, "Enable gRPC health check service")

	// TCP settings
	l.flags.BoolVar(&l.config.TCPEnabled, "tcp-enabled", l.config.TCPEnabled, "Enable TCP server")
	l.flags.IntVar(&l.config.TCPPort, "tcp-port", l.config.TCPPort, "TCP server port")
	l.flags.DurationVar(&l.config.TCPReadTimeout, "tcp-read-timeout", l.config.TCPReadTimeout, "TCP read timeout")
	l.flags.DurationVar(&l.config.TCPWriteTimeout, "tcp-write-timeout", l.config.TCPWriteTimeout, "TCP write timeout")
	l.flags.DurationVar(&l.config.TCPIdleTimeout, "tcp-idle-timeout", l.config.TCPIdleTimeout, "TCP idle timeout")
	l.flags.IntVar(&l.config.TCPMaxConnections, "tcp-max-connections", l.config.TCPMaxConnections, "TCP maximum connections")

	// TLS Passthrough settings
	l.flags.BoolVar(&l.config.TLSPassthroughEnabled, "tls-passthrough-enabled", l.config.TLSPassthroughEnabled, "Enable TLS passthrough server")
	l.flags.IntVar(&l.config.TLSPassthroughPort, "tls-passthrough-port", l.config.TLSPassthroughPort, "TLS passthrough server port")

	// Webhook Certificate settings
	l.flags.BoolVar(&l.config.WebhookSelfSignedCert, "webhook-self-signed-cert", l.config.WebhookSelfSignedCert, "Enable self-signed certificate generation for webhooks")
	l.flags.StringVar(&l.config.WebhookCertDir, "webhook-cert-dir", l.config.WebhookCertDir, "Directory to store webhook certificates")
	l.flags.DurationVar(&l.config.WebhookCertValidity, "webhook-cert-validity", l.config.WebhookCertValidity, "Webhook certificate validity period")
	l.flags.DurationVar(&l.config.WebhookCertRotation, "webhook-cert-rotation", l.config.WebhookCertRotation, "Time before expiry to rotate webhook certificates")
	l.flags.StringVar(&l.config.WebhookCertSecretName, "webhook-cert-secret-name", l.config.WebhookCertSecretName, "Name of the Kubernetes secret for webhook certificates")
	l.flags.StringVar(&l.config.WebhookServiceName, "webhook-service-name", l.config.WebhookServiceName, "Name of the webhook service")
	l.flags.StringVar(&l.config.WebhookServiceNamespace, "webhook-service-namespace", l.config.WebhookServiceNamespace, "Namespace of the webhook service")
	l.flags.StringVar(&l.config.WebhookValidatingConfigName, "webhook-validating-config-name", l.config.WebhookValidatingConfigName, "Name of the ValidatingWebhookConfiguration")
	l.flags.StringVar(&l.config.WebhookMutatingConfigName, "webhook-mutating-config-name", l.config.WebhookMutatingConfigName, "Name of the MutatingWebhookConfiguration")
}

// loadFromEnv loads configuration from environment variables.
// Environment variables take precedence over flags.
func (l *Loader) loadFromEnv() {
	// Server settings
	if v := os.Getenv("AVAPIGW_HTTP_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			l.config.HTTPPort = port
		}
	}
	if v := os.Getenv("AVAPIGW_GRPC_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			l.config.GRPCPort = port
		}
	}
	if v := os.Getenv("AVAPIGW_METRICS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			l.config.MetricsPort = port
		}
	}
	if v := os.Getenv("AVAPIGW_HEALTH_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			l.config.HealthPort = port
		}
	}

	// Server timeouts
	if v := os.Getenv("AVAPIGW_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.ReadTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.WriteTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.IdleTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.ShutdownTimeout = d
		}
	}

	// TLS settings
	if v := os.Getenv("AVAPIGW_TLS_ENABLED"); v != "" {
		l.config.TLSEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_TLS_CERT_FILE"); v != "" {
		l.config.TLSCertFile = v
	}
	if v := os.Getenv("AVAPIGW_TLS_KEY_FILE"); v != "" {
		l.config.TLSKeyFile = v
	}
	if v := os.Getenv("AVAPIGW_TLS_CA_FILE"); v != "" {
		l.config.TLSCAFile = v
	}

	// Vault settings
	if v := os.Getenv("AVAPIGW_VAULT_ENABLED"); v != "" {
		l.config.VaultEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_VAULT_ADDRESS"); v != "" {
		l.config.VaultAddress = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_NAMESPACE"); v != "" {
		l.config.VaultNamespace = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_AUTH_METHOD"); v != "" {
		l.config.VaultAuthMethod = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_ROLE"); v != "" {
		l.config.VaultRole = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_MOUNT_PATH"); v != "" {
		l.config.VaultMountPath = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_SECRET_MOUNT_POINT"); v != "" {
		l.config.VaultSecretMountPoint = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_TLS_SKIP_VERIFY"); v != "" {
		l.config.VaultTLSSkipVerify = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_VAULT_CA_CERT"); v != "" {
		l.config.VaultCACert = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_CLIENT_CERT"); v != "" {
		l.config.VaultClientCert = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_CLIENT_KEY"); v != "" {
		l.config.VaultClientKey = v
	}
	if v := os.Getenv("AVAPIGW_VAULT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.VaultTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_VAULT_MAX_RETRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.VaultMaxRetries = n
		}
	}
	if v := os.Getenv("AVAPIGW_VAULT_RETRY_WAIT_MIN"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.VaultRetryWaitMin = d
		}
	}
	if v := os.Getenv("AVAPIGW_VAULT_RETRY_WAIT_MAX"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.VaultRetryWaitMax = d
		}
	}
	if v := os.Getenv("AVAPIGW_VAULT_CACHE_ENABLED"); v != "" {
		l.config.VaultCacheEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_VAULT_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.VaultCacheTTL = d
		}
	}
	if v := os.Getenv("AVAPIGW_VAULT_TOKEN_RENEWAL"); v != "" {
		l.config.VaultTokenRenewal = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_VAULT_TOKEN_RENEWAL_TIME"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.VaultTokenRenewalTime = d
		}
	}

	// Secrets Provider settings
	if v := os.Getenv("AVAPIGW_SECRETS_PROVIDER"); v != "" {
		l.config.SecretsProvider = v
	}
	if v := os.Getenv("AVAPIGW_SECRETS_LOCAL_PATH"); v != "" {
		l.config.SecretsLocalPath = v
	}
	if v := os.Getenv("AVAPIGW_SECRETS_ENV_PREFIX"); v != "" {
		l.config.SecretsEnvPrefix = v
	}

	// Observability - Logging
	if v := os.Getenv("AVAPIGW_LOG_LEVEL"); v != "" {
		l.config.LogLevel = v
	}
	if v := os.Getenv("AVAPIGW_LOG_FORMAT"); v != "" {
		l.config.LogFormat = v
	}
	if v := os.Getenv("AVAPIGW_LOG_OUTPUT"); v != "" {
		l.config.LogOutput = v
	}
	if v := os.Getenv("AVAPIGW_ACCESS_LOG_ENABLED"); v != "" {
		l.config.AccessLogEnabled = parseBool(v)
	}

	// Observability - Tracing
	if v := os.Getenv("AVAPIGW_TRACING_ENABLED"); v != "" {
		l.config.TracingEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_TRACING_EXPORTER"); v != "" {
		l.config.TracingExporter = v
	}
	if v := os.Getenv("AVAPIGW_OTLP_ENDPOINT"); v != "" {
		l.config.OTLPEndpoint = v
	}
	if v := os.Getenv("AVAPIGW_TRACING_SAMPLE_RATE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			l.config.TracingSampleRate = f
		}
	}
	if v := os.Getenv("AVAPIGW_SERVICE_NAME"); v != "" {
		l.config.ServiceName = v
	}
	if v := os.Getenv("AVAPIGW_SERVICE_VERSION"); v != "" {
		l.config.ServiceVersion = v
	}
	if v := os.Getenv("AVAPIGW_TRACING_INSECURE"); v != "" {
		l.config.TracingInsecure = parseBool(v)
	}

	// Observability - Metrics
	if v := os.Getenv("AVAPIGW_METRICS_ENABLED"); v != "" {
		l.config.MetricsEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_METRICS_PATH"); v != "" {
		l.config.MetricsPath = v
	}

	// Rate limiting
	if v := os.Getenv("AVAPIGW_RATE_LIMIT_ENABLED"); v != "" {
		l.config.RateLimitEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_RATE_LIMIT_ALGORITHM"); v != "" {
		l.config.RateLimitAlgorithm = v
	}
	if v := os.Getenv("AVAPIGW_RATE_LIMIT_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.RateLimitRequests = n
		}
	}
	if v := os.Getenv("AVAPIGW_RATE_LIMIT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.RateLimitWindow = d
		}
	}
	if v := os.Getenv("AVAPIGW_RATE_LIMIT_BURST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.RateLimitBurst = n
		}
	}
	if v := os.Getenv("AVAPIGW_RATE_LIMIT_STORE_TYPE"); v != "" {
		l.config.RateLimitStoreType = v
	}
	if v := os.Getenv("AVAPIGW_REDIS_ADDRESS"); v != "" {
		l.config.RedisAddress = v
	}
	if v := os.Getenv("AVAPIGW_REDIS_PASSWORD"); v != "" {
		l.config.RedisPassword = v
	}
	if v := os.Getenv("AVAPIGW_REDIS_DB"); v != "" {
		if db, err := strconv.Atoi(v); err == nil {
			l.config.RedisDB = db
		}
	}

	// Circuit Breaker
	if v := os.Getenv("AVAPIGW_CIRCUIT_BREAKER_ENABLED"); v != "" {
		l.config.CircuitBreakerEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_CIRCUIT_BREAKER_MAX_FAILURES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.CircuitBreakerMaxFailures = n
		}
	}
	if v := os.Getenv("AVAPIGW_CIRCUIT_BREAKER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.CircuitBreakerTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_CIRCUIT_BREAKER_HALF_OPEN_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.CircuitBreakerHalfOpenMax = n
		}
	}
	if v := os.Getenv("AVAPIGW_CIRCUIT_BREAKER_SUCCESS_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.CircuitBreakerSuccessThreshold = n
		}
	}

	// Retry
	if v := os.Getenv("AVAPIGW_RETRY_ENABLED"); v != "" {
		l.config.RetryEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_RETRY_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.RetryMaxAttempts = n
		}
	}
	if v := os.Getenv("AVAPIGW_RETRY_INITIAL_BACKOFF"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.RetryInitialBackoff = d
		}
	}
	if v := os.Getenv("AVAPIGW_RETRY_MAX_BACKOFF"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.RetryMaxBackoff = d
		}
	}
	if v := os.Getenv("AVAPIGW_RETRY_BACKOFF_FACTOR"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			l.config.RetryBackoffFactor = f
		}
	}

	// Backend settings
	if v := os.Getenv("AVAPIGW_MAX_IDLE_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.MaxIdleConns = n
		}
	}
	if v := os.Getenv("AVAPIGW_MAX_IDLE_CONNS_PER_HOST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.MaxIdleConnsPerHost = n
		}
	}
	if v := os.Getenv("AVAPIGW_MAX_CONNS_PER_HOST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.MaxConnsPerHost = n
		}
	}
	if v := os.Getenv("AVAPIGW_IDLE_CONN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.IdleConnTimeout = d
		}
	}

	// Health check settings
	if v := os.Getenv("AVAPIGW_HEALTH_CHECK_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.HealthCheckInterval = d
		}
	}
	if v := os.Getenv("AVAPIGW_HEALTH_CHECK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.HealthCheckTimeout = d
		}
	}

	// Health server timeouts
	if v := os.Getenv("AVAPIGW_HEALTH_SERVER_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.HealthServerReadTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_HEALTH_SERVER_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.HealthServerWriteTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_HEALTH_SERVER_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.HealthServerShutdownTimeout = d
		}
	}

	// Metrics server timeouts
	if v := os.Getenv("AVAPIGW_METRICS_SERVER_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.MetricsServerReadTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_METRICS_SERVER_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.MetricsServerWriteTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_METRICS_SERVER_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.MetricsServerShutdownTimeout = d
		}
	}

	// Probe timeouts
	if v := os.Getenv("AVAPIGW_READINESS_PROBE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.ReadinessProbeTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_LIVENESS_PROBE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.LivenessProbeTimeout = d
		}
	}

	// gRPC settings
	if v := os.Getenv("AVAPIGW_GRPC_ENABLED"); v != "" {
		l.config.GRPCEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_GRPC_MAX_RECV_MSG_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.GRPCMaxRecvMsgSize = n
		}
	}
	if v := os.Getenv("AVAPIGW_GRPC_MAX_SEND_MSG_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.GRPCMaxSendMsgSize = n
		}
	}
	if v := os.Getenv("AVAPIGW_GRPC_MAX_CONCURRENT_STREAMS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.GRPCMaxConcurrentStreams = n
		}
	}
	if v := os.Getenv("AVAPIGW_GRPC_ENABLE_REFLECTION"); v != "" {
		l.config.GRPCEnableReflection = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_GRPC_ENABLE_HEALTH_CHECK"); v != "" {
		l.config.GRPCEnableHealthCheck = parseBool(v)
	}

	// TCP settings
	if v := os.Getenv("AVAPIGW_TCP_ENABLED"); v != "" {
		l.config.TCPEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_TCP_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			l.config.TCPPort = port
		}
	}
	if v := os.Getenv("AVAPIGW_TCP_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.TCPReadTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_TCP_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.TCPWriteTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_TCP_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.TCPIdleTimeout = d
		}
	}
	if v := os.Getenv("AVAPIGW_TCP_MAX_CONNECTIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.config.TCPMaxConnections = n
		}
	}

	// TLS Passthrough settings
	if v := os.Getenv("AVAPIGW_TLS_PASSTHROUGH_ENABLED"); v != "" {
		l.config.TLSPassthroughEnabled = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_TLS_PASSTHROUGH_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			l.config.TLSPassthroughPort = port
		}
	}

	// Webhook Certificate settings
	if v := os.Getenv("AVAPIGW_WEBHOOK_SELF_SIGNED_CERT"); v != "" {
		l.config.WebhookSelfSignedCert = parseBool(v)
	}
	if v := os.Getenv("AVAPIGW_WEBHOOK_CERT_DIR"); v != "" {
		l.config.WebhookCertDir = v
	}
	if v := os.Getenv("AVAPIGW_WEBHOOK_CERT_VALIDITY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.WebhookCertValidity = d
		}
	}
	if v := os.Getenv("AVAPIGW_WEBHOOK_CERT_ROTATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			l.config.WebhookCertRotation = d
		}
	}
	if v := os.Getenv("AVAPIGW_WEBHOOK_CERT_SECRET_NAME"); v != "" {
		l.config.WebhookCertSecretName = v
	}
	if v := os.Getenv("AVAPIGW_WEBHOOK_SERVICE_NAME"); v != "" {
		l.config.WebhookServiceName = v
	}
	if v := os.Getenv("AVAPIGW_WEBHOOK_SERVICE_NAMESPACE"); v != "" {
		l.config.WebhookServiceNamespace = v
	}
	if v := os.Getenv("AVAPIGW_WEBHOOK_VALIDATING_CONFIG_NAME"); v != "" {
		l.config.WebhookValidatingConfigName = v
	}
	if v := os.Getenv("AVAPIGW_WEBHOOK_MUTATING_CONFIG_NAME"); v != "" {
		l.config.WebhookMutatingConfigName = v
	}
}

// parseBool parses a string to boolean.
func parseBool(s string) bool {
	switch s {
	case "true", "True", "TRUE", "1", "yes", "Yes", "YES":
		return true
	default:
		return false
	}
}

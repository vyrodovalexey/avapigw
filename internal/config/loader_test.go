package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	t.Parallel()

	loader := NewLoader()

	assert.NotNil(t, loader)
	assert.NotNil(t, loader.config)
	assert.NotNil(t, loader.flags)
}

func TestLoader_LoadConfig_DefaultValues(t *testing.T) {
	t.Parallel()

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{})

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, 8080, cfg.HTTPPort)
	assert.Equal(t, 9090, cfg.GRPCPort)
	assert.Equal(t, 9091, cfg.MetricsPort)
	assert.Equal(t, 8081, cfg.HealthPort)
}

func TestLoader_LoadConfig_FlagParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		validate func(*testing.T, *Config)
	}{
		{
			name: "HTTP port flag",
			args: []string{"-http-port", "9000"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9000, cfg.HTTPPort)
			},
		},
		{
			name: "gRPC port flag",
			args: []string{"-grpc-port", "9100"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9100, cfg.GRPCPort)
			},
		},
		{
			name: "Metrics port flag",
			args: []string{"-metrics-port", "9200"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9200, cfg.MetricsPort)
			},
		},
		{
			name: "Health port flag",
			args: []string{"-health-port", "9300"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9300, cfg.HealthPort)
			},
		},
		{
			name: "Read timeout flag",
			args: []string{"-read-timeout", "60s"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 60*time.Second, cfg.ReadTimeout)
			},
		},
		{
			name: "Write timeout flag",
			args: []string{"-write-timeout", "45s"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 45*time.Second, cfg.WriteTimeout)
			},
		},
		{
			name: "Idle timeout flag",
			args: []string{"-idle-timeout", "180s"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 180*time.Second, cfg.IdleTimeout)
			},
		},
		{
			name: "Shutdown timeout flag",
			args: []string{"-shutdown-timeout", "15s"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 15*time.Second, cfg.ShutdownTimeout)
			},
		},
		{
			name: "TLS enabled flag",
			args: []string{"-tls-enabled", "-tls-cert-file", "/path/to/cert", "-tls-key-file", "/path/to/key"},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TLSEnabled)
				assert.Equal(t, "/path/to/cert", cfg.TLSCertFile)
				assert.Equal(t, "/path/to/key", cfg.TLSKeyFile)
			},
		},
		{
			name: "Log level flag",
			args: []string{"-log-level", "debug"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "debug", cfg.LogLevel)
			},
		},
		{
			name: "Log format flag",
			args: []string{"-log-format", "console"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "console", cfg.LogFormat)
			},
		},
		{
			name: "Tracing enabled flag",
			args: []string{"-tracing-enabled", "-otlp-endpoint", "localhost:4317"},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TracingEnabled)
				assert.Equal(t, "localhost:4317", cfg.OTLPEndpoint)
			},
		},
		{
			name: "Tracing sample rate flag",
			args: []string{"-tracing-sample-rate", "0.5"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 0.5, cfg.TracingSampleRate)
			},
		},
		{
			name: "Rate limit enabled flag",
			args: []string{"-rate-limit-enabled", "-rate-limit-requests", "200", "-rate-limit-window", "2m"},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.RateLimitEnabled)
				assert.Equal(t, 200, cfg.RateLimitRequests)
				assert.Equal(t, 2*time.Minute, cfg.RateLimitWindow)
			},
		},
		{
			name: "Circuit breaker enabled flag",
			args: []string{"-circuit-breaker-enabled", "-circuit-breaker-max-failures", "10"},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.CircuitBreakerEnabled)
				assert.Equal(t, 10, cfg.CircuitBreakerMaxFailures)
			},
		},
		{
			name: "Retry enabled flag",
			args: []string{"-retry-enabled", "-retry-max-attempts", "5"},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.RetryEnabled)
				assert.Equal(t, 5, cfg.RetryMaxAttempts)
			},
		},
		{
			name: "gRPC settings flags",
			args: []string{"-grpc-enabled", "-grpc-max-recv-msg-size", "8388608", "-grpc-max-send-msg-size", "8388608"},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.GRPCEnabled)
				assert.Equal(t, 8388608, cfg.GRPCMaxRecvMsgSize)
				assert.Equal(t, 8388608, cfg.GRPCMaxSendMsgSize)
			},
		},
		{
			name: "TCP settings flags",
			args: []string{"-tcp-enabled", "-tcp-port", "9443", "-tcp-max-connections", "5000"},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TCPEnabled)
				assert.Equal(t, 9443, cfg.TCPPort)
				assert.Equal(t, 5000, cfg.TCPMaxConnections)
			},
		},
		{
			name: "TLS passthrough flags",
			args: []string{"-tls-passthrough-enabled", "-tls-passthrough-port", "9444"},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TLSPassthroughEnabled)
				assert.Equal(t, 9444, cfg.TLSPassthroughPort)
			},
		},
		{
			name: "Multiple flags",
			args: []string{
				"-http-port", "8000",
				"-grpc-port", "9000",
				"-log-level", "warn",
				"-metrics-enabled",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 8000, cfg.HTTPPort)
				assert.Equal(t, 9000, cfg.GRPCPort)
				assert.Equal(t, "warn", cfg.LogLevel)
				assert.True(t, cfg.MetricsEnabled)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			loader := NewLoader()
			cfg, err := loader.LoadConfig(tt.args)
			require.NoError(t, err)
			tt.validate(t, cfg)
		})
	}
}

func TestLoader_LoadConfig_InvalidFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "Unknown flag",
			args: []string{"-unknown-flag", "value"},
		},
		{
			name: "Invalid port value",
			args: []string{"-http-port", "not-a-number"},
		},
		{
			name: "Invalid duration value",
			args: []string{"-read-timeout", "not-a-duration"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			loader := NewLoader()
			_, err := loader.LoadConfig(tt.args)
			assert.Error(t, err)
		})
	}
}

func TestLoader_LoadConfig_ValidationError(t *testing.T) {
	t.Parallel()

	loader := NewLoader()
	// Set an invalid port that will fail validation
	_, err := loader.LoadConfig([]string{"-http-port", "0"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPPort must be between 1 and 65535")
}

func TestLoader_LoadFromEnv(t *testing.T) {
	// Note: These tests modify environment variables, so they cannot run in parallel

	tests := []struct {
		name     string
		envVars  map[string]string
		validate func(*testing.T, *Config)
	}{
		{
			name: "HTTP port from env",
			envVars: map[string]string{
				"AVAPIGW_HTTP_PORT": "9000",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9000, cfg.HTTPPort)
			},
		},
		{
			name: "gRPC port from env",
			envVars: map[string]string{
				"AVAPIGW_GRPC_PORT": "9100",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9100, cfg.GRPCPort)
			},
		},
		{
			name: "Metrics port from env",
			envVars: map[string]string{
				"AVAPIGW_METRICS_PORT": "9200",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9200, cfg.MetricsPort)
			},
		},
		{
			name: "Health port from env",
			envVars: map[string]string{
				"AVAPIGW_HEALTH_PORT": "9300",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 9300, cfg.HealthPort)
			},
		},
		{
			name: "Read timeout from env",
			envVars: map[string]string{
				"AVAPIGW_READ_TIMEOUT": "60s",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 60*time.Second, cfg.ReadTimeout)
			},
		},
		{
			name: "Write timeout from env",
			envVars: map[string]string{
				"AVAPIGW_WRITE_TIMEOUT": "45s",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 45*time.Second, cfg.WriteTimeout)
			},
		},
		{
			name: "TLS enabled from env",
			envVars: map[string]string{
				"AVAPIGW_TLS_ENABLED":   "true",
				"AVAPIGW_TLS_CERT_FILE": "/path/to/cert",
				"AVAPIGW_TLS_KEY_FILE":  "/path/to/key",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TLSEnabled)
				assert.Equal(t, "/path/to/cert", cfg.TLSCertFile)
				assert.Equal(t, "/path/to/key", cfg.TLSKeyFile)
			},
		},
		{
			name: "Vault settings from env",
			envVars: map[string]string{
				"AVAPIGW_VAULT_ENABLED":     "true",
				"AVAPIGW_VAULT_ADDRESS":     "https://vault.example.com:8200",
				"AVAPIGW_VAULT_AUTH_METHOD": "token",
				"AVAPIGW_VAULT_NAMESPACE":   "my-namespace",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.VaultEnabled)
				assert.Equal(t, "https://vault.example.com:8200", cfg.VaultAddress)
				assert.Equal(t, "token", cfg.VaultAuthMethod)
				assert.Equal(t, "my-namespace", cfg.VaultNamespace)
			},
		},
		{
			name: "Log settings from env",
			envVars: map[string]string{
				"AVAPIGW_LOG_LEVEL":          "debug",
				"AVAPIGW_LOG_FORMAT":         "console",
				"AVAPIGW_LOG_OUTPUT":         "stderr",
				"AVAPIGW_ACCESS_LOG_ENABLED": "false",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "debug", cfg.LogLevel)
				assert.Equal(t, "console", cfg.LogFormat)
				assert.Equal(t, "stderr", cfg.LogOutput)
				assert.False(t, cfg.AccessLogEnabled)
			},
		},
		{
			name: "Tracing settings from env",
			envVars: map[string]string{
				"AVAPIGW_TRACING_ENABLED":     "true",
				"AVAPIGW_TRACING_EXPORTER":    "otlp-http",
				"AVAPIGW_OTLP_ENDPOINT":       "localhost:4318",
				"AVAPIGW_TRACING_SAMPLE_RATE": "0.5",
				"AVAPIGW_SERVICE_NAME":        "my-service",
				"AVAPIGW_SERVICE_VERSION":     "2.0.0",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TracingEnabled)
				assert.Equal(t, "otlp-http", cfg.TracingExporter)
				assert.Equal(t, "localhost:4318", cfg.OTLPEndpoint)
				assert.Equal(t, 0.5, cfg.TracingSampleRate)
				assert.Equal(t, "my-service", cfg.ServiceName)
				assert.Equal(t, "2.0.0", cfg.ServiceVersion)
			},
		},
		{
			name: "Rate limit settings from env",
			envVars: map[string]string{
				"AVAPIGW_RATE_LIMIT_ENABLED":    "true",
				"AVAPIGW_RATE_LIMIT_ALGORITHM":  "sliding_window",
				"AVAPIGW_RATE_LIMIT_REQUESTS":   "200",
				"AVAPIGW_RATE_LIMIT_WINDOW":     "2m",
				"AVAPIGW_RATE_LIMIT_BURST":      "20",
				"AVAPIGW_RATE_LIMIT_STORE_TYPE": "redis",
				"AVAPIGW_REDIS_ADDRESS":         "redis:6379",
				"AVAPIGW_REDIS_PASSWORD":        "secret",
				"AVAPIGW_REDIS_DB":              "1",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.RateLimitEnabled)
				assert.Equal(t, "sliding_window", cfg.RateLimitAlgorithm)
				assert.Equal(t, 200, cfg.RateLimitRequests)
				assert.Equal(t, 2*time.Minute, cfg.RateLimitWindow)
				assert.Equal(t, 20, cfg.RateLimitBurst)
				assert.Equal(t, "redis", cfg.RateLimitStoreType)
				assert.Equal(t, "redis:6379", cfg.RedisAddress)
				assert.Equal(t, "secret", cfg.RedisPassword)
				assert.Equal(t, 1, cfg.RedisDB)
			},
		},
		{
			name: "Circuit breaker settings from env",
			envVars: map[string]string{
				"AVAPIGW_CIRCUIT_BREAKER_ENABLED":           "true",
				"AVAPIGW_CIRCUIT_BREAKER_MAX_FAILURES":      "10",
				"AVAPIGW_CIRCUIT_BREAKER_TIMEOUT":           "60s",
				"AVAPIGW_CIRCUIT_BREAKER_HALF_OPEN_MAX":     "5",
				"AVAPIGW_CIRCUIT_BREAKER_SUCCESS_THRESHOLD": "3",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.CircuitBreakerEnabled)
				assert.Equal(t, 10, cfg.CircuitBreakerMaxFailures)
				assert.Equal(t, 60*time.Second, cfg.CircuitBreakerTimeout)
				assert.Equal(t, 5, cfg.CircuitBreakerHalfOpenMax)
				assert.Equal(t, 3, cfg.CircuitBreakerSuccessThreshold)
			},
		},
		{
			name: "Retry settings from env",
			envVars: map[string]string{
				"AVAPIGW_RETRY_ENABLED":         "true",
				"AVAPIGW_RETRY_MAX_ATTEMPTS":    "5",
				"AVAPIGW_RETRY_INITIAL_BACKOFF": "200ms",
				"AVAPIGW_RETRY_MAX_BACKOFF":     "20s",
				"AVAPIGW_RETRY_BACKOFF_FACTOR":  "3.0",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.RetryEnabled)
				assert.Equal(t, 5, cfg.RetryMaxAttempts)
				assert.Equal(t, 200*time.Millisecond, cfg.RetryInitialBackoff)
				assert.Equal(t, 20*time.Second, cfg.RetryMaxBackoff)
				assert.Equal(t, 3.0, cfg.RetryBackoffFactor)
			},
		},
		{
			name: "Backend settings from env",
			envVars: map[string]string{
				"AVAPIGW_MAX_IDLE_CONNS":          "200",
				"AVAPIGW_MAX_IDLE_CONNS_PER_HOST": "20",
				"AVAPIGW_MAX_CONNS_PER_HOST":      "200",
				"AVAPIGW_IDLE_CONN_TIMEOUT":       "120s",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 200, cfg.MaxIdleConns)
				assert.Equal(t, 20, cfg.MaxIdleConnsPerHost)
				assert.Equal(t, 200, cfg.MaxConnsPerHost)
				assert.Equal(t, 120*time.Second, cfg.IdleConnTimeout)
			},
		},
		{
			name: "Health check settings from env",
			envVars: map[string]string{
				"AVAPIGW_HEALTH_CHECK_INTERVAL":       "30s",
				"AVAPIGW_HEALTH_CHECK_TIMEOUT":        "10s",
				"AVAPIGW_HEALTH_SERVER_READ_TIMEOUT":  "10s",
				"AVAPIGW_HEALTH_SERVER_WRITE_TIMEOUT": "10s",
				"AVAPIGW_READINESS_PROBE_TIMEOUT":     "10s",
				"AVAPIGW_LIVENESS_PROBE_TIMEOUT":      "20s",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 30*time.Second, cfg.HealthCheckInterval)
				assert.Equal(t, 10*time.Second, cfg.HealthCheckTimeout)
				assert.Equal(t, 10*time.Second, cfg.HealthServerReadTimeout)
				assert.Equal(t, 10*time.Second, cfg.HealthServerWriteTimeout)
				assert.Equal(t, 10*time.Second, cfg.ReadinessProbeTimeout)
				assert.Equal(t, 20*time.Second, cfg.LivenessProbeTimeout)
			},
		},
		{
			name: "gRPC settings from env",
			envVars: map[string]string{
				"AVAPIGW_GRPC_ENABLED":                "true",
				"AVAPIGW_GRPC_MAX_RECV_MSG_SIZE":      "8388608",
				"AVAPIGW_GRPC_MAX_SEND_MSG_SIZE":      "8388608",
				"AVAPIGW_GRPC_MAX_CONCURRENT_STREAMS": "2000",
				"AVAPIGW_GRPC_ENABLE_REFLECTION":      "true",
				"AVAPIGW_GRPC_ENABLE_HEALTH_CHECK":    "true",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.GRPCEnabled)
				assert.Equal(t, 8388608, cfg.GRPCMaxRecvMsgSize)
				assert.Equal(t, 8388608, cfg.GRPCMaxSendMsgSize)
				assert.Equal(t, 2000, cfg.GRPCMaxConcurrentStreams)
				assert.True(t, cfg.GRPCEnableReflection)
				assert.True(t, cfg.GRPCEnableHealthCheck)
			},
		},
		{
			name: "TCP settings from env",
			envVars: map[string]string{
				"AVAPIGW_TCP_ENABLED":         "true",
				"AVAPIGW_TCP_PORT":            "9443",
				"AVAPIGW_TCP_READ_TIMEOUT":    "60s",
				"AVAPIGW_TCP_WRITE_TIMEOUT":   "60s",
				"AVAPIGW_TCP_IDLE_TIMEOUT":    "10m",
				"AVAPIGW_TCP_MAX_CONNECTIONS": "20000",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TCPEnabled)
				assert.Equal(t, 9443, cfg.TCPPort)
				assert.Equal(t, 60*time.Second, cfg.TCPReadTimeout)
				assert.Equal(t, 60*time.Second, cfg.TCPWriteTimeout)
				assert.Equal(t, 10*time.Minute, cfg.TCPIdleTimeout)
				assert.Equal(t, 20000, cfg.TCPMaxConnections)
			},
		},
		{
			name: "TLS passthrough settings from env",
			envVars: map[string]string{
				"AVAPIGW_TLS_PASSTHROUGH_ENABLED": "true",
				"AVAPIGW_TLS_PASSTHROUGH_PORT":    "9444",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TLSPassthroughEnabled)
				assert.Equal(t, 9444, cfg.TLSPassthroughPort)
			},
		},
		{
			name: "Boolean parsing variations",
			envVars: map[string]string{
				"AVAPIGW_TLS_ENABLED":      "True",
				"AVAPIGW_TLS_CERT_FILE":    "/path/to/cert",
				"AVAPIGW_TLS_KEY_FILE":     "/path/to/key",
				"AVAPIGW_METRICS_ENABLED":  "TRUE",
				"AVAPIGW_TRACING_ENABLED":  "1",
				"AVAPIGW_TRACING_INSECURE": "yes",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.TLSEnabled)
				assert.True(t, cfg.MetricsEnabled)
				assert.True(t, cfg.TracingEnabled)
				assert.True(t, cfg.TracingInsecure)
			},
		},
		{
			name: "Boolean parsing false variations",
			envVars: map[string]string{
				"AVAPIGW_METRICS_ENABLED": "false",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.False(t, cfg.MetricsEnabled)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear and set environment variables
			for key := range tt.envVars {
				os.Unsetenv(key)
			}
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			loader := NewLoader()
			cfg, err := loader.LoadConfig([]string{})
			require.NoError(t, err)
			tt.validate(t, cfg)
		})
	}
}

func TestLoader_EnvOverridesFlags(t *testing.T) {
	// Environment variables should take precedence over flags

	os.Setenv("AVAPIGW_HTTP_PORT", "9999")
	defer os.Unsetenv("AVAPIGW_HTTP_PORT")

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{"-http-port", "8888"})

	require.NoError(t, err)
	// Environment variable should override the flag
	assert.Equal(t, 9999, cfg.HTTPPort)
}

func TestLoader_InvalidEnvValues(t *testing.T) {
	// Invalid environment values should be ignored (use default or flag value)

	tests := []struct {
		name     string
		envVar   string
		envValue string
		validate func(*testing.T, *Config)
	}{
		{
			name:     "Invalid port value",
			envVar:   "AVAPIGW_HTTP_PORT",
			envValue: "not-a-number",
			validate: func(t *testing.T, cfg *Config) {
				// Should use default value
				assert.Equal(t, 8080, cfg.HTTPPort)
			},
		},
		{
			name:     "Invalid duration value",
			envVar:   "AVAPIGW_READ_TIMEOUT",
			envValue: "not-a-duration",
			validate: func(t *testing.T, cfg *Config) {
				// Should use default value
				assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
			},
		},
		{
			name:     "Invalid float value",
			envVar:   "AVAPIGW_TRACING_SAMPLE_RATE",
			envValue: "not-a-float",
			validate: func(t *testing.T, cfg *Config) {
				// Should use default value
				assert.Equal(t, 1.0, cfg.TracingSampleRate)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(tt.envVar, tt.envValue)
			defer os.Unsetenv(tt.envVar)

			loader := NewLoader()
			cfg, err := loader.LoadConfig([]string{})
			require.NoError(t, err)
			tt.validate(t, cfg)
		})
	}
}

func TestParseBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected bool
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"Yes", true},
		{"YES", true},
		{"false", false},
		{"False", false},
		{"FALSE", false},
		{"0", false},
		{"no", false},
		{"No", false},
		{"NO", false},
		{"", false},
		{"invalid", false},
		{"maybe", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			result := parseBool(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoader_VaultEnvSettings(t *testing.T) {
	envVars := map[string]string{
		"AVAPIGW_VAULT_ENABLED":            "true",
		"AVAPIGW_VAULT_ADDRESS":            "https://vault.example.com:8200",
		"AVAPIGW_VAULT_AUTH_METHOD":        "token",
		"AVAPIGW_VAULT_ROLE":               "my-role",
		"AVAPIGW_VAULT_MOUNT_PATH":         "auth/kubernetes",
		"AVAPIGW_VAULT_SECRET_MOUNT_POINT": "kv",
		"AVAPIGW_VAULT_TLS_SKIP_VERIFY":    "true",
		"AVAPIGW_VAULT_CA_CERT":            "/path/to/ca.crt",
		"AVAPIGW_VAULT_CLIENT_CERT":        "/path/to/client.crt",
		"AVAPIGW_VAULT_CLIENT_KEY":         "/path/to/client.key",
		"AVAPIGW_VAULT_TIMEOUT":            "60s",
		"AVAPIGW_VAULT_MAX_RETRIES":        "5",
		"AVAPIGW_VAULT_RETRY_WAIT_MIN":     "1s",
		"AVAPIGW_VAULT_RETRY_WAIT_MAX":     "10s",
		"AVAPIGW_VAULT_CACHE_ENABLED":      "true",
		"AVAPIGW_VAULT_CACHE_TTL":          "10m",
		"AVAPIGW_VAULT_TOKEN_RENEWAL":      "true",
		"AVAPIGW_VAULT_TOKEN_RENEWAL_TIME": "10m",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
	}
	defer func() {
		for key := range envVars {
			os.Unsetenv(key)
		}
	}()

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{})
	require.NoError(t, err)

	assert.True(t, cfg.VaultEnabled)
	assert.Equal(t, "https://vault.example.com:8200", cfg.VaultAddress)
	assert.Equal(t, "token", cfg.VaultAuthMethod)
	assert.Equal(t, "my-role", cfg.VaultRole)
	assert.Equal(t, "auth/kubernetes", cfg.VaultMountPath)
	assert.Equal(t, "kv", cfg.VaultSecretMountPoint)
	assert.True(t, cfg.VaultTLSSkipVerify)
	assert.Equal(t, "/path/to/ca.crt", cfg.VaultCACert)
	assert.Equal(t, "/path/to/client.crt", cfg.VaultClientCert)
	assert.Equal(t, "/path/to/client.key", cfg.VaultClientKey)
	assert.Equal(t, 60*time.Second, cfg.VaultTimeout)
	assert.Equal(t, 5, cfg.VaultMaxRetries)
	assert.Equal(t, 1*time.Second, cfg.VaultRetryWaitMin)
	assert.Equal(t, 10*time.Second, cfg.VaultRetryWaitMax)
	assert.True(t, cfg.VaultCacheEnabled)
	assert.Equal(t, 10*time.Minute, cfg.VaultCacheTTL)
	assert.True(t, cfg.VaultTokenRenewal)
	assert.Equal(t, 10*time.Minute, cfg.VaultTokenRenewalTime)
}

func TestLoader_MetricsServerEnvSettings(t *testing.T) {
	envVars := map[string]string{
		"AVAPIGW_METRICS_ENABLED":                 "true",
		"AVAPIGW_METRICS_PATH":                    "/custom-metrics",
		"AVAPIGW_METRICS_SERVER_READ_TIMEOUT":     "10s",
		"AVAPIGW_METRICS_SERVER_WRITE_TIMEOUT":    "20s",
		"AVAPIGW_METRICS_SERVER_SHUTDOWN_TIMEOUT": "10s",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
	}
	defer func() {
		for key := range envVars {
			os.Unsetenv(key)
		}
	}()

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{})
	require.NoError(t, err)

	assert.True(t, cfg.MetricsEnabled)
	assert.Equal(t, "/custom-metrics", cfg.MetricsPath)
	assert.Equal(t, 10*time.Second, cfg.MetricsServerReadTimeout)
	assert.Equal(t, 20*time.Second, cfg.MetricsServerWriteTimeout)
	assert.Equal(t, 10*time.Second, cfg.MetricsServerShutdownTimeout)
}

func TestLoader_HealthServerEnvSettings(t *testing.T) {
	envVars := map[string]string{
		"AVAPIGW_HEALTH_SERVER_READ_TIMEOUT":     "10s",
		"AVAPIGW_HEALTH_SERVER_WRITE_TIMEOUT":    "10s",
		"AVAPIGW_HEALTH_SERVER_SHUTDOWN_TIMEOUT": "10s",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
	}
	defer func() {
		for key := range envVars {
			os.Unsetenv(key)
		}
	}()

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{})
	require.NoError(t, err)

	assert.Equal(t, 10*time.Second, cfg.HealthServerReadTimeout)
	assert.Equal(t, 10*time.Second, cfg.HealthServerWriteTimeout)
	assert.Equal(t, 10*time.Second, cfg.HealthServerShutdownTimeout)
}

func TestLoader_LoadConfig_WithYAMLFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid YAML config file
	configContent := `
gateway:
  name: yaml-test-gateway
  listeners:
    - name: http
      port: 9000
      protocol: HTTP
    - name: grpc
      port: 9100
      protocol: GRPC

routes:
  - name: test-route
    pathMatch:
      type: PathPrefix
      value: /api
    backendRefs:
      - name: test-backend

backends:
  - name: test-backend
    protocol: HTTP
    endpoints:
      - address: localhost
        port: 8080

rateLimits:
  - name: test-rate-limit
    algorithm: sliding_window
    requests: 200
    window: 2m
    burst: 50
`
	configPath := tmpDir + "/config.yaml"
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{"--config-file", configPath})
	require.NoError(t, err)

	// Verify YAML config was loaded and merged
	assert.Equal(t, 9000, cfg.HTTPPort)
	assert.Equal(t, 9100, cfg.GRPCPort)
	assert.True(t, cfg.GRPCEnabled)
	assert.True(t, cfg.RateLimitEnabled)
	assert.Equal(t, "sliding_window", cfg.RateLimitAlgorithm)
	assert.Equal(t, 200, cfg.RateLimitRequests)
	assert.Equal(t, 2*time.Minute, cfg.RateLimitWindow)
	assert.Equal(t, 50, cfg.RateLimitBurst)
	assert.Equal(t, "yaml-test-gateway", cfg.ServiceName)

	// Verify local config is accessible
	localCfg := loader.GetLocalConfig()
	assert.NotNil(t, localCfg)
	assert.Equal(t, "yaml-test-gateway", localCfg.Gateway.Name)
	assert.Len(t, localCfg.Routes, 1)
	assert.Len(t, localCfg.Backends, 1)
	assert.Len(t, localCfg.RateLimits, 1)

	// Verify config file path is accessible
	assert.Equal(t, configPath, loader.GetConfigFilePath())
}

func TestLoader_LoadConfig_YAMLFileFromEnv(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid YAML config file
	configContent := `
gateway:
  name: env-yaml-gateway
  listeners:
    - name: http
      port: 9500
      protocol: HTTP
`
	configPath := tmpDir + "/env-config.yaml"
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variable
	os.Setenv("AVAPIGW_CONFIG_FILE", configPath)
	defer os.Unsetenv("AVAPIGW_CONFIG_FILE")

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{})
	require.NoError(t, err)

	// Verify YAML config was loaded from env var
	assert.Equal(t, 9500, cfg.HTTPPort)
	assert.Equal(t, "env-yaml-gateway", cfg.ServiceName)
}

func TestLoader_LoadConfig_EnvOverridesYAML(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid YAML config file
	configContent := `
gateway:
  name: yaml-gateway
  listeners:
    - name: http
      port: 9000
      protocol: HTTP
`
	configPath := tmpDir + "/config.yaml"
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variable to override YAML
	os.Setenv("AVAPIGW_HTTP_PORT", "9999")
	defer os.Unsetenv("AVAPIGW_HTTP_PORT")

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{"--config-file", configPath})
	require.NoError(t, err)

	// ENV should override YAML
	assert.Equal(t, 9999, cfg.HTTPPort)
}

func TestLoader_LoadConfig_InvalidYAMLFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an invalid YAML config file
	configContent := `invalid: yaml: content:`
	configPath := tmpDir + "/invalid-config.yaml"
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	loader := NewLoader()
	_, err = loader.LoadConfig([]string{"--config-file", configPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse YAML")
}

func TestLoader_LoadConfig_NonExistentYAMLFile(t *testing.T) {
	loader := NewLoader()
	_, err := loader.LoadConfig([]string{"--config-file", "/non/existent/config.yaml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestLoader_LoadConfig_YAMLValidationError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a YAML config file with validation errors
	configContent := `
gateway:
  name: ""
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	configPath := tmpDir + "/invalid-gateway.yaml"
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	loader := NewLoader()
	_, err = loader.LoadConfig([]string{"--config-file", configPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway name is required")
}

func TestLoadWithLocalConfig(t *testing.T) {
	// This test verifies the LoadWithLocalConfig function
	// Since it uses os.Args, we can't easily test it in isolation
	// But we can verify the loader methods work correctly

	loader := NewLoader()
	cfg, err := loader.LoadConfig([]string{})
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	// Without a config file, local config should be nil
	assert.Nil(t, loader.GetLocalConfig())
	assert.Empty(t, loader.GetConfigFilePath())
}

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	// Verify default values
	assert.Equal(t, 8080, cfg.HTTPPort)
	assert.Equal(t, 9090, cfg.GRPCPort)
	assert.Equal(t, 9091, cfg.MetricsPort)
	assert.Equal(t, 8081, cfg.HealthPort)

	// Server timeouts
	assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 120*time.Second, cfg.IdleTimeout)
	assert.Equal(t, 30*time.Second, cfg.ShutdownTimeout)

	// TLS settings
	assert.False(t, cfg.TLSEnabled)
	assert.Empty(t, cfg.TLSCertFile)
	assert.Empty(t, cfg.TLSKeyFile)

	// Vault settings
	assert.False(t, cfg.VaultEnabled)
	assert.Equal(t, "http://localhost:8200", cfg.VaultAddress)
	assert.Equal(t, "kubernetes", cfg.VaultAuthMethod)
	assert.Equal(t, "avapigw", cfg.VaultRole)

	// Logging
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)
	assert.Equal(t, "stdout", cfg.LogOutput)
	assert.True(t, cfg.AccessLogEnabled)

	// Tracing
	assert.False(t, cfg.TracingEnabled)
	assert.Equal(t, "otlp-grpc", cfg.TracingExporter)
	assert.Equal(t, 1.0, cfg.TracingSampleRate)

	// Metrics
	assert.True(t, cfg.MetricsEnabled)
	assert.Equal(t, "/metrics", cfg.MetricsPath)

	// Rate limiting
	assert.False(t, cfg.RateLimitEnabled)
	assert.Equal(t, "token_bucket", cfg.RateLimitAlgorithm)
	assert.Equal(t, 100, cfg.RateLimitRequests)
	assert.Equal(t, time.Minute, cfg.RateLimitWindow)

	// Circuit breaker
	assert.False(t, cfg.CircuitBreakerEnabled)
	assert.Equal(t, 5, cfg.CircuitBreakerMaxFailures)

	// Retry
	assert.False(t, cfg.RetryEnabled)
	assert.Equal(t, 3, cfg.RetryMaxAttempts)

	// Backend settings
	assert.Equal(t, 100, cfg.MaxIdleConns)
	assert.Equal(t, 10, cfg.MaxIdleConnsPerHost)
	assert.Equal(t, 100, cfg.MaxConnsPerHost)

	// gRPC settings
	assert.True(t, cfg.GRPCEnabled)
	assert.Equal(t, 4*1024*1024, cfg.GRPCMaxRecvMsgSize)
	assert.Equal(t, 4*1024*1024, cfg.GRPCMaxSendMsgSize)

	// TCP settings
	assert.False(t, cfg.TCPEnabled)
	assert.Equal(t, 8443, cfg.TCPPort)

	// TLS Passthrough
	assert.False(t, cfg.TLSPassthroughEnabled)
	assert.Equal(t, 8444, cfg.TLSPassthroughPort)

	// JWT settings
	assert.False(t, cfg.JWTEnabled)
	assert.Equal(t, time.Hour, cfg.JWKSCacheTTL)
	assert.Equal(t, time.Minute, cfg.JWTClockSkew)
	assert.Equal(t, []string{"RS256", "RS384", "RS512"}, cfg.JWTAlgorithms)
	assert.Equal(t, "Authorization", cfg.JWTTokenHeader)
	assert.Equal(t, "Bearer ", cfg.JWTTokenPrefix)

	// API Key settings
	assert.False(t, cfg.APIKeyEnabled)
	assert.Equal(t, "X-API-Key", cfg.APIKeyHeader)
	assert.Equal(t, "api_key", cfg.APIKeyQueryParam)

	// Basic Auth settings
	assert.False(t, cfg.BasicAuthEnabled)
	assert.Equal(t, "Restricted", cfg.BasicAuthRealm)

	// Security Headers
	assert.True(t, cfg.SecurityHeadersEnabled)
	assert.True(t, cfg.HSTSEnabled)
	assert.Equal(t, 31536000, cfg.HSTSMaxAge)
	assert.Equal(t, "DENY", cfg.XFrameOptions)
	assert.Equal(t, "nosniff", cfg.XContentTypeOptions)
}

func TestConfig_Validate_ValidConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_PortValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "HTTPPort too low",
			modify: func(c *Config) {
				c.HTTPPort = 0
			},
			wantError: "HTTPPort must be between 1 and 65535",
		},
		{
			name: "HTTPPort too high",
			modify: func(c *Config) {
				c.HTTPPort = 65536
			},
			wantError: "HTTPPort must be between 1 and 65535",
		},
		{
			name: "GRPCPort too low",
			modify: func(c *Config) {
				c.GRPCPort = -1
			},
			wantError: "GRPCPort must be between 1 and 65535",
		},
		{
			name: "MetricsPort too high",
			modify: func(c *Config) {
				c.MetricsPort = 100000
			},
			wantError: "MetricsPort must be between 1 and 65535",
		},
		{
			name: "HealthPort invalid",
			modify: func(c *Config) {
				c.HealthPort = 0
			},
			wantError: "HealthPort must be between 1 and 65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestConfig_Validate_TLSSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "TLS enabled without cert file",
			modify: func(c *Config) {
				c.TLSEnabled = true
				c.TLSKeyFile = "/path/to/key"
			},
			wantError: "TLSCertFile is required when TLS is enabled",
		},
		{
			name: "TLS enabled without key file",
			modify: func(c *Config) {
				c.TLSEnabled = true
				c.TLSCertFile = "/path/to/cert"
			},
			wantError: "TLSKeyFile is required when TLS is enabled",
		},
		{
			name: "TLS enabled with both files",
			modify: func(c *Config) {
				c.TLSEnabled = true
				c.TLSCertFile = "/path/to/cert"
				c.TLSKeyFile = "/path/to/key"
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_VaultSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Vault enabled without address",
			modify: func(c *Config) {
				c.VaultEnabled = true
				c.VaultAddress = ""
			},
			wantError: "VaultAddress is required when Vault is enabled",
		},
		{
			name: "Vault enabled with invalid auth method",
			modify: func(c *Config) {
				c.VaultEnabled = true
				c.VaultAuthMethod = "invalid"
			},
			wantError: "invalid VaultAuthMethod",
		},
		{
			name: "Vault kubernetes auth without role",
			modify: func(c *Config) {
				c.VaultEnabled = true
				c.VaultAuthMethod = "kubernetes"
				c.VaultRole = ""
			},
			wantError: "VaultRole is required when using Kubernetes auth",
		},
		{
			name: "Vault enabled with zero timeout",
			modify: func(c *Config) {
				c.VaultEnabled = true
				c.VaultTimeout = 0
			},
			wantError: "VaultTimeout must be positive",
		},
		{
			name: "Vault enabled with negative max retries",
			modify: func(c *Config) {
				c.VaultEnabled = true
				c.VaultMaxRetries = -1
			},
			wantError: "VaultMaxRetries must be non-negative",
		},
		{
			name: "Vault enabled with token auth method",
			modify: func(c *Config) {
				c.VaultEnabled = true
				c.VaultAuthMethod = "token"
			},
			wantError: "",
		},
		{
			name: "Vault enabled with approle auth method",
			modify: func(c *Config) {
				c.VaultEnabled = true
				c.VaultAuthMethod = "approle"
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_LogSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Invalid log level",
			modify: func(c *Config) {
				c.LogLevel = "invalid"
			},
			wantError: "invalid LogLevel",
		},
		{
			name: "Valid log level debug",
			modify: func(c *Config) {
				c.LogLevel = "debug"
			},
			wantError: "",
		},
		{
			name: "Valid log level warn",
			modify: func(c *Config) {
				c.LogLevel = "warn"
			},
			wantError: "",
		},
		{
			name: "Valid log level error",
			modify: func(c *Config) {
				c.LogLevel = "error"
			},
			wantError: "",
		},
		{
			name: "Invalid log format",
			modify: func(c *Config) {
				c.LogFormat = "xml"
			},
			wantError: "invalid LogFormat",
		},
		{
			name: "Valid log format console",
			modify: func(c *Config) {
				c.LogFormat = "console"
			},
			wantError: "",
		},
		{
			name: "Invalid log output",
			modify: func(c *Config) {
				c.LogOutput = "invalid"
			},
			wantError: "invalid LogOutput",
		},
		{
			name: "Valid log output stderr",
			modify: func(c *Config) {
				c.LogOutput = "stderr"
			},
			wantError: "",
		},
		{
			name: "Valid log output file path absolute",
			modify: func(c *Config) {
				c.LogOutput = "/var/log/app.log"
			},
			wantError: "",
		},
		{
			name: "Valid log output file path relative",
			modify: func(c *Config) {
				c.LogOutput = "./app.log"
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_TracingSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Tracing enabled without endpoint",
			modify: func(c *Config) {
				c.TracingEnabled = true
				c.OTLPEndpoint = ""
			},
			wantError: "OTLPEndpoint is required when tracing is enabled",
		},
		{
			name: "Tracing enabled with invalid exporter",
			modify: func(c *Config) {
				c.TracingEnabled = true
				c.TracingExporter = "invalid"
			},
			wantError: "invalid TracingExporter",
		},
		{
			name: "Tracing enabled with sample rate too low",
			modify: func(c *Config) {
				c.TracingEnabled = true
				c.TracingSampleRate = -0.1
			},
			wantError: "TracingSampleRate must be between 0.0 and 1.0",
		},
		{
			name: "Tracing enabled with sample rate too high",
			modify: func(c *Config) {
				c.TracingEnabled = true
				c.TracingSampleRate = 1.5
			},
			wantError: "TracingSampleRate must be between 0.0 and 1.0",
		},
		{
			name: "Tracing enabled with otlp-http exporter",
			modify: func(c *Config) {
				c.TracingEnabled = true
				c.TracingExporter = "otlp-http"
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_RateLimitSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Rate limit enabled with invalid algorithm",
			modify: func(c *Config) {
				c.RateLimitEnabled = true
				c.RateLimitAlgorithm = "invalid"
			},
			wantError: "invalid RateLimitAlgorithm",
		},
		{
			name: "Rate limit enabled with invalid store type",
			modify: func(c *Config) {
				c.RateLimitEnabled = true
				c.RateLimitStoreType = "invalid"
			},
			wantError: "invalid RateLimitStoreType",
		},
		{
			name: "Rate limit redis store without address",
			modify: func(c *Config) {
				c.RateLimitEnabled = true
				c.RateLimitStoreType = "redis"
				c.RedisAddress = ""
			},
			wantError: "RedisAddress is required when rate limit store type is redis",
		},
		{
			name: "Rate limit enabled with zero requests",
			modify: func(c *Config) {
				c.RateLimitEnabled = true
				c.RateLimitRequests = 0
			},
			wantError: "RateLimitRequests must be positive",
		},
		{
			name: "Rate limit enabled with zero window",
			modify: func(c *Config) {
				c.RateLimitEnabled = true
				c.RateLimitWindow = 0
			},
			wantError: "RateLimitWindow must be positive",
		},
		{
			name: "Rate limit enabled with zero burst",
			modify: func(c *Config) {
				c.RateLimitEnabled = true
				c.RateLimitBurst = 0
			},
			wantError: "RateLimitBurst must be positive",
		},
		{
			name: "Rate limit enabled with sliding_window algorithm",
			modify: func(c *Config) {
				c.RateLimitEnabled = true
				c.RateLimitAlgorithm = "sliding_window"
			},
			wantError: "",
		},
		{
			name: "Rate limit enabled with fixed_window algorithm",
			modify: func(c *Config) {
				c.RateLimitEnabled = true
				c.RateLimitAlgorithm = "fixed_window"
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_CircuitBreakerSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Circuit breaker enabled with zero max failures",
			modify: func(c *Config) {
				c.CircuitBreakerEnabled = true
				c.CircuitBreakerMaxFailures = 0
			},
			wantError: "CircuitBreakerMaxFailures must be positive",
		},
		{
			name: "Circuit breaker enabled with zero timeout",
			modify: func(c *Config) {
				c.CircuitBreakerEnabled = true
				c.CircuitBreakerTimeout = 0
			},
			wantError: "CircuitBreakerTimeout must be positive",
		},
		{
			name: "Circuit breaker enabled with zero half open max",
			modify: func(c *Config) {
				c.CircuitBreakerEnabled = true
				c.CircuitBreakerHalfOpenMax = 0
			},
			wantError: "CircuitBreakerHalfOpenMax must be positive",
		},
		{
			name: "Circuit breaker enabled with zero success threshold",
			modify: func(c *Config) {
				c.CircuitBreakerEnabled = true
				c.CircuitBreakerSuccessThreshold = 0
			},
			wantError: "CircuitBreakerSuccessThreshold must be positive",
		},
		{
			name: "Circuit breaker enabled with valid settings",
			modify: func(c *Config) {
				c.CircuitBreakerEnabled = true
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_RetrySettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Retry enabled with negative max attempts",
			modify: func(c *Config) {
				c.RetryEnabled = true
				c.RetryMaxAttempts = -1
			},
			wantError: "RetryMaxAttempts must be non-negative",
		},
		{
			name: "Retry enabled with zero initial backoff",
			modify: func(c *Config) {
				c.RetryEnabled = true
				c.RetryInitialBackoff = 0
			},
			wantError: "RetryInitialBackoff must be positive",
		},
		{
			name: "Retry enabled with zero max backoff",
			modify: func(c *Config) {
				c.RetryEnabled = true
				c.RetryMaxBackoff = 0
			},
			wantError: "RetryMaxBackoff must be positive",
		},
		{
			name: "Retry enabled with zero backoff factor",
			modify: func(c *Config) {
				c.RetryEnabled = true
				c.RetryBackoffFactor = 0
			},
			wantError: "RetryBackoffFactor must be positive",
		},
		{
			name: "Retry enabled with valid settings",
			modify: func(c *Config) {
				c.RetryEnabled = true
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_TimeoutSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Zero read timeout",
			modify: func(c *Config) {
				c.ReadTimeout = 0
			},
			wantError: "ReadTimeout must be positive",
		},
		{
			name: "Zero write timeout",
			modify: func(c *Config) {
				c.WriteTimeout = 0
			},
			wantError: "WriteTimeout must be positive",
		},
		{
			name: "Zero idle timeout",
			modify: func(c *Config) {
				c.IdleTimeout = 0
			},
			wantError: "IdleTimeout must be positive",
		},
		{
			name: "Zero shutdown timeout",
			modify: func(c *Config) {
				c.ShutdownTimeout = 0
			},
			wantError: "ShutdownTimeout must be positive",
		},
		{
			name: "Zero health server read timeout",
			modify: func(c *Config) {
				c.HealthServerReadTimeout = 0
			},
			wantError: "HealthServerReadTimeout must be positive",
		},
		{
			name: "Zero health server write timeout",
			modify: func(c *Config) {
				c.HealthServerWriteTimeout = 0
			},
			wantError: "HealthServerWriteTimeout must be positive",
		},
		{
			name: "Zero health server shutdown timeout",
			modify: func(c *Config) {
				c.HealthServerShutdownTimeout = 0
			},
			wantError: "HealthServerShutdownTimeout must be positive",
		},
		{
			name: "Zero metrics server read timeout",
			modify: func(c *Config) {
				c.MetricsServerReadTimeout = 0
			},
			wantError: "MetricsServerReadTimeout must be positive",
		},
		{
			name: "Zero metrics server write timeout",
			modify: func(c *Config) {
				c.MetricsServerWriteTimeout = 0
			},
			wantError: "MetricsServerWriteTimeout must be positive",
		},
		{
			name: "Zero metrics server shutdown timeout",
			modify: func(c *Config) {
				c.MetricsServerShutdownTimeout = 0
			},
			wantError: "MetricsServerShutdownTimeout must be positive",
		},
		{
			name: "Zero readiness probe timeout",
			modify: func(c *Config) {
				c.ReadinessProbeTimeout = 0
			},
			wantError: "ReadinessProbeTimeout must be positive",
		},
		{
			name: "Zero liveness probe timeout",
			modify: func(c *Config) {
				c.LivenessProbeTimeout = 0
			},
			wantError: "LivenessProbeTimeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestConfig_Validate_BackendSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Zero max idle conns",
			modify: func(c *Config) {
				c.MaxIdleConns = 0
			},
			wantError: "MaxIdleConns must be positive",
		},
		{
			name: "Zero max idle conns per host",
			modify: func(c *Config) {
				c.MaxIdleConnsPerHost = 0
			},
			wantError: "MaxIdleConnsPerHost must be positive",
		},
		{
			name: "Zero max conns per host",
			modify: func(c *Config) {
				c.MaxConnsPerHost = 0
			},
			wantError: "MaxConnsPerHost must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestConfig_Validate_TCPSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "TCP enabled with invalid port",
			modify: func(c *Config) {
				c.TCPEnabled = true
				c.TCPPort = 0
			},
			wantError: "TCPPort must be between 1 and 65535",
		},
		{
			name: "TCP enabled with zero read timeout",
			modify: func(c *Config) {
				c.TCPEnabled = true
				c.TCPReadTimeout = 0
			},
			wantError: "TCPReadTimeout must be positive",
		},
		{
			name: "TCP enabled with zero write timeout",
			modify: func(c *Config) {
				c.TCPEnabled = true
				c.TCPWriteTimeout = 0
			},
			wantError: "TCPWriteTimeout must be positive",
		},
		{
			name: "TCP enabled with zero idle timeout",
			modify: func(c *Config) {
				c.TCPEnabled = true
				c.TCPIdleTimeout = 0
			},
			wantError: "TCPIdleTimeout must be positive",
		},
		{
			name: "TCP enabled with zero max connections",
			modify: func(c *Config) {
				c.TCPEnabled = true
				c.TCPMaxConnections = 0
			},
			wantError: "TCPMaxConnections must be positive",
		},
		{
			name: "TCP enabled with valid settings",
			modify: func(c *Config) {
				c.TCPEnabled = true
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_TLSPassthroughSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "TLS passthrough enabled with invalid port",
			modify: func(c *Config) {
				c.TLSPassthroughEnabled = true
				c.TLSPassthroughPort = 0
			},
			wantError: "TLSPassthroughPort must be between 1 and 65535",
		},
		{
			name: "TLS passthrough enabled with valid settings",
			modify: func(c *Config) {
				c.TLSPassthroughEnabled = true
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_JWTSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "JWT enabled without JWKS URL or issuer",
			modify: func(c *Config) {
				c.JWTEnabled = true
				c.JWKSURL = ""
				c.JWTIssuer = ""
			},
			wantError: "either JWKSURL or JWTIssuer is required when JWT is enabled",
		},
		{
			name: "JWT enabled with zero JWKS cache TTL",
			modify: func(c *Config) {
				c.JWTEnabled = true
				c.JWKSURL = "https://example.com/.well-known/jwks.json"
				c.JWKSCacheTTL = 0
			},
			wantError: "JWKSCacheTTL must be positive",
		},
		{
			name: "JWT enabled with negative clock skew",
			modify: func(c *Config) {
				c.JWTEnabled = true
				c.JWKSURL = "https://example.com/.well-known/jwks.json"
				c.JWTClockSkew = -1 * time.Second
			},
			wantError: "JWTClockSkew must be non-negative",
		},
		{
			name: "JWT enabled with JWKS URL",
			modify: func(c *Config) {
				c.JWTEnabled = true
				c.JWKSURL = "https://example.com/.well-known/jwks.json"
			},
			wantError: "",
		},
		{
			name: "JWT enabled with issuer",
			modify: func(c *Config) {
				c.JWTEnabled = true
				c.JWTIssuer = "https://example.com"
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_OAuth2Settings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "OAuth2 enabled without token endpoint",
			modify: func(c *Config) {
				c.OAuth2Enabled = true
				c.OAuth2TokenEndpoint = ""
				c.OAuth2ClientID = "client-id"
			},
			wantError: "OAuth2TokenEndpoint is required when OAuth2 is enabled",
		},
		{
			name: "OAuth2 enabled without client ID",
			modify: func(c *Config) {
				c.OAuth2Enabled = true
				c.OAuth2TokenEndpoint = "https://example.com/token"
				c.OAuth2ClientID = ""
			},
			wantError: "OAuth2ClientID is required when OAuth2 is enabled",
		},
		{
			name: "OAuth2 enabled with zero timeout",
			modify: func(c *Config) {
				c.OAuth2Enabled = true
				c.OAuth2TokenEndpoint = "https://example.com/token"
				c.OAuth2ClientID = "client-id"
				c.OAuth2Timeout = 0
			},
			wantError: "OAuth2Timeout must be positive",
		},
		{
			name: "OAuth2 enabled with valid settings",
			modify: func(c *Config) {
				c.OAuth2Enabled = true
				c.OAuth2TokenEndpoint = "https://example.com/token"
				c.OAuth2ClientID = "client-id"
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_Validate_SecurityHeadersSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modify    func(*Config)
		wantError string
	}{
		{
			name: "Security headers enabled with negative HSTS max age",
			modify: func(c *Config) {
				c.SecurityHeadersEnabled = true
				c.HSTSEnabled = true
				c.HSTSMaxAge = -1
			},
			wantError: "HSTSMaxAge must be non-negative",
		},
		{
			name: "Security headers enabled with invalid X-Frame-Options",
			modify: func(c *Config) {
				c.SecurityHeadersEnabled = true
				c.XFrameOptions = "INVALID"
			},
			wantError: "invalid XFrameOptions",
		},
		{
			name: "Security headers enabled with SAMEORIGIN X-Frame-Options",
			modify: func(c *Config) {
				c.SecurityHeadersEnabled = true
				c.XFrameOptions = "SAMEORIGIN"
			},
			wantError: "",
		},
		{
			name: "Security headers enabled with empty X-Frame-Options",
			modify: func(c *Config) {
				c.SecurityHeadersEnabled = true
				c.XFrameOptions = ""
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestConfig_String(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	str := cfg.String()

	assert.Contains(t, str, "HTTPPort: 8080")
	assert.Contains(t, str, "GRPCPort: 9090")
	assert.Contains(t, str, "MetricsPort: 9091")
	assert.Contains(t, str, "HealthPort: 8081")
	assert.Contains(t, str, "TLSEnabled: false")
	assert.Contains(t, str, "VaultEnabled: false")
	assert.Contains(t, str, "LogLevel: info")
	assert.Contains(t, str, "TracingEnabled: false")
	assert.Contains(t, str, "TCPEnabled: false")
	assert.Contains(t, str, "TCPPort: 8443")
	assert.Contains(t, str, "TLSPassthroughEnabled: false")
	assert.Contains(t, str, "TLSPassthroughPort: 8444")
}

func TestValidatePort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		port      int
		portName  string
		wantError bool
	}{
		{
			name:      "Valid port 1",
			port:      1,
			portName:  "TestPort",
			wantError: false,
		},
		{
			name:      "Valid port 80",
			port:      80,
			portName:  "TestPort",
			wantError: false,
		},
		{
			name:      "Valid port 443",
			port:      443,
			portName:  "TestPort",
			wantError: false,
		},
		{
			name:      "Valid port 8080",
			port:      8080,
			portName:  "TestPort",
			wantError: false,
		},
		{
			name:      "Valid port 65535",
			port:      65535,
			portName:  "TestPort",
			wantError: false,
		},
		{
			name:      "Invalid port 0",
			port:      0,
			portName:  "TestPort",
			wantError: true,
		},
		{
			name:      "Invalid port negative",
			port:      -1,
			portName:  "TestPort",
			wantError: true,
		},
		{
			name:      "Invalid port 65536",
			port:      65536,
			portName:  "TestPort",
			wantError: true,
		},
		{
			name:      "Invalid port very large",
			port:      100000,
			portName:  "TestPort",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePort(tt.port, tt.portName)
			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.portName)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

package external

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfig_Validate_Disabled tests that validation passes when config is disabled.
func TestConfig_Validate_Disabled(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *Config
	}{
		{
			name:   "NilConfig",
			config: nil,
		},
		{
			name: "DisabledConfig",
			config: &Config{
				Enabled: false,
				Type:    "", // Invalid type, but should pass because disabled
			},
		},
		{
			name: "DisabledWithInvalidType",
			config: &Config{
				Enabled: false,
				Type:    "invalid",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			err := tc.config.Validate()

			// Assert
			assert.NoError(t, err)
		})
	}
}

// TestConfig_Validate_InvalidType tests that validation fails for invalid types.
func TestConfig_Validate_InvalidType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		configType  string
		expectedErr string
	}{
		{
			name:        "EmptyType",
			configType:  "",
			expectedErr: "invalid type",
		},
		{
			name:        "UnknownType",
			configType:  "unknown",
			expectedErr: "invalid type",
		},
		{
			name:        "CaseSensitive_OPA",
			configType:  "OPA",
			expectedErr: "invalid type",
		},
		{
			name:        "CaseSensitive_GRPC",
			configType:  "GRPC",
			expectedErr: "invalid type",
		},
		{
			name:        "CaseSensitive_HTTP",
			configType:  "HTTP",
			expectedErr: "invalid type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			config := &Config{
				Enabled: true,
				Type:    tc.configType,
			}

			// Act
			err := config.Validate()

			// Assert
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// TestConfig_Validate_OPA_MissingConfig tests that validation fails when OPA config is missing.
func TestConfig_Validate_OPA_MissingConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &Config{
		Enabled: true,
		Type:    "opa",
		OPA:     nil,
	}

	// Act
	err := config.Validate()

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opa configuration is required")
}

// TestConfig_Validate_OPA_Valid tests that validation passes for valid OPA config.
func TestConfig_Validate_OPA_Valid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *Config
	}{
		{
			name: "MinimalOPAConfig",
			config: &Config{
				Enabled: true,
				Type:    "opa",
				OPA: &OPAConfig{
					URL: "http://localhost:8181",
				},
			},
		},
		{
			name: "FullOPAConfig",
			config: &Config{
				Enabled: true,
				Type:    "opa",
				OPA: &OPAConfig{
					URL:    "http://localhost:8181",
					Policy: "authz/allow",
					Query:  "data.authz.allow",
					Headers: map[string]string{
						"Authorization": "Bearer token",
					},
				},
				Timeout:  5 * time.Second,
				FailOpen: true,
				Cache: &CacheConfig{
					Enabled: true,
					TTL:     5 * time.Minute,
					MaxSize: 1000,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			err := tc.config.Validate()

			// Assert
			assert.NoError(t, err)
		})
	}
}

// TestOPAConfig_Validate_MissingURL tests that OPA validation fails when URL is missing.
func TestOPAConfig_Validate_MissingURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *OPAConfig
	}{
		{
			name: "EmptyURL",
			config: &OPAConfig{
				URL:    "",
				Policy: "authz/allow",
			},
		},
		{
			name: "OnlyPolicy",
			config: &OPAConfig{
				Policy: "authz/allow",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			err := tc.config.Validate()

			// Assert
			require.Error(t, err)
			assert.Contains(t, err.Error(), "url is required")
		})
	}
}

// TestOPAConfig_Validate_Valid tests that OPA validation passes for valid config.
func TestOPAConfig_Validate_Valid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *OPAConfig
	}{
		{
			name: "MinimalConfig",
			config: &OPAConfig{
				URL: "http://localhost:8181",
			},
		},
		{
			name: "WithPolicy",
			config: &OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
		{
			name: "WithQuery",
			config: &OPAConfig{
				URL:   "http://localhost:8181",
				Query: "data.authz.allow",
			},
		},
		{
			name: "WithHeaders",
			config: &OPAConfig{
				URL: "http://localhost:8181",
				Headers: map[string]string{
					"X-Custom": "value",
				},
			},
		},
		{
			name: "FullConfig",
			config: &OPAConfig{
				URL:    "http://opa.example.com:8181",
				Policy: "authz/allow",
				Query:  "data.authz.allow",
				Headers: map[string]string{
					"Authorization": "Bearer token",
					"X-Request-ID":  "123",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			err := tc.config.Validate()

			// Assert
			assert.NoError(t, err)
		})
	}
}

// TestDefaultConfig tests that DefaultConfig returns expected default values.
func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	// Act
	config := DefaultConfig()

	// Assert
	require.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.Equal(t, "opa", config.Type)
	assert.Equal(t, 100*time.Millisecond, config.Timeout)
	assert.False(t, config.FailOpen)

	// Verify cache defaults
	require.NotNil(t, config.Cache)
	assert.True(t, config.Cache.Enabled)
	assert.Equal(t, 5*time.Minute, config.Cache.TTL)
	assert.Equal(t, 10000, config.Cache.MaxSize)

	// Verify OPA, GRPC, HTTP are nil by default
	assert.Nil(t, config.OPA)
	assert.Nil(t, config.GRPC)
	assert.Nil(t, config.HTTP)
}

// TestConfig_Validate_GRPC_MissingConfig tests that validation fails when GRPC config is missing.
func TestConfig_Validate_GRPC_MissingConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &Config{
		Enabled: true,
		Type:    "grpc",
		GRPC:    nil,
	}

	// Act
	err := config.Validate()

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "grpc configuration is required")
}

// TestConfig_Validate_GRPC_Valid tests that validation passes for valid GRPC config.
func TestConfig_Validate_GRPC_Valid(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &Config{
		Enabled: true,
		Type:    "grpc",
		GRPC: &GRPCConfig{
			Address: "localhost:9090",
		},
	}

	// Act
	err := config.Validate()

	// Assert
	assert.NoError(t, err)
}

// TestGRPCConfig_Validate tests GRPC config validation.
func TestGRPCConfig_Validate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		config      *GRPCConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "ValidAddress",
			config: &GRPCConfig{
				Address: "localhost:9090",
			},
			expectError: false,
		},
		{
			name: "EmptyAddress",
			config: &GRPCConfig{
				Address: "",
			},
			expectError: true,
			errorMsg:    "address is required",
		},
		{
			name: "WithTLS",
			config: &GRPCConfig{
				Address: "localhost:9090",
				TLS: &TLSConfig{
					Enabled: true,
					CAFile:  "/path/to/ca.crt",
				},
			},
			expectError: false,
		},
		{
			name: "WithMetadata",
			config: &GRPCConfig{
				Address: "localhost:9090",
				Metadata: map[string]string{
					"key": "value",
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			err := tc.config.Validate()

			// Assert
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfig_Validate_HTTP_MissingConfig tests that validation fails when HTTP config is missing.
func TestConfig_Validate_HTTP_MissingConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &Config{
		Enabled: true,
		Type:    "http",
		HTTP:    nil,
	}

	// Act
	err := config.Validate()

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http configuration is required")
}

// TestConfig_Validate_HTTP_Valid tests that validation passes for valid HTTP config.
func TestConfig_Validate_HTTP_Valid(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &Config{
		Enabled: true,
		Type:    "http",
		HTTP: &HTTPConfig{
			URL:    "http://localhost:8080/authz",
			Method: "POST",
		},
	}

	// Act
	err := config.Validate()

	// Assert
	assert.NoError(t, err)
}

// TestHTTPConfig_Validate tests HTTP config validation.
func TestHTTPConfig_Validate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		config      *HTTPConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "ValidURL",
			config: &HTTPConfig{
				URL: "http://localhost:8080/authz",
			},
			expectError: false,
		},
		{
			name: "EmptyURL",
			config: &HTTPConfig{
				URL: "",
			},
			expectError: true,
			errorMsg:    "url is required",
		},
		{
			name: "ValidGETMethod",
			config: &HTTPConfig{
				URL:    "http://localhost:8080/authz",
				Method: "GET",
			},
			expectError: false,
		},
		{
			name: "ValidPOSTMethod",
			config: &HTTPConfig{
				URL:    "http://localhost:8080/authz",
				Method: "POST",
			},
			expectError: false,
		},
		{
			name: "InvalidMethod",
			config: &HTTPConfig{
				URL:    "http://localhost:8080/authz",
				Method: "PUT",
			},
			expectError: true,
			errorMsg:    "invalid method",
		},
		{
			name: "EmptyMethodIsValid",
			config: &HTTPConfig{
				URL:    "http://localhost:8080/authz",
				Method: "",
			},
			expectError: false,
		},
		{
			name: "WithHeaders",
			config: &HTTPConfig{
				URL: "http://localhost:8080/authz",
				Headers: map[string]string{
					"Authorization": "Bearer token",
				},
			},
			expectError: false,
		},
		{
			name: "WithTLS",
			config: &HTTPConfig{
				URL: "https://localhost:8443/authz",
				TLS: &TLSConfig{
					Enabled: true,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			err := tc.config.Validate()

			// Assert
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfig_Validate_NegativeTimeout tests that validation fails for negative timeout.
func TestConfig_Validate_NegativeTimeout(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &Config{
		Enabled: true,
		Type:    "opa",
		OPA: &OPAConfig{
			URL: "http://localhost:8181",
		},
		Timeout: -1 * time.Second,
	}

	// Act
	err := config.Validate()

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout must be non-negative")
}

// TestConfig_Validate_CacheConfig tests cache configuration validation.
func TestConfig_Validate_CacheConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		cache       *CacheConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "NilCache",
			cache:       nil,
			expectError: false,
		},
		{
			name: "DisabledCache",
			cache: &CacheConfig{
				Enabled: false,
				TTL:     -1, // Invalid but should pass because disabled
				MaxSize: -1,
			},
			expectError: false,
		},
		{
			name: "ValidCache",
			cache: &CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: 1000,
			},
			expectError: false,
		},
		{
			name: "ZeroTTL",
			cache: &CacheConfig{
				Enabled: true,
				TTL:     0,
				MaxSize: 1000,
			},
			expectError: false,
		},
		{
			name: "NegativeTTL",
			cache: &CacheConfig{
				Enabled: true,
				TTL:     -1 * time.Second,
				MaxSize: 1000,
			},
			expectError: true,
			errorMsg:    "cache.ttl must be non-negative",
		},
		{
			name: "ZeroMaxSize",
			cache: &CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: 0,
			},
			expectError: false,
		},
		{
			name: "NegativeMaxSize",
			cache: &CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: -1,
			},
			expectError: true,
			errorMsg:    "cache.maxSize must be non-negative",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			config := &Config{
				Enabled: true,
				Type:    "opa",
				OPA: &OPAConfig{
					URL: "http://localhost:8181",
				},
				Cache: tc.cache,
			}

			// Act
			err := config.Validate()

			// Assert
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfig_GetEffectiveTimeout tests GetEffectiveTimeout method.
func TestConfig_GetEffectiveTimeout(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "ZeroTimeout",
			timeout:         0,
			expectedTimeout: 100 * time.Millisecond,
		},
		{
			name:            "NegativeTimeout",
			timeout:         -1 * time.Second,
			expectedTimeout: 100 * time.Millisecond,
		},
		{
			name:            "CustomTimeout",
			timeout:         5 * time.Second,
			expectedTimeout: 5 * time.Second,
		},
		{
			name:            "SmallTimeout",
			timeout:         10 * time.Millisecond,
			expectedTimeout: 10 * time.Millisecond,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			config := &Config{
				Timeout: tc.timeout,
			}

			// Act
			result := config.GetEffectiveTimeout()

			// Assert
			assert.Equal(t, tc.expectedTimeout, result)
		})
	}
}

// TestTLSConfig tests TLS configuration structure.
func TestTLSConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	tlsConfig := &TLSConfig{
		Enabled:            true,
		CAFile:             "/path/to/ca.crt",
		CertFile:           "/path/to/cert.crt",
		KeyFile:            "/path/to/key.pem",
		InsecureSkipVerify: false,
	}

	// Assert - verify all fields are accessible
	assert.True(t, tlsConfig.Enabled)
	assert.Equal(t, "/path/to/ca.crt", tlsConfig.CAFile)
	assert.Equal(t, "/path/to/cert.crt", tlsConfig.CertFile)
	assert.Equal(t, "/path/to/key.pem", tlsConfig.KeyFile)
	assert.False(t, tlsConfig.InsecureSkipVerify)
}

// TestCacheConfig tests CacheConfig structure.
func TestCacheConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	cacheConfig := &CacheConfig{
		Enabled: true,
		TTL:     10 * time.Minute,
		MaxSize: 5000,
	}

	// Assert - verify all fields are accessible
	assert.True(t, cacheConfig.Enabled)
	assert.Equal(t, 10*time.Minute, cacheConfig.TTL)
	assert.Equal(t, 5000, cacheConfig.MaxSize)
}

// TestConfig_AllTypes tests validation for all supported types.
func TestConfig_AllTypes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *Config
	}{
		{
			name: "OPAType",
			config: &Config{
				Enabled: true,
				Type:    "opa",
				OPA: &OPAConfig{
					URL: "http://localhost:8181",
				},
			},
		},
		{
			name: "GRPCType",
			config: &Config{
				Enabled: true,
				Type:    "grpc",
				GRPC: &GRPCConfig{
					Address: "localhost:9090",
				},
			},
		},
		{
			name: "HTTPType",
			config: &Config{
				Enabled: true,
				Type:    "http",
				HTTP: &HTTPConfig{
					URL: "http://localhost:8080/authz",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			err := tc.config.Validate()

			// Assert
			assert.NoError(t, err)
		})
	}
}

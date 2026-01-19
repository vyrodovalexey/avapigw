package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadYAMLConfig(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	t.Run("valid config file", func(t *testing.T) {
		t.Parallel()

		configContent := `
gateway:
  name: test-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP

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
`
		configPath := filepath.Join(tmpDir, "valid-config.yaml")
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadYAMLConfig(configPath)
		require.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, "test-gateway", cfg.Gateway.Name)
		assert.Len(t, cfg.Gateway.Listeners, 1)
		assert.Len(t, cfg.Routes, 1)
		assert.Len(t, cfg.Backends, 1)
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		_, err := LoadYAMLConfig("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config file path is empty")
	})

	t.Run("non-existent file", func(t *testing.T) {
		t.Parallel()

		_, err := LoadYAMLConfig("/non/existent/path.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})

	t.Run("directory instead of file", func(t *testing.T) {
		t.Parallel()

		_, err := LoadYAMLConfig(tmpDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is a directory")
	})

	t.Run("invalid YAML", func(t *testing.T) {
		t.Parallel()

		configPath := filepath.Join(tmpDir, "invalid-yaml.yaml")
		err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0644)
		require.NoError(t, err)

		_, err = LoadYAMLConfig(configPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse YAML")
	})
}

func TestLoadAndValidateYAMLConfig(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()

		configContent := `
gateway:
  name: test-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP

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
`
		configPath := filepath.Join(tmpDir, "valid-config.yaml")
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadAndValidateYAMLConfig(configPath)
		require.NoError(t, err)
		assert.NotNil(t, cfg)
	})

	t.Run("invalid config - missing gateway name", func(t *testing.T) {
		t.Parallel()

		configContent := `
gateway:
  name: ""
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
		configPath := filepath.Join(tmpDir, "invalid-gateway.yaml")
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		_, err = LoadAndValidateYAMLConfig(configPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gateway name is required")
	})
}

func TestValidateLocalConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()

		err := ValidateLocalConfig(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config is nil")
	})

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()

		cfg := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
			},
		}

		err := ValidateLocalConfig(cfg)
		assert.NoError(t, err)
	})
}

func TestMergeConfigs(t *testing.T) {
	t.Parallel()

	t.Run("nil base config", func(t *testing.T) {
		t.Parallel()

		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "http", Port: 9000, Protocol: "HTTP"},
				},
			},
		}

		result := MergeConfigs(nil, local)
		assert.NotNil(t, result)
		assert.Equal(t, 9000, result.HTTPPort)
	})

	t.Run("nil local config", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		result := MergeConfigs(base, nil)
		assert.Equal(t, base, result)
	})

	t.Run("merge HTTP listener", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "http", Port: 9000, Protocol: "HTTP"},
				},
			},
		}

		result := MergeConfigs(base, local)
		assert.Equal(t, 9000, result.HTTPPort)
	})

	t.Run("merge HTTPS listener", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "https", Port: 9443, Protocol: "HTTPS", TLS: &ListenerTLSConfig{}},
				},
			},
		}

		result := MergeConfigs(base, local)
		assert.Equal(t, 9443, result.HTTPPort)
		assert.True(t, result.TLSEnabled)
	})

	t.Run("merge gRPC listener", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "grpc", Port: 9100, Protocol: "GRPC"},
				},
			},
		}

		result := MergeConfigs(base, local)
		assert.Equal(t, 9100, result.GRPCPort)
		assert.True(t, result.GRPCEnabled)
	})

	t.Run("merge TCP listener", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "tcp", Port: 9500, Protocol: "TCP"},
				},
			},
		}

		result := MergeConfigs(base, local)
		assert.Equal(t, 9500, result.TCPPort)
		assert.True(t, result.TCPEnabled)
	})

	t.Run("merge rate limit", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
			},
			RateLimits: []LocalRateLimit{
				{
					Name:      "test-rate-limit",
					Algorithm: "sliding_window",
					Requests:  200,
					Window:    2 * time.Minute,
					Burst:     50,
				},
			},
		}

		result := MergeConfigs(base, local)
		assert.True(t, result.RateLimitEnabled)
		assert.Equal(t, "sliding_window", result.RateLimitAlgorithm)
		assert.Equal(t, 200, result.RateLimitRequests)
		assert.Equal(t, 2*time.Minute, result.RateLimitWindow)
		assert.Equal(t, 50, result.RateLimitBurst)
	})

	t.Run("merge JWT auth policy", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
			},
			AuthPolicies: []LocalAuthPolicy{
				{
					Name: "jwt-auth",
					JWT: &JWTAuthConfig{
						Issuer:     "https://auth.example.com",
						JWKSURL:    "https://auth.example.com/.well-known/jwks.json",
						Audiences:  []string{"api.example.com"},
						Algorithms: []string{"RS256"},
						TokenSource: &TokenSourceConfig{
							Header: "X-Auth-Token",
							Prefix: "Token ",
						},
					},
				},
			},
		}

		result := MergeConfigs(base, local)
		assert.True(t, result.JWTEnabled)
		assert.Equal(t, "https://auth.example.com", result.JWTIssuer)
		assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", result.JWKSURL)
		assert.Equal(t, []string{"api.example.com"}, result.JWTAudiences)
		assert.Equal(t, []string{"RS256"}, result.JWTAlgorithms)
		assert.Equal(t, "X-Auth-Token", result.JWTTokenHeader)
		assert.Equal(t, "Token ", result.JWTTokenPrefix)
	})

	t.Run("merge API key auth policy", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
			},
			AuthPolicies: []LocalAuthPolicy{
				{
					Name: "apikey-auth",
					APIKey: &APIKeyAuthConfig{
						Header: "X-Custom-API-Key",
						Query:  "apikey",
					},
				},
			},
		}

		result := MergeConfigs(base, local)
		assert.True(t, result.APIKeyEnabled)
		assert.Equal(t, "X-Custom-API-Key", result.APIKeyHeader)
		assert.Equal(t, "apikey", result.APIKeyQueryParam)
	})

	t.Run("merge service name from gateway", func(t *testing.T) {
		t.Parallel()

		base := DefaultConfig()
		local := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "my-custom-gateway",
			},
		}

		result := MergeConfigs(base, local)
		assert.Equal(t, "my-custom-gateway", result.ServiceName)
	})
}

func TestSaveYAMLConfig(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	t.Run("save valid config", func(t *testing.T) {
		t.Parallel()

		cfg := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
			},
		}

		configPath := filepath.Join(tmpDir, "saved-config.yaml")
		err := SaveYAMLConfig(cfg, configPath)
		require.NoError(t, err)

		// Verify the file was created and can be loaded
		loadedCfg, err := LoadYAMLConfig(configPath)
		require.NoError(t, err)
		assert.Equal(t, cfg.Gateway.Name, loadedCfg.Gateway.Name)
	})

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()

		configPath := filepath.Join(tmpDir, "nil-config.yaml")
		err := SaveYAMLConfig(nil, configPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config is nil")
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		cfg := &LocalConfig{
			Gateway: GatewayConfig{
				Name: "test-gateway",
			},
		}

		err := SaveYAMLConfig(cfg, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path is empty")
	})
}

func TestDefaultLocalConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultLocalConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, "default-gateway", cfg.Gateway.Name)
	assert.Len(t, cfg.Gateway.Listeners, 1)
	assert.Equal(t, "http", cfg.Gateway.Listeners[0].Name)
	assert.Equal(t, 8080, cfg.Gateway.Listeners[0].Port)
	assert.Equal(t, "HTTP", cfg.Gateway.Listeners[0].Protocol)
	assert.Empty(t, cfg.Routes)
	assert.Empty(t, cfg.Backends)
	assert.Empty(t, cfg.RateLimits)
	assert.Empty(t, cfg.AuthPolicies)
}

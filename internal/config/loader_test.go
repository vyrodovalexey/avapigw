package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	t.Parallel()

	loader := NewLoader()
	assert.NotNil(t, loader)
	assert.NotNil(t, loader.loadedFiles)
	assert.Equal(t, 10, loader.maxIncludes)
}

func TestLoader_Load(t *testing.T) {
	t.Parallel()

	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test-gateway
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	loader := NewLoader()
	cfg, err := loader.Load(configPath)

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "gateway.avapigw.io/v1", cfg.APIVersion)
	assert.Equal(t, "Gateway", cfg.Kind)
	assert.Equal(t, "test-gateway", cfg.Metadata.Name)
	assert.Len(t, cfg.Spec.Listeners, 1)
}

func TestLoader_Load_FileNotFound(t *testing.T) {
	t.Parallel()

	loader := NewLoader()
	_, err := loader.Load("/nonexistent/path/config.yaml")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoader_LoadFromReader(t *testing.T) {
	t.Parallel()

	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: reader-gateway
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	reader := strings.NewReader(configContent)

	loader := NewLoader()
	cfg, err := loader.LoadFromReader(reader)

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "reader-gateway", cfg.Metadata.Name)
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: load-config-test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "load-config-test", cfg.Metadata.Name)
}

func TestLoadConfigFromReader(t *testing.T) {
	t.Parallel()

	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: from-reader
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	reader := strings.NewReader(configContent)

	cfg, err := LoadConfigFromReader(reader)

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "from-reader", cfg.Metadata.Name)
}

func TestLoader_SubstituteEnvVars(t *testing.T) {
	// Note: Cannot use t.Parallel() because subtests use t.Setenv

	tests := []struct {
		name     string
		input    string
		envVars  map[string]string
		expected string
	}{
		{
			name:     "simple substitution",
			input:    "port: ${PORT}",
			envVars:  map[string]string{"PORT": "8080"},
			expected: "port: 8080",
		},
		{
			name:     "with default value",
			input:    "port: ${PORT:-9090}",
			envVars:  map[string]string{},
			expected: "port: 9090",
		},
		{
			name:     "env var overrides default",
			input:    "port: ${PORT:-9090}",
			envVars:  map[string]string{"PORT": "8080"},
			expected: "port: 8080",
		},
		{
			name:     "multiple substitutions",
			input:    "host: ${HOST}, port: ${PORT}",
			envVars:  map[string]string{"HOST": "localhost", "PORT": "8080"},
			expected: "host: localhost, port: 8080",
		},
		{
			name:     "escaped dollar sign",
			input:    "price: $$100",
			envVars:  map[string]string{},
			expected: "price: $100",
		},
		{
			name:     "missing env var without default",
			input:    "port: ${MISSING_VAR}",
			envVars:  map[string]string{},
			expected: "port: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			loader := NewLoader()
			result := loader.substituteEnvVars(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoader_LoadWithIncludes(t *testing.T) {
	t.Parallel()

	// Create temporary config files
	tmpDir := t.TempDir()

	// Main config
	mainConfigPath := filepath.Join(tmpDir, "main.yaml")
	mainContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: main-gateway
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	err := os.WriteFile(mainConfigPath, []byte(mainContent), 0644)
	require.NoError(t, err)

	loader := NewLoader()
	cfg, err := loader.LoadWithIncludes(mainConfigPath)

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "main-gateway", cfg.Metadata.Name)
}

func TestLoader_LoadWithIncludes_CircularDetection(t *testing.T) {
	t.Parallel()

	// Create temporary config files with circular includes
	tmpDir := t.TempDir()

	// Config A includes B
	configAPath := filepath.Join(tmpDir, "a.yaml")
	configAContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: config-a
includes:
  - b.yaml
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	err := os.WriteFile(configAPath, []byte(configAContent), 0644)
	require.NoError(t, err)

	// Config B includes A (circular)
	configBPath := filepath.Join(tmpDir, "b.yaml")
	configBContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: config-b
includes:
  - a.yaml
spec:
  listeners: []
`
	err = os.WriteFile(configBPath, []byte(configBContent), 0644)
	require.NoError(t, err)

	loader := NewLoader()
	_, err = loader.LoadWithIncludes(configAPath)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circular include")
}

func TestMergeConfigs(t *testing.T) {
	t.Parallel()

	t.Run("empty configs", func(t *testing.T) {
		t.Parallel()
		result := MergeConfigs()
		assert.NotNil(t, result)
		assert.Equal(t, "default-gateway", result.Metadata.Name)
	})

	t.Run("single config", func(t *testing.T) {
		t.Parallel()
		cfg := &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "single"},
		}
		result := MergeConfigs(cfg)
		assert.Equal(t, "single", result.Metadata.Name)
	})

	t.Run("merge two configs", func(t *testing.T) {
		t.Parallel()
		base := &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: Metadata{
				Name:   "base",
				Labels: map[string]string{"env": "dev"},
			},
			Spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []Route{
					{Name: "base-route"},
				},
			},
		}

		override := &GatewayConfig{
			Metadata: Metadata{
				Name:   "override",
				Labels: map[string]string{"version": "v1"},
			},
			Spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "https", Port: 443, Protocol: "HTTPS"},
				},
				Routes: []Route{
					{Name: "override-route"},
				},
			},
		}

		result := MergeConfigs(base, override)

		assert.Equal(t, "override", result.Metadata.Name)
		assert.Equal(t, "dev", result.Metadata.Labels["env"])
		assert.Equal(t, "v1", result.Metadata.Labels["version"])
		assert.Len(t, result.Spec.Listeners, 1)
		assert.Equal(t, "https", result.Spec.Listeners[0].Name)
		assert.Len(t, result.Spec.Routes, 2)
	})
}

func TestMergeTwo(t *testing.T) {
	t.Parallel()

	t.Run("nil base", func(t *testing.T) {
		t.Parallel()
		override := &GatewayConfig{Metadata: Metadata{Name: "override"}}
		result := mergeTwo(nil, override)
		assert.Equal(t, "override", result.Metadata.Name)
	})

	t.Run("nil override", func(t *testing.T) {
		t.Parallel()
		base := &GatewayConfig{Metadata: Metadata{Name: "base"}}
		result := mergeTwo(base, nil)
		assert.Equal(t, "base", result.Metadata.Name)
	})

	t.Run("merge rate limit", func(t *testing.T) {
		t.Parallel()
		base := &GatewayConfig{
			Spec: GatewaySpec{
				RateLimit: &RateLimitConfig{Enabled: true, RequestsPerSecond: 100},
			},
		}
		override := &GatewayConfig{
			Spec: GatewaySpec{
				RateLimit: &RateLimitConfig{Enabled: true, RequestsPerSecond: 200},
			},
		}
		result := mergeTwo(base, override)
		assert.Equal(t, 200, result.Spec.RateLimit.RequestsPerSecond)
	})

	t.Run("merge circuit breaker", func(t *testing.T) {
		t.Parallel()
		base := &GatewayConfig{}
		override := &GatewayConfig{
			Spec: GatewaySpec{
				CircuitBreaker: &CircuitBreakerConfig{Enabled: true, Threshold: 5},
			},
		}
		result := mergeTwo(base, override)
		assert.NotNil(t, result.Spec.CircuitBreaker)
		assert.Equal(t, 5, result.Spec.CircuitBreaker.Threshold)
	})

	t.Run("merge CORS", func(t *testing.T) {
		t.Parallel()
		base := &GatewayConfig{}
		override := &GatewayConfig{
			Spec: GatewaySpec{
				CORS: &CORSConfig{AllowOrigins: []string{"*"}},
			},
		}
		result := mergeTwo(base, override)
		assert.NotNil(t, result.Spec.CORS)
		assert.Contains(t, result.Spec.CORS.AllowOrigins, "*")
	})

	t.Run("merge observability", func(t *testing.T) {
		t.Parallel()
		base := &GatewayConfig{}
		override := &GatewayConfig{
			Spec: GatewaySpec{
				Observability: &ObservabilityConfig{
					Metrics: &MetricsConfig{Enabled: true},
				},
			},
		}
		result := mergeTwo(base, override)
		assert.NotNil(t, result.Spec.Observability)
		assert.True(t, result.Spec.Observability.Metrics.Enabled)
	})

	t.Run("merge annotations", func(t *testing.T) {
		t.Parallel()
		base := &GatewayConfig{
			Metadata: Metadata{
				Annotations: map[string]string{"key1": "value1"},
			},
		}
		override := &GatewayConfig{
			Metadata: Metadata{
				Annotations: map[string]string{"key2": "value2"},
			},
		}
		result := mergeTwo(base, override)
		assert.Equal(t, "value1", result.Metadata.Annotations["key1"])
		assert.Equal(t, "value2", result.Metadata.Annotations["key2"])
	})
}

func TestResolveConfigPath(t *testing.T) {
	t.Parallel()

	t.Run("absolute path exists", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte("test"), 0644)
		require.NoError(t, err)

		result, err := ResolveConfigPath(configPath)
		require.NoError(t, err)
		assert.Equal(t, configPath, result)
	})

	t.Run("absolute path not found", func(t *testing.T) {
		t.Parallel()
		_, err := ResolveConfigPath("/nonexistent/absolute/path.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config file not found")
	})

	t.Run("relative path exists", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configPath, []byte("test"), 0644)
		require.NoError(t, err)

		// Change to temp directory
		oldWd, _ := os.Getwd()
		defer func() { _ = os.Chdir(oldWd) }()
		_ = os.Chdir(tmpDir)

		result, err := ResolveConfigPath("config.yaml")
		require.NoError(t, err)
		assert.Contains(t, result, "config.yaml")
	})

	t.Run("relative path not found", func(t *testing.T) {
		t.Parallel()
		_, err := ResolveConfigPath("nonexistent.yaml")
		assert.Error(t, err)
	})
}

func TestLoader_ParseConfig_InvalidYAML(t *testing.T) {
	t.Parallel()

	loader := NewLoader()
	_, err := loader.parseConfig([]byte("invalid: yaml: content: ["))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse YAML")
}

func TestLoader_LoadWithIncludes_MaxDepthExceeded(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a chain of includes that exceeds max depth
	for i := 0; i <= 11; i++ {
		var content string
		if i < 11 {
			content = `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: config-` + string(rune('a'+i)) + `
includes:
  - config` + string(rune('a'+i+1)) + `.yaml
spec:
  listeners: []
`
		} else {
			content = `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: config-final
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
		}
		configPath := filepath.Join(tmpDir, "config"+string(rune('a'+i))+".yaml")
		err := os.WriteFile(configPath, []byte(content), 0644)
		require.NoError(t, err)
	}

	loader := NewLoader()
	_, err := loader.LoadWithIncludes(filepath.Join(tmpDir, "configa.yaml"))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum include depth")
}

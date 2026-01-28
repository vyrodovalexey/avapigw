//go:build functional
// +build functional

package functional

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestFunctional_Config_LoadAndValidate(t *testing.T) {
	t.Parallel()

	t.Run("load valid configuration", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "gateway.avapigw.io/v1", cfg.APIVersion)
		assert.Equal(t, "Gateway", cfg.Kind)
		assert.Equal(t, "test-gateway", cfg.Metadata.Name)
	})

	t.Run("validate configuration structure", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		err = config.ValidateConfig(cfg)
		require.NoError(t, err)
	})

	t.Run("validate listeners", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		require.Len(t, cfg.Spec.Listeners, 1)
		listener := cfg.Spec.Listeners[0]
		assert.Equal(t, "http", listener.Name)
		assert.Equal(t, 18080, listener.Port)
		assert.Equal(t, "HTTP", listener.Protocol)
	})

	t.Run("validate routes", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		require.GreaterOrEqual(t, len(cfg.Spec.Routes), 3)

		// Find items-api route
		var itemsRoute *config.Route
		for i := range cfg.Spec.Routes {
			if cfg.Spec.Routes[i].Name == "items-api" {
				itemsRoute = &cfg.Spec.Routes[i]
				break
			}
		}
		require.NotNil(t, itemsRoute)
		assert.Len(t, itemsRoute.Route, 2)
	})

	t.Run("validate backends", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		require.Len(t, cfg.Spec.Backends, 2)
		assert.Equal(t, "backend-1", cfg.Spec.Backends[0].Name)
		assert.Equal(t, "backend-2", cfg.Spec.Backends[1].Name)
	})

	t.Run("validate rate limit config", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		require.NotNil(t, cfg.Spec.RateLimit)
		assert.True(t, cfg.Spec.RateLimit.Enabled)
		assert.Equal(t, 100, cfg.Spec.RateLimit.RequestsPerSecond)
		assert.Equal(t, 200, cfg.Spec.RateLimit.Burst)
	})

	t.Run("validate circuit breaker config", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		require.NotNil(t, cfg.Spec.CircuitBreaker)
		assert.True(t, cfg.Spec.CircuitBreaker.Enabled)
		assert.Equal(t, 5, cfg.Spec.CircuitBreaker.Threshold)
	})

	t.Run("validate CORS config", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		require.NotNil(t, cfg.Spec.CORS)
		assert.Contains(t, cfg.Spec.CORS.AllowOrigins, "*")
		assert.Contains(t, cfg.Spec.CORS.AllowMethods, "GET")
		assert.Contains(t, cfg.Spec.CORS.AllowMethods, "POST")
	})

	t.Run("invalid configuration - missing apiVersion", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			Kind: "Gateway",
			Metadata: config.Metadata{
				Name: "test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "apiVersion")
	})

	t.Run("invalid configuration - missing listeners", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "test",
			},
			Spec: config.GatewaySpec{},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "listener")
	})

	t.Run("invalid configuration - invalid port", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: -1, Protocol: "HTTP"},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "port")
	})

	t.Run("invalid configuration - duplicate route names", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "route1",
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "localhost", Port: 8080}},
						},
					},
					{
						Name: "route1",
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "localhost", Port: 8081}},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate")
	})
}

func TestFunctional_Config_EnvironmentVariables(t *testing.T) {
	t.Parallel()

	t.Run("substitute environment variables", func(t *testing.T) {
		t.Parallel()

		yamlContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: ${TEST_GATEWAY_NAME:-default-gateway}
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
		reader := strings.NewReader(yamlContent)
		cfg, err := config.LoadConfigFromReader(reader)
		require.NoError(t, err)

		// Should use default value since TEST_GATEWAY_NAME is not set
		assert.Equal(t, "default-gateway", cfg.Metadata.Name)
	})
}

func TestFunctional_Config_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	require.NotNil(t, cfg)

	assert.Equal(t, "gateway.avapigw.io/v1", cfg.APIVersion)
	assert.Equal(t, "Gateway", cfg.Kind)
	assert.Equal(t, "default-gateway", cfg.Metadata.Name)
	assert.Len(t, cfg.Spec.Listeners, 1)
	assert.Equal(t, 8080, cfg.Spec.Listeners[0].Port)
}

func TestFunctional_Config_MergeConfigs(t *testing.T) {
	t.Parallel()

	base := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "base-gateway",
			Labels: map[string]string{
				"env": "dev",
			},
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP"},
			},
		},
	}

	override := &config.GatewayConfig{
		Metadata: config.Metadata{
			Name: "override-gateway",
			Labels: map[string]string{
				"version": "v1",
			},
		},
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{Name: "new-route"},
			},
		},
	}

	merged := config.MergeConfigs(base, override)
	require.NotNil(t, merged)

	assert.Equal(t, "override-gateway", merged.Metadata.Name)
	assert.Equal(t, "dev", merged.Metadata.Labels["env"])
	assert.Equal(t, "v1", merged.Metadata.Labels["version"])
	assert.Len(t, merged.Spec.Routes, 1)
}

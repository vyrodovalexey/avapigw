// Package main provides iteration 2 unit tests for coverage improvement.
package main

import (
	"context"
	"os"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================
// loadAndValidateConfig: config with TLS 1.0 warnings
// ============================================================

func TestLoadAndValidateConfig_WithWarnings(t *testing.T) {
	// Create a config file that produces validation warnings.
	// TLS 1.0 is deprecated and should produce a warning.
	tmpDir := t.TempDir()
	configPath := tmpDir + "/gateway.yaml"

	configContent := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test-gateway-warnings
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
      tls:
        certFile: /tmp/cert.pem
        keyFile: /tmp/key.pem
        minVersion: "1.0"
  routes: []
  backends: []
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	logger := observability.NopLogger()
	cfg := loadAndValidateConfig(configPath, logger)

	// The config should load successfully (warnings are not errors)
	assert.NotNil(t, cfg)
	assert.Equal(t, "test-gateway-warnings", cfg.Metadata.Name)
}

// ============================================================
// grpcConfigChanged: DeepEqual catches destination changes
// ============================================================

func TestGrpcConfigChanged_DeepEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		oldCfg   *config.GatewayConfig
		newCfg   *config.GatewayConfig
		expected bool
	}{
		{
			name: "same route name but different destination host",
			oldCfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					GRPCRoutes: []config.GRPCRoute{
						{
							Name: "route-a",
							Match: []config.GRPCRouteMatch{
								{Service: &config.StringMatch{Exact: "test.Service"}},
							},
							Route: []config.RouteDestination{
								{Destination: config.Destination{Host: "host-a", Port: 50052}},
							},
						},
					},
				},
			},
			newCfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					GRPCRoutes: []config.GRPCRoute{
						{
							Name: "route-a",
							Match: []config.GRPCRouteMatch{
								{Service: &config.StringMatch{Exact: "test.Service"}},
							},
							Route: []config.RouteDestination{
								{Destination: config.Destination{Host: "host-b", Port: 50052}},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "same route name but different destination port",
			oldCfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					GRPCRoutes: []config.GRPCRoute{
						{
							Name: "route-a",
							Match: []config.GRPCRouteMatch{
								{Service: &config.StringMatch{Exact: "test.Service"}},
							},
							Route: []config.RouteDestination{
								{Destination: config.Destination{Host: "host-a", Port: 50052}},
							},
						},
					},
				},
			},
			newCfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					GRPCRoutes: []config.GRPCRoute{
						{
							Name: "route-a",
							Match: []config.GRPCRouteMatch{
								{Service: &config.StringMatch{Exact: "test.Service"}},
							},
							Route: []config.RouteDestination{
								{Destination: config.Destination{Host: "host-a", Port: 60000}},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "same backend name but different host address",
			oldCfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					GRPCBackends: []config.GRPCBackend{
						{
							Name: "backend-a",
							Hosts: []config.BackendHost{
								{Address: "10.0.0.1", Port: 50052},
							},
						},
					},
				},
			},
			newCfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					GRPCBackends: []config.GRPCBackend{
						{
							Name: "backend-a",
							Hosts: []config.BackendHost{
								{Address: "10.0.0.2", Port: 50052},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "identical routes and backends",
			oldCfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					GRPCRoutes: []config.GRPCRoute{
						{
							Name: "route-a",
							Match: []config.GRPCRouteMatch{
								{Service: &config.StringMatch{Exact: "test.Service"}},
							},
							Route: []config.RouteDestination{
								{Destination: config.Destination{Host: "host-a", Port: 50052}},
							},
						},
					},
					GRPCBackends: []config.GRPCBackend{
						{
							Name: "backend-a",
							Hosts: []config.BackendHost{
								{Address: "10.0.0.1", Port: 50052},
							},
						},
					},
				},
			},
			newCfg: &config.GatewayConfig{
				Spec: config.GatewaySpec{
					GRPCRoutes: []config.GRPCRoute{
						{
							Name: "route-a",
							Match: []config.GRPCRouteMatch{
								{Service: &config.StringMatch{Exact: "test.Service"}},
							},
							Route: []config.RouteDestination{
								{Destination: config.Destination{Host: "host-a", Port: 50052}},
							},
						},
					},
					GRPCBackends: []config.GRPCBackend{
						{
							Name: "backend-a",
							Hosts: []config.BackendHost{
								{Address: "10.0.0.1", Port: 50052},
							},
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := grpcConfigChanged(tt.oldCfg, tt.newCfg)
			assert.Equal(t, tt.expected, result)

			// Also verify that reflect.DeepEqual is consistent
			if !tt.expected {
				assert.True(t, reflect.DeepEqual(tt.oldCfg.Spec.GRPCRoutes, tt.newCfg.Spec.GRPCRoutes))
				assert.True(t, reflect.DeepEqual(tt.oldCfg.Spec.GRPCBackends, tt.newCfg.Spec.GRPCBackends))
			}
		})
	}
}

// ============================================================
// initVaultClient: missing address (fast failure path)
// ============================================================

// TestInitVaultClient_MissingAddress tests initVaultClient when VAULT_ADDR is empty.
// Not parallel — modifies package-level exitFunc and environment variables.
func TestInitVaultClient_MissingAddress(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	// Save and restore env vars
	origAddr := os.Getenv("VAULT_ADDR")
	origToken := os.Getenv("VAULT_TOKEN")
	origAuthMethod := os.Getenv("VAULT_AUTH_METHOD")
	defer func() {
		os.Setenv("VAULT_ADDR", origAddr)
		os.Setenv("VAULT_TOKEN", origToken)
		os.Setenv("VAULT_AUTH_METHOD", origAuthMethod)
	}()

	os.Setenv("VAULT_ADDR", "")
	os.Setenv("VAULT_TOKEN", "test-token")
	os.Unsetenv("VAULT_AUTH_METHOD")

	logger := observability.NopLogger()

	// initVaultClient should fail because VAULT_ADDR is empty
	client := initVaultClient(logger)

	// The vault client creation should fail (empty address)
	// and call fatalWithSync -> exitFunc(1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, client)
}

// ============================================================
// getEnvOrDefault: verify env var priority
// ============================================================

func TestGetEnvOrDefault_Priority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		key          string
		envValue     string
		setEnv       bool
		defaultValue string
		expected     string
	}{
		{
			name:         "env var takes priority over default",
			key:          "TEST_ITER2_PRIORITY_1",
			envValue:     "from-env",
			setEnv:       true,
			defaultValue: "from-default",
			expected:     "from-env",
		},
		{
			name:         "default used when env not set",
			key:          "TEST_ITER2_PRIORITY_2",
			setEnv:       false,
			defaultValue: "fallback",
			expected:     "fallback",
		},
		{
			name:         "empty env var returns default",
			key:          "TEST_ITER2_PRIORITY_3",
			envValue:     "",
			setEnv:       true,
			defaultValue: "non-empty-default",
			expected:     "non-empty-default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer os.Unsetenv(tt.key)

			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
			}

			result := getEnvOrDefault(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================
// startMetricsServerIfEnabled: disabled and enabled paths
// ============================================================

func TestStartMetricsServerIfEnabled_Disabled_NilObservability(t *testing.T) {
	app := &application{
		config: &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Observability: nil,
			},
		},
	}

	logger := observability.NopLogger()
	startMetricsServerIfEnabled(app, logger)
	assert.Nil(t, app.metricsServer)
}

func TestStartMetricsServerIfEnabled_Disabled_NilMetrics(t *testing.T) {
	app := &application{
		config: &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Observability: &config.ObservabilityConfig{
					Metrics: nil,
				},
			},
		},
	}

	logger := observability.NopLogger()
	startMetricsServerIfEnabled(app, logger)
	assert.Nil(t, app.metricsServer)
}

func TestStartMetricsServerIfEnabled_Disabled_MetricsDisabled(t *testing.T) {
	app := &application{
		config: &config.GatewayConfig{
			Spec: config.GatewaySpec{
				Observability: &config.ObservabilityConfig{
					Metrics: &config.MetricsConfig{
						Enabled: false,
					},
				},
			},
		},
	}

	logger := observability.NopLogger()
	startMetricsServerIfEnabled(app, logger)
	assert.Nil(t, app.metricsServer)
}

// ============================================================
// startConfigWatcher: error path when watcher.Start fails
// ============================================================

// TestStartConfigWatcher_ReturnsWatcher verifies that startConfigWatcher
// returns a non-nil watcher for a valid config path.
func TestStartConfigWatcher_ReturnsWatcher(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/gateway.yaml"

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
  routes: []
  backends: []
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test-watcher")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	app := &application{
		gateway: gw,
		config:  cfg,
	}

	watcher := startConfigWatcher(context.Background(), app, configPath, logger)
	assert.NotNil(t, watcher)

	if watcher != nil {
		_ = watcher.Stop()
	}
}

// Note: initApplication with Vault TLS is not tested here because
// initVaultClient requires network access to a Vault server.
// The needsVaultTLS function is already tested in vault_wiring_test.go.

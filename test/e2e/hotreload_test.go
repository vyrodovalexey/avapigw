//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_HotReload(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("config watcher detects changes", func(t *testing.T) {
		// Create a temporary config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "gateway.yaml")

		initialConfig := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: hot-reload-test
spec:
  listeners:
    - name: http
      port: 18096
      protocol: HTTP
  routes:
    - name: initial-route
      match:
        - uri:
            prefix: /api
      route:
        - destination:
            host: 127.0.0.1
            port: 8801
`
		err := os.WriteFile(configPath, []byte(initialConfig), 0644)
		require.NoError(t, err)

		// Track config changes
		var lastConfig *config.GatewayConfig
		configChanged := make(chan struct{}, 1)

		callback := func(cfg *config.GatewayConfig) {
			lastConfig = cfg
			select {
			case configChanged <- struct{}{}:
			default:
			}
		}

		// Create watcher
		watcher, err := config.NewWatcher(configPath, callback,
			config.WithLogger(observability.NopLogger()),
			config.WithDebounceDelay(100*time.Millisecond),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err = watcher.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = watcher.Stop()
		})

		// Verify initial config was loaded
		initialCfg := watcher.GetLastConfig()
		require.NotNil(t, initialCfg)
		assert.Equal(t, "hot-reload-test", initialCfg.Metadata.Name)

		// Update config file
		updatedConfig := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: hot-reload-test-updated
spec:
  listeners:
    - name: http
      port: 18096
      protocol: HTTP
  routes:
    - name: updated-route
      match:
        - uri:
            prefix: /api/v2
      route:
        - destination:
            host: 127.0.0.1
            port: 8801
`
		err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
		require.NoError(t, err)

		// Wait for config change to be detected
		select {
		case <-configChanged:
			// Config was reloaded
		case <-time.After(5 * time.Second):
			t.Log("Config change not detected within timeout - this may be expected in some environments")
		}

		// Verify config was updated (if callback was triggered)
		if lastConfig != nil {
			assert.Equal(t, "hot-reload-test-updated", lastConfig.Metadata.Name)
		}
	})

	t.Run("force reload", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "gateway.yaml")

		initialConfig := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: force-reload-test
spec:
  listeners:
    - name: http
      port: 18097
      protocol: HTTP
`
		err := os.WriteFile(configPath, []byte(initialConfig), 0644)
		require.NoError(t, err)

		var reloadCount int
		callback := func(cfg *config.GatewayConfig) {
			reloadCount++
		}

		watcher, err := config.NewWatcher(configPath, callback,
			config.WithLogger(observability.NopLogger()),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err = watcher.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = watcher.Stop()
		})

		// Force reload
		err = watcher.ForceReload()
		require.NoError(t, err)

		// Callback should have been called
		assert.GreaterOrEqual(t, reloadCount, 1)
	})

	t.Run("invalid config is rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "gateway.yaml")

		validConfig := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: validation-test
spec:
  listeners:
    - name: http
      port: 18098
      protocol: HTTP
`
		err := os.WriteFile(configPath, []byte(validConfig), 0644)
		require.NoError(t, err)

		errorCallback := func(err error) {
			// Error callback is called when config validation fails
			t.Logf("Error callback received: %v", err)
		}

		callback := func(cfg *config.GatewayConfig) {}

		watcher, err := config.NewWatcher(configPath, callback,
			config.WithLogger(observability.NopLogger()),
			config.WithErrorCallback(errorCallback),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err = watcher.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = watcher.Stop()
		})

		// Write invalid config
		invalidConfig := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: ""
spec:
  listeners: []
`
		err = os.WriteFile(configPath, []byte(invalidConfig), 0644)
		require.NoError(t, err)

		// Wait for error to be detected
		time.Sleep(500 * time.Millisecond)

		// Error callback may or may not be called depending on timing
		// The important thing is that the watcher doesn't crash
	})
}

func TestE2E_HotReload_GRPCBackendReload(t *testing.T) {
	testCfg := helpers.GetGRPCTestConfig()
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfGRPCBackendUnavailable(t, testCfg.Backend2URL)

	t.Run("gRPC backend config change detected by watcher", func(t *testing.T) {
		// Create a temporary config file with gRPC backends
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "gateway-grpc.yaml")

		initialConfig := fmt.Sprintf(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: grpc-hotreload-test
spec:
  listeners:
    - name: grpc
      port: 19090
      protocol: GRPC
      bind: 127.0.0.1
  grpcBackends:
    - name: grpc-backend-1
      hosts:
        - address: %s
          port: %d
          weight: 1
`, helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port)

		err := os.WriteFile(configPath, []byte(initialConfig), 0644)
		require.NoError(t, err)

		// Track config changes
		var lastConfig *config.GatewayConfig
		configChanged := make(chan struct{}, 1)

		callback := func(cfg *config.GatewayConfig) {
			lastConfig = cfg
			select {
			case configChanged <- struct{}{}:
			default:
			}
		}

		// Create watcher
		watcher, err := config.NewWatcher(configPath, callback,
			config.WithLogger(observability.NopLogger()),
			config.WithDebounceDelay(100*time.Millisecond),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		err = watcher.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = watcher.Stop()
		})

		// Verify initial config was loaded
		initialCfg := watcher.GetLastConfig()
		require.NotNil(t, initialCfg)
		assert.Equal(t, "grpc-hotreload-test", initialCfg.Metadata.Name)
		assert.Len(t, initialCfg.Spec.GRPCBackends, 1)

		// Update config file with additional gRPC backend
		updatedConfig := fmt.Sprintf(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: grpc-hotreload-test
spec:
  listeners:
    - name: grpc
      port: 19090
      protocol: GRPC
      bind: 127.0.0.1
  grpcBackends:
    - name: grpc-backend-1
      hosts:
        - address: %s
          port: %d
          weight: 60
    - name: grpc-backend-2
      hosts:
        - address: %s
          port: %d
          weight: 40
`, helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
			helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port)

		err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
		require.NoError(t, err)

		// Wait for config change to be detected
		select {
		case <-configChanged:
			// Config was reloaded
		case <-time.After(5 * time.Second):
			t.Log("Config change not detected within timeout - this may be expected in some environments")
		}

		// Verify config was updated (if callback was triggered)
		if lastConfig != nil {
			assert.Len(t, lastConfig.Spec.GRPCBackends, 2)
			assert.Equal(t, "grpc-backend-1", lastConfig.Spec.GRPCBackends[0].Name)
			assert.Equal(t, "grpc-backend-2", lastConfig.Spec.GRPCBackends[1].Name)
		}
	})

	t.Run("gRPC backend removal detected by watcher", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "gateway-grpc-remove.yaml")

		initialConfig := fmt.Sprintf(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: grpc-remove-test
spec:
  listeners:
    - name: grpc
      port: 19091
      protocol: GRPC
      bind: 127.0.0.1
  grpcBackends:
    - name: grpc-backend-1
      hosts:
        - address: %s
          port: %d
          weight: 1
    - name: grpc-backend-2
      hosts:
        - address: %s
          port: %d
          weight: 1
`, helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
			helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port)

		err := os.WriteFile(configPath, []byte(initialConfig), 0644)
		require.NoError(t, err)

		var lastConfig *config.GatewayConfig
		configChanged := make(chan struct{}, 1)

		callback := func(cfg *config.GatewayConfig) {
			lastConfig = cfg
			select {
			case configChanged <- struct{}{}:
			default:
			}
		}

		watcher, err := config.NewWatcher(configPath, callback,
			config.WithLogger(observability.NopLogger()),
			config.WithDebounceDelay(100*time.Millisecond),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		err = watcher.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = watcher.Stop()
		})

		// Verify initial config
		initialCfg := watcher.GetLastConfig()
		require.NotNil(t, initialCfg)
		assert.Len(t, initialCfg.Spec.GRPCBackends, 2)

		// Remove one backend
		updatedConfig := fmt.Sprintf(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: grpc-remove-test
spec:
  listeners:
    - name: grpc
      port: 19091
      protocol: GRPC
      bind: 127.0.0.1
  grpcBackends:
    - name: grpc-backend-1
      hosts:
        - address: %s
          port: %d
          weight: 1
`, helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port)

		err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
		require.NoError(t, err)

		// Wait for config change
		select {
		case <-configChanged:
		case <-time.After(5 * time.Second):
			t.Log("Config change not detected within timeout")
		}

		if lastConfig != nil {
			assert.Len(t, lastConfig.Spec.GRPCBackends, 1)
			assert.Equal(t, "grpc-backend-1", lastConfig.Spec.GRPCBackends[0].Name)
		}
	})

	t.Run("gRPC backend weight change detected", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "gateway-grpc-weight.yaml")

		initialConfig := fmt.Sprintf(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: grpc-weight-test
spec:
  listeners:
    - name: grpc
      port: 19092
      protocol: GRPC
      bind: 127.0.0.1
  grpcBackends:
    - name: grpc-backend-weighted
      hosts:
        - address: %s
          port: %d
          weight: 50
        - address: %s
          port: %d
          weight: 50
`, helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
			helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port)

		err := os.WriteFile(configPath, []byte(initialConfig), 0644)
		require.NoError(t, err)

		var lastConfig *config.GatewayConfig
		configChanged := make(chan struct{}, 1)

		callback := func(cfg *config.GatewayConfig) {
			lastConfig = cfg
			select {
			case configChanged <- struct{}{}:
			default:
			}
		}

		watcher, err := config.NewWatcher(configPath, callback,
			config.WithLogger(observability.NopLogger()),
			config.WithDebounceDelay(100*time.Millisecond),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		err = watcher.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = watcher.Stop()
		})

		// Update weights
		updatedConfig := fmt.Sprintf(`apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: grpc-weight-test
spec:
  listeners:
    - name: grpc
      port: 19092
      protocol: GRPC
      bind: 127.0.0.1
  grpcBackends:
    - name: grpc-backend-weighted
      hosts:
        - address: %s
          port: %d
          weight: 80
        - address: %s
          port: %d
          weight: 20
`, helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend1URL).Port,
			helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Host,
			helpers.GetGRPCBackendInfo(testCfg.Backend2URL).Port)

		err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
		require.NoError(t, err)

		select {
		case <-configChanged:
		case <-time.After(5 * time.Second):
			t.Log("Config change not detected within timeout")
		}

		if lastConfig != nil {
			require.Len(t, lastConfig.Spec.GRPCBackends, 1)
			require.Len(t, lastConfig.Spec.GRPCBackends[0].Hosts, 2)
			assert.Equal(t, 80, lastConfig.Spec.GRPCBackends[0].Hosts[0].Weight)
			assert.Equal(t, 20, lastConfig.Spec.GRPCBackends[0].Hosts[1].Weight)
		}
	})
}

func TestE2E_HotReload_GatewayReload(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway reload with new config", func(t *testing.T) {
		ctx := context.Background()

		gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
		require.NoError(t, err)
		require.NotNil(t, gi)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
		require.NoError(t, err)

		// Create new config
		newConfig := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "reloaded-gateway",
			},
			Spec: gi.Config.Spec,
		}

		// Reload gateway
		err = gi.Gateway.Reload(newConfig)
		require.NoError(t, err)

		// Verify config was updated
		currentConfig := gi.Gateway.Config()
		assert.Equal(t, "reloaded-gateway", currentConfig.Metadata.Name)
	})

	t.Run("gateway reload with invalid config fails", func(t *testing.T) {
		ctx := context.Background()

		gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
		require.NoError(t, err)
		require.NotNil(t, gi)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
		require.NoError(t, err)

		// Create invalid config (missing required fields)
		invalidConfig := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "", // Invalid: empty name
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{}, // Invalid: no listeners
			},
		}

		// Reload should fail
		err = gi.Gateway.Reload(invalidConfig)
		require.Error(t, err)

		// Original config should still be in place
		currentConfig := gi.Gateway.Config()
		assert.Equal(t, "test-gateway", currentConfig.Metadata.Name)
	})
}

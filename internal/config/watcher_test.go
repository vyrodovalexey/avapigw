package config

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// validConfigYAML is a minimal valid configuration for testing
const validConfigYAML = `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test-gateway
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  routes:
    - name: test-route
      match:
        - uri:
            prefix: /
      route:
        - destination:
            host: localhost
            port: 8081
  backends:
    - name: test-backend
      hosts:
        - address: localhost
          port: 8081
`

// invalidConfigYAML is an invalid configuration for testing error handling
const invalidConfigYAML = `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test-gateway
spec:
  listeners:
    - name: ""
      port: -1
`

func TestNewWatcher(t *testing.T) {
	t.Parallel()

	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)
	require.NotNil(t, watcher)

	assert.Equal(t, configPath, watcher.path)
	assert.NotNil(t, watcher.callback)
	assert.Equal(t, 100*time.Millisecond, watcher.debounceDelay)
}

func TestNewWatcher_WithOptions(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}
	logger := observability.NopLogger()
	errorCallback := func(err error) {}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(200*time.Millisecond),
		WithLogger(logger),
		WithErrorCallback(errorCallback),
	)
	require.NoError(t, err)
	require.NotNil(t, watcher)

	assert.Equal(t, 200*time.Millisecond, watcher.debounceDelay)
	assert.Equal(t, logger, watcher.logger)
	assert.NotNil(t, watcher.errorCallback)
}

func TestWatcher_Start(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	var callbackCalled atomic.Bool
	callback := func(cfg *GatewayConfig) {
		callbackCalled.Store(true)
	}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(10*time.Millisecond),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Verify initial config was loaded
	cfg := watcher.GetLastConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, "test-gateway", cfg.Metadata.Name)

	// Stop the watcher
	err = watcher.Stop()
	require.NoError(t, err)
}

func TestWatcher_Start_AlreadyRunning(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Start again should return nil (already running)
	err = watcher.Start(ctx)
	assert.NoError(t, err)

	err = watcher.Stop()
	require.NoError(t, err)
}

func TestWatcher_Start_InvalidConfig(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(invalidConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	ctx := context.Background()
	err = watcher.Start(ctx)
	assert.Error(t, err)
}

func TestWatcher_Start_FileNotFound(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nonexistent.yaml")

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	ctx := context.Background()
	err = watcher.Start(ctx)
	assert.Error(t, err)
}

func TestWatcher_Stop_NotRunning(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	// Stop without starting should return nil
	err = watcher.Stop()
	assert.NoError(t, err)
}

func TestWatcher_GetLastConfig(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	// Before start, should return nil
	cfg := watcher.GetLastConfig()
	assert.Nil(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// After start, should return config
	cfg = watcher.GetLastConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, "test-gateway", cfg.Metadata.Name)

	err = watcher.Stop()
	require.NoError(t, err)
}

func TestWatcher_FileChange(t *testing.T) {
	// Not parallel due to file system operations and timing

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	var mu sync.Mutex
	var receivedConfig *GatewayConfig
	callbackCalled := make(chan struct{}, 1)

	callback := func(cfg *GatewayConfig) {
		mu.Lock()
		receivedConfig = cfg
		mu.Unlock()
		select {
		case callbackCalled <- struct{}{}:
		default:
		}
	}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(50*time.Millisecond),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Modify the config file
	updatedConfig := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: updated-gateway
spec:
  listeners:
    - name: http
      port: 9090
      protocol: HTTP
  routes:
    - name: updated-route
      match:
        - uri:
            prefix: /
      route:
        - destination:
            host: localhost
            port: 8081
  backends:
    - name: test-backend
      hosts:
        - address: localhost
          port: 8081
`
	// Wait a bit before modifying to ensure watcher is ready
	time.Sleep(100 * time.Millisecond)

	err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
	require.NoError(t, err)

	// Wait for callback to be called
	select {
	case <-callbackCalled:
		mu.Lock()
		assert.NotNil(t, receivedConfig)
		assert.Equal(t, "updated-gateway", receivedConfig.Metadata.Name)
		mu.Unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("callback was not called after file change")
	}

	err = watcher.Stop()
	require.NoError(t, err)
}

func TestWatcher_FileChange_InvalidConfig(t *testing.T) {
	// Not parallel due to file system operations and timing

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	var errorReceived atomic.Bool
	errorCallback := func(err error) {
		errorReceived.Store(true)
	}

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(50*time.Millisecond),
		WithErrorCallback(errorCallback),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait a bit before modifying
	time.Sleep(100 * time.Millisecond)

	// Write invalid config
	err = os.WriteFile(configPath, []byte(invalidConfigYAML), 0644)
	require.NoError(t, err)

	// Wait for error callback
	time.Sleep(500 * time.Millisecond)

	assert.True(t, errorReceived.Load(), "error callback should have been called")

	err = watcher.Stop()
	require.NoError(t, err)
}

func TestWatcher_ContextCancellation(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Cancel context
	cancel()

	// Give some time for the watcher to stop
	time.Sleep(100 * time.Millisecond)

	// Watcher should have stopped
	err = watcher.Stop()
	assert.NoError(t, err)
}

func TestWatcher_ForceReload(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	var callbackCount atomic.Int32
	callback := func(cfg *GatewayConfig) {
		callbackCount.Add(1)
	}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	// ForceReload without starting
	err = watcher.ForceReload()
	require.NoError(t, err)

	// Callback should have been called
	assert.Equal(t, int32(1), callbackCount.Load())

	// Config should be loaded
	cfg := watcher.GetLastConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, "test-gateway", cfg.Metadata.Name)
}

func TestWatcher_ForceReload_InvalidConfig(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(invalidConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	err = watcher.ForceReload()
	assert.Error(t, err)
}

func TestWatcher_ForceReload_FileNotFound(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create watcher with valid path first
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	// Remove the file
	err = os.Remove(configPath)
	require.NoError(t, err)

	// ForceReload should fail
	err = watcher.ForceReload()
	assert.Error(t, err)
}

func TestWithDebounceDelay(t *testing.T) {
	t.Parallel()

	w := &Watcher{}
	opt := WithDebounceDelay(500 * time.Millisecond)
	opt(w)

	assert.Equal(t, 500*time.Millisecond, w.debounceDelay)
}

func TestWithLogger(t *testing.T) {
	t.Parallel()

	w := &Watcher{}
	logger := observability.NopLogger()
	opt := WithLogger(logger)
	opt(w)

	assert.Equal(t, logger, w.logger)
}

func TestWithErrorCallback(t *testing.T) {
	t.Parallel()

	w := &Watcher{}
	var called bool
	errorCallback := func(err error) {
		called = true
	}
	opt := WithErrorCallback(errorCallback)
	opt(w)

	assert.NotNil(t, w.errorCallback)
	w.errorCallback(nil)
	assert.True(t, called)
}

func TestWatcher_HandleWatchError(t *testing.T) {
	t.Parallel()

	var errorReceived error
	errorCallback := func(err error) {
		errorReceived = err
	}

	w := &Watcher{
		logger:        observability.NopLogger(),
		errorCallback: errorCallback,
	}

	testErr := assert.AnError
	w.handleWatchError(testErr)

	assert.Equal(t, testErr, errorReceived)
}

func TestWatcher_HandleWatchError_NoCallback(t *testing.T) {
	t.Parallel()

	w := &Watcher{
		logger:        observability.NopLogger(),
		errorCallback: nil,
	}

	// Should not panic
	w.handleWatchError(assert.AnError)
}

func TestWatcher_ForceReload_NilCallback(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	watcher, err := NewWatcher(configPath, nil)
	require.NoError(t, err)

	// ForceReload with nil callback should not panic
	err = watcher.ForceReload()
	require.NoError(t, err)

	cfg := watcher.GetLastConfig()
	require.NotNil(t, cfg)
}

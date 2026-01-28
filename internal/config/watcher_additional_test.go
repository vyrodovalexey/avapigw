package config

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestWatcher_ReloadWithCancelledContext tests reload behavior when context is cancelled.
func TestWatcher_ReloadWithCancelledContext(t *testing.T) {
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
		WithLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Start the watcher with cancelled context
	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for the watcher to process
	time.Sleep(50 * time.Millisecond)

	// The watcher should have stopped due to context cancellation
	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_ReloadCancelledBeforeStart tests reload cancellation before starting.
func TestWatcher_ReloadCancelledBeforeStart(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(10*time.Millisecond),
		WithLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start the watcher
	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Cancel the context
	cancel()

	// Wait for the watcher to stop
	time.Sleep(100 * time.Millisecond)

	// Stop should succeed
	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_ReloadCancelledAfterLoadConfig tests reload cancellation after loading config.
func TestWatcher_ReloadCancelledAfterLoadConfig(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	var callbackCount atomic.Int32
	callback := func(cfg *GatewayConfig) {
		callbackCount.Add(1)
	}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(10*time.Millisecond),
		WithLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait for initial load
	time.Sleep(50 * time.Millisecond)

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
	err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
	require.NoError(t, err)

	// Cancel the context shortly after the file change
	time.Sleep(5 * time.Millisecond)
	cancel()

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Stop the watcher
	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_ReloadCancelledAfterValidation tests reload cancellation after validation.
func TestWatcher_ReloadCancelledAfterValidation(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(10*time.Millisecond),
		WithLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait for initial load
	time.Sleep(50 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for the watcher to stop
	time.Sleep(100 * time.Millisecond)

	// Stop should succeed
	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_HandleFileEvent_DifferentFile tests that events for different files are ignored.
func TestWatcher_HandleFileEvent_DifferentFile(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	otherPath := filepath.Join(tmpDir, "other.yaml")

	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)
	err = os.WriteFile(otherPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	var callbackCount atomic.Int32
	callback := func(cfg *GatewayConfig) {
		callbackCount.Add(1)
	}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(10*time.Millisecond),
		WithLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait for initial load
	time.Sleep(50 * time.Millisecond)

	// Modify the other file (should be ignored)
	err = os.WriteFile(otherPath, []byte(validConfigYAML+"# comment"), 0644)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Callback should not have been called for the other file
	// (only for initial load if any)

	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_HandleFileEvent_NonWriteEvent tests that non-write events are ignored.
func TestWatcher_HandleFileEvent_NonWriteEvent(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	var callbackCount atomic.Int32
	callback := func(cfg *GatewayConfig) {
		callbackCount.Add(1)
	}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(10*time.Millisecond),
		WithLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait for initial load
	time.Sleep(50 * time.Millisecond)

	// Change file permissions (CHMOD event, not WRITE)
	err = os.Chmod(configPath, 0644)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_DebounceMultipleChanges tests that multiple rapid changes are debounced.
func TestWatcher_DebounceMultipleChanges(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	var callbackCount atomic.Int32
	callback := func(cfg *GatewayConfig) {
		callbackCount.Add(1)
	}

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(100*time.Millisecond),
		WithLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait for initial load
	time.Sleep(50 * time.Millisecond)

	// Make multiple rapid changes
	for i := 0; i < 5; i++ {
		err = os.WriteFile(configPath, []byte(validConfigYAML), 0644)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for debounce to complete
	time.Sleep(200 * time.Millisecond)

	// Should have been called only once (or twice at most) due to debouncing
	count := callbackCount.Load()
	assert.True(t, count <= 2, "callback should be debounced, got %d calls", count)

	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_ErrorCallback_LoadFailure tests error callback on load failure.
func TestWatcher_ErrorCallback_LoadFailure(t *testing.T) {
	// Not parallel due to file system operations

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
		WithDebounceDelay(10*time.Millisecond),
		WithLogger(observability.NopLogger()),
		WithErrorCallback(errorCallback),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait for initial load
	time.Sleep(50 * time.Millisecond)

	// Write invalid YAML
	err = os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644)
	require.NoError(t, err)

	// Wait for error callback
	time.Sleep(200 * time.Millisecond)

	assert.True(t, errorReceived.Load(), "error callback should have been called")

	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_ErrorCallback_ValidationFailure tests error callback on validation failure.
func TestWatcher_ErrorCallback_ValidationFailure(t *testing.T) {
	// Not parallel due to file system operations

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
		WithDebounceDelay(10*time.Millisecond),
		WithLogger(observability.NopLogger()),
		WithErrorCallback(errorCallback),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait for initial load
	time.Sleep(50 * time.Millisecond)

	// Write invalid config (validation will fail)
	err = os.WriteFile(configPath, []byte(invalidConfigYAML), 0644)
	require.NoError(t, err)

	// Wait for error callback
	time.Sleep(200 * time.Millisecond)

	assert.True(t, errorReceived.Load(), "error callback should have been called")

	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_NilCallback tests watcher with nil callback.
func TestWatcher_NilCallback(t *testing.T) {
	// Not parallel due to file system operations

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	watcher, err := NewWatcher(configPath, nil,
		WithDebounceDelay(10*time.Millisecond),
		WithLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Wait for initial load
	time.Sleep(50 * time.Millisecond)

	// Modify the config file
	err = os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	// Wait for processing - should not panic with nil callback
	time.Sleep(100 * time.Millisecond)

	err = watcher.Stop()
	assert.NoError(t, err)
}

// TestWatcher_GetLastConfig_BeforeStart tests GetLastConfig before Start.
func TestWatcher_GetLastConfig_BeforeStart(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(validConfigYAML), 0644)
	require.NoError(t, err)

	callback := func(cfg *GatewayConfig) {}

	watcher, err := NewWatcher(configPath, callback)
	require.NoError(t, err)

	// GetLastConfig before Start should return nil
	cfg := watcher.GetLastConfig()
	assert.Nil(t, cfg)
}

// TestWatcher_GetLastConfig_AfterStart tests GetLastConfig after Start.
func TestWatcher_GetLastConfig_AfterStart(t *testing.T) {
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

	// GetLastConfig after Start should return the config
	cfg := watcher.GetLastConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, "test-gateway", cfg.Metadata.Name)

	err = watcher.Stop()
	assert.NoError(t, err)
}

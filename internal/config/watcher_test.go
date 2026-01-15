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
	"go.uber.org/zap"
)

func TestNewConfigWatcher(t *testing.T) {
	t.Parallel()

	t.Run("valid watcher", func(t *testing.T) {
		t.Parallel()

		callback := func(cfg *LocalConfig) error {
			return nil
		}

		watcher, err := NewConfigWatcher("/path/to/config.yaml", callback)
		require.NoError(t, err)
		assert.NotNil(t, watcher)
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		callback := func(cfg *LocalConfig) error {
			return nil
		}

		_, err := NewConfigWatcher("", callback)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConfigPathEmpty)
	})

	t.Run("nil callback", func(t *testing.T) {
		t.Parallel()

		_, err := NewConfigWatcher("/path/to/config.yaml", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrCallbackNil)
	})

	t.Run("with options", func(t *testing.T) {
		t.Parallel()

		callback := func(cfg *LocalConfig) error {
			return nil
		}

		logger := zap.NewNop()
		watcher, err := NewConfigWatcher(
			"/path/to/config.yaml",
			callback,
			WithDebounce(1*time.Second),
			WithLogger(logger),
		)
		require.NoError(t, err)
		assert.NotNil(t, watcher)
		assert.Equal(t, 1*time.Second, watcher.debounce)
	})
}

func TestConfigWatcher_StartStop(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a valid config file
	configContent := `
gateway:
  name: test-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	var callbackCalled atomic.Int32
	callback := func(cfg *LocalConfig) error {
		callbackCalled.Add(1)
		return nil
	}

	watcher, err := NewConfigWatcher(
		configPath,
		callback,
		WithDebounce(100*time.Millisecond),
		WithLogger(zap.NewNop()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start watcher in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- watcher.Start(ctx)
	}()

	// Wait for initial load
	time.Sleep(200 * time.Millisecond)

	// Verify initial callback was called
	assert.GreaterOrEqual(t, callbackCalled.Load(), int32(1))

	// Stop the watcher
	err = watcher.Stop()
	assert.NoError(t, err)

	// Wait for watcher to stop
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("watcher did not stop in time")
	}
}

func TestConfigWatcher_HotReload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping hot reload test in short mode")
	}

	tmpDir := t.TempDir()

	// Create initial config file
	initialConfig := `
gateway:
  name: initial-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(initialConfig), 0644)
	require.NoError(t, err)

	var lastGatewayName atomic.Value
	lastGatewayName.Store("")

	var callbackCount atomic.Int32
	callback := func(cfg *LocalConfig) error {
		callbackCount.Add(1)
		lastGatewayName.Store(cfg.Gateway.Name)
		return nil
	}

	watcher, err := NewConfigWatcher(
		configPath,
		callback,
		WithDebounce(100*time.Millisecond),
		WithLogger(zap.NewNop()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start watcher in goroutine
	go func() {
		_ = watcher.Start(ctx)
	}()

	// Wait for initial load
	time.Sleep(300 * time.Millisecond)

	// Verify initial config was loaded
	assert.Equal(t, "initial-gateway", lastGatewayName.Load().(string))
	initialCount := callbackCount.Load()

	// Update the config file
	updatedConfig := `
gateway:
  name: updated-gateway
  listeners:
    - name: http
      port: 9000
      protocol: HTTP
`
	err = os.WriteFile(configPath, []byte(updatedConfig), 0644)
	require.NoError(t, err)

	// Wait for hot reload (debounce + processing time)
	time.Sleep(500 * time.Millisecond)

	// Verify config was reloaded
	assert.Equal(t, "updated-gateway", lastGatewayName.Load().(string))
	assert.Greater(t, callbackCount.Load(), initialCount)

	// Stop the watcher
	err = watcher.Stop()
	assert.NoError(t, err)
}

func TestConfigWatcher_ForceReload(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a valid config file
	configContent := `
gateway:
  name: test-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	var callbackCount atomic.Int32
	callback := func(cfg *LocalConfig) error {
		callbackCount.Add(1)
		return nil
	}

	watcher, err := NewConfigWatcher(
		configPath,
		callback,
		WithLogger(zap.NewNop()),
	)
	require.NoError(t, err)

	// Force reload without starting the watcher
	err = watcher.ForceReload()
	require.NoError(t, err)

	assert.Equal(t, int32(1), callbackCount.Load())

	// Force reload again
	err = watcher.ForceReload()
	require.NoError(t, err)

	assert.Equal(t, int32(2), callbackCount.Load())
}

func TestConfigWatcher_GetLastConfig(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a valid config file
	configContent := `
gateway:
  name: test-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	callback := func(cfg *LocalConfig) error {
		return nil
	}

	watcher, err := NewConfigWatcher(
		configPath,
		callback,
		WithLogger(zap.NewNop()),
	)
	require.NoError(t, err)

	// Before reload, last config should be nil
	assert.Nil(t, watcher.GetLastConfig())

	// Force reload
	err = watcher.ForceReload()
	require.NoError(t, err)

	// After reload, last config should be set
	lastConfig := watcher.GetLastConfig()
	assert.NotNil(t, lastConfig)
	assert.Equal(t, "test-gateway", lastConfig.Gateway.Name)
}

func TestConfigWatcher_GetLastReloadTime(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a valid config file
	configContent := `
gateway:
  name: test-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	callback := func(cfg *LocalConfig) error {
		return nil
	}

	watcher, err := NewConfigWatcher(
		configPath,
		callback,
		WithLogger(zap.NewNop()),
	)
	require.NoError(t, err)

	// Before reload, last reload time should be zero
	assert.True(t, watcher.GetLastReloadTime().IsZero())

	beforeReload := time.Now()

	// Force reload
	err = watcher.ForceReload()
	require.NoError(t, err)

	afterReload := time.Now()

	// After reload, last reload time should be set
	lastReloadTime := watcher.GetLastReloadTime()
	assert.False(t, lastReloadTime.IsZero())
	assert.True(t, lastReloadTime.After(beforeReload) || lastReloadTime.Equal(beforeReload))
	assert.True(t, lastReloadTime.Before(afterReload) || lastReloadTime.Equal(afterReload))
}

func TestConfigWatcher_IsRunning(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a valid config file
	configContent := `
gateway:
  name: test-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	callback := func(cfg *LocalConfig) error {
		return nil
	}

	watcher, err := NewConfigWatcher(
		configPath,
		callback,
		WithLogger(zap.NewNop()),
	)
	require.NoError(t, err)

	// Before start, should not be running
	assert.False(t, watcher.IsRunning())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start watcher in goroutine
	go func() {
		_ = watcher.Start(ctx)
	}()

	// Wait for watcher to start
	time.Sleep(200 * time.Millisecond)

	// Should be running now
	assert.True(t, watcher.IsRunning())

	// Stop the watcher
	err = watcher.Stop()
	assert.NoError(t, err)

	// Wait for watcher to stop
	time.Sleep(200 * time.Millisecond)

	// Should not be running anymore
	assert.False(t, watcher.IsRunning())
}

func TestConfigWatcher_DoubleStart(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a valid config file
	configContent := `
gateway:
  name: test-gateway
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	callback := func(cfg *LocalConfig) error {
		return nil
	}

	watcher, err := NewConfigWatcher(
		configPath,
		callback,
		WithLogger(zap.NewNop()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start watcher in goroutine
	go func() {
		_ = watcher.Start(ctx)
	}()

	// Wait for watcher to start
	time.Sleep(200 * time.Millisecond)

	// Try to start again - should return error
	err = watcher.Start(ctx)
	assert.ErrorIs(t, err, ErrWatcherAlreadyRunning)

	// Stop the watcher
	err = watcher.Stop()
	assert.NoError(t, err)
}

func TestConfigError(t *testing.T) {
	t.Parallel()

	t.Run("with path", func(t *testing.T) {
		t.Parallel()

		err := &ConfigError{
			Op:   "load",
			Path: "/path/to/config.yaml",
			Err:  os.ErrNotExist,
		}

		assert.Contains(t, err.Error(), "config load")
		assert.Contains(t, err.Error(), "/path/to/config.yaml")
		assert.Contains(t, err.Error(), "file does not exist")
	})

	t.Run("without path", func(t *testing.T) {
		t.Parallel()

		err := &ConfigError{
			Op:  "validate",
			Err: errConfigPathEmpty,
		}

		assert.Contains(t, err.Error(), "config validate")
		assert.Contains(t, err.Error(), "config path is empty")
	})

	t.Run("unwrap", func(t *testing.T) {
		t.Parallel()

		innerErr := os.ErrNotExist
		err := &ConfigError{
			Op:   "load",
			Path: "/path/to/config.yaml",
			Err:  innerErr,
		}

		assert.Equal(t, innerErr, err.Unwrap())
	})
}

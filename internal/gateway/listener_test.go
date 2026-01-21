package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewListener(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler)

	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, cfg, listener.config)
	assert.NotNil(t, listener.handler)
}

func TestNewListener_WithLogger(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	logger := observability.NopLogger()

	listener, err := NewListener(cfg, handler, WithListenerLogger(logger))

	require.NoError(t, err)
	assert.Equal(t, logger, listener.logger)
}

func TestListener_Name(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "my-listener",
		Port:     8080,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	assert.Equal(t, "my-listener", listener.Name())
}

func TestListener_Port(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     9090,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	assert.Equal(t, 9090, listener.Port())
}

func TestListener_Address(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   config.Listener
		expected string
	}{
		{
			name: "default bind address",
			config: config.Listener{
				Name:     "test",
				Port:     8080,
				Protocol: "HTTP",
			},
			expected: "0.0.0.0:8080",
		},
		{
			name: "custom bind address",
			config: config.Listener{
				Name:     "test",
				Port:     8080,
				Bind:     "127.0.0.1",
				Protocol: "HTTP",
			},
			expected: "127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			listener, err := NewListener(tt.config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			require.NoError(t, err)

			assert.Equal(t, tt.expected, listener.Address())
		})
	}
}

func TestListener_IsRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0, // Random port
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	assert.False(t, listener.IsRunning())
}

func TestListener_StartStop(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0, // Random port
		Protocol: "HTTP",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler)
	require.NoError(t, err)

	ctx := context.Background()

	// Start
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	// Give it time to start
	time.Sleep(10 * time.Millisecond)

	// Stop
	err = listener.Stop(ctx)
	require.NoError(t, err)

	// Give it time to stop
	time.Sleep(10 * time.Millisecond)
	assert.False(t, listener.IsRunning())
}

func TestListener_Start_AlreadyRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	// Start first time
	err = listener.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = listener.Stop(ctx) }()

	// Try to start again
	err = listener.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestListener_Stop_NotRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	// Stop without starting - should be no-op
	err = listener.Stop(ctx)
	assert.NoError(t, err)
}

func TestListener_Start_InvalidPort(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     99999, // Invalid port
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	err = listener.Start(ctx)
	assert.Error(t, err)
}

func TestListener_Stop_WithTimeout(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: "HTTP",
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	ctx := context.Background()

	err = listener.Start(ctx)
	require.NoError(t, err)

	// Stop with timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = listener.Stop(timeoutCtx)
	assert.NoError(t, err)
}

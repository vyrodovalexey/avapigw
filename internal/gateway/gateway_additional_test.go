package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestGateway_StartWithGRPCListener(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-grpc"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)

	assert.True(t, gw.IsRunning())
	assert.Len(t, gw.GetGRPCListeners(), 1)

	err = gw.Stop(ctx)
	require.NoError(t, err)
}

func TestGateway_StartWithMixedListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-mixed"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)

	assert.True(t, gw.IsRunning())
	assert.Len(t, gw.GetListeners(), 1)
	assert.Len(t, gw.GetGRPCListeners(), 1)

	err = gw.Stop(ctx)
	require.NoError(t, err)
}

func TestGateway_StopWithTimeout(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg, WithShutdownTimeout(5*time.Second))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)

	// Stop with a context that has a deadline
	stopCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err = gw.Stop(stopCtx)
	require.NoError(t, err)
	assert.False(t, gw.IsRunning())
}

func TestGateway_SetupRoutesWithHandler(t *testing.T) {
	t.Parallel()

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg, WithRouteHandler(handler))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Make a request to the gateway
	engine := gw.Engine()
	require.NotNil(t, engine)

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
}

func TestGateway_CreateListenersError(t *testing.T) {
	t.Parallel()

	// Create a config with an invalid gRPC listener that will fail
	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "grpc",
					Port:     0,
					Protocol: config.ProtocolGRPC,
					GRPC: &config.GRPCListenerConfig{
						TLS: &config.TLSConfig{
							Enabled:  true,
							Mode:     config.TLSModeSimple,
							CertFile: "/nonexistent/cert.pem",
							KeyFile:  "/nonexistent/key.pem",
						},
					},
				},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	// This should fail because the TLS cert files don't exist
	assert.Error(t, err)
	assert.Equal(t, StateStopped, gw.State())
}

func TestGateway_StopListenersWithErrors(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http1", Port: 0, Protocol: config.ProtocolHTTP},
				{Name: "http2", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)

	// Stop should handle multiple listeners gracefully
	err = gw.Stop(ctx)
	require.NoError(t, err)
}

func TestGateway_ReloadWithValidConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	// Reload with a new valid config
	newCfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "reloaded-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 9090, Protocol: config.ProtocolHTTP},
			},
		},
	}

	err = gw.Reload(newCfg)
	require.NoError(t, err)

	assert.Equal(t, "reloaded-gateway", gw.Config().Metadata.Name)
	assert.Equal(t, 9090, gw.Config().Spec.Listeners[0].Port)
}

func TestGateway_UptimeAfterStop(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	uptimeBeforeStop := gw.Uptime()
	assert.Greater(t, uptimeBeforeStop, time.Duration(0))

	err = gw.Stop(ctx)
	require.NoError(t, err)

	// Uptime should still be available after stop
	uptimeAfterStop := gw.Uptime()
	assert.Greater(t, uptimeAfterStop, time.Duration(0))
}

func TestGateway_StateTransitions(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	// Initial state should be stopped
	assert.Equal(t, StateStopped, gw.State())
	assert.Equal(t, "stopped", gw.State().String())

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)

	// After start, state should be running
	assert.Equal(t, StateRunning, gw.State())
	assert.Equal(t, "running", gw.State().String())

	err = gw.Stop(ctx)
	require.NoError(t, err)

	// After stop, state should be stopped
	assert.Equal(t, StateStopped, gw.State())
}

func TestState_StringUnknown(t *testing.T) {
	t.Parallel()

	// Test unknown state
	unknownState := State(100)
	assert.Equal(t, "unknown", unknownState.String())
}

func TestState_StringAllValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    State
		expected string
	}{
		{StateStopped, "stopped"},
		{StateStarting, "starting"},
		{StateRunning, "running"},
		{StateStopping, "stopping"},
		{State(-1), "unknown"},
		{State(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestGateway_StartFailsOnListenerError(t *testing.T) {
	t.Parallel()

	// Use an invalid port that will cause listener start to fail
	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 99999, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	assert.Error(t, err)
	assert.Equal(t, StateStopped, gw.State())
}

func TestGateway_GetGRPCListenersEmpty(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Should return empty slice for HTTP-only gateway
	grpcListeners := gw.GetGRPCListeners()
	assert.Empty(t, grpcListeners)
}

func TestGateway_ConfigConcurrentAccess(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	// Concurrent reads and writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = gw.Config()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func(idx int) {
			newCfg := &config.GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   config.Metadata{Name: "test-gateway"},
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{Name: "http", Port: 8080 + idx, Protocol: config.ProtocolHTTP},
					},
				},
			}
			_ = gw.Reload(newCfg)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

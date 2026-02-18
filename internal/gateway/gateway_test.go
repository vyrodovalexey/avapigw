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

func TestState_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    State
		expected string
	}{
		{StateStopped, "stopped"},
		{StateStarting, "starting"},
		{StateRunning, "running"},
		{StateStopping, "stopping"},
		{State(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg)

	require.NoError(t, err)
	assert.NotNil(t, gw)
	assert.Equal(t, cfg, gw.Config())
	assert.Equal(t, StateStopped, gw.State())
}

func TestNew_NilConfig(t *testing.T) {
	t.Parallel()

	gw, err := New(nil)

	assert.Error(t, err)
	assert.Nil(t, gw)
	assert.ErrorIs(t, err, ErrNilConfig)
}

func TestNew_WithOptions(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}
	logger := observability.NopLogger()

	gw, err := New(cfg,
		WithLogger(logger),
		WithShutdownTimeout(60*time.Second),
	)

	require.NoError(t, err)
	assert.Equal(t, logger, gw.logger)
	assert.Equal(t, 60*time.Second, gw.shutdownTimeout)
}

func TestNew_WithRouteHandler(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	gw, err := New(cfg, WithRouteHandler(handler))

	require.NoError(t, err)
	assert.NotNil(t, gw.routeHandler)
}

func TestGateway_State(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, StateStopped, gw.State())
}

func TestGateway_IsRunning(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, gw.IsRunning())
}

func TestGateway_Uptime_NotStarted(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, time.Duration(0), gw.Uptime())
}

func TestGateway_Config(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, cfg, gw.Config())
}

func TestGateway_Start_AlreadyStarted(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"}, // Port 0 for random port
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the gateway
	err = gw.Start(ctx)
	require.NoError(t, err)

	// Try to start again
	err = gw.Start(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrGatewayNotStopped)

	// Cleanup
	_ = gw.Stop(ctx)
}

func TestGateway_Stop_NotRunning(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Stop(ctx)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrGatewayNotRunning)
}

func TestGateway_StartStop(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"}, // Port 0 for random port
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start
	err = gw.Start(ctx)
	require.NoError(t, err)
	assert.Equal(t, StateRunning, gw.State())
	assert.True(t, gw.IsRunning())

	// Stop
	err = gw.Stop(ctx)
	require.NoError(t, err)
	assert.Equal(t, StateStopped, gw.State())
	assert.False(t, gw.IsRunning())
}

func TestGateway_Reload(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	newCfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "updated-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 9090, Protocol: "HTTP"},
			},
		},
	}

	err = gw.Reload(newCfg)
	require.NoError(t, err)

	assert.Equal(t, "updated-gateway", gw.Config().Metadata.Name)
}

func TestGateway_Reload_InvalidConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	// Invalid config - missing required fields
	invalidCfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: ""},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "", Port: -1, Protocol: "INVALID"},
			},
		},
	}

	err = gw.Reload(invalidCfg)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestGateway_Engine(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	engine := gw.Engine()
	assert.NotNil(t, engine)
}

func TestGateway_GetListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
				{Name: "https", Port: 0, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	listeners := gw.GetListeners()
	assert.Len(t, listeners, 2)
}

func TestGateway_Uptime_AfterStart(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	time.Sleep(10 * time.Millisecond)

	uptime := gw.Uptime()
	assert.Greater(t, uptime, time.Duration(0))
}

func TestGateway_GetGRPCListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	grpcListeners := gw.GetGRPCListeners()
	assert.NotNil(t, grpcListeners)
	assert.Len(t, grpcListeners, 0) // No gRPC listeners configured
}

func TestGateway_Stop_WithTimeout(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg, WithShutdownTimeout(100*time.Millisecond))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)

	// Stop with context that has no deadline
	err = gw.Stop(context.Background())
	require.NoError(t, err)
	assert.Equal(t, StateStopped, gw.State())
}

func TestGateway_Stop_WithContextDeadline(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)

	// Stop with context that has deadline
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = gw.Stop(stopCtx)
	require.NoError(t, err)
	assert.Equal(t, StateStopped, gw.State())
}

func TestGateway_Start_WithRouteHandler(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	gw, err := New(cfg, WithRouteHandler(handler))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	assert.Equal(t, StateRunning, gw.State())
}

func TestGateway_Start_FailedListener(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: -1, Protocol: "HTTP"}, // Invalid port
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	assert.Error(t, err)
	assert.Equal(t, StateStopped, gw.State())
}

func TestGateway_Engine_BeforeStart(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	// Engine should be nil before start
	engine := gw.Engine()
	assert.Nil(t, engine)
}

func TestGateway_GetListeners_BeforeStart(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	// Listeners should be nil before start
	listeners := gw.GetListeners()
	assert.Nil(t, listeners)
}

// --- ClearAllAuthCaches tests ---

func TestGateway_ClearAllAuthCaches_NoListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-no-grpc"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Gateway with no gRPC listeners should not panic
	assert.NotPanics(t, func() {
		gw.ClearAllAuthCaches()
	})
}

func TestGateway_ClearAllAuthCaches_BeforeStart(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-before-start"},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Gateway before start has nil grpcListeners slice — should not panic
	assert.NotPanics(t, func() {
		gw.ClearAllAuthCaches()
	})
}

func TestGateway_ClearAllAuthCaches_MultipleListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-multi-grpc"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "grpc-1", Port: 0, Protocol: config.ProtocolGRPC},
				{Name: "grpc-2", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Verify we have 2 gRPC listeners
	grpcListeners := gw.GetGRPCListeners()
	require.Len(t, grpcListeners, 2)

	// ClearAllAuthCaches should clear all listeners without panic
	assert.NotPanics(t, func() {
		gw.ClearAllAuthCaches()
	})
}

func TestGateway_ClearAllAuthCaches_WithHTTPAndGRPCListeners(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gateway-mixed"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
				{Name: "grpc", Port: 0, Protocol: config.ProtocolGRPC},
			},
		},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	// Verify we have 1 gRPC listener and 1 HTTP listener
	assert.Len(t, gw.GetGRPCListeners(), 1)
	assert.Len(t, gw.GetListeners(), 1)

	// ClearAllAuthCaches should only affect gRPC listeners, not panic
	assert.NotPanics(t, func() {
		gw.ClearAllAuthCaches()
	})
}

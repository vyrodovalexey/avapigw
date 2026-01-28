package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcmiddleware "github.com/vyrodovalexey/avapigw/internal/grpc/middleware"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewGRPCListener(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     config.Listener
		opts    []GRPCListenerOption
		wantErr bool
	}{
		{
			name: "basic gRPC listener",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     0, // Random port
				Protocol: config.ProtocolGRPC,
			},
			wantErr: false,
		},
		{
			name: "gRPC listener with custom bind",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     0,
				Bind:     "127.0.0.1",
				Protocol: config.ProtocolGRPC,
			},
			wantErr: false,
		},
		{
			name: "gRPC listener with logger",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     0,
				Protocol: config.ProtocolGRPC,
			},
			opts:    []GRPCListenerOption{WithGRPCListenerLogger(observability.NopLogger())},
			wantErr: false,
		},
		{
			name: "gRPC listener with custom router",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     0,
				Protocol: config.ProtocolGRPC,
			},
			opts:    []GRPCListenerOption{WithGRPCRouter(grpcrouter.New())},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			listener, err := NewGRPCListener(tt.cfg, tt.opts...)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, listener)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, listener)
				assert.Equal(t, tt.cfg.Name, listener.Name())
				assert.Equal(t, tt.cfg.Port, listener.Port())
			}
		})
	}
}

func TestGRPCListener_Name(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "my-grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	assert.Equal(t, "my-grpc-listener", listener.Name())
}

func TestGRPCListener_Port(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     50051,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	assert.Equal(t, 50051, listener.Port())
}

func TestGRPCListener_Address(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      config.Listener
		expected string
	}{
		{
			name: "default bind address",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     50051,
				Protocol: config.ProtocolGRPC,
			},
			expected: "0.0.0.0:50051",
		},
		{
			name: "custom bind address",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     50051,
				Bind:     "127.0.0.1",
				Protocol: config.ProtocolGRPC,
			},
			expected: "127.0.0.1:50051",
		},
		{
			name: "localhost bind",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     8080,
				Bind:     "localhost",
				Protocol: config.ProtocolGRPC,
			},
			expected: "localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			listener, err := NewGRPCListener(tt.cfg)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, listener.Address())
		})
	}
}

func TestGRPCListener_IsRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	// Initially not running
	assert.False(t, listener.IsRunning())
}

func TestGRPCListener_StartStop(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0, // Random port
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg, WithGRPCListenerLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()

	// Start
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	// Give it time to start
	time.Sleep(50 * time.Millisecond)

	// Stop
	err = listener.Stop(ctx)
	require.NoError(t, err)

	// Give it time to stop
	time.Sleep(50 * time.Millisecond)
	assert.False(t, listener.IsRunning())
}

func TestGRPCListener_Start_AlreadyRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg, WithGRPCListenerLogger(observability.NopLogger()))
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

func TestGRPCListener_Stop_NotRunning(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Stop without starting - should be no-op
	err = listener.Stop(ctx)
	assert.NoError(t, err)
}

func TestGRPCListener_Stop_WithTimeout(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg, WithGRPCListenerLogger(observability.NopLogger()))
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

func TestGRPCListener_Router(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	customRouter := grpcrouter.New()
	listener, err := NewGRPCListener(cfg, WithGRPCRouter(customRouter))
	require.NoError(t, err)

	assert.Equal(t, customRouter, listener.Router())
}

func TestGRPCListener_Server(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	assert.NotNil(t, listener.Server())
}

func TestGRPCListener_Proxy(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	assert.NotNil(t, listener.Proxy())
}

func TestGRPCListener_LoadRoutes(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	routes := []config.GRPCRoute{
		{
			Name: "test-route",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "test.Service"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: "localhost",
						Port: 50052,
					},
				},
			},
		},
	}

	err = listener.LoadRoutes(routes)
	assert.NoError(t, err)
}

func TestGRPCListener_IsTLSEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      config.Listener
		expected bool
	}{
		{
			name: "no TLS config",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     0,
				Protocol: config.ProtocolGRPC,
			},
			expected: false,
		},
		{
			name: "with GRPC config but no TLS",
			cfg: config.Listener{
				Name:     "grpc-listener",
				Port:     0,
				Protocol: config.ProtocolGRPC,
				GRPC:     &config.GRPCListenerConfig{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			listener, err := NewGRPCListener(tt.cfg)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, listener.IsTLSEnabled())
		})
	}
}

func TestGRPCListener_IsMTLSEnabled(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	// Without TLS config, mTLS should be disabled
	assert.False(t, listener.IsMTLSEnabled())
}

func TestGRPCListener_TLSMode(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	// Without TLS config, mode should be insecure
	assert.Equal(t, config.TLSModeInsecure, listener.TLSMode())
}

func TestGRPCListener_TLSManager(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	// Without TLS config, TLS manager should be nil
	assert.Nil(t, listener.TLSManager())
}

func TestGRPCListenerOptions(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	logger := observability.NopLogger()
	router := grpcrouter.New()

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(logger),
		WithGRPCRouter(router),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, router, listener.Router())
}

func TestGRPCListener_WithGRPCConfig(t *testing.T) {
	t.Parallel()

	grpcCfg := &config.GRPCListenerConfig{
		MaxRecvMsgSize:       4 * 1024 * 1024,
		MaxSendMsgSize:       4 * 1024 * 1024,
		MaxConcurrentStreams: 100,
	}

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
		GRPC:     grpcCfg,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)
	assert.NotNil(t, listener)
}

func TestGRPCListener_StartWithContext(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg, WithGRPCListenerLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	// Cleanup
	err = listener.Stop(context.Background())
	assert.NoError(t, err)
}

func TestGRPCListener_LoadEmptyRoutes(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	// Load empty routes should succeed
	err = listener.LoadRoutes([]config.GRPCRoute{})
	assert.NoError(t, err)
}

func TestGRPCListener_LoadNilRoutes(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	// Load nil routes should succeed
	err = listener.LoadRoutes(nil)
	assert.NoError(t, err)
}

func TestGRPCListener_MultipleRoutes(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg)
	require.NoError(t, err)

	routes := []config.GRPCRoute{
		{
			Name: "route-1",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "service1.Service"},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: "localhost",
						Port: 50052,
					},
				},
			},
		},
		{
			Name: "route-2",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Prefix: "service2."},
				},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{
						Host: "localhost",
						Port: 50053,
					},
				},
			},
		},
	}

	err = listener.LoadRoutes(routes)
	assert.NoError(t, err)
}

// ============================================================
// MUST-FIX-02: WithGRPCAuditLogger, WithGRPCRateLimiter, WithGRPCCircuitBreaker
// ============================================================

func TestWithGRPCAuditLogger(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	auditLogger := &noopAuditLogger{}
	listener, err := NewGRPCListener(cfg, WithGRPCAuditLogger(auditLogger))
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, auditLogger, listener.auditLogger)
}

func TestWithGRPCRateLimiter(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	limiter := grpcmiddleware.NewGRPCRateLimiter(100, 10, false)
	listener, err := NewGRPCListener(cfg, WithGRPCRateLimiter(limiter))
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, limiter, listener.rateLimiter)
}

func TestWithGRPCCircuitBreaker(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	cb := grpcmiddleware.NewGRPCCircuitBreaker("test", 5, 30*time.Second)
	listener, err := NewGRPCListener(cfg, WithGRPCCircuitBreaker(cb))
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, cb, listener.circuitBreaker)
}

func TestBuildInterceptors_WithAudit(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	auditLogger := &noopAuditLogger{}
	listener, err := NewGRPCListener(cfg, WithGRPCAuditLogger(auditLogger))
	require.NoError(t, err)

	// buildInterceptors is called during NewGRPCListener, so we verify
	// the listener was created successfully with audit logger set.
	assert.NotNil(t, listener)
	assert.Equal(t, auditLogger, listener.auditLogger)
}

func TestBuildInterceptors_WithRateLimiter(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	limiter := grpcmiddleware.NewGRPCRateLimiter(100, 10, false)
	listener, err := NewGRPCListener(cfg, WithGRPCRateLimiter(limiter))
	require.NoError(t, err)

	assert.NotNil(t, listener)
	assert.Equal(t, limiter, listener.rateLimiter)
}

func TestBuildInterceptors_WithCircuitBreaker(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	cb := grpcmiddleware.NewGRPCCircuitBreaker("test", 5, 30*time.Second)
	listener, err := NewGRPCListener(cfg, WithGRPCCircuitBreaker(cb))
	require.NoError(t, err)

	assert.NotNil(t, listener)
	assert.Equal(t, cb, listener.circuitBreaker)
}

func TestBuildInterceptors_AllOptional(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	auditLogger := &noopAuditLogger{}
	limiter := grpcmiddleware.NewGRPCRateLimiter(100, 10, false)
	cb := grpcmiddleware.NewGRPCCircuitBreaker("test", 5, 30*time.Second)

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCAuditLogger(auditLogger),
		WithGRPCRateLimiter(limiter),
		WithGRPCCircuitBreaker(cb),
	)
	require.NoError(t, err)

	assert.NotNil(t, listener)
	assert.Equal(t, auditLogger, listener.auditLogger)
	assert.Equal(t, limiter, listener.rateLimiter)
	assert.Equal(t, cb, listener.circuitBreaker)
}

// noopAuditLogger is a minimal audit.Logger for testing.
type noopAuditLogger struct{}

func (l *noopAuditLogger) LogEvent(_ context.Context, _ *audit.Event) {}
func (l *noopAuditLogger) LogAuthentication(_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject) {
}
func (l *noopAuditLogger) LogAuthorization(_ context.Context, _ audit.Outcome, _ *audit.Subject, _ *audit.Resource) {
}
func (l *noopAuditLogger) LogSecurity(_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject, _ map[string]interface{}) {
}
func (l *noopAuditLogger) Close() error { return nil }

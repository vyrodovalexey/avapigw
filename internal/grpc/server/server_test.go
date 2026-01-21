package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNew(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultGRPCListenerConfig()
	s, err := New(cfg)

	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, cfg, s.config)
	assert.Equal(t, StateStopped, s.State())
}

func TestNew_NilConfig(t *testing.T) {
	t.Parallel()

	s, err := New(nil)

	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, uint32(100), s.maxConcurrentStreams)
	assert.Equal(t, 4*1024*1024, s.maxRecvMsgSize)
	assert.Equal(t, 4*1024*1024, s.maxSendMsgSize)
}

func TestNew_WithOptions(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultGRPCListenerConfig()
	logger := observability.NopLogger()

	s, err := New(cfg,
		WithLogger(logger),
		WithAddress(":50051"),
		WithMaxConcurrentStreams(200),
		WithMaxRecvMsgSize(8*1024*1024),
		WithMaxSendMsgSize(8*1024*1024),
		WithReflection(true),
		WithHealthService(true),
		WithConnectionTimeout(60*time.Second),
		WithGracefulStopTimeout(15*time.Second),
	)

	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, ":50051", s.address)
	assert.Equal(t, uint32(200), s.maxConcurrentStreams)
	assert.Equal(t, 8*1024*1024, s.maxRecvMsgSize)
	assert.Equal(t, 8*1024*1024, s.maxSendMsgSize)
	assert.True(t, s.reflectionEnabled)
	assert.True(t, s.healthServiceEnabled)
	assert.Equal(t, 60*time.Second, s.connectionTimeout)
	assert.Equal(t, 15*time.Second, s.gracefulStopTimeout)
}

func TestNew_WithKeepalive(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultGRPCListenerConfig()
	kp := keepalive.ServerParameters{
		Time:    30 * time.Second,
		Timeout: 10 * time.Second,
	}
	kep := keepalive.EnforcementPolicy{
		PermitWithoutStream: true,
	}

	s, err := New(cfg,
		WithKeepaliveParams(kp),
		WithKeepaliveEnforcementPolicy(kep),
	)

	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.NotNil(t, s.keepaliveParams)
	assert.NotNil(t, s.keepaliveEnforcement)
}

func TestNew_WithInterceptors(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultGRPCListenerConfig()

	unaryInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}

	streamInterceptor := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}

	s, err := New(cfg,
		WithUnaryInterceptors(unaryInterceptor),
		WithStreamInterceptors(streamInterceptor),
	)

	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Len(t, s.unaryInterceptors, 1)
	assert.Len(t, s.streamInterceptors, 1)
}

func TestNew_WithUnknownServiceHandler(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultGRPCListenerConfig()

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	s, err := New(cfg, WithUnknownServiceHandler(handler))

	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.NotNil(t, s.unknownServiceHandler)
}

func TestNew_WithConfigKeepalive(t *testing.T) {
	t.Parallel()

	cfg := &config.GRPCListenerConfig{
		MaxConcurrentStreams: 150,
		MaxRecvMsgSize:       2 * 1024 * 1024,
		MaxSendMsgSize:       2 * 1024 * 1024,
		Keepalive: &config.GRPCKeepaliveConfig{
			Time:                  config.Duration(60 * time.Second),
			Timeout:               config.Duration(20 * time.Second),
			PermitWithoutStream:   true,
			MaxConnectionIdle:     config.Duration(10 * time.Minute),
			MaxConnectionAge:      config.Duration(1 * time.Hour),
			MaxConnectionAgeGrace: config.Duration(10 * time.Second),
		},
		Reflection:  true,
		HealthCheck: true,
	}

	s, err := New(cfg)

	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, uint32(150), s.maxConcurrentStreams)
	assert.Equal(t, 2*1024*1024, s.maxRecvMsgSize)
	assert.Equal(t, 2*1024*1024, s.maxSendMsgSize)
	assert.NotNil(t, s.keepaliveParams)
	assert.NotNil(t, s.keepaliveEnforcement)
	assert.True(t, s.reflectionEnabled)
	assert.True(t, s.healthServiceEnabled)
}

func TestServer_State(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	assert.Equal(t, StateStopped, s.State())
	assert.False(t, s.IsRunning())
}

func TestServer_Address(t *testing.T) {
	t.Parallel()

	s, err := New(nil, WithAddress(":50051"))
	require.NoError(t, err)

	assert.Equal(t, ":50051", s.Address())
}

func TestServer_Uptime_NotStarted(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	assert.Equal(t, time.Duration(0), s.Uptime())
}

func TestServer_GRPCServer_NotStarted(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	assert.Nil(t, s.GRPCServer())
}

func TestServer_HealthServer_NotStarted(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	assert.Nil(t, s.HealthServer())
}

func TestServer_SetServingStatus_NotStarted(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	// Should not panic
	s.SetServingStatus("test.Service", 1)
}

func TestServer_RegisterService_NotStarted(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	// Should not panic
	s.RegisterService(nil, nil)
}

func TestServer_GetServiceInfo_NotStarted(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	info := s.GetServiceInfo()
	assert.Nil(t, info)
}

func TestServer_Start_Stop(t *testing.T) {
	t.Parallel()

	s, err := New(nil, WithAddress("127.0.0.1:0"))
	require.NoError(t, err)

	ctx := context.Background()

	// Start server
	err = s.Start(ctx)
	require.NoError(t, err)

	assert.Equal(t, StateRunning, s.State())
	assert.True(t, s.IsRunning())
	assert.NotNil(t, s.GRPCServer())
	assert.Greater(t, s.Uptime(), time.Duration(0))

	// Stop server
	err = s.Stop(ctx)
	require.NoError(t, err)

	assert.Equal(t, StateStopped, s.State())
	assert.False(t, s.IsRunning())
}

func TestServer_Start_AlreadyRunning(t *testing.T) {
	t.Parallel()

	s, err := New(nil, WithAddress("127.0.0.1:0"))
	require.NoError(t, err)

	ctx := context.Background()

	// Start server
	err = s.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = s.Stop(ctx) }()

	// Try to start again
	err = s.Start(ctx)
	assert.Error(t, err)
}

func TestServer_Stop_NotRunning(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	ctx := context.Background()

	// Stop without starting - should not error
	err = s.Stop(ctx)
	require.NoError(t, err)
}

func TestServer_GracefulStop(t *testing.T) {
	t.Parallel()

	s, err := New(nil, WithAddress("127.0.0.1:0"), WithGracefulStopTimeout(1*time.Second))
	require.NoError(t, err)

	ctx := context.Background()

	// Start server
	err = s.Start(ctx)
	require.NoError(t, err)

	// Graceful stop
	err = s.GracefulStop(ctx)
	require.NoError(t, err)

	assert.Equal(t, StateStopped, s.State())
}

func TestServer_GracefulStop_NotRunning(t *testing.T) {
	t.Parallel()

	s, err := New(nil)
	require.NoError(t, err)

	ctx := context.Background()

	// Graceful stop without starting - should not error
	err = s.GracefulStop(ctx)
	require.NoError(t, err)
}

func TestServer_GracefulStop_WithTimeout(t *testing.T) {
	t.Parallel()

	s, err := New(nil, WithAddress("127.0.0.1:0"), WithGracefulStopTimeout(100*time.Millisecond))
	require.NoError(t, err)

	ctx := context.Background()

	// Start server
	err = s.Start(ctx)
	require.NoError(t, err)

	// Graceful stop with context deadline
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err = s.GracefulStop(ctx)
	require.NoError(t, err)

	assert.Equal(t, StateStopped, s.State())
}

func TestServer_Start_WithHealthService(t *testing.T) {
	t.Parallel()

	s, err := New(nil, WithAddress("127.0.0.1:0"), WithHealthService(true))
	require.NoError(t, err)

	ctx := context.Background()

	err = s.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = s.Stop(ctx) }()

	assert.NotNil(t, s.HealthServer())
}

func TestServer_Start_WithReflection(t *testing.T) {
	t.Parallel()

	s, err := New(nil, WithAddress("127.0.0.1:0"), WithReflection(true))
	require.NoError(t, err)

	ctx := context.Background()

	err = s.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = s.Stop(ctx) }()

	// Reflection service should be registered
	info := s.GetServiceInfo()
	assert.NotNil(t, info)
}

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

func TestServer_Start_InvalidAddress(t *testing.T) {
	t.Parallel()

	s, err := New(nil, WithAddress("invalid:address:format"))
	require.NoError(t, err)

	ctx := context.Background()

	err = s.Start(ctx)
	assert.Error(t, err)
	assert.Equal(t, StateStopped, s.State())
}

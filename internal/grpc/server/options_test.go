package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestWithLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	s := &Server{}

	opt := WithLogger(logger)
	opt(s)

	assert.NotNil(t, s.logger)
}

func TestWithMaxConcurrentStreams(t *testing.T) {
	t.Parallel()

	s := &Server{}

	opt := WithMaxConcurrentStreams(200)
	opt(s)

	assert.Equal(t, uint32(200), s.maxConcurrentStreams)
}

func TestWithMaxRecvMsgSize(t *testing.T) {
	t.Parallel()

	s := &Server{}

	opt := WithMaxRecvMsgSize(8 * 1024 * 1024)
	opt(s)

	assert.Equal(t, 8*1024*1024, s.maxRecvMsgSize)
}

func TestWithMaxSendMsgSize(t *testing.T) {
	t.Parallel()

	s := &Server{}

	opt := WithMaxSendMsgSize(8 * 1024 * 1024)
	opt(s)

	assert.Equal(t, 8*1024*1024, s.maxSendMsgSize)
}

func TestWithKeepaliveParams(t *testing.T) {
	t.Parallel()

	s := &Server{}
	kp := keepalive.ServerParameters{
		Time:    30 * time.Second,
		Timeout: 10 * time.Second,
	}

	opt := WithKeepaliveParams(kp)
	opt(s)

	assert.NotNil(t, s.keepaliveParams)
	assert.Equal(t, 30*time.Second, s.keepaliveParams.Time)
	assert.Equal(t, 10*time.Second, s.keepaliveParams.Timeout)
}

func TestWithKeepaliveEnforcementPolicy(t *testing.T) {
	t.Parallel()

	s := &Server{}
	kep := keepalive.EnforcementPolicy{
		PermitWithoutStream: true,
	}

	opt := WithKeepaliveEnforcementPolicy(kep)
	opt(s)

	assert.NotNil(t, s.keepaliveEnforcement)
	assert.True(t, s.keepaliveEnforcement.PermitWithoutStream)
}

func TestWithUnaryInterceptors(t *testing.T) {
	t.Parallel()

	s := &Server{}

	interceptor1 := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}
	interceptor2 := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}

	opt := WithUnaryInterceptors(interceptor1, interceptor2)
	opt(s)

	assert.Len(t, s.unaryInterceptors, 2)
}

func TestWithStreamInterceptors(t *testing.T) {
	t.Parallel()

	s := &Server{}

	interceptor1 := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}
	interceptor2 := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}

	opt := WithStreamInterceptors(interceptor1, interceptor2)
	opt(s)

	assert.Len(t, s.streamInterceptors, 2)
}

func TestWithTLSCredentials(t *testing.T) {
	t.Parallel()

	s := &Server{}

	opt := WithTLSCredentials("/path/to/cert.pem", "/path/to/key.pem")
	opt(s)

	assert.Equal(t, "/path/to/cert.pem", s.tlsCertFile)
	assert.Equal(t, "/path/to/key.pem", s.tlsKeyFile)
}

func TestWithAddress(t *testing.T) {
	t.Parallel()

	s := &Server{}

	opt := WithAddress(":50051")
	opt(s)

	assert.Equal(t, ":50051", s.address)
}

func TestWithUnknownServiceHandler(t *testing.T) {
	t.Parallel()

	s := &Server{}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	opt := WithUnknownServiceHandler(handler)
	opt(s)

	assert.NotNil(t, s.unknownServiceHandler)
}

func TestWithReflection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enabled",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disabled",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{}
			opt := WithReflection(tt.enabled)
			opt(s)

			assert.Equal(t, tt.expected, s.reflectionEnabled)
		})
	}
}

func TestWithHealthService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enabled",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disabled",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{}
			opt := WithHealthService(tt.enabled)
			opt(s)

			assert.Equal(t, tt.expected, s.healthServiceEnabled)
		})
	}
}

func TestWithConnectionTimeout(t *testing.T) {
	t.Parallel()

	s := &Server{}

	opt := WithConnectionTimeout(60 * time.Second)
	opt(s)

	assert.Equal(t, 60*time.Second, s.connectionTimeout)
}

func TestWithGracefulStopTimeout(t *testing.T) {
	t.Parallel()

	s := &Server{}

	opt := WithGracefulStopTimeout(15 * time.Second)
	opt(s)

	assert.Equal(t, 15*time.Second, s.gracefulStopTimeout)
}

func TestWithUnaryInterceptors_Append(t *testing.T) {
	t.Parallel()

	s := &Server{}

	interceptor1 := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}
	interceptor2 := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}

	// Add first interceptor
	opt1 := WithUnaryInterceptors(interceptor1)
	opt1(s)
	assert.Len(t, s.unaryInterceptors, 1)

	// Add second interceptor - should append
	opt2 := WithUnaryInterceptors(interceptor2)
	opt2(s)
	assert.Len(t, s.unaryInterceptors, 2)
}

func TestWithStreamInterceptors_Append(t *testing.T) {
	t.Parallel()

	s := &Server{}

	interceptor1 := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}
	interceptor2 := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}

	// Add first interceptor
	opt1 := WithStreamInterceptors(interceptor1)
	opt1(s)
	assert.Len(t, s.streamInterceptors, 1)

	// Add second interceptor - should append
	opt2 := WithStreamInterceptors(interceptor2)
	opt2(s)
	assert.Len(t, s.streamInterceptors, 2)
}

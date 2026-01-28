package middleware

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestUnaryLoggingInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handlerErr  error
		expectedErr bool
	}{
		{
			name:        "successful request",
			handlerErr:  nil,
			expectedErr: false,
		},
		{
			name:        "failed request",
			handlerErr:  status.Error(codes.Internal, "internal error"),
			expectedErr: true,
		},
		{
			name:        "not found request",
			handlerErr:  status.Error(codes.NotFound, "not found"),
			expectedErr: true,
		},
		{
			name:        "permission denied",
			handlerErr:  status.Error(codes.PermissionDenied, "permission denied"),
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			interceptor := UnaryLoggingInterceptor(logger)

			ctx := context.Background()
			ctx = metadata.NewIncomingContext(ctx, metadata.MD{
				"x-request-id": []string{"test-request-id"},
			})
			ctx = peer.NewContext(ctx, &peer.Peer{
				Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			})

			info := &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/Method",
			}

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return "response", tt.handlerErr
			}

			resp, err := interceptor(ctx, "request", info, handler)

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "response", resp)
			}
		})
	}
}

func TestStreamLoggingInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handlerErr  error
		expectedErr bool
	}{
		{
			name:        "successful stream",
			handlerErr:  nil,
			expectedErr: false,
		},
		{
			name:        "failed stream",
			handlerErr:  status.Error(codes.Internal, "internal error"),
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			interceptor := StreamLoggingInterceptor(logger)

			ctx := context.Background()
			ctx = metadata.NewIncomingContext(ctx, metadata.MD{
				"x-request-id": []string{"test-request-id"},
			})
			ctx = peer.NewContext(ctx, &peer.Peer{
				Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			})

			stream := &mockServerStream{ctx: ctx}
			info := &grpc.StreamServerInfo{
				FullMethod: "/test.Service/StreamMethod",
			}

			handler := func(srv interface{}, stream grpc.ServerStream) error {
				return tt.handlerErr
			}

			err := interceptor(nil, stream, info, handler)

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoggingServerStream_SendMsg(t *testing.T) {
	t.Parallel()

	inner := &mockServerStream{ctx: context.Background()}
	stream := &loggingServerStream{
		ServerStream: inner,
	}

	err := stream.SendMsg("message")
	assert.NoError(t, err)
	assert.Equal(t, int64(1), stream.msgsSent)

	err = stream.SendMsg("message2")
	assert.NoError(t, err)
	assert.Equal(t, int64(2), stream.msgsSent)
}

func TestLoggingServerStream_SendMsg_Error(t *testing.T) {
	t.Parallel()

	inner := &mockServerStream{
		ctx:     context.Background(),
		sendErr: errors.New("send error"),
	}
	stream := &loggingServerStream{
		ServerStream: inner,
	}

	err := stream.SendMsg("message")
	assert.Error(t, err)
	assert.Equal(t, int64(0), stream.msgsSent)
}

func TestLoggingServerStream_RecvMsg(t *testing.T) {
	t.Parallel()

	inner := &mockServerStream{ctx: context.Background()}
	stream := &loggingServerStream{
		ServerStream: inner,
	}

	err := stream.RecvMsg(nil)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), stream.msgsReceived)

	err = stream.RecvMsg(nil)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), stream.msgsReceived)
}

func TestLoggingServerStream_RecvMsg_Error(t *testing.T) {
	t.Parallel()

	inner := &mockServerStream{
		ctx:     context.Background(),
		recvErr: errors.New("recv error"),
	}
	stream := &loggingServerStream{
		ServerStream: inner,
	}

	err := stream.RecvMsg(nil)
	assert.Error(t, err)
	assert.Equal(t, int64(0), stream.msgsReceived)
}

func TestGetClientAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name: "with peer",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
			}),
			expected: "192.168.1.1:12345",
		},
		{
			name:     "without peer",
			ctx:      context.Background(),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := getClientAddr(tt.ctx)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name: "from metadata",
			ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{
				"x-request-id": []string{"test-id"},
			}),
			expected: "test-id",
		},
		{
			name:     "from observability context",
			ctx:      observability.ContextWithRequestID(context.Background(), "obs-id"),
			expected: "obs-id",
		},
		{
			name:     "not present",
			ctx:      context.Background(),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := getRequestID(tt.ctx)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     codes.Code
		expected string
	}{
		{name: "OK", code: codes.OK, expected: "info"},
		{name: "Canceled", code: codes.Canceled, expected: "warn"},
		{name: "InvalidArgument", code: codes.InvalidArgument, expected: "warn"},
		{name: "NotFound", code: codes.NotFound, expected: "warn"},
		{name: "AlreadyExists", code: codes.AlreadyExists, expected: "warn"},
		{name: "PermissionDenied", code: codes.PermissionDenied, expected: "warn"},
		{name: "Unauthenticated", code: codes.Unauthenticated, expected: "warn"},
		{name: "Internal", code: codes.Internal, expected: "error"},
		{name: "Unavailable", code: codes.Unavailable, expected: "error"},
		{name: "Unknown", code: codes.Unknown, expected: "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := getLogLevel(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLogRequest(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	// Should not panic for any level
	logRequest(logger, "debug", "test message")
	logRequest(logger, "info", "test message")
	logRequest(logger, "warn", "test message")
	logRequest(logger, "error", "test message")
	logRequest(logger, "unknown", "test message")
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	ctx     context.Context
	sendErr error
	recvErr error
}

func (m *mockServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockServerStream) SendHeader(_ metadata.MD) error { return nil }
func (m *mockServerStream) SetTrailer(_ metadata.MD)       {}
func (m *mockServerStream) Context() context.Context       { return m.ctx }
func (m *mockServerStream) SendMsg(_ interface{}) error    { return m.sendErr }
func (m *mockServerStream) RecvMsg(_ interface{}) error    { return m.recvErr }

func TestUnaryLoggingInterceptor_NoMetadata(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := UnaryLoggingInterceptor(logger)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	resp, err := interceptor(ctx, "request", info, handler)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)
}

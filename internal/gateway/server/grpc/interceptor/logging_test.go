package interceptor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"net"
)

// TestUnaryLoggingInterceptor tests the basic unary logging interceptor
func TestUnaryLoggingInterceptor(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	interceptor := UnaryLoggingInterceptor(logger)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

	assert.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.GreaterOrEqual(t, logs.Len(), 1)
}

// TestUnaryLoggingInterceptorWithConfig tests the configurable unary logging interceptor
func TestUnaryLoggingInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips logging for configured methods", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		config := LoggingConfig{
			Logger:      logger,
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := UnaryLoggingInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
		assert.Equal(t, 0, logs.Len())
	})

	t.Run("skips health check methods when configured", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		config := LoggingConfig{
			Logger:          logger,
			SkipHealthCheck: true,
		}

		interceptor := UnaryLoggingInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
		assert.Equal(t, 0, logs.Len())
	})

	t.Run("logs errors", func(t *testing.T) {
		core, logs := observer.New(zap.ErrorLevel)
		logger := zap.New(core)

		config := LoggingConfig{
			Logger: logger,
		}

		interceptor := UnaryLoggingInterceptorWithConfig(config)

		errorHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, errors.New("test error")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, errorHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.GreaterOrEqual(t, logs.Len(), 1)
	})

	t.Run("uses nop logger when nil", func(t *testing.T) {
		config := LoggingConfig{
			Logger: nil,
		}

		interceptor := UnaryLoggingInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("includes peer info when available", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		config := LoggingConfig{
			Logger: logger,
		}

		interceptor := UnaryLoggingInterceptorWithConfig(config)

		addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
		assert.GreaterOrEqual(t, logs.Len(), 1)
	})

	t.Run("uses existing request ID from metadata", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		config := LoggingConfig{
			Logger: logger,
		}

		interceptor := UnaryLoggingInterceptorWithConfig(config)

		md := metadata.MD{
			RequestIDKey: []string{"existing-request-id"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
		assert.GreaterOrEqual(t, logs.Len(), 1)

		// Check that the log contains the request ID
		logEntry := logs.All()[0]
		found := false
		for _, field := range logEntry.Context {
			if field.Key == "requestID" && field.String == "existing-request-id" {
				found = true
				break
			}
		}
		assert.True(t, found, "request ID should be in log")
	})
}

// TestStreamLoggingInterceptor tests the basic stream logging interceptor
func TestStreamLoggingInterceptor(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	interceptor := StreamLoggingInterceptor(logger)

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/Method",
		IsClientStream: true,
		IsServerStream: true,
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, logs.Len(), 1)
}

// TestStreamLoggingInterceptorWithConfig tests the configurable stream logging interceptor
func TestStreamLoggingInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips logging for configured methods", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		config := LoggingConfig{
			Logger:      logger,
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := StreamLoggingInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
		assert.Equal(t, 0, logs.Len())
	})

	t.Run("skips health check watch method when configured", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		config := LoggingConfig{
			Logger:          logger,
			SkipHealthCheck: true,
		}

		interceptor := StreamLoggingInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/grpc.health.v1.Health/Watch"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
		assert.Equal(t, 0, logs.Len())
	})

	t.Run("logs stream errors", func(t *testing.T) {
		core, logs := observer.New(zap.ErrorLevel)
		logger := zap.New(core)

		config := LoggingConfig{
			Logger: logger,
		}

		interceptor := StreamLoggingInterceptorWithConfig(config)

		errorHandler := func(srv interface{}, ss grpc.ServerStream) error {
			return errors.New("stream error")
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, errorHandler)

		assert.Error(t, err)
		assert.GreaterOrEqual(t, logs.Len(), 1)
	})
}

// TestLoggingServerStream tests the logging server stream wrapper
func TestLoggingServerStream(t *testing.T) {
	t.Parallel()

	t.Run("counts received messages", func(t *testing.T) {
		ctx := context.Background()
		baseStream := &mockServerStreamWithMessages{
			mockServerStream: mockServerStream{ctx: ctx},
			recvMessages:     []interface{}{"msg1", "msg2"},
		}

		wrappedStream := &loggingServerStream{
			ServerStream: baseStream,
			requestID:    "test-id",
		}

		var msg interface{}
		err := wrappedStream.RecvMsg(&msg)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), wrappedStream.recvCount)

		err = wrappedStream.RecvMsg(&msg)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), wrappedStream.recvCount)
	})

	t.Run("counts sent messages", func(t *testing.T) {
		ctx := context.Background()
		baseStream := &mockServerStreamWithMessages{
			mockServerStream: mockServerStream{ctx: ctx},
		}

		wrappedStream := &loggingServerStream{
			ServerStream: baseStream,
			requestID:    "test-id",
		}

		err := wrappedStream.SendMsg("msg1")
		assert.NoError(t, err)
		assert.Equal(t, int64(1), wrappedStream.sentCount)

		err = wrappedStream.SendMsg("msg2")
		assert.NoError(t, err)
		assert.Equal(t, int64(2), wrappedStream.sentCount)
	})

	t.Run("does not count on error", func(t *testing.T) {
		ctx := context.Background()
		baseStream := &mockServerStreamWithMessages{
			mockServerStream: mockServerStream{ctx: ctx},
			recvErr:          errors.New("recv error"),
			sendErr:          errors.New("send error"),
		}

		wrappedStream := &loggingServerStream{
			ServerStream: baseStream,
			requestID:    "test-id",
		}

		var msg interface{}
		err := wrappedStream.RecvMsg(&msg)
		assert.Error(t, err)
		assert.Equal(t, int64(0), wrappedStream.recvCount)

		err = wrappedStream.SendMsg("msg")
		assert.Error(t, err)
		assert.Equal(t, int64(0), wrappedStream.sentCount)
	})
}

// mockServerStreamWithMessages extends mockServerStream with message handling
type mockServerStreamWithMessages struct {
	mockServerStream
	recvMessages []interface{}
	recvIndex    int
	recvErr      error
	sendErr      error
}

func (m *mockServerStreamWithMessages) RecvMsg(msg interface{}) error {
	if m.recvErr != nil {
		return m.recvErr
	}
	if m.recvIndex < len(m.recvMessages) {
		m.recvIndex++
		return nil
	}
	return errors.New("no more messages")
}

func (m *mockServerStreamWithMessages) SendMsg(msg interface{}) error {
	return m.sendErr
}

// TestGetOrGenerateRequestID tests request ID generation
func TestGetOrGenerateRequestID(t *testing.T) {
	t.Parallel()

	t.Run("returns existing request ID from metadata", func(t *testing.T) {
		md := metadata.MD{
			RequestIDKey: []string{"existing-id"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		requestID := getOrGenerateRequestID(ctx)

		assert.Equal(t, "existing-id", requestID)
	})

	t.Run("generates new request ID when not in metadata", func(t *testing.T) {
		ctx := context.Background()

		requestID := getOrGenerateRequestID(ctx)

		assert.NotEmpty(t, requestID)
		// UUID format check
		assert.Len(t, requestID, 36)
	})

	t.Run("generates new request ID for empty metadata", func(t *testing.T) {
		md := metadata.MD{}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		requestID := getOrGenerateRequestID(ctx)

		assert.NotEmpty(t, requestID)
	})
}

// TestGetPeerAddress tests peer address extraction
func TestGetPeerAddress(t *testing.T) {
	t.Parallel()

	t.Run("returns peer address when available", func(t *testing.T) {
		addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})

		peerAddr := getPeerAddress(ctx)

		assert.Equal(t, "192.168.1.1:12345", peerAddr)
	})

	t.Run("returns empty string when no peer", func(t *testing.T) {
		ctx := context.Background()

		peerAddr := getPeerAddress(ctx)

		assert.Empty(t, peerAddr)
	})
}

// TestIsHealthCheckMethod tests health check method detection
func TestIsHealthCheckMethod(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		method   string
		expected bool
	}{
		{"/grpc.health.v1.Health/Check", true},
		{"/grpc.health.v1.Health/Watch", true},
		{"/test.Service/Method", false},
		{"/grpc.health.v1.Health/Other", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()

			result := isHealthCheckMethod(tc.method)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestGetRequestID tests GetRequestID function
func TestGetRequestID(t *testing.T) {
	t.Parallel()

	t.Run("returns request ID from metadata", func(t *testing.T) {
		md := metadata.MD{
			RequestIDKey: []string{"test-request-id"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		requestID := GetRequestID(ctx)

		assert.Equal(t, "test-request-id", requestID)
	})

	t.Run("returns empty string when no metadata", func(t *testing.T) {
		ctx := context.Background()

		requestID := GetRequestID(ctx)

		assert.Empty(t, requestID)
	})

	t.Run("returns empty string when request ID not in metadata", func(t *testing.T) {
		md := metadata.MD{
			"other-key": []string{"value"},
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)

		requestID := GetRequestID(ctx)

		assert.Empty(t, requestID)
	})
}

// TestRequestIDKey tests the request ID key constant
func TestRequestIDKey(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "x-request-id", RequestIDKey)
}

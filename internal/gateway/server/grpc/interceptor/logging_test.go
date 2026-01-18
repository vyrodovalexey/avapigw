package interceptor

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
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

// TestStreamLoggingInterceptorWithPeerInfo tests stream logging with peer info
func TestStreamLoggingInterceptorWithPeerInfo(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	config := LoggingConfig{
		Logger: logger,
	}

	interceptor := StreamLoggingInterceptorWithConfig(config)

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/Method",
		IsClientStream: true,
		IsServerStream: true,
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, logs.Len(), 1)

	// Check that peer info is in log
	logEntry := logs.All()[0]
	hasPeer := false
	for _, field := range logEntry.Context {
		if field.Key == "peer" {
			hasPeer = true
			break
		}
	}
	assert.True(t, hasPeer, "peer info should be in log")
}

// TestStreamLoggingInterceptorWithRequestID tests stream logging with request ID
func TestStreamLoggingInterceptorWithRequestID(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	config := LoggingConfig{
		Logger: logger,
	}

	interceptor := StreamLoggingInterceptorWithConfig(config)

	md := metadata.MD{
		RequestIDKey: []string{"stream-request-id-123"},
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/Method",
		IsClientStream: false,
		IsServerStream: true,
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, logs.Len(), 1)

	// Check that request ID is in log
	logEntry := logs.All()[0]
	hasRequestID := false
	for _, field := range logEntry.Context {
		if field.Key == "requestID" && field.String == "stream-request-id-123" {
			hasRequestID = true
			break
		}
	}
	assert.True(t, hasRequestID, "request ID should be in log")
}

// TestBuildStreamLogFieldsWithPeer tests buildStreamLogFields with peer info
func TestBuildStreamLogFieldsWithPeer(t *testing.T) {
	t.Parallel()

	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})

	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/Method",
		IsClientStream: true,
		IsServerStream: false,
	}

	wrappedStream := &loggingServerStream{
		requestID: "test-id",
		recvCount: 5,
		sentCount: 3,
	}

	fields := buildStreamLogFields("test-id", info, wrappedStream, 100*time.Millisecond, ctx, nil)

	assert.NotEmpty(t, fields)

	// Check for peer field
	hasPeer := false
	for _, field := range fields {
		if field.Key == "peer" {
			hasPeer = true
			break
		}
	}
	assert.True(t, hasPeer, "peer field should be present")
}

// TestBuildUnaryLogFieldsWithPeer tests buildUnaryLogFields with peer info
func TestBuildUnaryLogFieldsWithPeer(t *testing.T) {
	t.Parallel()

	addr := &net.TCPAddr{IP: net.ParseIP("172.16.0.1"), Port: 9090}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})

	fields := buildUnaryLogFields("request-123", "/test.Service/Method", 50*time.Millisecond, ctx, nil)

	assert.NotEmpty(t, fields)

	// Check for peer field
	hasPeer := false
	for _, field := range fields {
		if field.Key == "peer" {
			hasPeer = true
			break
		}
	}
	assert.True(t, hasPeer, "peer field should be present")
}

// TestBuildUnaryLogFieldsWithError tests buildUnaryLogFields with error
func TestBuildUnaryLogFieldsWithError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	err := status.Error(codes.NotFound, "not found")

	fields := buildUnaryLogFields("request-456", "/test.Service/Method", 75*time.Millisecond, ctx, err)

	assert.NotEmpty(t, fields)

	// Check for grpcCode field
	hasGRPCCode := false
	for _, field := range fields {
		if field.Key == "grpcCode" && field.String == "NotFound" {
			hasGRPCCode = true
			break
		}
	}
	assert.True(t, hasGRPCCode, "grpcCode field should be present with NotFound")
}

// TestShouldSkipUnaryLoggingEdgeCases tests shouldSkipUnaryLogging edge cases
func TestShouldSkipUnaryLoggingEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("skips when method in skip list", func(t *testing.T) {
		skipMethods := map[string]bool{
			"/test.Service/Skip": true,
		}

		result := shouldSkipUnaryLogging(skipMethods, "/test.Service/Skip", false)
		assert.True(t, result)
	})

	t.Run("does not skip when method not in skip list", func(t *testing.T) {
		skipMethods := map[string]bool{
			"/test.Service/Skip": true,
		}

		result := shouldSkipUnaryLogging(skipMethods, "/test.Service/Other", false)
		assert.False(t, result)
	})

	t.Run("skips health check when configured", func(t *testing.T) {
		skipMethods := map[string]bool{}

		result := shouldSkipUnaryLogging(skipMethods, "/grpc.health.v1.Health/Check", true)
		assert.True(t, result)
	})

	t.Run("does not skip health check when not configured", func(t *testing.T) {
		skipMethods := map[string]bool{}

		result := shouldSkipUnaryLogging(skipMethods, "/grpc.health.v1.Health/Check", false)
		assert.False(t, result)
	})
}

// TestShouldSkipStreamLoggingEdgeCases tests shouldSkipStreamLogging edge cases
func TestShouldSkipStreamLoggingEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("skips when method in skip list", func(t *testing.T) {
		skipMethods := map[string]bool{
			"/test.Service/Skip": true,
		}

		result := shouldSkipStreamLogging(skipMethods, "/test.Service/Skip", false)
		assert.True(t, result)
	})

	t.Run("does not skip when method not in skip list", func(t *testing.T) {
		skipMethods := map[string]bool{
			"/test.Service/Skip": true,
		}

		result := shouldSkipStreamLogging(skipMethods, "/test.Service/Other", false)
		assert.False(t, result)
	})

	t.Run("skips health watch when configured", func(t *testing.T) {
		skipMethods := map[string]bool{}

		result := shouldSkipStreamLogging(skipMethods, "/grpc.health.v1.Health/Watch", true)
		assert.True(t, result)
	})
}

// TestBuildSkipMethodsMap tests buildSkipMethodsMap function
func TestBuildSkipMethodsMap(t *testing.T) {
	t.Parallel()

	t.Run("builds map from slice", func(t *testing.T) {
		methods := []string{"/test.Service/Method1", "/test.Service/Method2"}

		result := buildSkipMethodsMap(methods)

		assert.Len(t, result, 2)
		assert.True(t, result["/test.Service/Method1"])
		assert.True(t, result["/test.Service/Method2"])
	})

	t.Run("handles empty slice", func(t *testing.T) {
		methods := []string{}

		result := buildSkipMethodsMap(methods)

		assert.Empty(t, result)
	})

	t.Run("handles nil slice", func(t *testing.T) {
		var methods []string

		result := buildSkipMethodsMap(methods)

		assert.Empty(t, result)
	})
}

// TestLogUnaryResult tests logUnaryResult function
func TestLogUnaryResult(t *testing.T) {
	t.Parallel()

	t.Run("logs info on success", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		fields := []zap.Field{
			zap.String("method", "/test.Service/Method"),
		}

		logUnaryResult(logger, nil, fields)

		assert.Equal(t, 1, logs.Len())
		assert.Equal(t, "gRPC request completed", logs.All()[0].Message)
	})

	t.Run("logs error on failure", func(t *testing.T) {
		core, logs := observer.New(zap.ErrorLevel)
		logger := zap.New(core)

		fields := []zap.Field{
			zap.String("method", "/test.Service/Method"),
		}

		logUnaryResult(logger, errors.New("test error"), fields)

		assert.Equal(t, 1, logs.Len())
		assert.Equal(t, "gRPC request failed", logs.All()[0].Message)
	})
}

// TestLogStreamResult tests logStreamResult function
func TestLogStreamResult(t *testing.T) {
	t.Parallel()

	t.Run("logs info on success", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		fields := []zap.Field{
			zap.String("method", "/test.Service/Method"),
		}

		logStreamResult(logger, nil, fields)

		assert.Equal(t, 1, logs.Len())
		assert.Equal(t, "gRPC stream completed", logs.All()[0].Message)
	})

	t.Run("logs error on failure", func(t *testing.T) {
		core, logs := observer.New(zap.ErrorLevel)
		logger := zap.New(core)

		fields := []zap.Field{
			zap.String("method", "/test.Service/Method"),
		}

		logStreamResult(logger, errors.New("stream error"), fields)

		assert.Equal(t, 1, logs.Len())
		assert.Equal(t, "gRPC stream failed", logs.All()[0].Message)
	})
}

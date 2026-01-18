package interceptor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestUnaryRecoveryInterceptor tests the basic unary recovery interceptor
func TestUnaryRecoveryInterceptor(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	interceptor := UnaryRecoveryInterceptor(logger)

	t.Run("passes through normal requests", func(t *testing.T) {
		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("recovers from panic", func(t *testing.T) {
		panicHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			panic("test panic")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, panicHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

// TestUnaryRecoveryInterceptorWithConfig tests the configurable unary recovery interceptor
func TestUnaryRecoveryInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("logs panic with stack trace", func(t *testing.T) {
		core, logs := observer.New(zap.ErrorLevel)
		logger := zap.New(core)

		config := RecoveryConfig{
			Logger:           logger,
			EnableStackTrace: true,
		}

		interceptor := UnaryRecoveryInterceptorWithConfig(config)

		panicHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			panic("test panic with stack")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, panicHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.GreaterOrEqual(t, logs.Len(), 1)

		// Check that stack trace is in log
		logEntry := logs.All()[0]
		hasStack := false
		for _, field := range logEntry.Context {
			if field.Key == "stack" {
				hasStack = true
				break
			}
		}
		assert.True(t, hasStack, "stack trace should be in log")
	})

	t.Run("logs panic without stack trace", func(t *testing.T) {
		core, logs := observer.New(zap.ErrorLevel)
		logger := zap.New(core)

		config := RecoveryConfig{
			Logger:           logger,
			EnableStackTrace: false,
		}

		interceptor := UnaryRecoveryInterceptorWithConfig(config)

		panicHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			panic("test panic without stack")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, panicHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.GreaterOrEqual(t, logs.Len(), 1)

		// Check that stack trace is NOT in log
		logEntry := logs.All()[0]
		hasStack := false
		for _, field := range logEntry.Context {
			if field.Key == "stack" {
				hasStack = true
				break
			}
		}
		assert.False(t, hasStack, "stack trace should not be in log")
	})

	t.Run("uses custom panic handler", func(t *testing.T) {
		customErr := errors.New("custom error")
		config := RecoveryConfig{
			Logger: zap.NewNop(),
			PanicHandler: func(ctx context.Context, p interface{}) error {
				return customErr
			},
		}

		interceptor := UnaryRecoveryInterceptorWithConfig(config)

		panicHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			panic("test panic")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, panicHandler)

		assert.Error(t, err)
		assert.Equal(t, customErr, err)
		assert.Nil(t, resp)
	})

	t.Run("uses nop logger when nil", func(t *testing.T) {
		config := RecoveryConfig{
			Logger: nil,
		}

		interceptor := UnaryRecoveryInterceptorWithConfig(config)

		panicHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			panic("test panic")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, panicHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)
	})
}

// TestStreamRecoveryInterceptor tests the basic stream recovery interceptor
func TestStreamRecoveryInterceptor(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	interceptor := StreamRecoveryInterceptor(logger)

	t.Run("passes through normal streams", func(t *testing.T) {
		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("recovers from panic", func(t *testing.T) {
		panicHandler := func(srv interface{}, ss grpc.ServerStream) error {
			panic("stream panic")
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, panicHandler)

		assert.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

// TestStreamRecoveryInterceptorWithConfig tests the configurable stream recovery interceptor
func TestStreamRecoveryInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("logs panic with stack trace", func(t *testing.T) {
		core, logs := observer.New(zap.ErrorLevel)
		logger := zap.New(core)

		config := RecoveryConfig{
			Logger:           logger,
			EnableStackTrace: true,
		}

		interceptor := StreamRecoveryInterceptorWithConfig(config)

		panicHandler := func(srv interface{}, ss grpc.ServerStream) error {
			panic("stream panic with stack")
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, panicHandler)

		assert.Error(t, err)
		assert.GreaterOrEqual(t, logs.Len(), 1)
	})

	t.Run("uses custom panic handler", func(t *testing.T) {
		customErr := errors.New("custom stream error")
		config := RecoveryConfig{
			Logger: zap.NewNop(),
			PanicHandler: func(ctx context.Context, p interface{}) error {
				return customErr
			},
		}

		interceptor := StreamRecoveryInterceptorWithConfig(config)

		panicHandler := func(srv interface{}, ss grpc.ServerStream) error {
			panic("stream panic")
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, panicHandler)

		assert.Error(t, err)
		assert.Equal(t, customErr, err)
	})
}

// TestHandlePanic tests the handlePanic function
func TestHandlePanic(t *testing.T) {
	t.Parallel()

	t.Run("returns internal error by default", func(t *testing.T) {
		config := RecoveryConfig{
			Logger: zap.NewNop(),
		}

		err := handlePanic(context.Background(), "test panic", "/test.Service/Method", config)

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, st.Message(), "internal server error")
	})

	t.Run("uses custom panic handler", func(t *testing.T) {
		customErr := errors.New("custom error")
		config := RecoveryConfig{
			Logger: zap.NewNop(),
			PanicHandler: func(ctx context.Context, p interface{}) error {
				return customErr
			},
		}

		err := handlePanic(context.Background(), "test panic", "/test.Service/Method", config)

		assert.Equal(t, customErr, err)
	})

	t.Run("includes stack trace when enabled", func(t *testing.T) {
		core, logs := observer.New(zap.ErrorLevel)
		logger := zap.New(core)

		config := RecoveryConfig{
			Logger:           logger,
			EnableStackTrace: true,
		}

		_ = handlePanic(context.Background(), "test panic", "/test.Service/Method", config)

		assert.GreaterOrEqual(t, logs.Len(), 1)
		logEntry := logs.All()[0]
		hasStack := false
		for _, field := range logEntry.Context {
			if field.Key == "stack" {
				hasStack = true
				break
			}
		}
		assert.True(t, hasStack)
	})
}

// TestWithRecoveryHandler tests the WithRecoveryHandler helper
func TestWithRecoveryHandler(t *testing.T) {
	t.Parallel()

	customErr := errors.New("custom recovery error")
	handler := func(ctx context.Context, p interface{}) error {
		return customErr
	}

	config := WithRecoveryHandler(handler)

	assert.NotNil(t, config.PanicHandler)

	err := config.PanicHandler(context.Background(), "panic")
	assert.Equal(t, customErr, err)
}

// TestWithRecoveryHandlerContext tests the WithRecoveryHandlerContext helper
func TestWithRecoveryHandlerContext(t *testing.T) {
	t.Parallel()

	var receivedMethod string
	handler := func(ctx context.Context, p interface{}, method string) error {
		receivedMethod = method
		return errors.New("context error")
	}

	config := WithRecoveryHandlerContext(handler, "/test.Service/Method")

	assert.NotNil(t, config.PanicHandler)

	err := config.PanicHandler(context.Background(), "panic")
	assert.Error(t, err)
	assert.Equal(t, "/test.Service/Method", receivedMethod)
}

// TestRecoveryConfig tests RecoveryConfig struct
func TestRecoveryConfig(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		config := RecoveryConfig{}

		assert.Nil(t, config.Logger)
		assert.False(t, config.EnableStackTrace)
		assert.Nil(t, config.PanicHandler)
	})

	t.Run("with all fields", func(t *testing.T) {
		logger := zap.NewNop()
		handler := func(ctx context.Context, p interface{}) error {
			return nil
		}

		config := RecoveryConfig{
			Logger:           logger,
			EnableStackTrace: true,
			PanicHandler:     handler,
		}

		assert.NotNil(t, config.Logger)
		assert.True(t, config.EnableStackTrace)
		assert.NotNil(t, config.PanicHandler)
	})
}

// TestRecoveryHandlerFuncTypes tests the recovery handler function types
func TestRecoveryHandlerFuncTypes(t *testing.T) {
	t.Parallel()

	t.Run("RecoveryHandlerFunc", func(t *testing.T) {
		var handler RecoveryHandlerFunc = func(ctx context.Context, p interface{}) error {
			return errors.New("handler error")
		}

		err := handler(context.Background(), "panic")
		assert.Error(t, err)
	})

	t.Run("RecoveryHandlerFuncContext", func(t *testing.T) {
		var handler RecoveryHandlerFuncContext = func(ctx context.Context, p interface{}, method string) error {
			return errors.New("context handler error")
		}

		err := handler(context.Background(), "panic", "/test.Service/Method")
		assert.Error(t, err)
	})
}

// TestRecoveryWithDifferentPanicTypes tests recovery with different panic value types
func TestRecoveryWithDifferentPanicTypes(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	interceptor := UnaryRecoveryInterceptor(logger)

	testCases := []struct {
		name       string
		panicValue interface{}
	}{
		{"string panic", "string panic value"},
		{"error panic", errors.New("error panic value")},
		{"int panic", 42},
		{"struct panic", struct{ msg string }{"struct panic"}},
		{"nil panic", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			panicHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
				panic(tc.panicValue)
			}

			ctx := context.Background()
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			resp, err := interceptor(ctx, "request", info, panicHandler)

			assert.Error(t, err)
			assert.Nil(t, resp)
		})
	}
}

// TestRecoveryDoesNotRecoverFromNormalErrors tests that recovery doesn't affect normal errors
func TestRecoveryDoesNotRecoverFromNormalErrors(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	interceptor := UnaryRecoveryInterceptor(logger)

	normalError := errors.New("normal error")
	errorHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, normalError
	}

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	resp, err := interceptor(ctx, "request", info, errorHandler)

	assert.Error(t, err)
	assert.Equal(t, normalError, err)
	assert.Nil(t, resp)
}

// TestStreamRecoveryInterceptorWithConfigNilLogger tests stream recovery with nil logger
func TestStreamRecoveryInterceptorWithConfigNilLogger(t *testing.T) {
	t.Parallel()

	config := RecoveryConfig{
		Logger:           nil,
		EnableStackTrace: true,
	}

	interceptor := StreamRecoveryInterceptorWithConfig(config)

	panicHandler := func(srv interface{}, ss grpc.ServerStream) error {
		panic("stream panic with nil logger")
	}

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

	err := interceptor(nil, stream, info, panicHandler)

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// TestHandlePanicWithRequestID tests handlePanic with request ID in context
func TestHandlePanicWithRequestID(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)

	config := RecoveryConfig{
		Logger:           logger,
		EnableStackTrace: false,
	}

	// Create context with request ID
	md := metadata.MD{
		RequestIDKey: []string{"test-request-id-456"},
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := handlePanic(ctx, "test panic", "/test.Service/Method", config)

	assert.Error(t, err)
	assert.GreaterOrEqual(t, logs.Len(), 1)

	// Check that request ID is in log
	logEntry := logs.All()[0]
	hasRequestID := false
	for _, field := range logEntry.Context {
		if field.Key == "requestID" && field.String == "test-request-id-456" {
			hasRequestID = true
			break
		}
	}
	assert.True(t, hasRequestID, "request ID should be in log")
}

// TestRecoveryWithRuntimeError tests recovery from runtime errors
func TestRecoveryWithRuntimeError(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	interceptor := UnaryRecoveryInterceptor(logger)

	// Handler that causes a runtime panic (nil pointer dereference)
	panicHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		var nilPtr *string
		_ = *nilPtr // This will panic
		return "response", nil
	}

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	resp, err := interceptor(ctx, "request", info, panicHandler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

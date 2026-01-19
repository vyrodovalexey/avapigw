package interceptor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestUnaryCircuitBreakerInterceptor tests the basic unary circuit breaker interceptor
func TestUnaryCircuitBreakerInterceptor(t *testing.T) {
	t.Parallel()

	registry := circuitbreaker.NewRegistry(nil, nil)
	interceptor := UnaryCircuitBreakerInterceptor(registry)

	t.Run("allows request when circuit is closed", func(t *testing.T) {
		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestUnaryCircuitBreakerInterceptorWithConfig tests the configurable unary circuit breaker interceptor
func TestUnaryCircuitBreakerInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips circuit breaker for configured methods", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		// Open the circuit breaker
		cb := registry.GetOrCreate("/test.Service/SkippedMethod")
		for i := 0; i < 10; i++ {
			cb.RecordFailure()
		}

		config := CircuitBreakerConfig{
			Registry:    registry,
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := UnaryCircuitBreakerInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("uses custom name function", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		config := CircuitBreakerConfig{
			Registry: registry,
			NameFunc: func(method string) string {
				return "custom-name"
			},
		}

		interceptor := UnaryCircuitBreakerInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)

		// Verify circuit breaker was created with custom name
		cb := registry.Get("custom-name")
		assert.NotNil(t, cb)
	})

	t.Run("records success on successful request", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		config := CircuitBreakerConfig{
			Registry: registry,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Success"}

		_, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)

		cb := registry.Get("/test.Service/Success")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})

	t.Run("records failure on error", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		config := CircuitBreakerConfig{
			Registry: registry,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithConfig(config)

		errorHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, status.Error(codes.Unavailable, "service unavailable")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Failure"}

		_, err := interceptor(ctx, "request", info, errorHandler)

		assert.Error(t, err)

		cb := registry.Get("/test.Service/Failure")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Failures)
	})

	t.Run("records success for non-failure error codes", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		config := CircuitBreakerConfig{
			Registry: registry,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithConfig(config)

		errorHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, status.Error(codes.NotFound, "not found")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/NotFound"}

		_, err := interceptor(ctx, "request", info, errorHandler)

		assert.Error(t, err)

		cb := registry.Get("/test.Service/NotFound")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes) // NotFound is not a circuit breaker failure
	})

	t.Run("uses default registry when nil", func(t *testing.T) {
		config := CircuitBreakerConfig{
			Registry: nil,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("uses nop logger when nil", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		config := CircuitBreakerConfig{
			Registry: registry,
			Logger:   nil,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestStreamCircuitBreakerInterceptor tests the basic stream circuit breaker interceptor
func TestStreamCircuitBreakerInterceptor(t *testing.T) {
	t.Parallel()

	registry := circuitbreaker.NewRegistry(nil, nil)
	interceptor := StreamCircuitBreakerInterceptor(registry)

	t.Run("allows stream when circuit is closed", func(t *testing.T) {
		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})
}

// TestStreamCircuitBreakerInterceptorWithConfig tests the configurable stream circuit breaker interceptor
func TestStreamCircuitBreakerInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips circuit breaker for configured methods", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		config := CircuitBreakerConfig{
			Registry:    registry,
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := StreamCircuitBreakerInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("records success on successful stream", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		config := CircuitBreakerConfig{
			Registry: registry,
		}

		interceptor := StreamCircuitBreakerInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamSuccess"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)

		cb := registry.Get("/test.Service/StreamSuccess")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})

	t.Run("records failure on stream error", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		config := CircuitBreakerConfig{
			Registry: registry,
		}

		interceptor := StreamCircuitBreakerInterceptorWithConfig(config)

		errorHandler := func(srv interface{}, ss grpc.ServerStream) error {
			return status.Error(codes.Unavailable, "service unavailable")
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamFailure"}

		err := interceptor(nil, stream, info, errorHandler)

		assert.Error(t, err)

		cb := registry.Get("/test.Service/StreamFailure")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Failures)
	})
}

// TestIsCircuitBreakerFailure tests the IsCircuitBreakerFailure function
func TestIsCircuitBreakerFailure(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		code     codes.Code
		expected bool
	}{
		{codes.Unavailable, true},
		{codes.ResourceExhausted, true},
		{codes.Internal, true},
		{codes.Unknown, true},
		{codes.DeadlineExceeded, true},
		{codes.OK, false},
		{codes.NotFound, false},
		{codes.InvalidArgument, false},
		{codes.PermissionDenied, false},
		{codes.Unauthenticated, false},
		{codes.Canceled, false},
	}

	for _, tc := range testCases {
		t.Run(tc.code.String(), func(t *testing.T) {
			t.Parallel()

			result := IsCircuitBreakerFailure(tc.code)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestUnaryClientCircuitBreakerInterceptor tests the unary client circuit breaker interceptor
func TestUnaryClientCircuitBreakerInterceptor(t *testing.T) {
	t.Parallel()

	registry := circuitbreaker.NewRegistry(nil, nil)
	interceptor := UnaryClientCircuitBreakerInterceptor(registry)

	t.Run("allows request when circuit is closed", func(t *testing.T) {
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			return nil
		}

		err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

		assert.NoError(t, err)
	})

	t.Run("rejects request when circuit is open", func(t *testing.T) {
		// Open the circuit
		cb := registry.GetOrCreate("/test.Service/OpenMethod")
		for i := 0; i < 10; i++ {
			cb.RecordFailure()
		}

		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			return nil
		}

		err := interceptor(context.Background(), "/test.Service/OpenMethod", nil, nil, nil, invoker)

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("records success on successful call", func(t *testing.T) {
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			return nil
		}

		err := interceptor(context.Background(), "/test.Service/ClientSuccess", nil, nil, nil, invoker)

		assert.NoError(t, err)

		cb := registry.Get("/test.Service/ClientSuccess")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})

	t.Run("records failure on error", func(t *testing.T) {
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			return status.Error(codes.Unavailable, "unavailable")
		}

		err := interceptor(context.Background(), "/test.Service/ClientFailure", nil, nil, nil, invoker)

		assert.Error(t, err)

		cb := registry.Get("/test.Service/ClientFailure")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Failures)
	})
}

// TestStreamClientCircuitBreakerInterceptor tests the stream client circuit breaker interceptor
func TestStreamClientCircuitBreakerInterceptor(t *testing.T) {
	t.Parallel()

	registry := circuitbreaker.NewRegistry(nil, nil)
	interceptor := StreamClientCircuitBreakerInterceptor(registry)

	t.Run("allows stream when circuit is closed", func(t *testing.T) {
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return nil, nil
		}

		stream, err := interceptor(context.Background(), nil, nil, "/test.Service/StreamMethod", streamer)

		assert.NoError(t, err)
		assert.Nil(t, stream)
	})

	t.Run("rejects stream when circuit is open", func(t *testing.T) {
		// Open the circuit
		cb := registry.GetOrCreate("/test.Service/OpenStreamMethod")
		for i := 0; i < 10; i++ {
			cb.RecordFailure()
		}

		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return nil, nil
		}

		stream, err := interceptor(context.Background(), nil, nil, "/test.Service/OpenStreamMethod", streamer)

		assert.Error(t, err)
		assert.Nil(t, stream)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("records success on successful stream creation", func(t *testing.T) {
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return nil, nil
		}

		_, err := interceptor(context.Background(), nil, nil, "/test.Service/StreamClientSuccess", streamer)

		assert.NoError(t, err)

		cb := registry.Get("/test.Service/StreamClientSuccess")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})

	t.Run("records failure on stream creation error", func(t *testing.T) {
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return nil, status.Error(codes.Unavailable, "unavailable")
		}

		_, err := interceptor(context.Background(), nil, nil, "/test.Service/StreamClientFailure", streamer)

		assert.Error(t, err)

		cb := registry.Get("/test.Service/StreamClientFailure")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Failures)
	})
}

// TestCircuitBreakerConfig tests CircuitBreakerConfig struct
func TestCircuitBreakerConfig(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		config := CircuitBreakerConfig{}

		assert.Nil(t, config.Registry)
		assert.Nil(t, config.NameFunc)
		assert.Nil(t, config.Logger)
		assert.Nil(t, config.SkipMethods)
	})

	t.Run("with all fields", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		logger := zap.NewNop()
		nameFunc := func(method string) string { return method }

		config := CircuitBreakerConfig{
			Registry:    registry,
			NameFunc:    nameFunc,
			Logger:      logger,
			SkipMethods: []string{"/test.Service/Method"},
		}

		assert.NotNil(t, config.Registry)
		assert.NotNil(t, config.NameFunc)
		assert.NotNil(t, config.Logger)
		assert.Len(t, config.SkipMethods, 1)
	})
}

// TestUnaryCircuitBreakerInterceptorWithCore tests the core-based unary circuit breaker interceptor
func TestUnaryCircuitBreakerInterceptorWithCore(t *testing.T) {
	t.Parallel()

	t.Run("skips circuit breaker for configured methods", func(t *testing.T) {
		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				SkipPaths: []string{"/test.Service/SkippedMethod"},
			},
		}

		interceptor := UnaryCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("allows request when circuit is closed", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: registry,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("rejects request when circuit is open", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		// Open the circuit
		cb := registry.GetOrCreate("/test.Service/OpenMethod")
		for i := 0; i < 10; i++ {
			cb.RecordFailure()
		}

		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: registry,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/OpenMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("records success on successful request", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: registry,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SuccessMethod"}

		_, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)

		cb := registry.Get("/test.Service/SuccessMethod")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})

	t.Run("records failure on error", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: registry,
		}

		interceptor := UnaryCircuitBreakerInterceptorWithCore(coreConfig)

		errorHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, status.Error(codes.Unavailable, "service unavailable")
		}

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/FailureMethod"}

		_, err := interceptor(ctx, "request", info, errorHandler)

		assert.Error(t, err)

		cb := registry.Get("/test.Service/FailureMethod")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Failures)
	})

	t.Run("uses nil registry gracefully", func(t *testing.T) {
		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: nil, // Will create default registry
		}

		interceptor := UnaryCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestStreamCircuitBreakerInterceptorWithCore tests the core-based stream circuit breaker interceptor
func TestStreamCircuitBreakerInterceptorWithCore(t *testing.T) {
	t.Parallel()

	t.Run("skips circuit breaker for configured methods", func(t *testing.T) {
		coreConfig := core.CircuitBreakerCoreConfig{
			BaseConfig: core.BaseConfig{
				SkipPaths: []string{"/test.Service/SkippedMethod"},
			},
		}

		interceptor := StreamCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("allows stream when circuit is closed", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: registry,
		}

		interceptor := StreamCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("rejects stream when circuit is open", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		// Open the circuit
		cb := registry.GetOrCreate("/test.Service/OpenStreamMethod")
		for i := 0; i < 10; i++ {
			cb.RecordFailure()
		}

		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: registry,
		}

		interceptor := StreamCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/OpenStreamMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("records success on successful stream", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: registry,
		}

		interceptor := StreamCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamSuccessMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)

		cb := registry.Get("/test.Service/StreamSuccessMethod")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})

	t.Run("records failure on stream error", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: registry,
		}

		interceptor := StreamCircuitBreakerInterceptorWithCore(coreConfig)

		errorHandler := func(srv interface{}, ss grpc.ServerStream) error {
			return status.Error(codes.Unavailable, "service unavailable")
		}

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamFailureMethod"}

		err := interceptor(nil, stream, info, errorHandler)

		assert.Error(t, err)

		cb := registry.Get("/test.Service/StreamFailureMethod")
		assert.NotNil(t, cb)
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Failures)
	})

	t.Run("uses nil registry gracefully", func(t *testing.T) {
		coreConfig := core.CircuitBreakerCoreConfig{
			Registry: nil, // Will create default registry
		}

		interceptor := StreamCircuitBreakerInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})
}

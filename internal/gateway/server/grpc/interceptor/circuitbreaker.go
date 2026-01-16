package interceptor

import (
	"context"

	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CircuitBreakerConfig holds configuration for the circuit breaker interceptor.
type CircuitBreakerConfig struct {
	// Registry is the circuit breaker registry.
	Registry *circuitbreaker.Registry

	// NameFunc extracts the circuit breaker name from the method.
	// If nil, uses the full method name.
	NameFunc func(method string) string

	// Logger for logging circuit breaker events.
	Logger *zap.Logger

	// SkipMethods is a list of methods to skip circuit breaker.
	SkipMethods []string
}

// UnaryCircuitBreakerInterceptor returns a unary interceptor that applies circuit breaker protection.
func UnaryCircuitBreakerInterceptor(registry *circuitbreaker.Registry) grpc.UnaryServerInterceptor {
	return UnaryCircuitBreakerInterceptorWithConfig(CircuitBreakerConfig{Registry: registry})
}

// UnaryCircuitBreakerInterceptorWithConfig returns a unary circuit breaker interceptor with custom configuration.
func UnaryCircuitBreakerInterceptorWithConfig(config CircuitBreakerConfig) grpc.UnaryServerInterceptor {
	cbCore := core.NewCircuitBreakerCore(core.CircuitBreakerCoreConfig{
		BaseConfig: core.BaseConfig{
			Logger:    config.Logger,
			SkipPaths: config.SkipMethods,
		},
		Registry: config.Registry,
		NameFunc: config.NameFunc,
	})

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip circuit breaker for certain methods
		if cbCore.ShouldSkip(info.FullMethod) {
			return handler(ctx, req)
		}

		// Check if circuit allows the request
		if !cbCore.Allow(info.FullMethod) {
			return nil, status.Error(codes.Unavailable, "circuit breaker is open")
		}

		// Execute handler
		resp, err := handler(ctx, req)

		// Record result
		cbCore.RecordResult(info.FullMethod, err)

		return resp, err
	}
}

// StreamCircuitBreakerInterceptor returns a stream interceptor that applies circuit breaker protection.
func StreamCircuitBreakerInterceptor(registry *circuitbreaker.Registry) grpc.StreamServerInterceptor {
	return StreamCircuitBreakerInterceptorWithConfig(CircuitBreakerConfig{Registry: registry})
}

// StreamCircuitBreakerInterceptorWithConfig returns a stream circuit breaker interceptor with custom configuration.
func StreamCircuitBreakerInterceptorWithConfig(config CircuitBreakerConfig) grpc.StreamServerInterceptor {
	cbCore := core.NewCircuitBreakerCore(core.CircuitBreakerCoreConfig{
		BaseConfig: core.BaseConfig{
			Logger:    config.Logger,
			SkipPaths: config.SkipMethods,
		},
		Registry: config.Registry,
		NameFunc: config.NameFunc,
	})

	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip circuit breaker for certain methods
		if cbCore.ShouldSkip(info.FullMethod) {
			return handler(srv, ss)
		}

		// Check if circuit allows the request
		if !cbCore.Allow(info.FullMethod) {
			return status.Error(codes.Unavailable, "circuit breaker is open")
		}

		// Execute handler
		err := handler(srv, ss)

		// Record result
		cbCore.RecordResult(info.FullMethod, err)

		return err
	}
}

// UnaryCircuitBreakerInterceptorWithCore returns a unary interceptor using the core circuit breaker.
func UnaryCircuitBreakerInterceptorWithCore(coreConfig core.CircuitBreakerCoreConfig) grpc.UnaryServerInterceptor {
	cbCore := core.NewCircuitBreakerCore(coreConfig)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip circuit breaker for certain methods
		if cbCore.ShouldSkip(info.FullMethod) {
			return handler(ctx, req)
		}

		// Check if circuit allows the request
		if !cbCore.Allow(info.FullMethod) {
			return nil, status.Error(codes.Unavailable, "circuit breaker is open")
		}

		// Execute handler
		resp, err := handler(ctx, req)

		// Record result
		cbCore.RecordResult(info.FullMethod, err)

		return resp, err
	}
}

// StreamCircuitBreakerInterceptorWithCore returns a stream interceptor using the core circuit breaker.
func StreamCircuitBreakerInterceptorWithCore(coreConfig core.CircuitBreakerCoreConfig) grpc.StreamServerInterceptor {
	cbCore := core.NewCircuitBreakerCore(coreConfig)

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip circuit breaker for certain methods
		if cbCore.ShouldSkip(info.FullMethod) {
			return handler(srv, ss)
		}

		// Check if circuit allows the request
		if !cbCore.Allow(info.FullMethod) {
			return status.Error(codes.Unavailable, "circuit breaker is open")
		}

		// Execute handler
		err := handler(srv, ss)

		// Record result
		cbCore.RecordResult(info.FullMethod, err)

		return err
	}
}

// UnaryClientCircuitBreakerInterceptor returns a unary client interceptor with circuit breaker.
func UnaryClientCircuitBreakerInterceptor(registry *circuitbreaker.Registry) grpc.UnaryClientInterceptor {
	cbCore := core.NewCircuitBreakerCore(core.CircuitBreakerCoreConfig{
		Registry: registry,
	})

	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if !cbCore.Allow(method) {
			return status.Error(codes.Unavailable, "circuit breaker is open")
		}

		err := invoker(ctx, method, req, reply, cc, opts...)

		cbCore.RecordResult(method, err)

		return err
	}
}

// StreamClientCircuitBreakerInterceptor returns a stream client interceptor with circuit breaker.
func StreamClientCircuitBreakerInterceptor(registry *circuitbreaker.Registry) grpc.StreamClientInterceptor {
	cbCore := core.NewCircuitBreakerCore(core.CircuitBreakerCoreConfig{
		Registry: registry,
	})

	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		if !cbCore.Allow(method) {
			return nil, status.Error(codes.Unavailable, "circuit breaker is open")
		}

		stream, err := streamer(ctx, desc, cc, method, opts...)

		cbCore.RecordResult(method, err)

		return stream, err
	}
}

// IsCircuitBreakerFailure determines if a gRPC status code should count as a failure.
// This is exported for testing and external use.
func IsCircuitBreakerFailure(code codes.Code) bool {
	switch code {
	case codes.Unavailable,
		codes.ResourceExhausted,
		codes.Internal,
		codes.Unknown,
		codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}

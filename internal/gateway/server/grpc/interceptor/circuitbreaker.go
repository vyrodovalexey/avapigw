package interceptor

import (
	"context"

	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
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
	if config.Registry == nil {
		config.Registry = circuitbreaker.NewRegistry(nil, nil)
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.NameFunc == nil {
		config.NameFunc = func(method string) string {
			return method
		}
	}

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip circuit breaker for certain methods
		if skipMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Get circuit breaker name
		name := config.NameFunc(info.FullMethod)

		// Get or create circuit breaker
		cb := config.Registry.GetOrCreate(name)

		// Check if circuit allows the request
		if !cb.Allow() {
			config.Logger.Debug("circuit breaker open",
				zap.String("method", info.FullMethod),
				zap.String("name", name),
				zap.String("state", cb.State().String()),
			)
			return nil, status.Error(codes.Unavailable, "circuit breaker is open")
		}

		// Execute handler
		resp, err := handler(ctx, req)

		// Record result
		if err != nil {
			st, ok := status.FromError(err)
			if ok && isCircuitBreakerFailure(st.Code()) {
				cb.RecordFailure()
			} else {
				cb.RecordSuccess()
			}
		} else {
			cb.RecordSuccess()
		}

		return resp, err
	}
}

// StreamCircuitBreakerInterceptor returns a stream interceptor that applies circuit breaker protection.
func StreamCircuitBreakerInterceptor(registry *circuitbreaker.Registry) grpc.StreamServerInterceptor {
	return StreamCircuitBreakerInterceptorWithConfig(CircuitBreakerConfig{Registry: registry})
}

// StreamCircuitBreakerInterceptorWithConfig returns a stream circuit breaker interceptor with custom configuration.
func StreamCircuitBreakerInterceptorWithConfig(config CircuitBreakerConfig) grpc.StreamServerInterceptor {
	if config.Registry == nil {
		config.Registry = circuitbreaker.NewRegistry(nil, nil)
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.NameFunc == nil {
		config.NameFunc = func(method string) string {
			return method
		}
	}

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip circuit breaker for certain methods
		if skipMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Get circuit breaker name
		name := config.NameFunc(info.FullMethod)

		// Get or create circuit breaker
		cb := config.Registry.GetOrCreate(name)

		// Check if circuit allows the request
		if !cb.Allow() {
			config.Logger.Debug("circuit breaker open",
				zap.String("method", info.FullMethod),
				zap.String("name", name),
				zap.String("state", cb.State().String()),
			)
			return status.Error(codes.Unavailable, "circuit breaker is open")
		}

		// Execute handler
		err := handler(srv, ss)

		// Record result
		if err != nil {
			st, ok := status.FromError(err)
			if ok && isCircuitBreakerFailure(st.Code()) {
				cb.RecordFailure()
			} else {
				cb.RecordSuccess()
			}
		} else {
			cb.RecordSuccess()
		}

		return err
	}
}

// isCircuitBreakerFailure determines if a gRPC status code should count as a failure.
func isCircuitBreakerFailure(code codes.Code) bool {
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

// UnaryClientCircuitBreakerInterceptor returns a unary client interceptor with circuit breaker.
func UnaryClientCircuitBreakerInterceptor(registry *circuitbreaker.Registry) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		cb := registry.GetOrCreate(method)

		if !cb.Allow() {
			return status.Error(codes.Unavailable, "circuit breaker is open")
		}

		err := invoker(ctx, method, req, reply, cc, opts...)

		if err != nil {
			st, ok := status.FromError(err)
			if ok && isCircuitBreakerFailure(st.Code()) {
				cb.RecordFailure()
			} else {
				cb.RecordSuccess()
			}
		} else {
			cb.RecordSuccess()
		}

		return err
	}
}

// StreamClientCircuitBreakerInterceptor returns a stream client interceptor with circuit breaker.
func StreamClientCircuitBreakerInterceptor(registry *circuitbreaker.Registry) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		cb := registry.GetOrCreate(method)

		if !cb.Allow() {
			return nil, status.Error(codes.Unavailable, "circuit breaker is open")
		}

		stream, err := streamer(ctx, desc, cc, method, opts...)

		if err != nil {
			st, ok := status.FromError(err)
			if ok && isCircuitBreakerFailure(st.Code()) {
				cb.RecordFailure()
			} else {
				cb.RecordSuccess()
			}
		} else {
			cb.RecordSuccess()
		}

		return stream, err
	}
}

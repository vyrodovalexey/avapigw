package middleware

import (
	"context"
	"time"

	"github.com/sony/gobreaker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCCircuitBreaker wraps gobreaker.CircuitBreaker for gRPC.
type GRPCCircuitBreaker struct {
	cb     *gobreaker.CircuitBreaker
	logger observability.Logger
}

// CircuitBreakerOption is a functional option for configuring the circuit breaker.
type CircuitBreakerOption func(*GRPCCircuitBreaker)

// WithCircuitBreakerLogger sets the logger for the circuit breaker.
func WithCircuitBreakerLogger(logger observability.Logger) CircuitBreakerOption {
	return func(cb *GRPCCircuitBreaker) {
		cb.logger = logger
	}
}

// NewGRPCCircuitBreaker creates a new gRPC circuit breaker.
func NewGRPCCircuitBreaker(
	name string,
	threshold int,
	timeout time.Duration,
	opts ...CircuitBreakerOption,
) *GRPCCircuitBreaker {
	cb := &GRPCCircuitBreaker{
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(cb)
	}

	thresholdU32 := safeIntToUint32(threshold)

	settings := gobreaker.Settings{
		Name:        name,
		MaxRequests: thresholdU32,
		Interval:    timeout,
		Timeout:     timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= thresholdU32 && failureRatio >= 0.5
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			cb.logger.Info("circuit breaker state change",
				observability.String("name", name),
				observability.String("from", from.String()),
				observability.String("to", to.String()),
			)
		},
		IsSuccessful: func(err error) bool {
			if err == nil {
				return true
			}
			// Consider certain gRPC codes as non-failures
			code := status.Code(err)
			switch code {
			case codes.OK, codes.Canceled, codes.InvalidArgument,
				codes.NotFound, codes.AlreadyExists, codes.PermissionDenied,
				codes.Unauthenticated, codes.FailedPrecondition, codes.OutOfRange:
				return true
			default:
				return false
			}
		},
	}

	cb.cb = gobreaker.NewCircuitBreaker(settings)
	return cb
}

// safeIntToUint32 safely converts int to uint32.
func safeIntToUint32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > int(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(n) //nolint:gosec // bounds checked above
}

// State returns the current state of the circuit breaker.
func (cb *GRPCCircuitBreaker) State() gobreaker.State {
	return cb.cb.State()
}

// UnaryCircuitBreakerInterceptor returns a unary server interceptor that applies circuit breaker.
func UnaryCircuitBreakerInterceptor(cb *GRPCCircuitBreaker) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if circuit breaker is open
		if cb.State() == gobreaker.StateOpen {
			cb.logger.Warn("circuit breaker open",
				observability.String("method", info.FullMethod),
			)
			return nil, status.Error(codes.Unavailable, "service unavailable: circuit breaker open")
		}

		// Execute with circuit breaker
		result, err := cb.cb.Execute(func() (interface{}, error) {
			return handler(ctx, req)
		})

		if err != nil {
			return nil, err
		}

		return result, nil
	}
}

// StreamCircuitBreakerInterceptor returns a stream server interceptor that applies circuit breaker.
func StreamCircuitBreakerInterceptor(cb *GRPCCircuitBreaker) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Check if circuit breaker is open
		if cb.State() == gobreaker.StateOpen {
			cb.logger.Warn("circuit breaker open",
				observability.String("method", info.FullMethod),
			)
			return status.Error(codes.Unavailable, "service unavailable: circuit breaker open")
		}

		// Execute with circuit breaker
		_, err := cb.cb.Execute(func() (interface{}, error) {
			return nil, handler(srv, stream)
		})

		return err
	}
}

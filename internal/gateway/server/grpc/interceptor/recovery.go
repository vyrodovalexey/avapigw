package interceptor

import (
	"context"
	"runtime/debug"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryConfig holds configuration for the recovery interceptor.
type RecoveryConfig struct {
	Logger           *zap.Logger
	EnableStackTrace bool
	PanicHandler     func(ctx context.Context, p interface{}) error
}

// UnaryRecoveryInterceptor returns a unary interceptor that recovers from panics.
func UnaryRecoveryInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return UnaryRecoveryInterceptorWithConfig(RecoveryConfig{
		Logger:           logger,
		EnableStackTrace: true,
	})
}

// UnaryRecoveryInterceptorWithConfig returns a unary recovery interceptor with custom configuration.
func UnaryRecoveryInterceptorWithConfig(config RecoveryConfig) grpc.UnaryServerInterceptor {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if p := recover(); p != nil {
				err = handlePanic(ctx, p, info.FullMethod, config)
			}
		}()

		return handler(ctx, req)
	}
}

// StreamRecoveryInterceptor returns a stream interceptor that recovers from panics.
func StreamRecoveryInterceptor(logger *zap.Logger) grpc.StreamServerInterceptor {
	return StreamRecoveryInterceptorWithConfig(RecoveryConfig{
		Logger:           logger,
		EnableStackTrace: true,
	})
}

// StreamRecoveryInterceptorWithConfig returns a stream recovery interceptor with custom configuration.
func StreamRecoveryInterceptorWithConfig(config RecoveryConfig) grpc.StreamServerInterceptor {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = handlePanic(ss.Context(), p, info.FullMethod, config)
			}
		}()

		return handler(srv, ss)
	}
}

// handlePanic handles a panic and returns an appropriate error.
func handlePanic(ctx context.Context, p interface{}, method string, config RecoveryConfig) error {
	// Get stack trace
	var stack []byte
	if config.EnableStackTrace {
		stack = debug.Stack()
	}

	// Build log fields
	fields := []zap.Field{
		zap.Any("panic", p),
		zap.String("method", method),
	}

	// Add request ID if available
	if requestID := GetRequestID(ctx); requestID != "" {
		fields = append(fields, zap.String("requestID", requestID))
	}

	if config.EnableStackTrace {
		fields = append(fields, zap.ByteString("stack", stack))
	}

	config.Logger.Error("gRPC panic recovered", fields...)

	// Record error in span if tracing is enabled
	span := GetSpanFromContext(ctx)
	if span != nil {
		span.RecordError(status.Errorf(codes.Internal, "panic: %v", p))
	}

	// Call custom panic handler if provided
	if config.PanicHandler != nil {
		return config.PanicHandler(ctx, p)
	}

	// Return internal error
	return status.Errorf(codes.Internal, "internal server error")
}

// RecoveryHandlerFunc is a function that handles panics.
type RecoveryHandlerFunc func(ctx context.Context, p interface{}) error

// RecoveryHandlerFuncContext is a function that handles panics with full context.
type RecoveryHandlerFuncContext func(ctx context.Context, p interface{}, method string) error

// WithRecoveryHandler returns a recovery config with a custom handler.
func WithRecoveryHandler(handler RecoveryHandlerFunc) RecoveryConfig {
	return RecoveryConfig{
		PanicHandler: handler,
	}
}

// WithRecoveryHandlerContext returns a recovery config with a custom context-aware handler.
func WithRecoveryHandlerContext(handler RecoveryHandlerFuncContext, method string) RecoveryConfig {
	return RecoveryConfig{
		PanicHandler: func(ctx context.Context, p interface{}) error {
			return handler(ctx, p, method)
		},
	}
}

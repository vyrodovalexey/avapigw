package middleware

import (
	"context"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// UnaryRecoveryInterceptor returns a unary server interceptor that recovers from panics.
func UnaryRecoveryInterceptor(logger observability.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				logger.Error("panic recovered in gRPC handler",
					observability.String("method", info.FullMethod),
					observability.Any("panic", r),
					observability.String("stack", stack),
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

// StreamRecoveryInterceptor returns a stream server interceptor that recovers from panics.
func StreamRecoveryInterceptor(logger observability.Logger) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				logger.Error("panic recovered in gRPC stream handler",
					observability.String("method", info.FullMethod),
					observability.Any("panic", r),
					observability.String("stack", stack),
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(srv, stream)
	}
}

// RecoveryHandlerFunc is a function that handles panics.
type RecoveryHandlerFunc func(p interface{}) error

// UnaryRecoveryInterceptorWithHandler returns a unary server interceptor with a custom recovery handler.
func UnaryRecoveryInterceptorWithHandler(handler RecoveryHandlerFunc) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		grpcHandler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = handler(r)
			}
		}()

		return grpcHandler(ctx, req)
	}
}

// StreamRecoveryInterceptorWithHandler returns a stream server interceptor with a custom recovery handler.
func StreamRecoveryInterceptorWithHandler(handler RecoveryHandlerFunc) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		grpcHandler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = handler(r)
			}
		}()

		return grpcHandler(srv, stream)
	}
}

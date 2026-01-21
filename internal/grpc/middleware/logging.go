package middleware

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// UnaryLoggingInterceptor returns a unary server interceptor that logs requests.
func UnaryLoggingInterceptor(logger observability.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Extract request info
		service, method := router.ParseFullMethod(info.FullMethod)
		clientAddr := getClientAddr(ctx)
		requestID := getRequestID(ctx)

		// Call handler
		resp, err := handler(ctx, req)

		// Calculate duration
		duration := time.Since(start)

		// Get status code
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		// Log request
		logLevel := getLogLevel(code)
		logRequest(logger, logLevel, "grpc unary request",
			observability.String("service", service),
			observability.String("method", method),
			observability.String("grpc_code", code.String()),
			observability.Duration("duration", duration),
			observability.String("client_addr", clientAddr),
			observability.String("request_id", requestID),
		)

		return resp, err
	}
}

// StreamLoggingInterceptor returns a stream server interceptor that logs requests.
func StreamLoggingInterceptor(logger observability.Logger) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		ctx := stream.Context()

		// Extract request info
		service, method := router.ParseFullMethod(info.FullMethod)
		clientAddr := getClientAddr(ctx)
		requestID := getRequestID(ctx)

		// Wrap stream to count messages
		wrapped := &loggingServerStream{
			ServerStream: stream,
		}

		// Call handler
		err := handler(srv, wrapped)

		// Calculate duration
		duration := time.Since(start)

		// Get status code
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		// Log request
		logLevel := getLogLevel(code)
		logRequest(logger, logLevel, "grpc stream request",
			observability.String("service", service),
			observability.String("method", method),
			observability.String("grpc_code", code.String()),
			observability.Duration("duration", duration),
			observability.String("client_addr", clientAddr),
			observability.String("request_id", requestID),
			observability.Int64("msgs_sent", wrapped.msgsSent),
			observability.Int64("msgs_received", wrapped.msgsReceived),
		)

		return err
	}
}

// loggingServerStream wraps grpc.ServerStream to count messages.
type loggingServerStream struct {
	grpc.ServerStream
	msgsSent     int64
	msgsReceived int64
}

// SendMsg counts sent messages.
func (s *loggingServerStream) SendMsg(m interface{}) error {
	err := s.ServerStream.SendMsg(m)
	if err == nil {
		s.msgsSent++
	}
	return err
}

// RecvMsg counts received messages.
func (s *loggingServerStream) RecvMsg(m interface{}) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil {
		s.msgsReceived++
	}
	return err
}

// getClientAddr extracts the client address from context.
func getClientAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}

// getRequestID extracts the request ID from context metadata.
func getRequestID(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("x-request-id"); len(values) > 0 {
			return values[0]
		}
	}
	return observability.RequestIDFromContext(ctx)
}

// getLogLevel returns the appropriate log level based on status code.
func getLogLevel(code codes.Code) string {
	switch code {
	case codes.OK:
		return "info"
	case codes.Canceled, codes.InvalidArgument, codes.NotFound,
		codes.AlreadyExists, codes.PermissionDenied, codes.Unauthenticated:
		return "warn"
	default:
		return "error"
	}
}

// logRequest logs a request at the appropriate level.
func logRequest(logger observability.Logger, level, msg string, fields ...observability.Field) {
	switch level {
	case "debug":
		logger.Debug(msg, fields...)
	case "warn":
		logger.Warn(msg, fields...)
	case "error":
		logger.Error(msg, fields...)
	default:
		logger.Info(msg, fields...)
	}
}

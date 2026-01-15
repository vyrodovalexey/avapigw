// Package interceptor provides gRPC interceptors for the API Gateway.
package interceptor

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	// RequestIDKey is the metadata key for request ID.
	RequestIDKey = "x-request-id"
)

// LoggingConfig holds configuration for the logging interceptor.
type LoggingConfig struct {
	Logger          *zap.Logger
	SkipMethods     []string
	SkipHealthCheck bool
}

// UnaryLoggingInterceptor returns a unary interceptor that logs gRPC requests.
func UnaryLoggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return UnaryLoggingInterceptorWithConfig(LoggingConfig{Logger: logger})
}

// UnaryLoggingInterceptorWithConfig returns a unary logging interceptor with custom configuration.
func UnaryLoggingInterceptorWithConfig(config LoggingConfig) grpc.UnaryServerInterceptor {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip logging for certain methods
		if skipMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Skip health check endpoints if configured
		if config.SkipHealthCheck && isHealthCheckMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		start := time.Now()

		// Get or generate request ID
		requestID := getOrGenerateRequestID(ctx)

		// Add request ID to outgoing context
		ctx = metadata.AppendToOutgoingContext(ctx, RequestIDKey, requestID)

		// Process request
		resp, err := handler(ctx, req)

		// Calculate latency
		latency := time.Since(start)

		// Get status code
		st, _ := status.FromError(err)

		// Build log fields
		fields := []zap.Field{
			zap.String("requestID", requestID),
			zap.String("method", info.FullMethod),
			zap.Duration("latency", latency),
			zap.String("grpcCode", st.Code().String()),
		}

		// Add peer info if available
		if peerAddr := getPeerAddress(ctx); peerAddr != "" {
			fields = append(fields, zap.String("peer", peerAddr))
		}

		// Log based on error
		if err != nil {
			fields = append(fields, zap.Error(err))
			config.Logger.Error("gRPC request failed", fields...)
		} else {
			config.Logger.Info("gRPC request completed", fields...)
		}

		return resp, err
	}
}

// StreamLoggingInterceptor returns a stream interceptor that logs gRPC requests.
func StreamLoggingInterceptor(logger *zap.Logger) grpc.StreamServerInterceptor {
	return StreamLoggingInterceptorWithConfig(LoggingConfig{Logger: logger})
}

// StreamLoggingInterceptorWithConfig returns a stream logging interceptor with custom configuration.
func StreamLoggingInterceptorWithConfig(config LoggingConfig) grpc.StreamServerInterceptor {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip logging for certain methods
		if skipMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Skip health check endpoints if configured
		if config.SkipHealthCheck && isHealthCheckMethod(info.FullMethod) {
			return handler(srv, ss)
		}

		start := time.Now()
		ctx := ss.Context()

		// Get or generate request ID
		requestID := getOrGenerateRequestID(ctx)

		// Wrap the stream to track messages
		wrappedStream := &loggingServerStream{
			ServerStream: ss,
			requestID:    requestID,
		}

		// Process stream
		err := handler(srv, wrappedStream)

		// Calculate latency
		latency := time.Since(start)

		// Get status code
		st, _ := status.FromError(err)

		// Build log fields
		fields := []zap.Field{
			zap.String("requestID", requestID),
			zap.String("method", info.FullMethod),
			zap.Duration("latency", latency),
			zap.String("grpcCode", st.Code().String()),
			zap.Bool("clientStream", info.IsClientStream),
			zap.Bool("serverStream", info.IsServerStream),
			zap.Int64("recvMsgs", wrappedStream.recvCount),
			zap.Int64("sentMsgs", wrappedStream.sentCount),
		}

		// Add peer info if available
		if peerAddr := getPeerAddress(ctx); peerAddr != "" {
			fields = append(fields, zap.String("peer", peerAddr))
		}

		// Log based on error
		if err != nil {
			fields = append(fields, zap.Error(err))
			config.Logger.Error("gRPC stream failed", fields...)
		} else {
			config.Logger.Info("gRPC stream completed", fields...)
		}

		return err
	}
}

// loggingServerStream wraps a grpc.ServerStream to track message counts.
type loggingServerStream struct {
	grpc.ServerStream
	requestID string
	recvCount int64
	sentCount int64
}

// RecvMsg wraps the RecvMsg method to count received messages.
func (s *loggingServerStream) RecvMsg(m interface{}) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil {
		s.recvCount++
	}
	return err
}

// SendMsg wraps the SendMsg method to count sent messages.
func (s *loggingServerStream) SendMsg(m interface{}) error {
	err := s.ServerStream.SendMsg(m)
	if err == nil {
		s.sentCount++
	}
	return err
}

// getOrGenerateRequestID gets the request ID from metadata or generates a new one.
func getOrGenerateRequestID(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if ids := md.Get(RequestIDKey); len(ids) > 0 {
			return ids[0]
		}
	}
	return uuid.New().String()
}

// getPeerAddress gets the peer address from the context.
func getPeerAddress(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}

// isHealthCheckMethod checks if the method is a health check method.
func isHealthCheckMethod(method string) bool {
	return method == "/grpc.health.v1.Health/Check" ||
		method == "/grpc.health.v1.Health/Watch"
}

// GetRequestID returns the request ID from the context.
func GetRequestID(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if ids := md.Get(RequestIDKey); len(ids) > 0 {
			return ids[0]
		}
	}
	return ""
}

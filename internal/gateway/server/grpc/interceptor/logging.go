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

	skipMethods := buildSkipMethodsMap(config.SkipMethods)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if shouldSkipUnaryLogging(skipMethods, info.FullMethod, config.SkipHealthCheck) {
			return handler(ctx, req)
		}

		start := time.Now()
		requestID := getOrGenerateRequestID(ctx)
		ctx = metadata.AppendToOutgoingContext(ctx, RequestIDKey, requestID)

		resp, err := handler(ctx, req)

		fields := buildUnaryLogFields(requestID, info.FullMethod, time.Since(start), ctx, err)
		logUnaryResult(config.Logger, err, fields)

		return resp, err
	}
}

// buildSkipMethodsMap creates a map of methods to skip for logging.
func buildSkipMethodsMap(methods []string) map[string]bool {
	skipMethods := make(map[string]bool)
	for _, method := range methods {
		skipMethods[method] = true
	}
	return skipMethods
}

// shouldSkipUnaryLogging determines if logging should be skipped for the unary call.
func shouldSkipUnaryLogging(skipMethods map[string]bool, method string, skipHealthCheck bool) bool {
	if skipMethods[method] {
		return true
	}
	if skipHealthCheck && isHealthCheckMethod(method) {
		return true
	}
	return false
}

// buildUnaryLogFields constructs log fields for unary request logging.
func buildUnaryLogFields(
	requestID string,
	method string,
	latency time.Duration,
	ctx context.Context,
	err error,
) []zap.Field {
	st, _ := status.FromError(err)

	fields := []zap.Field{
		zap.String("requestID", requestID),
		zap.String("method", method),
		zap.Duration("latency", latency),
		zap.String("grpcCode", st.Code().String()),
	}

	if peerAddr := getPeerAddress(ctx); peerAddr != "" {
		fields = append(fields, zap.String("peer", peerAddr))
	}

	return fields
}

// logUnaryResult logs the unary request result based on error status.
func logUnaryResult(logger *zap.Logger, err error, fields []zap.Field) {
	if err != nil {
		fields = append(fields, zap.Error(err))
		logger.Error("gRPC request failed", fields...)
	} else {
		logger.Info("gRPC request completed", fields...)
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

	skipMethods := buildSkipMethodsMap(config.SkipMethods)

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if shouldSkipStreamLogging(skipMethods, info.FullMethod, config.SkipHealthCheck) {
			return handler(srv, ss)
		}

		start := time.Now()
		ctx := ss.Context()
		requestID := getOrGenerateRequestID(ctx)

		wrappedStream := &loggingServerStream{ServerStream: ss, requestID: requestID}
		err := handler(srv, wrappedStream)

		fields := buildStreamLogFields(requestID, info, wrappedStream, time.Since(start), ctx, err)
		logStreamResult(config.Logger, err, fields)

		return err
	}
}

// shouldSkipStreamLogging determines if logging should be skipped for the stream.
func shouldSkipStreamLogging(skipMethods map[string]bool, method string, skipHealthCheck bool) bool {
	if skipMethods[method] {
		return true
	}
	if skipHealthCheck && isHealthCheckMethod(method) {
		return true
	}
	return false
}

// buildStreamLogFields constructs log fields for stream logging.
func buildStreamLogFields(
	requestID string,
	info *grpc.StreamServerInfo,
	wrappedStream *loggingServerStream,
	latency time.Duration,
	ctx context.Context,
	err error,
) []zap.Field {
	st, _ := status.FromError(err)

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

	if peerAddr := getPeerAddress(ctx); peerAddr != "" {
		fields = append(fields, zap.String("peer", peerAddr))
	}

	return fields
}

// logStreamResult logs the stream result based on error status.
func logStreamResult(logger *zap.Logger, err error, fields []zap.Field) {
	if err != nil {
		fields = append(fields, zap.Error(err))
		logger.Error("gRPC stream failed", fields...)
	} else {
		logger.Info("gRPC stream completed", fields...)
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

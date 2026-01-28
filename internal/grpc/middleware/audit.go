package middleware

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// UnaryAuditInterceptor returns a unary server interceptor that logs audit events.
// It captures the gRPC method, client address, request ID, and duration,
// then emits request and response audit events via the provided audit logger.
func UnaryAuditInterceptor(logger audit.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Extract request context
		service, method := router.ParseFullMethod(info.FullMethod)
		clientAddr := getClientAddrFromContext(ctx)
		requestID := getAuditRequestID(ctx)
		traceID := observability.TraceIDFromContext(ctx)
		spanID := observability.SpanIDFromContext(ctx)

		// Build and log request audit event
		reqEvent := buildGRPCRequestEvent(info.FullMethod, service, method, clientAddr, requestID)
		enrichGRPCTraceContext(reqEvent, traceID, spanID)
		logger.LogEvent(ctx, reqEvent)

		// Call the handler
		resp, err := handler(ctx, req)

		// Calculate duration and determine outcome
		duration := time.Since(start)
		grpcCode := codes.OK
		if err != nil {
			grpcCode = status.Code(err)
		}

		// Build and log response audit event
		respEvent := buildGRPCResponseEvent(
			info.FullMethod, service, method, clientAddr, requestID, grpcCode, duration, err)
		enrichGRPCTraceContext(respEvent, traceID, spanID)
		logger.LogEvent(ctx, respEvent)

		return resp, err
	}
}

// StreamAuditInterceptor returns a stream server interceptor that logs audit events.
// It captures the gRPC method, client address, request ID, and duration,
// then emits request and response audit events via the provided audit logger.
func StreamAuditInterceptor(logger audit.Logger) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		ctx := stream.Context()

		// Extract request context
		service, method := router.ParseFullMethod(info.FullMethod)
		clientAddr := getClientAddrFromContext(ctx)
		requestID := getAuditRequestID(ctx)
		traceID := observability.TraceIDFromContext(ctx)
		spanID := observability.SpanIDFromContext(ctx)

		// Build and log request audit event
		reqEvent := buildGRPCRequestEvent(info.FullMethod, service, method, clientAddr, requestID)
		enrichGRPCTraceContext(reqEvent, traceID, spanID)
		logger.LogEvent(ctx, reqEvent)

		// Call the handler
		err := handler(srv, stream)

		// Calculate duration and determine outcome
		duration := time.Since(start)
		grpcCode := codes.OK
		if err != nil {
			grpcCode = status.Code(err)
		}

		// Build and log response audit event
		respEvent := buildGRPCResponseEvent(
			info.FullMethod, service, method, clientAddr, requestID, grpcCode, duration, err)
		enrichGRPCTraceContext(respEvent, traceID, spanID)
		logger.LogEvent(ctx, respEvent)

		return err
	}
}

// buildGRPCRequestEvent creates an audit event for a gRPC request.
func buildGRPCRequestEvent(
	fullMethod, service, method, clientAddr, requestID string,
) *audit.Event {
	reqDetails := &audit.RequestDetails{
		Method:     method,
		Path:       fullMethod,
		RemoteAddr: clientAddr,
		Protocol:   "gRPC",
	}

	subject := &audit.Subject{
		IPAddress: clientAddr,
	}

	event := audit.RequestEvent(reqDetails, subject)
	event.Resource = &audit.Resource{
		Type:    "grpc",
		Path:    fullMethod,
		Method:  method,
		Service: service,
	}

	if requestID != "" {
		event.WithMetadata("request_id", requestID)
	}

	return event
}

// buildGRPCResponseEvent creates an audit event for a gRPC response.
func buildGRPCResponseEvent(
	fullMethod, service, method, clientAddr, requestID string,
	grpcCode codes.Code,
	duration time.Duration,
	err error,
) *audit.Event {
	statusCode := int(grpcCode)

	respDetails := &audit.ResponseDetails{
		StatusCode: statusCode,
	}

	action := audit.ActionGRPCResponse
	outcome := audit.OutcomeSuccess
	if grpcCode != codes.OK {
		outcome = audit.OutcomeFailure
	}

	event := audit.NewEvent(audit.EventTypeResponse, action, outcome).
		WithResponse(respDetails).
		WithDuration(duration)

	event.Resource = &audit.Resource{
		Type:    "grpc",
		Path:    fullMethod,
		Method:  method,
		Service: service,
	}

	event.Subject = &audit.Subject{
		IPAddress: clientAddr,
	}

	if requestID != "" {
		event.WithMetadata("request_id", requestID)
	}

	if err != nil {
		event.WithError(&audit.ErrorDetails{
			Code:    grpcCode.String(),
			Message: err.Error(),
		})
	}

	return event
}

// enrichGRPCTraceContext sets TraceID and SpanID on an audit event
// if the values are available from the request context.
func enrichGRPCTraceContext(event *audit.Event, traceID, spanID string) {
	if traceID != "" {
		event.WithTraceID(traceID)
	}
	if spanID != "" {
		event.WithSpanID(spanID)
	}
}

// getAuditRequestID extracts the request ID from context metadata.
func getAuditRequestID(ctx context.Context) string {
	// First check observability context (set by RequestID interceptor)
	if requestID := observability.RequestIDFromContext(ctx); requestID != "" {
		return requestID
	}

	// Then check metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(RequestIDHeader); len(values) > 0 {
			return values[0]
		}
	}

	return ""
}

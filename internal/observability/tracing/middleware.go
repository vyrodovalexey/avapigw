// Package tracing provides OpenTelemetry tracing for the API Gateway.
package tracing

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// TracerName is the name of the tracer.
	TracerName = "avapigw"
	// SpanContextKey is the context key for the span.
	SpanContextKey = "otel-span"
)

// HTTPMiddlewareConfig holds configuration for the HTTP tracing middleware.
type HTTPMiddlewareConfig struct {
	// TracerProvider is the tracer provider to use.
	TracerProvider trace.TracerProvider

	// Propagators is the text map propagator to use.
	Propagators propagation.TextMapPropagator

	// ServiceName is the name of the service.
	ServiceName string

	// SkipPaths is a list of paths to skip tracing.
	SkipPaths []string

	// SpanNameFormatter formats the span name.
	SpanNameFormatter func(*http.Request) string

	// Filter determines if a request should be traced.
	Filter func(*http.Request) bool
}

// DefaultHTTPMiddlewareConfig returns a HTTPMiddlewareConfig with default values.
func DefaultHTTPMiddlewareConfig() *HTTPMiddlewareConfig {
	return &HTTPMiddlewareConfig{
		ServiceName: TracerName,
		SpanNameFormatter: func(r *http.Request) string {
			return fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		},
	}
}

// HTTPMiddleware returns an HTTP middleware that creates spans for requests.
func HTTPMiddleware(serviceName string) func(http.Handler) http.Handler {
	return HTTPMiddlewareWithConfig(&HTTPMiddlewareConfig{
		ServiceName: serviceName,
	})
}

// HTTPMiddlewareWithConfig returns an HTTP middleware with custom configuration.
func HTTPMiddlewareWithConfig(config *HTTPMiddlewareConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultHTTPMiddlewareConfig()
	}
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}
	if config.Propagators == nil {
		config.Propagators = otel.GetTextMapPropagator()
	}
	if config.ServiceName == "" {
		config.ServiceName = TracerName
	}
	if config.SpanNameFormatter == nil {
		config.SpanNameFormatter = func(r *http.Request) string {
			return fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		}
	}

	tracer := config.TracerProvider.Tracer(config.ServiceName)
	skipPaths := make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip tracing for certain paths
			if skipPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Apply filter if provided
			if config.Filter != nil && !config.Filter(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract trace context from incoming request
			ctx := config.Propagators.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			// Create span name
			spanName := config.SpanNameFormatter(r)

			// Start span
			ctx, span := tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
			)
			defer span.End()

			// Set span attributes
			span.SetAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.url", r.URL.String()),
				attribute.String("http.target", r.URL.Path),
				attribute.String("http.host", r.Host),
				attribute.String("http.scheme", r.URL.Scheme),
				attribute.String("http.user_agent", r.UserAgent()),
				attribute.String("net.peer.ip", getClientIP(r)),
			)

			// Wrap response writer to capture status code
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Process request with updated context
			next.ServeHTTP(wrapped, r.WithContext(ctx))

			// Set response attributes
			span.SetAttributes(
				attribute.Int("http.status_code", wrapped.statusCode),
				attribute.Int("http.response_content_length", wrapped.size),
			)

			// Set span status based on HTTP status code
			switch {
			case wrapped.statusCode >= 500:
				span.SetStatus(codes.Error, http.StatusText(wrapped.statusCode))
			case wrapped.statusCode >= 400:
				span.SetStatus(codes.Error, http.StatusText(wrapped.statusCode))
			default:
				span.SetStatus(codes.Ok, "")
			}
		})
	}
}

// GinMiddleware returns a Gin middleware that creates spans for requests.
func GinMiddleware(serviceName string) gin.HandlerFunc {
	return GinMiddlewareWithConfig(&HTTPMiddlewareConfig{
		ServiceName: serviceName,
	})
}

// GinMiddlewareWithConfig returns a Gin middleware with custom configuration.
func GinMiddlewareWithConfig(config *HTTPMiddlewareConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultHTTPMiddlewareConfig()
	}
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}
	if config.Propagators == nil {
		config.Propagators = otel.GetTextMapPropagator()
	}
	if config.ServiceName == "" {
		config.ServiceName = TracerName
	}
	if config.SpanNameFormatter == nil {
		config.SpanNameFormatter = func(r *http.Request) string {
			return fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		}
	}

	tracer := config.TracerProvider.Tracer(config.ServiceName)
	skipPaths := make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	return func(c *gin.Context) {
		// Skip tracing for certain paths
		if skipPaths[c.Request.URL.Path] {
			c.Next()
			return
		}

		// Apply filter if provided
		if config.Filter != nil && !config.Filter(c.Request) {
			c.Next()
			return
		}

		// Extract trace context from incoming request
		ctx := config.Propagators.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		// Create span name
		spanName := config.SpanNameFormatter(c.Request)

		// Start span
		ctx, span := tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		// Set span attributes
		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.url", c.Request.URL.String()),
			attribute.String("http.target", c.Request.URL.Path),
			attribute.String("http.host", c.Request.Host),
			attribute.String("http.user_agent", c.Request.UserAgent()),
			attribute.String("net.peer.ip", c.ClientIP()),
		)

		// Store span in context
		c.Set(SpanContextKey, span)
		c.Request = c.Request.WithContext(ctx)

		// Process request
		c.Next()

		// Set response attributes
		span.SetAttributes(
			attribute.Int("http.status_code", c.Writer.Status()),
			attribute.Int("http.response_content_length", c.Writer.Size()),
		)

		// Record errors
		if len(c.Errors) > 0 {
			span.SetAttributes(attribute.String("error", c.Errors.String()))
			span.RecordError(fmt.Errorf("%s", c.Errors.String()))
		}

		// Set span status based on HTTP status code
		statusCode := c.Writer.Status()
		switch {
		case statusCode >= 500:
			span.SetStatus(codes.Error, http.StatusText(statusCode))
		case statusCode >= 400:
			span.SetStatus(codes.Error, http.StatusText(statusCode))
		default:
			span.SetStatus(codes.Ok, "")
		}
	}
}

// GetSpanFromGin returns the span from the Gin context.
func GetSpanFromGin(c *gin.Context) trace.Span {
	if span, exists := c.Get(SpanContextKey); exists {
		if s, ok := span.(trace.Span); ok {
			return s
		}
	}
	return nil
}

// gRPC Interceptors

// UnaryServerInterceptor returns a gRPC unary server interceptor for tracing.
func UnaryServerInterceptor(serviceName string) grpc.UnaryServerInterceptor {
	tracer := otel.GetTracerProvider().Tracer(serviceName)
	propagators := otel.GetTextMapPropagator()

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Extract metadata from context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Extract trace context
		ctx = propagators.Extract(ctx, MetadataCarrier(md))

		// Parse service and method from full method name
		service, method := parseFullMethod(info.FullMethod)

		// Start span
		ctx, span := tracer.Start(ctx, info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", service),
				attribute.String("rpc.method", method),
			),
		)
		defer span.End()

		// Call handler
		resp, err := handler(ctx, req)

		// Record error if any
		if err != nil {
			st, _ := status.FromError(err)
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(st.Code())))
			span.SetStatus(codes.Error, st.Message())
			span.RecordError(err)
		} else {
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", 0))
			span.SetStatus(codes.Ok, "")
		}

		return resp, err
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor for tracing.
func StreamServerInterceptor(serviceName string) grpc.StreamServerInterceptor {
	tracer := otel.GetTracerProvider().Tracer(serviceName)
	propagators := otel.GetTextMapPropagator()

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		// Extract metadata from context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}

		// Extract trace context
		ctx = propagators.Extract(ctx, MetadataCarrier(md))

		// Parse service and method from full method name
		service, method := parseFullMethod(info.FullMethod)

		// Start span
		ctx, span := tracer.Start(ctx, info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", service),
				attribute.String("rpc.method", method),
				attribute.Bool("rpc.grpc.is_client_stream", info.IsClientStream),
				attribute.Bool("rpc.grpc.is_server_stream", info.IsServerStream),
			),
		)
		defer span.End()

		// Wrap stream with traced context
		wrappedStream := &tracedServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		// Call handler
		err := handler(srv, wrappedStream)

		// Record error if any
		if err != nil {
			st, _ := status.FromError(err)
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(st.Code())))
			span.SetStatus(codes.Error, st.Message())
			span.RecordError(err)
		} else {
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", 0))
			span.SetStatus(codes.Ok, "")
		}

		return err
	}
}

// UnaryClientInterceptor returns a gRPC unary client interceptor for tracing.
func UnaryClientInterceptor(serviceName string) grpc.UnaryClientInterceptor {
	tracer := otel.GetTracerProvider().Tracer(serviceName)
	propagators := otel.GetTextMapPropagator()

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// Parse service and method from full method name
		service, methodName := parseFullMethod(method)

		// Start span
		ctx, span := tracer.Start(ctx, method,
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", service),
				attribute.String("rpc.method", methodName),
			),
		)
		defer span.End()

		// Inject trace context into metadata
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}
		propagators.Inject(ctx, MetadataCarrier(md))
		ctx = metadata.NewOutgoingContext(ctx, md)

		// Call invoker
		err := invoker(ctx, method, req, reply, cc, opts...)

		// Record error if any
		if err != nil {
			st, _ := status.FromError(err)
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(st.Code())))
			span.SetStatus(codes.Error, st.Message())
			span.RecordError(err)
		} else {
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", 0))
			span.SetStatus(codes.Ok, "")
		}

		return err
	}
}

// StreamClientInterceptor returns a gRPC stream client interceptor for tracing.
func StreamClientInterceptor(serviceName string) grpc.StreamClientInterceptor {
	tracer := otel.GetTracerProvider().Tracer(serviceName)
	propagators := otel.GetTextMapPropagator()

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		// Parse service and method from full method name
		service, methodName := parseFullMethod(method)

		// Start span
		ctx, span := tracer.Start(ctx, method,
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", service),
				attribute.String("rpc.method", methodName),
				attribute.Bool("rpc.grpc.is_client_stream", desc.ClientStreams),
				attribute.Bool("rpc.grpc.is_server_stream", desc.ServerStreams),
			),
		)

		// Inject trace context into metadata
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			md = metadata.MD{}
		}
		propagators.Inject(ctx, MetadataCarrier(md))
		ctx = metadata.NewOutgoingContext(ctx, md)

		// Call streamer
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			st, _ := status.FromError(err)
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(st.Code())))
			span.SetStatus(codes.Error, st.Message())
			span.RecordError(err)
			span.End()
			return nil, err
		}

		return &tracedClientStream{
			ClientStream: stream,
			span:         span,
		}, nil
	}
}

// tracedServerStream wraps grpc.ServerStream with traced context.
type tracedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the traced context.
func (s *tracedServerStream) Context() context.Context {
	return s.ctx
}

// tracedClientStream wraps grpc.ClientStream with tracing.
type tracedClientStream struct {
	grpc.ClientStream
	span trace.Span
}

// CloseSend ends the span when the stream is closed.
func (s *tracedClientStream) CloseSend() error {
	err := s.ClientStream.CloseSend()
	if err != nil {
		s.span.RecordError(err)
	}
	return err
}

// RecvMsg records errors on receive.
func (s *tracedClientStream) RecvMsg(m interface{}) error {
	err := s.ClientStream.RecvMsg(m)
	if err != nil {
		s.span.RecordError(err)
		s.span.End()
	}
	return err
}

// responseWriter wraps http.ResponseWriter to capture status code and size.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the response size.
func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// parseFullMethod parses a gRPC full method name into service and method.
// Returns the service name and method name.
func parseFullMethod(fullMethod string) (service string, method string) {
	// Full method format: /package.service/method
	parts := strings.Split(strings.TrimPrefix(fullMethod, "/"), "/")
	if len(parts) != 2 {
		return "", fullMethod
	}
	return parts[0], parts[1]
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

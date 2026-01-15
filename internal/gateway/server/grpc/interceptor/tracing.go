package interceptor

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	grpcstatus "google.golang.org/grpc/status"
)

const (
	// TracerName is the name of the tracer.
	TracerName = "avapigw-grpc"
	// SpanKey is the context key for the span.
	SpanKey = "otel-grpc-span"
)

// TracingConfig holds configuration for the tracing interceptor.
type TracingConfig struct {
	TracerProvider trace.TracerProvider
	Propagators    propagation.TextMapPropagator
	ServiceName    string
	SkipMethods    []string
}

// UnaryTracingInterceptor returns a unary interceptor that creates OpenTelemetry spans.
func UnaryTracingInterceptor() grpc.UnaryServerInterceptor {
	return UnaryTracingInterceptorWithConfig(TracingConfig{})
}

// UnaryTracingInterceptorWithConfig returns a unary tracing interceptor with custom configuration.
func UnaryTracingInterceptorWithConfig(config TracingConfig) grpc.UnaryServerInterceptor {
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}
	if config.Propagators == nil {
		config.Propagators = otel.GetTextMapPropagator()
	}
	if config.ServiceName == "" {
		config.ServiceName = TracerName
	}

	tracer := config.TracerProvider.Tracer(config.ServiceName)

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip tracing for certain methods
		if skipMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract trace context from incoming metadata
		md, _ := metadata.FromIncomingContext(ctx)
		ctx = config.Propagators.Extract(ctx, metadataCarrier(md))

		// Start span
		ctx, span := tracer.Start(ctx, info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		// Set span attributes
		span.SetAttributes(
			attribute.String("rpc.system", "grpc"),
			attribute.String("rpc.service", extractService(info.FullMethod)),
			attribute.String("rpc.method", extractMethod(info.FullMethod)),
		)

		// Add peer info
		if p, ok := peer.FromContext(ctx); ok {
			span.SetAttributes(attribute.String("net.peer.ip", p.Addr.String()))
		}

		// Add request ID if available
		if requestID := GetRequestID(ctx); requestID != "" {
			span.SetAttributes(attribute.String("request.id", requestID))
		}

		// Process request
		resp, err := handler(ctx, req)

		// Set status based on error
		if err != nil {
			st, _ := grpcstatus.FromError(err)
			span.SetAttributes(attribute.String("rpc.grpc.status_code", st.Code().String()))
			span.SetStatus(codes.Error, st.Message())
			span.RecordError(err)
		} else {
			span.SetAttributes(attribute.String("rpc.grpc.status_code", "OK"))
			span.SetStatus(codes.Ok, "")
		}

		return resp, err
	}
}

// StreamTracingInterceptor returns a stream interceptor that creates OpenTelemetry spans.
func StreamTracingInterceptor() grpc.StreamServerInterceptor {
	return StreamTracingInterceptorWithConfig(TracingConfig{})
}

// StreamTracingInterceptorWithConfig returns a stream tracing interceptor with custom configuration.
func StreamTracingInterceptorWithConfig(config TracingConfig) grpc.StreamServerInterceptor {
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}
	if config.Propagators == nil {
		config.Propagators = otel.GetTextMapPropagator()
	}
	if config.ServiceName == "" {
		config.ServiceName = TracerName
	}

	tracer := config.TracerProvider.Tracer(config.ServiceName)

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip tracing for certain methods
		if skipMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		ctx := ss.Context()

		// Extract trace context from incoming metadata
		md, _ := metadata.FromIncomingContext(ctx)
		ctx = config.Propagators.Extract(ctx, metadataCarrier(md))

		// Start span
		ctx, span := tracer.Start(ctx, info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		// Set span attributes
		span.SetAttributes(
			attribute.String("rpc.system", "grpc"),
			attribute.String("rpc.service", extractService(info.FullMethod)),
			attribute.String("rpc.method", extractMethod(info.FullMethod)),
			attribute.Bool("rpc.grpc.client_stream", info.IsClientStream),
			attribute.Bool("rpc.grpc.server_stream", info.IsServerStream),
		)

		// Add peer info
		if p, ok := peer.FromContext(ctx); ok {
			span.SetAttributes(attribute.String("net.peer.ip", p.Addr.String()))
		}

		// Wrap the stream with the new context
		wrappedStream := &tracingServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		// Process stream
		err := handler(srv, wrappedStream)

		// Set status based on error
		if err != nil {
			st, _ := grpcstatus.FromError(err)
			span.SetAttributes(attribute.String("rpc.grpc.status_code", st.Code().String()))
			span.SetStatus(codes.Error, st.Message())
			span.RecordError(err)
		} else {
			span.SetAttributes(attribute.String("rpc.grpc.status_code", "OK"))
			span.SetStatus(codes.Ok, "")
		}

		return err
	}
}

// tracingServerStream wraps a grpc.ServerStream with a new context.
type tracingServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (s *tracingServerStream) Context() context.Context {
	return s.ctx
}

// metadataCarrier adapts metadata.MD to propagation.TextMapCarrier.
type metadataCarrier metadata.MD

// Get returns the value for the given key.
func (c metadataCarrier) Get(key string) string {
	values := metadata.MD(c).Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// Set sets the value for the given key.
func (c metadataCarrier) Set(key, value string) {
	metadata.MD(c).Set(key, value)
}

// Keys returns all keys in the carrier.
func (c metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	return keys
}

// extractService extracts the service name from the full method.
func extractService(fullMethod string) string {
	if len(fullMethod) == 0 {
		return ""
	}
	if fullMethod[0] == '/' {
		fullMethod = fullMethod[1:]
	}
	for i := len(fullMethod) - 1; i >= 0; i-- {
		if fullMethod[i] == '/' {
			return fullMethod[:i]
		}
	}
	return fullMethod
}

// extractMethod extracts the method name from the full method.
func extractMethod(fullMethod string) string {
	if len(fullMethod) == 0 {
		return ""
	}
	for i := len(fullMethod) - 1; i >= 0; i-- {
		if fullMethod[i] == '/' {
			return fullMethod[i+1:]
		}
	}
	return ""
}

// GetSpanFromContext returns the span from the context.
func GetSpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddSpanAttribute adds an attribute to the current span.
func AddSpanAttribute(ctx context.Context, key string, value interface{}) {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return
	}

	switch v := value.(type) {
	case string:
		span.SetAttributes(attribute.String(key, v))
	case int:
		span.SetAttributes(attribute.Int(key, v))
	case int64:
		span.SetAttributes(attribute.Int64(key, v))
	case float64:
		span.SetAttributes(attribute.Float64(key, v))
	case bool:
		span.SetAttributes(attribute.Bool(key, v))
	}
}

// RecordSpanError records an error on the current span.
func RecordSpanError(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	if span != nil {
		span.RecordError(err)
	}
}

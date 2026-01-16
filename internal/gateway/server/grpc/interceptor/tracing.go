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
	config, tracer, skipMethods := normalizeTracingConfig(config)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if skipMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		ctx = extractTraceContext(ctx, config.Propagators)
		ctx, span := startUnarySpan(ctx, tracer, info.FullMethod)
		defer span.End()

		setUnarySpanAttributes(ctx, span, info.FullMethod)
		resp, err := handler(ctx, req)
		setSpanStatus(span, err)

		return resp, err
	}
}

// normalizeTracingConfig ensures config has all required defaults.
func normalizeTracingConfig(config TracingConfig) (TracingConfig, trace.Tracer, map[string]bool) {
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

	return config, tracer, skipMethods
}

// extractTraceContext extracts trace context from incoming metadata.
func extractTraceContext(ctx context.Context, propagators propagation.TextMapPropagator) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	return propagators.Extract(ctx, metadataCarrier(md))
}

// startUnarySpan starts a new span for a unary RPC.
func startUnarySpan(ctx context.Context, tracer trace.Tracer, method string) (context.Context, trace.Span) {
	return tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindServer))
}

// setUnarySpanAttributes sets common attributes on a unary span.
func setUnarySpanAttributes(ctx context.Context, span trace.Span, method string) {
	span.SetAttributes(
		attribute.String("rpc.system", "grpc"),
		attribute.String("rpc.service", extractService(method)),
		attribute.String("rpc.method", extractMethod(method)),
	)

	if p, ok := peer.FromContext(ctx); ok {
		span.SetAttributes(attribute.String("net.peer.ip", p.Addr.String()))
	}

	if requestID := GetRequestID(ctx); requestID != "" {
		span.SetAttributes(attribute.String("request.id", requestID))
	}
}

// setSpanStatus sets the span status based on the error.
func setSpanStatus(span trace.Span, err error) {
	if err != nil {
		st, _ := grpcstatus.FromError(err)
		span.SetAttributes(attribute.String("rpc.grpc.status_code", st.Code().String()))
		span.SetStatus(codes.Error, st.Message())
		span.RecordError(err)
	} else {
		span.SetAttributes(attribute.String("rpc.grpc.status_code", "OK"))
		span.SetStatus(codes.Ok, "")
	}
}

// StreamTracingInterceptor returns a stream interceptor that creates OpenTelemetry spans.
func StreamTracingInterceptor() grpc.StreamServerInterceptor {
	return StreamTracingInterceptorWithConfig(TracingConfig{})
}

// StreamTracingInterceptorWithConfig returns a stream tracing interceptor with custom configuration.
func StreamTracingInterceptorWithConfig(config TracingConfig) grpc.StreamServerInterceptor {
	config, tracer, skipMethods := normalizeTracingConfig(config)

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if skipMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		ctx := extractTraceContext(ss.Context(), config.Propagators)
		ctx, span := startStreamSpan(ctx, tracer, info.FullMethod)
		defer span.End()

		setStreamSpanAttributes(ctx, span, info)
		wrappedStream := &tracingServerStream{ServerStream: ss, ctx: ctx}
		err := handler(srv, wrappedStream)
		setSpanStatus(span, err)

		return err
	}
}

// startStreamSpan starts a new span for a stream RPC.
func startStreamSpan(ctx context.Context, tracer trace.Tracer, method string) (context.Context, trace.Span) {
	return tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindServer))
}

// setStreamSpanAttributes sets common attributes on a stream span.
func setStreamSpanAttributes(ctx context.Context, span trace.Span, info *grpc.StreamServerInfo) {
	span.SetAttributes(
		attribute.String("rpc.system", "grpc"),
		attribute.String("rpc.service", extractService(info.FullMethod)),
		attribute.String("rpc.method", extractMethod(info.FullMethod)),
		attribute.Bool("rpc.grpc.client_stream", info.IsClientStream),
		attribute.Bool("rpc.grpc.server_stream", info.IsServerStream),
	)

	if p, ok := peer.FromContext(ctx); ok {
		span.SetAttributes(attribute.String("net.peer.ip", p.Addr.String()))
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
	if fullMethod == "" {
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
	if fullMethod == "" {
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

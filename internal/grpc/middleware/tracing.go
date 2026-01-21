package middleware

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TracingConfig contains tracing configuration.
type TracingConfig struct {
	Tracer      trace.Tracer
	Propagator  propagation.TextMapPropagator
	ServiceName string
}

// DefaultTracingConfig returns default tracing configuration.
func DefaultTracingConfig(serviceName string) *TracingConfig {
	return &TracingConfig{
		Tracer:      otel.Tracer(serviceName),
		Propagator:  otel.GetTextMapPropagator(),
		ServiceName: serviceName,
	}
}

// UnaryTracingInterceptor returns a unary server interceptor that adds tracing.
func UnaryTracingInterceptor(cfg *TracingConfig) grpc.UnaryServerInterceptor {
	if cfg == nil {
		cfg = DefaultTracingConfig("grpc-server")
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Extract trace context from incoming metadata
		ctx = extractTraceContext(ctx, cfg.Propagator)

		// Extract service and method
		service, method := router.ParseFullMethod(info.FullMethod)

		// Start span
		ctx, span := cfg.Tracer.Start(ctx, info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", service),
				attribute.String("rpc.method", method),
				attribute.String("rpc.grpc.full_method", info.FullMethod),
			),
		)
		defer span.End()

		// Add peer info
		if p, ok := peer.FromContext(ctx); ok {
			span.SetAttributes(attribute.String("net.peer.name", p.Addr.String()))
		}

		// Add trace context to logging context
		ctx = addTraceToContext(ctx, span)

		// Call handler
		resp, err := handler(ctx, req)

		// Record result
		if err != nil {
			code := status.Code(err)
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(code)))
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		} else {
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(grpccodes.OK)))
			span.SetStatus(codes.Ok, "")
		}

		return resp, err
	}
}

// StreamTracingInterceptor returns a stream server interceptor that adds tracing.
func StreamTracingInterceptor(cfg *TracingConfig) grpc.StreamServerInterceptor {
	if cfg == nil {
		cfg = DefaultTracingConfig("grpc-server")
	}

	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := stream.Context()

		// Extract trace context from incoming metadata
		ctx = extractTraceContext(ctx, cfg.Propagator)

		// Extract service and method
		service, method := router.ParseFullMethod(info.FullMethod)

		// Start span
		ctx, span := cfg.Tracer.Start(ctx, info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.service", service),
				attribute.String("rpc.method", method),
				attribute.String("rpc.grpc.full_method", info.FullMethod),
				attribute.Bool("rpc.grpc.is_client_stream", info.IsClientStream),
				attribute.Bool("rpc.grpc.is_server_stream", info.IsServerStream),
			),
		)
		defer span.End()

		// Add peer info
		if p, ok := peer.FromContext(ctx); ok {
			span.SetAttributes(attribute.String("net.peer.name", p.Addr.String()))
		}

		// Add trace context to logging context
		ctx = addTraceToContext(ctx, span)

		// Wrap stream with new context
		wrapped := &tracingServerStream{
			ServerStream: stream,
			ctx:          ctx,
			span:         span,
		}

		// Call handler
		err := handler(srv, wrapped)

		// Record result
		if err != nil {
			code := status.Code(err)
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(code)))
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		} else {
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(grpccodes.OK)))
			span.SetStatus(codes.Ok, "")
		}

		return err
	}
}

// tracingServerStream wraps grpc.ServerStream with tracing context.
type tracingServerStream struct {
	grpc.ServerStream
	ctx  context.Context
	span trace.Span
}

// Context returns the wrapped context.
func (s *tracingServerStream) Context() context.Context {
	return s.ctx
}

// SendMsg adds span events for sent messages.
func (s *tracingServerStream) SendMsg(m interface{}) error {
	err := s.ServerStream.SendMsg(m)
	if err == nil {
		s.span.AddEvent("message sent")
	}
	return err
}

// RecvMsg adds span events for received messages.
func (s *tracingServerStream) RecvMsg(m interface{}) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil {
		s.span.AddEvent("message received")
	}
	return err
}

// extractTraceContext extracts trace context from incoming metadata.
func extractTraceContext(ctx context.Context, propagator propagation.TextMapPropagator) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	return propagator.Extract(ctx, metadataCarrier(md))
}

// addTraceToContext adds trace and span IDs to context for logging.
func addTraceToContext(ctx context.Context, span trace.Span) context.Context {
	if span.SpanContext().HasTraceID() {
		ctx = observability.ContextWithTraceID(ctx, span.SpanContext().TraceID().String())
	}
	if span.SpanContext().HasSpanID() {
		ctx = observability.ContextWithSpanID(ctx, span.SpanContext().SpanID().String())
	}
	return ctx
}

// metadataCarrier adapts metadata.MD to propagation.TextMapCarrier.
type metadataCarrier metadata.MD

// Get returns the value for a key.
func (m metadataCarrier) Get(key string) string {
	values := metadata.MD(m).Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// Set sets a key-value pair.
func (m metadataCarrier) Set(key, value string) {
	metadata.MD(m).Set(key, value)
}

// Keys returns all keys.
func (m metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// InjectTraceContext injects trace context into outgoing metadata.
func InjectTraceContext(ctx context.Context, md metadata.MD) {
	propagator := otel.GetTextMapPropagator()
	propagator.Inject(ctx, metadataCarrier(md))
}

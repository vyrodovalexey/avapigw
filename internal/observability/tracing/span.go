// Package tracing provides OpenTelemetry tracing for the API Gateway.
package tracing

import (
	"context"
	"fmt"
	"runtime"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// DefaultTracerName is the default tracer name.
	DefaultTracerName = "avapigw"
)

// SpanOption is a function that configures a span.
type SpanOption func(*spanOptions)

type spanOptions struct {
	kind       trace.SpanKind
	attributes []attribute.KeyValue
	links      []trace.Link
}

// WithSpanKind sets the span kind.
func WithSpanKind(kind trace.SpanKind) SpanOption {
	return func(o *spanOptions) {
		o.kind = kind
	}
}

// WithAttributes sets span attributes.
func WithAttributes(attrs ...attribute.KeyValue) SpanOption {
	return func(o *spanOptions) {
		o.attributes = append(o.attributes, attrs...)
	}
}

// WithLinks sets span links.
func WithLinks(links ...trace.Link) SpanOption {
	return func(o *spanOptions) {
		o.links = append(o.links, links...)
	}
}

// StartSpan starts a new span with the given name.
func StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, trace.Span) {
	options := &spanOptions{
		kind: trace.SpanKindInternal,
	}
	for _, opt := range opts {
		opt(options)
	}

	tracer := otel.GetTracerProvider().Tracer(DefaultTracerName)

	spanOpts := []trace.SpanStartOption{
		trace.WithSpanKind(options.kind),
	}
	if len(options.attributes) > 0 {
		spanOpts = append(spanOpts, trace.WithAttributes(options.attributes...))
	}
	if len(options.links) > 0 {
		spanOpts = append(spanOpts, trace.WithLinks(options.links...))
	}

	return tracer.Start(ctx, name, spanOpts...)
}

// StartServerSpan starts a new server span.
func StartServerSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return StartSpan(ctx, name, WithSpanKind(trace.SpanKindServer), WithAttributes(attrs...))
}

// StartClientSpan starts a new client span.
func StartClientSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return StartSpan(ctx, name, WithSpanKind(trace.SpanKindClient), WithAttributes(attrs...))
}

// StartInternalSpan starts a new internal span.
func StartInternalSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return StartSpan(ctx, name, WithSpanKind(trace.SpanKindInternal), WithAttributes(attrs...))
}

// StartProducerSpan starts a new producer span.
func StartProducerSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return StartSpan(ctx, name, WithSpanKind(trace.SpanKindProducer), WithAttributes(attrs...))
}

// StartConsumerSpan starts a new consumer span.
func StartConsumerSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return StartSpan(ctx, name, WithSpanKind(trace.SpanKindConsumer), WithAttributes(attrs...))
}

// SpanFromContext returns the current span from the context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// ContextWithSpan returns a new context with the given span.
func ContextWithSpan(ctx context.Context, span trace.Span) context.Context {
	return trace.ContextWithSpan(ctx, span)
}

// SetSpanStatus sets the span status.
func SetSpanStatus(span trace.Span, code codes.Code, description string) {
	span.SetStatus(code, description)
}

// SetSpanOK sets the span status to OK.
func SetSpanOK(span trace.Span) {
	span.SetStatus(codes.Ok, "")
}

// SetSpanError sets the span status to Error.
func SetSpanError(span trace.Span, err error) {
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
	}
}

// RecordError records an error on the span.
func RecordError(span trace.Span, err error, opts ...trace.EventOption) {
	if err != nil {
		span.RecordError(err, opts...)
	}
}

// AddEvent adds an event to the span.
func AddEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SetAttributes sets attributes on the span.
func SetAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(attrs...)
}

// Attribute helpers

// StringAttr creates a string attribute.
func StringAttr(key, value string) attribute.KeyValue {
	return attribute.String(key, value)
}

// IntAttr creates an int attribute.
func IntAttr(key string, value int) attribute.KeyValue {
	return attribute.Int(key, value)
}

// Int64Attr creates an int64 attribute.
func Int64Attr(key string, value int64) attribute.KeyValue {
	return attribute.Int64(key, value)
}

// Float64Attr creates a float64 attribute.
func Float64Attr(key string, value float64) attribute.KeyValue {
	return attribute.Float64(key, value)
}

// BoolAttr creates a bool attribute.
func BoolAttr(key string, value bool) attribute.KeyValue {
	return attribute.Bool(key, value)
}

// StringSliceAttr creates a string slice attribute.
func StringSliceAttr(key string, value []string) attribute.KeyValue {
	return attribute.StringSlice(key, value)
}

// IntSliceAttr creates an int slice attribute.
func IntSliceAttr(key string, value []int) attribute.KeyValue {
	return attribute.IntSlice(key, value)
}

// HTTP semantic convention attributes

// HTTPMethodAttr creates an HTTP method attribute.
func HTTPMethodAttr(method string) attribute.KeyValue {
	return attribute.String("http.method", method)
}

// HTTPURLAttr creates an HTTP URL attribute.
func HTTPURLAttr(url string) attribute.KeyValue {
	return attribute.String("http.url", url)
}

// HTTPTargetAttr creates an HTTP target attribute.
func HTTPTargetAttr(target string) attribute.KeyValue {
	return attribute.String("http.target", target)
}

// HTTPHostAttr creates an HTTP host attribute.
func HTTPHostAttr(host string) attribute.KeyValue {
	return attribute.String("http.host", host)
}

// HTTPSchemeAttr creates an HTTP scheme attribute.
func HTTPSchemeAttr(scheme string) attribute.KeyValue {
	return attribute.String("http.scheme", scheme)
}

// HTTPStatusCodeAttr creates an HTTP status code attribute.
func HTTPStatusCodeAttr(code int) attribute.KeyValue {
	return attribute.Int("http.status_code", code)
}

// HTTPUserAgentAttr creates an HTTP user agent attribute.
func HTTPUserAgentAttr(userAgent string) attribute.KeyValue {
	return attribute.String("http.user_agent", userAgent)
}

// HTTPRequestContentLengthAttr creates an HTTP request content length attribute.
func HTTPRequestContentLengthAttr(length int64) attribute.KeyValue {
	return attribute.Int64("http.request_content_length", length)
}

// HTTPResponseContentLengthAttr creates an HTTP response content length attribute.
func HTTPResponseContentLengthAttr(length int64) attribute.KeyValue {
	return attribute.Int64("http.response_content_length", length)
}

// NetPeerIPAttr creates a network peer IP attribute.
func NetPeerIPAttr(ip string) attribute.KeyValue {
	return attribute.String("net.peer.ip", ip)
}

// NetPeerPortAttr creates a network peer port attribute.
func NetPeerPortAttr(port int) attribute.KeyValue {
	return attribute.Int("net.peer.port", port)
}

// gRPC semantic convention attributes

// RPCSystemAttr creates an RPC system attribute.
func RPCSystemAttr(system string) attribute.KeyValue {
	return attribute.String("rpc.system", system)
}

// RPCServiceAttr creates an RPC service attribute.
func RPCServiceAttr(service string) attribute.KeyValue {
	return attribute.String("rpc.service", service)
}

// RPCMethodAttr creates an RPC method attribute.
func RPCMethodAttr(method string) attribute.KeyValue {
	return attribute.String("rpc.method", method)
}

// RPCGRPCStatusCodeAttr creates a gRPC status code attribute.
func RPCGRPCStatusCodeAttr(code int) attribute.KeyValue {
	return attribute.Int("rpc.grpc.status_code", code)
}

// Custom attributes

// RequestIDAttr creates a request ID attribute.
func RequestIDAttr(id string) attribute.KeyValue {
	return attribute.String("request.id", id)
}

// UserIDAttr creates a user ID attribute.
func UserIDAttr(id string) attribute.KeyValue {
	return attribute.String("user.id", id)
}

// BackendAttr creates a backend attribute.
func BackendAttr(backend string) attribute.KeyValue {
	return attribute.String("backend", backend)
}

// RouteAttr creates a route attribute.
func RouteAttr(route string) attribute.KeyValue {
	return attribute.String("route", route)
}

// ErrorTypeAttr creates an error type attribute.
func ErrorTypeAttr(errType string) attribute.KeyValue {
	return attribute.String("error.type", errType)
}

// ErrorMessageAttr creates an error message attribute.
func ErrorMessageAttr(message string) attribute.KeyValue {
	return attribute.String("error.message", message)
}

// TraceIDFromContext returns the trace ID from the context.
func TraceIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return ""
	}
	return span.SpanContext().TraceID().String()
}

// SpanIDFromContext returns the span ID from the context.
func SpanIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return ""
	}
	return span.SpanContext().SpanID().String()
}

// IsTracingEnabled returns true if the span context is valid and sampled.
func IsTracingEnabled(ctx context.Context) bool {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return false
	}
	return span.SpanContext().IsSampled()
}

// WrapError wraps an error with span information.
func WrapError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}

	span := trace.SpanFromContext(ctx)
	if span == nil {
		return err
	}

	traceID := span.SpanContext().TraceID().String()
	spanID := span.SpanContext().SpanID().String()

	return fmt.Errorf("%w [trace_id=%s, span_id=%s]", err, traceID, spanID)
}

// AddStackTrace adds a stack trace event to the span.
func AddStackTrace(span trace.Span) {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])

	var stack string
	for {
		frame, more := frames.Next()
		stack += fmt.Sprintf("%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}

	span.AddEvent("stack_trace", trace.WithAttributes(
		attribute.String("stack", stack),
	))
}

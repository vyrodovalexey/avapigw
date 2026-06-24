package aggregate

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the OpenTelemetry instrumentation name for aggregate spans.
const tracerName = "avapigw/aggregate"

// Span is the minimal span surface used by the aggregate engine. It mirrors the
// subset of trace.Span needed so the engine can be exercised with a no-op
// implementation in tests.
type Span interface {
	// End completes the span.
	End()

	// RecordError records an error on the span.
	RecordError(err error)
}

// Tracer starts aggregate spans. Implementations propagate context so child
// spans (per-target, merge, spool) nest correctly under the fan-out span.
type Tracer interface {
	// Start begins a new span with the given name and returns the derived
	// context and span.
	Start(ctx context.Context, name string) (context.Context, Span)
}

// otelTracer is the production Tracer backed by the global OpenTelemetry
// provider (with B3/Jaeger propagation configured at process startup).
type otelTracer struct {
	tracer trace.Tracer
}

// NewTracer returns a Tracer backed by the global OpenTelemetry provider.
func NewTracer() Tracer {
	return &otelTracer{tracer: otel.Tracer(tracerName)}
}

// Start implements the Tracer interface.
func (t *otelTracer) Start(ctx context.Context, name string) (context.Context, Span) {
	ctx, span := t.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindClient))
	return ctx, &otelSpan{span: span}
}

// otelSpan adapts trace.Span to the Span interface.
type otelSpan struct {
	span trace.Span
}

// End implements the Span interface.
func (s *otelSpan) End() { s.span.End() }

// RecordError implements the Span interface.
func (s *otelSpan) RecordError(err error) {
	if err != nil {
		s.span.RecordError(err)
	}
}

// nopTracer is a no-op Tracer.
type nopTracer struct{}

// NopTracer returns a Tracer that does nothing. Useful for tests and when
// tracing is disabled.
func NopTracer() Tracer { return nopTracer{} }

// Start implements the Tracer interface. It returns the context unchanged and a
// no-op span.
func (nopTracer) Start(ctx context.Context, _ string) (context.Context, Span) {
	return ctx, nopSpan{}
}

// nopSpan is a no-op Span.
type nopSpan struct{}

// End is a no-op. The span carries no state, so there is nothing to flush.
func (nopSpan) End() {}

// RecordError is a no-op. The span carries no state, so errors are discarded.
func (nopSpan) RecordError(error) {}

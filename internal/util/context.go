package util

import (
	"context"
	"time"
)

// Context keys.
type ctxKey string

const (
	ctxKeyRequestID  ctxKey = "request_id"
	ctxKeyTraceID    ctxKey = "trace_id"
	ctxKeySpanID     ctxKey = "span_id"
	ctxKeyStartTime  ctxKey = "start_time"
	ctxKeyRoute      ctxKey = "route"
	ctxKeyBackend    ctxKey = "backend"
	ctxKeyPathParams ctxKey = "path_params"
)

// ContextWithRequestID adds a request ID to the context.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, requestID)
}

// RequestIDFromContext extracts the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// ContextWithTraceID adds a trace ID to the context.
func ContextWithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, ctxKeyTraceID, traceID)
}

// TraceIDFromContext extracts the trace ID from context.
func TraceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyTraceID).(string); ok {
		return v
	}
	return ""
}

// ContextWithSpanID adds a span ID to the context.
func ContextWithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, ctxKeySpanID, spanID)
}

// SpanIDFromContext extracts the span ID from context.
func SpanIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeySpanID).(string); ok {
		return v
	}
	return ""
}

// ContextWithStartTime adds a start time to the context.
func ContextWithStartTime(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, ctxKeyStartTime, t)
}

// StartTimeFromContext extracts the start time from context.
func StartTimeFromContext(ctx context.Context) time.Time {
	if v, ok := ctx.Value(ctxKeyStartTime).(time.Time); ok {
		return v
	}
	return time.Time{}
}

// ContextWithRoute adds a route name to the context.
func ContextWithRoute(ctx context.Context, route string) context.Context {
	return context.WithValue(ctx, ctxKeyRoute, route)
}

// RouteFromContext extracts the route name from context.
func RouteFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRoute).(string); ok {
		return v
	}
	return ""
}

// ContextWithBackend adds a backend name to the context.
func ContextWithBackend(ctx context.Context, backend string) context.Context {
	return context.WithValue(ctx, ctxKeyBackend, backend)
}

// BackendFromContext extracts the backend name from context.
func BackendFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyBackend).(string); ok {
		return v
	}
	return ""
}

// ContextWithPathParams adds path parameters to the context.
func ContextWithPathParams(ctx context.Context, params map[string]string) context.Context {
	return context.WithValue(ctx, ctxKeyPathParams, params)
}

// PathParamsFromContext extracts path parameters from context.
func PathParamsFromContext(ctx context.Context) map[string]string {
	if v, ok := ctx.Value(ctxKeyPathParams).(map[string]string); ok {
		return v
	}
	return nil
}

// NewTimeoutContext creates a context with a timeout.
// Returns the context and a cancel function that should be deferred.
func NewTimeoutContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// NewDeadlineContext creates a context with a deadline.
// Returns the context and a cancel function that should be deferred.
func NewDeadlineContext(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(parent, deadline)
}

// ElapsedTime returns the elapsed time since the start time in context.
func ElapsedTime(ctx context.Context) time.Duration {
	startTime := StartTimeFromContext(ctx)
	if startTime.IsZero() {
		return 0
	}
	return time.Since(startTime)
}

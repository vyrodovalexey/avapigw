package middleware

import (
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// auditResponseWriter wraps http.ResponseWriter to capture status code and response size
// for audit logging purposes.
type auditResponseWriter struct {
	http.ResponseWriter
	status      int
	size        int
	wroteHeader bool
}

// WriteHeader captures the status code before delegating to the underlying writer.
func (w *auditResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write captures the response size before delegating to the underlying writer.
func (w *auditResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

// Flush implements http.Flusher interface for streaming support.
func (w *auditResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// enrichWithTraceContext sets TraceID and SpanID on an audit event
// if the values are available from the request context.
func enrichWithTraceContext(
	event *audit.Event,
	traceID, spanID string,
) {
	if traceID != "" {
		event.WithTraceID(traceID)
	}
	if spanID != "" {
		event.WithSpanID(spanID)
	}
}

// Audit returns an HTTP middleware that logs audit events for each request/response cycle.
// It captures method, path, status code, duration, client IP, and request ID,
// then emits request and response audit events via the provided audit logger.
func Audit(auditLogger audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := r.Context()

			// Extract request ID from context (set by RequestID middleware)
			requestID := observability.RequestIDFromContext(ctx)
			clientIP := getClientIP(r)

			// Extract trace context (set by TracingMiddleware which runs before Audit)
			traceID := observability.TraceIDFromContext(ctx)
			spanID := observability.SpanIDFromContext(ctx)

			// Build request details for audit
			reqDetails := &audit.RequestDetails{
				Method:        r.Method,
				Path:          r.URL.Path,
				Query:         r.URL.RawQuery,
				RemoteAddr:    clientIP,
				Protocol:      r.Proto,
				ContentType:   r.Header.Get("Content-Type"),
				ContentLength: r.ContentLength,
			}

			// Build subject from available request info
			subject := &audit.Subject{
				IPAddress: clientIP,
				UserAgent: r.UserAgent(),
			}

			// Log request event with trace context
			reqEvent := audit.RequestEvent(reqDetails, subject)
			reqEvent.Resource = &audit.Resource{
				Type:   "http",
				Path:   r.URL.Path,
				Method: r.Method,
			}
			if requestID != "" {
				reqEvent.WithMetadata("request_id", requestID)
			}
			enrichWithTraceContext(reqEvent, traceID, spanID)
			auditLogger.LogEvent(ctx, reqEvent)

			// Wrap response writer to capture status and size
			aw := &auditResponseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			// Process request through the rest of the chain
			next.ServeHTTP(aw, r)

			// Calculate duration
			duration := time.Since(start)

			// Build response details for audit
			respDetails := &audit.ResponseDetails{
				StatusCode:    aw.status,
				ContentType:   aw.Header().Get("Content-Type"),
				ContentLength: int64(aw.size),
			}

			// Log response event with trace context
			respEvent := audit.ResponseEvent(respDetails, duration)
			respEvent.Resource = &audit.Resource{
				Type:   "http",
				Path:   r.URL.Path,
				Method: r.Method,
			}
			if requestID != "" {
				respEvent.WithMetadata("request_id", requestID)
			}
			enrichWithTraceContext(respEvent, traceID, spanID)
			auditLogger.LogEvent(ctx, respEvent)
		})
	}
}

package middleware

import (
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// responseWriter wraps http.ResponseWriter to capture status code and size.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the response size.
func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// Flush implements http.Flusher interface for streaming support.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Logging returns a middleware that logs HTTP requests.
func Logging(logger observability.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Add start time to context
			ctx := util.ContextWithStartTime(r.Context(), start)
			r = r.WithContext(ctx)

			// Wrap response writer
			rw := &responseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			// Process request
			next.ServeHTTP(rw, r)

			// Calculate duration
			duration := time.Since(start)

			// Get request ID from context (r.Context() is the correct context to use here)
			//nolint:contextcheck // Using request context is correct here
			requestID := observability.RequestIDFromContext(r.Context())

			// Log request
			logger.Info("http request",
				observability.String("method", r.Method),
				observability.String("path", r.URL.Path),
				observability.String("query", r.URL.RawQuery),
				observability.Int("status", rw.status),
				observability.Int("size", rw.size),
				observability.Duration("duration", duration),
				observability.String("remote_addr", r.RemoteAddr),
				observability.String("user_agent", r.UserAgent()),
				observability.String("request_id", requestID),
			)
		})
	}
}

// AccessLog returns a middleware that logs access in a specific format.
func AccessLog(logger observability.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer
			rw := &responseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			// Process request
			next.ServeHTTP(rw, r)

			// Calculate duration
			duration := time.Since(start)

			// Get route from context
			route := util.RouteFromContext(r.Context())

			// Log access
			logger.Info("access",
				observability.String("method", r.Method),
				observability.String("path", r.URL.Path),
				observability.Int("status", rw.status),
				observability.Duration("latency", duration),
				observability.String("client_ip", getClientIP(r)),
				observability.String("route", route),
			)
		})
	}
}

// getClientIP extracts the client IP from the request using the global
// extractor (secure default: only RemoteAddr, no header trust).
func getClientIP(r *http.Request) string {
	return globalExtractor.Extract(r)
}

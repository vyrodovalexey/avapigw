package middleware

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

const (
	// RequestIDHeader is the header name for request ID.
	RequestIDHeader = "X-Request-ID"
)

// RequestID returns a middleware that adds a request ID to each request.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request ID already exists
			requestID := r.Header.Get(RequestIDHeader)
			if requestID == "" {
				requestID = uuid.New().String()
			}

			// Add to request context
			ctx := observability.ContextWithRequestID(r.Context(), requestID)
			r = r.WithContext(ctx)

			// Add to response header
			w.Header().Set(RequestIDHeader, requestID)

			next.ServeHTTP(w, r)
		})
	}
}

// RequestIDWithGenerator returns a middleware that uses a custom ID generator.
func RequestIDWithGenerator(generator func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request ID already exists
			requestID := r.Header.Get(RequestIDHeader)
			if requestID == "" {
				requestID = generator()
			}

			// Add to request context
			ctx := observability.ContextWithRequestID(r.Context(), requestID)
			r = r.WithContext(ctx)

			// Add to response header
			w.Header().Set(RequestIDHeader, requestID)

			next.ServeHTTP(w, r)
		})
	}
}

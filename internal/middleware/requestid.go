package middleware

import (
	"net/http"
	"regexp"

	"github.com/google/uuid"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

const (
	// RequestIDHeader is the header name for request ID.
	RequestIDHeader = "X-Request-ID"

	// maxRequestIDLength is the maximum allowed length for a client-provided request ID.
	maxRequestIDLength = 128
)

// validRequestIDPattern matches alphanumeric characters, hyphens, and underscores.
var validRequestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)

// isValidRequestID checks whether a client-provided request ID is safe to use.
// It must be non-empty, at most maxRequestIDLength characters, and contain
// only alphanumeric characters, hyphens, or underscores.
func isValidRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLength {
		return false
	}
	return validRequestIDPattern.MatchString(id)
}

// RequestID returns a middleware that adds a request ID to each request.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request ID already exists and is valid
			requestID := r.Header.Get(RequestIDHeader)
			if !isValidRequestID(requestID) {
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
			// Check if request ID already exists and is valid
			requestID := r.Header.Get(RequestIDHeader)
			if !isValidRequestID(requestID) {
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

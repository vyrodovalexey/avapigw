package util

import (
	"fmt"
	"net/http"
)

// ServerError represents a server-side error for circuit breaker tracking.
// It is used to signal that a backend returned a 5xx status code.
type ServerError struct {
	StatusCode int
}

// Error implements the error interface.
func (e *ServerError) Error() string {
	return fmt.Sprintf("server error: status %d", e.StatusCode)
}

// NewServerError creates a new ServerError with the given status code.
func NewServerError(statusCode int) *ServerError {
	return &ServerError{StatusCode: statusCode}
}

// StatusCapturingResponseWriter wraps http.ResponseWriter to track status code.
// It is used by circuit breakers and other middleware that need to inspect
// the response status code after the handler has completed.
type StatusCapturingResponseWriter struct {
	http.ResponseWriter
	StatusCode    int
	HeaderWritten bool
}

// NewStatusCapturingResponseWriter creates a new StatusCapturingResponseWriter
// wrapping the provided http.ResponseWriter with a default status of 200 OK.
func NewStatusCapturingResponseWriter(w http.ResponseWriter) *StatusCapturingResponseWriter {
	return &StatusCapturingResponseWriter{
		ResponseWriter: w,
		StatusCode:     http.StatusOK,
	}
}

// WriteHeader captures the status code and writes it to the underlying ResponseWriter.
func (w *StatusCapturingResponseWriter) WriteHeader(code int) {
	if w.HeaderWritten {
		return
	}
	w.StatusCode = code
	w.HeaderWritten = true
	w.ResponseWriter.WriteHeader(code)
}

// Write writes data to the underlying ResponseWriter and marks header as written.
func (w *StatusCapturingResponseWriter) Write(b []byte) (int, error) {
	if !w.HeaderWritten {
		w.HeaderWritten = true
	}
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher interface for streaming support.
func (w *StatusCapturingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Compile-time interface assertion.
var _ http.Flusher = (*StatusCapturingResponseWriter)(nil)

// Package util provides utility functions and types for the
// API Gateway.
//
// This package contains shared utilities used across the gateway
// including context helpers, error types, HTTP utilities, and
// validation functions.
//
// # Context Helpers
//
// Context utilities for request-scoped data:
//
//	ctx = util.ContextWithRequestID(ctx, "req-123")
//	requestID := util.RequestIDFromContext(ctx)
//
// # Error Types
//
// Structured error types for consistent error handling:
//
//   - ConfigError: configuration validation errors
//   - ServerError: backend server errors with status codes
//   - Common sentinel errors: ErrNotFound, ErrTimeout, etc.
//
// # HTTP Utilities
//
// Response writer wrappers for status code capture:
//
//	w := util.NewStatusCapturingResponseWriter(responseWriter)
//	handler.ServeHTTP(w, r)
//	statusCode := w.StatusCode
//
// # Validation
//
// Input validation helpers for URLs, durations, and headers:
//
//	err := util.ValidateURL("https://example.com")
//	err := util.ValidateHeaderName("X-Custom-Header")
package util

// Package middleware provides HTTP middleware components for the
// API Gateway.
//
// This package implements a comprehensive set of HTTP middleware for
// request processing, security, observability, and traffic management.
//
// # Middleware Components
//
//   - Logging: structured request/response logging
//   - Recovery: panic recovery with stack trace logging
//   - CORS: Cross-Origin Resource Sharing headers
//   - Rate Limiting: token bucket rate limiter
//   - Circuit Breaker: per-route circuit breaking
//   - Timeout: request timeout enforcement
//   - Body Limit: request body size limiting
//   - Headers: custom request/response header manipulation
//   - Request ID: unique request identifier injection
//   - Retry: automatic request retry with backoff
//   - Max Sessions: concurrent session limiting
//   - Audit: audit logging for request tracking
//   - Client IP: trusted proxy-aware client IP extraction
//
// # Usage
//
// Middleware functions follow the standard Go pattern:
//
//	handler := middleware.Logging(logger)(
//	    middleware.Recovery(logger)(
//	        middleware.RequestID()(yourHandler),
//	    ),
//	)
package middleware

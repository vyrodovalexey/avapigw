// Package middleware provides HTTP middleware components for the API Gateway.
package middleware

import (
	"net/http"
	"strings"
)

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// unknownRoute is the fallback label value used when the route name
// is not available in the request context.
const unknownRoute = "unknown"

// HTTP header constants.
const (
	// HeaderContentType is the Content-Type header name.
	HeaderContentType = "Content-Type"

	// HeaderRetryAfter is the Retry-After header name.
	HeaderRetryAfter = "Retry-After"

	// HeaderAccept is the Accept header name.
	HeaderAccept = "Accept"

	// HeaderOrigin is the Origin header name.
	HeaderOrigin = "Origin"

	// HeaderXRequestID is the X-Request-ID header name.
	HeaderXRequestID = "X-Request-ID"

	// HeaderXForwardedFor is the X-Forwarded-For header name.
	HeaderXForwardedFor = "X-Forwarded-For"

	// HeaderXForwardedProto is the X-Forwarded-Proto header name.
	HeaderXForwardedProto = "X-Forwarded-Proto"

	// HeaderXForwardedHost is the X-Forwarded-Host header name.
	HeaderXForwardedHost = "X-Forwarded-Host"

	// HeaderXRealIP is the X-Real-IP header name.
	HeaderXRealIP = "X-Real-IP"

	// HeaderCookie is the Cookie header name.
	HeaderCookie = "Cookie"

	// HeaderSetCookie is the Set-Cookie header name.
	HeaderSetCookie = "Set-Cookie"
)

// Content type constants.
const (
	// ContentTypeJSON is the JSON content type.
	ContentTypeJSON = "application/json"

	// ContentTypeXML is the XML content type.
	ContentTypeXML = "application/xml"

	// ContentTypeFormURLEncoded is the form URL encoded content type.
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"

	// ContentTypeTextPlain is the plain text content type.
	ContentTypeTextPlain = "text/plain"

	// ContentTypeHTML is the HTML content type.
	ContentTypeHTML = "text/html"
)

// Error response constants.
const (
	// ErrRateLimitExceeded is the error message for rate limit exceeded.
	ErrRateLimitExceeded = `{"error":"rate limit exceeded"}`

	// ErrGatewayTimeout is the error message for gateway timeout.
	ErrGatewayTimeout = `{"error":"gateway timeout"}`

	// ErrServiceUnavailable is the error message for service unavailable.
	ErrServiceUnavailable = `{"error":"service unavailable","message":"circuit breaker open"}`

	// ErrBadGateway is the error message for bad gateway.
	ErrBadGateway = `{"error":"bad gateway","message":"all retries exhausted"}`

	// ErrInternalServerError is the error message for internal server error.
	ErrInternalServerError = `{"error":"internal server error"}`

	// ErrRequestEntityTooLarge is the error message for request body too large.
	ErrRequestEntityTooLarge = `{"error":"request entity too large"}`

	// ErrMaxSessionsExceeded is the error message for max sessions exceeded.
	ErrMaxSessionsExceeded = `{"error":"max sessions exceeded","message":"server at capacity"}`
)

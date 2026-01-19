package middleware

import (
	"github.com/gin-gonic/gin"
)

// HeadersConfig holds configuration for the headers middleware.
type HeadersConfig struct {
	// RequestHeaders to modify on incoming requests
	RequestHeaders *HeaderModification

	// ResponseHeaders to modify on outgoing responses
	ResponseHeaders *HeaderModification

	// SecurityHeaders to add to responses
	SecurityHeaders *SecurityHeadersConfig
}

// HeaderModification defines header modification operations.
type HeaderModification struct {
	// Set overwrites headers with the given values
	Set map[string]string

	// Add adds headers (allows multiple values)
	Add map[string]string

	// Remove removes headers by name
	Remove []string
}

// SecurityHeadersConfig holds configuration for security headers.
type SecurityHeadersConfig struct {
	// StrictTransportSecurity sets the Strict-Transport-Security header
	StrictTransportSecurity string

	// ContentSecurityPolicy sets the Content-Security-Policy header
	ContentSecurityPolicy string

	// XContentTypeOptions sets the X-Content-Type-Options header
	XContentTypeOptions string

	// XFrameOptions sets the X-Frame-Options header
	XFrameOptions string

	// XXSSProtection sets the X-XSS-Protection header
	XXSSProtection string

	// ReferrerPolicy sets the Referrer-Policy header
	ReferrerPolicy string

	// PermissionsPolicy sets the Permissions-Policy header
	PermissionsPolicy string
}

// DefaultSecurityHeaders returns default security headers configuration.
func DefaultSecurityHeaders() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "DENY",
		XXSSProtection:          "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
	}
}

// Headers returns a middleware that modifies request and response headers.
func Headers(config HeadersConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Modify request headers
		if config.RequestHeaders != nil {
			modifyRequestHeaders(c, config.RequestHeaders)
		}

		// Process request
		c.Next()

		// Modify response headers
		if config.ResponseHeaders != nil {
			modifyResponseHeaders(c, config.ResponseHeaders)
		}

		// Add security headers
		if config.SecurityHeaders != nil {
			addSecurityHeaders(c, config.SecurityHeaders)
		}
	}
}

// RequestHeaderModifier returns a middleware that modifies request headers.
func RequestHeaderModifier(modification *HeaderModification) gin.HandlerFunc {
	return func(c *gin.Context) {
		modifyRequestHeaders(c, modification)
		c.Next()
	}
}

// ResponseHeaderModifier returns a middleware that modifies response headers.
func ResponseHeaderModifier(modification *HeaderModification) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		modifyResponseHeaders(c, modification)
	}
}

// SecurityHeaders returns a middleware that adds security headers.
func SecurityHeaders() gin.HandlerFunc {
	return SecurityHeadersWithConfig(DefaultSecurityHeaders())
}

// SecurityHeadersWithConfig returns a security headers middleware with custom configuration.
func SecurityHeadersWithConfig(config *SecurityHeadersConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		addSecurityHeaders(c, config)
	}
}

// modifyRequestHeaders modifies request headers based on the configuration.
func modifyRequestHeaders(c *gin.Context, mod *HeaderModification) {
	if mod == nil {
		return
	}

	// Remove headers first
	for _, name := range mod.Remove {
		c.Request.Header.Del(name)
	}

	// Set headers (overwrites existing)
	for name, value := range mod.Set {
		c.Request.Header.Set(name, value)
	}

	// Add headers
	for name, value := range mod.Add {
		c.Request.Header.Add(name, value)
	}
}

// modifyResponseHeaders modifies response headers based on the configuration.
func modifyResponseHeaders(c *gin.Context, mod *HeaderModification) {
	if mod == nil {
		return
	}

	// Remove headers first
	for _, name := range mod.Remove {
		c.Writer.Header().Del(name)
	}

	// Set headers (overwrites existing)
	for name, value := range mod.Set {
		c.Writer.Header().Set(name, value)
	}

	// Add headers
	for name, value := range mod.Add {
		c.Writer.Header().Add(name, value)
	}
}

// addSecurityHeaders adds security headers to the response.
func addSecurityHeaders(c *gin.Context, config *SecurityHeadersConfig) {
	if config == nil {
		return
	}

	if config.StrictTransportSecurity != "" {
		c.Writer.Header().Set("Strict-Transport-Security", config.StrictTransportSecurity)
	}

	if config.ContentSecurityPolicy != "" {
		c.Writer.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
	}

	if config.XContentTypeOptions != "" {
		c.Writer.Header().Set("X-Content-Type-Options", config.XContentTypeOptions)
	}

	if config.XFrameOptions != "" {
		c.Writer.Header().Set("X-Frame-Options", config.XFrameOptions)
	}

	if config.XXSSProtection != "" {
		c.Writer.Header().Set("X-XSS-Protection", config.XXSSProtection)
	}

	if config.ReferrerPolicy != "" {
		c.Writer.Header().Set("Referrer-Policy", config.ReferrerPolicy)
	}

	if config.PermissionsPolicy != "" {
		c.Writer.Header().Set("Permissions-Policy", config.PermissionsPolicy)
	}
}

// SetHeader returns a middleware that sets a single header.
func SetHeader(name, value string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		c.Writer.Header().Set(name, value)
	}
}

// AddHeader returns a middleware that adds a single header.
func AddHeader(name, value string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		c.Writer.Header().Add(name, value)
	}
}

// RemoveHeader returns a middleware that removes a header.
func RemoveHeader(name string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		c.Writer.Header().Del(name)
	}
}

// SetRequestHeader returns a middleware that sets a request header.
func SetRequestHeader(name, value string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Header.Set(name, value)
		c.Next()
	}
}

// AddRequestHeader returns a middleware that adds a request header.
func AddRequestHeader(name, value string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Header.Add(name, value)
		c.Next()
	}
}

// RemoveRequestHeader returns a middleware that removes a request header.
func RemoveRequestHeader(name string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Header.Del(name)
		c.Next()
	}
}

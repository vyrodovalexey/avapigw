package middleware

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// ExtendedSecurityConfig holds extended configuration for security headers middleware.
type ExtendedSecurityConfig struct {
	// HSTS configuration
	HSTSEnabled           bool
	HSTSMaxAge            int
	HSTSIncludeSubDomains bool
	HSTSPreload           bool

	// Content Security Policy
	ContentSecurityPolicy string

	// X-Frame-Options
	XFrameOptions string

	// X-Content-Type-Options
	XContentTypeOptions string

	// X-XSS-Protection
	XXSSProtection string

	// Referrer-Policy
	ReferrerPolicy string

	// Permissions-Policy
	PermissionsPolicy string

	// Cross-Origin-Embedder-Policy
	CrossOriginEmbedderPolicy string

	// Cross-Origin-Opener-Policy
	CrossOriginOpenerPolicy string

	// Cross-Origin-Resource-Policy
	CrossOriginResourcePolicy string

	// Cache-Control for sensitive responses
	CacheControl string

	// Custom headers
	CustomHeaders map[string]string

	// Headers to remove
	RemoveHeaders []string
}

// DefaultExtendedSecurityConfig returns an ExtendedSecurityConfig with secure defaults.
func DefaultExtendedSecurityConfig() *ExtendedSecurityConfig {
	return &ExtendedSecurityConfig{
		HSTSEnabled:               true,
		HSTSMaxAge:                31536000, // 1 year
		HSTSIncludeSubDomains:     true,
		HSTSPreload:               false,
		XFrameOptions:             "DENY",
		XContentTypeOptions:       "nosniff",
		XXSSProtection:            "1; mode=block",
		ReferrerPolicy:            "strict-origin-when-cross-origin",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
	}
}

// ExtendedSecurityHeaders returns a middleware that adds extended security headers.
func ExtendedSecurityHeaders() gin.HandlerFunc {
	return ExtendedSecurityHeadersWithConfig(DefaultExtendedSecurityConfig())
}

// ExtendedSecurityHeadersWithConfig returns an extended security headers middleware with custom configuration.
func ExtendedSecurityHeadersWithConfig(config *ExtendedSecurityConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultExtendedSecurityConfig()
	}

	// Pre-compute HSTS header value
	var hstsValue string
	if config.HSTSEnabled {
		hstsValue = fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
		if config.HSTSIncludeSubDomains {
			hstsValue += "; includeSubDomains"
		}
		if config.HSTSPreload {
			hstsValue += "; preload"
		}
	}

	return func(c *gin.Context) {
		// Remove specified headers
		for _, header := range config.RemoveHeaders {
			c.Header(header, "")
		}

		// HSTS
		if config.HSTSEnabled && hstsValue != "" {
			c.Header("Strict-Transport-Security", hstsValue)
		}

		// Content Security Policy
		if config.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		// X-Frame-Options
		if config.XFrameOptions != "" {
			c.Header("X-Frame-Options", config.XFrameOptions)
		}

		// X-Content-Type-Options
		if config.XContentTypeOptions != "" {
			c.Header("X-Content-Type-Options", config.XContentTypeOptions)
		}

		// X-XSS-Protection
		if config.XXSSProtection != "" {
			c.Header("X-XSS-Protection", config.XXSSProtection)
		}

		// Referrer-Policy
		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
		}

		// Permissions-Policy
		if config.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", config.PermissionsPolicy)
		}

		// Cross-Origin-Embedder-Policy
		if config.CrossOriginEmbedderPolicy != "" {
			c.Header("Cross-Origin-Embedder-Policy", config.CrossOriginEmbedderPolicy)
		}

		// Cross-Origin-Opener-Policy
		if config.CrossOriginOpenerPolicy != "" {
			c.Header("Cross-Origin-Opener-Policy", config.CrossOriginOpenerPolicy)
		}

		// Cross-Origin-Resource-Policy
		if config.CrossOriginResourcePolicy != "" {
			c.Header("Cross-Origin-Resource-Policy", config.CrossOriginResourcePolicy)
		}

		// Cache-Control
		if config.CacheControl != "" {
			c.Header("Cache-Control", config.CacheControl)
		}

		// Custom headers
		for name, value := range config.CustomHeaders {
			c.Header(name, value)
		}

		c.Next()
	}
}

// HSTSConfig holds configuration for HSTS middleware.
type HSTSConfig struct {
	MaxAge            int
	IncludeSubDomains bool
	Preload           bool
}

// DefaultHSTSConfig returns an HSTSConfig with default values.
func DefaultHSTSConfig() *HSTSConfig {
	return &HSTSConfig{
		MaxAge:            31536000, // 1 year
		IncludeSubDomains: true,
		Preload:           false,
	}
}

// HSTS returns a middleware that adds the Strict-Transport-Security header.
func HSTS(maxAge int) gin.HandlerFunc {
	return HSTSWithConfig(&HSTSConfig{
		MaxAge:            maxAge,
		IncludeSubDomains: true,
		Preload:           false,
	})
}

// HSTSWithConfig returns an HSTS middleware with custom configuration.
func HSTSWithConfig(config *HSTSConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultHSTSConfig()
	}

	value := fmt.Sprintf("max-age=%d", config.MaxAge)
	if config.IncludeSubDomains {
		value += "; includeSubDomains"
	}
	if config.Preload {
		value += "; preload"
	}

	return func(c *gin.Context) {
		c.Header("Strict-Transport-Security", value)
		c.Next()
	}
}

// ContentSecurityPolicy returns a middleware that adds the Content-Security-Policy header.
func ContentSecurityPolicy(policy string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", policy)
		c.Next()
	}
}

// CSPBuilder helps build Content Security Policy directives.
type CSPBuilder struct {
	directives map[string][]string
}

// NewCSPBuilder creates a new CSP builder.
func NewCSPBuilder() *CSPBuilder {
	return &CSPBuilder{
		directives: make(map[string][]string),
	}
}

// DefaultSrc sets the default-src directive.
func (b *CSPBuilder) DefaultSrc(sources ...string) *CSPBuilder {
	b.directives["default-src"] = sources
	return b
}

// ScriptSrc sets the script-src directive.
func (b *CSPBuilder) ScriptSrc(sources ...string) *CSPBuilder {
	b.directives["script-src"] = sources
	return b
}

// StyleSrc sets the style-src directive.
func (b *CSPBuilder) StyleSrc(sources ...string) *CSPBuilder {
	b.directives["style-src"] = sources
	return b
}

// ImgSrc sets the img-src directive.
func (b *CSPBuilder) ImgSrc(sources ...string) *CSPBuilder {
	b.directives["img-src"] = sources
	return b
}

// FontSrc sets the font-src directive.
func (b *CSPBuilder) FontSrc(sources ...string) *CSPBuilder {
	b.directives["font-src"] = sources
	return b
}

// ConnectSrc sets the connect-src directive.
func (b *CSPBuilder) ConnectSrc(sources ...string) *CSPBuilder {
	b.directives["connect-src"] = sources
	return b
}

// FrameSrc sets the frame-src directive.
func (b *CSPBuilder) FrameSrc(sources ...string) *CSPBuilder {
	b.directives["frame-src"] = sources
	return b
}

// FrameAncestors sets the frame-ancestors directive.
func (b *CSPBuilder) FrameAncestors(sources ...string) *CSPBuilder {
	b.directives["frame-ancestors"] = sources
	return b
}

// ObjectSrc sets the object-src directive.
func (b *CSPBuilder) ObjectSrc(sources ...string) *CSPBuilder {
	b.directives["object-src"] = sources
	return b
}

// MediaSrc sets the media-src directive.
func (b *CSPBuilder) MediaSrc(sources ...string) *CSPBuilder {
	b.directives["media-src"] = sources
	return b
}

// BaseUri sets the base-uri directive.
func (b *CSPBuilder) BaseUri(sources ...string) *CSPBuilder {
	b.directives["base-uri"] = sources
	return b
}

// FormAction sets the form-action directive.
func (b *CSPBuilder) FormAction(sources ...string) *CSPBuilder {
	b.directives["form-action"] = sources
	return b
}

// ReportUri sets the report-uri directive.
func (b *CSPBuilder) ReportUri(uri string) *CSPBuilder {
	b.directives["report-uri"] = []string{uri}
	return b
}

// ReportTo sets the report-to directive.
func (b *CSPBuilder) ReportTo(groupName string) *CSPBuilder {
	b.directives["report-to"] = []string{groupName}
	return b
}

// UpgradeInsecureRequests adds the upgrade-insecure-requests directive.
func (b *CSPBuilder) UpgradeInsecureRequests() *CSPBuilder {
	b.directives["upgrade-insecure-requests"] = nil
	return b
}

// BlockAllMixedContent adds the block-all-mixed-content directive.
func (b *CSPBuilder) BlockAllMixedContent() *CSPBuilder {
	b.directives["block-all-mixed-content"] = nil
	return b
}

// Build builds the CSP string.
// Sorts directives for deterministic output order.
func (b *CSPBuilder) Build() string {
	// Get sorted directive names for deterministic output
	directives := make([]string, 0, len(b.directives))
	for directive := range b.directives {
		directives = append(directives, directive)
	}
	sort.Strings(directives)

	var parts []string
	for _, directive := range directives {
		sources := b.directives[directive]
		if sources == nil {
			parts = append(parts, directive)
		} else {
			parts = append(parts, directive+" "+strings.Join(sources, " "))
		}
	}
	return strings.Join(parts, "; ")
}

// Middleware returns a middleware that adds the built CSP header.
func (b *CSPBuilder) Middleware() gin.HandlerFunc {
	policy := b.Build()
	return ContentSecurityPolicy(policy)
}

// XFrameOptions returns a middleware that adds the X-Frame-Options header.
func XFrameOptions(value string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", value)
		c.Next()
	}
}

// XFrameOptionsDeny returns a middleware that sets X-Frame-Options to DENY.
func XFrameOptionsDeny() gin.HandlerFunc {
	return XFrameOptions("DENY")
}

// XFrameOptionsSameOrigin returns a middleware that sets X-Frame-Options to SAMEORIGIN.
func XFrameOptionsSameOrigin() gin.HandlerFunc {
	return XFrameOptions("SAMEORIGIN")
}

// XContentTypeOptions returns a middleware that adds the X-Content-Type-Options header.
func XContentTypeOptions() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Next()
	}
}

// XXSSProtection returns a middleware that adds the X-XSS-Protection header.
func XXSSProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Next()
	}
}

// ReferrerPolicy returns a middleware that adds the Referrer-Policy header.
func ReferrerPolicy(policy string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Referrer-Policy", policy)
		c.Next()
	}
}

// PermissionsPolicy returns a middleware that adds the Permissions-Policy header.
func PermissionsPolicy(policy string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Permissions-Policy", policy)
		c.Next()
	}
}

// PermissionsPolicyBuilder helps build Permissions-Policy directives.
type PermissionsPolicyBuilder struct {
	directives map[string][]string
}

// NewPermissionsPolicyBuilder creates a new Permissions-Policy builder.
func NewPermissionsPolicyBuilder() *PermissionsPolicyBuilder {
	return &PermissionsPolicyBuilder{
		directives: make(map[string][]string),
	}
}

// Accelerometer sets the accelerometer directive.
func (b *PermissionsPolicyBuilder) Accelerometer(allowlist ...string) *PermissionsPolicyBuilder {
	b.directives["accelerometer"] = allowlist
	return b
}

// Camera sets the camera directive.
func (b *PermissionsPolicyBuilder) Camera(allowlist ...string) *PermissionsPolicyBuilder {
	b.directives["camera"] = allowlist
	return b
}

// Geolocation sets the geolocation directive.
func (b *PermissionsPolicyBuilder) Geolocation(allowlist ...string) *PermissionsPolicyBuilder {
	b.directives["geolocation"] = allowlist
	return b
}

// Microphone sets the microphone directive.
func (b *PermissionsPolicyBuilder) Microphone(allowlist ...string) *PermissionsPolicyBuilder {
	b.directives["microphone"] = allowlist
	return b
}

// Payment sets the payment directive.
func (b *PermissionsPolicyBuilder) Payment(allowlist ...string) *PermissionsPolicyBuilder {
	b.directives["payment"] = allowlist
	return b
}

// Fullscreen sets the fullscreen directive.
func (b *PermissionsPolicyBuilder) Fullscreen(allowlist ...string) *PermissionsPolicyBuilder {
	b.directives["fullscreen"] = allowlist
	return b
}

// Build builds the Permissions-Policy string.
// Sorts directives for deterministic output order.
func (b *PermissionsPolicyBuilder) Build() string {
	// Get sorted directive names for deterministic output
	directives := make([]string, 0, len(b.directives))
	for directive := range b.directives {
		directives = append(directives, directive)
	}
	sort.Strings(directives)

	var parts []string
	for _, directive := range directives {
		allowlist := b.directives[directive]
		if len(allowlist) == 0 {
			parts = append(parts, directive+"=()")
		} else {
			parts = append(parts, directive+"=("+strings.Join(allowlist, " ")+")")
		}
	}
	return strings.Join(parts, ", ")
}

// PermissionsPolicyMiddleware returns a middleware that adds the built Permissions-Policy header.
func (b *PermissionsPolicyBuilder) PermissionsPolicyMiddleware() gin.HandlerFunc {
	policy := b.Build()
	return PermissionsPolicy(policy)
}

// NoCacheHeaders returns a middleware that adds headers to prevent caching.
func NoCacheHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}

// CacheControl returns a middleware that adds the Cache-Control header.
func CacheControl(maxAge int, directives ...string) gin.HandlerFunc {
	value := "max-age=" + strconv.Itoa(maxAge)
	if len(directives) > 0 {
		value += ", " + strings.Join(directives, ", ")
	}

	return func(c *gin.Context) {
		c.Header("Cache-Control", value)
		c.Next()
	}
}

// RemoveServerHeader returns a middleware that removes the Server header.
func RemoveServerHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Server", "")
		c.Next()
	}
}

// RemoveResponseHeaders returns a middleware that removes specified headers from response.
func RemoveResponseHeaders(headers ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		for _, header := range headers {
			c.Writer.Header().Del(header)
		}
	}
}

// AddResponseHeaders returns a middleware that adds specified headers to response.
func AddResponseHeaders(headers map[string]string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		for name, value := range headers {
			c.Writer.Header().Set(name, value)
		}
	}
}

// SecureDefaults returns a middleware with secure default headers.
func SecureDefaults() gin.HandlerFunc {
	return ExtendedSecurityHeadersWithConfig(&ExtendedSecurityConfig{
		HSTSEnabled:               true,
		HSTSMaxAge:                31536000,
		HSTSIncludeSubDomains:     true,
		XFrameOptions:             "DENY",
		XContentTypeOptions:       "nosniff",
		XXSSProtection:            "1; mode=block",
		ReferrerPolicy:            "strict-origin-when-cross-origin",
		ContentSecurityPolicy:     "default-src 'self'",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
	})
}

// APISecurityHeaders returns security headers suitable for API responses.
func APISecurityHeaders() gin.HandlerFunc {
	return ExtendedSecurityHeadersWithConfig(&ExtendedSecurityConfig{
		XContentTypeOptions:       "nosniff",
		XFrameOptions:             "DENY",
		CacheControl:              "no-store",
		CrossOriginResourcePolicy: "same-origin",
	})
}

// CrossOriginHeaders returns a middleware that adds Cross-Origin headers.
func CrossOriginHeaders(embedderPolicy, openerPolicy, resourcePolicy string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if embedderPolicy != "" {
			c.Header("Cross-Origin-Embedder-Policy", embedderPolicy)
		}
		if openerPolicy != "" {
			c.Header("Cross-Origin-Opener-Policy", openerPolicy)
		}
		if resourcePolicy != "" {
			c.Header("Cross-Origin-Resource-Policy", resourcePolicy)
		}
		c.Next()
	}
}

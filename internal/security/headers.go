package security

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// HeadersMiddleware adds security headers to HTTP responses.
type HeadersMiddleware struct {
	config *Config
	logger observability.Logger
}

// HeadersMiddlewareOption is a functional option for the headers middleware.
type HeadersMiddlewareOption func(*HeadersMiddleware)

// WithHeadersLogger sets the logger.
func WithHeadersLogger(logger observability.Logger) HeadersMiddlewareOption {
	return func(m *HeadersMiddleware) {
		m.logger = logger
	}
}

// NewHeadersMiddleware creates a new headers middleware.
func NewHeadersMiddleware(config *Config, opts ...HeadersMiddlewareOption) *HeadersMiddleware {
	m := &HeadersMiddleware{
		config: config,
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Handler returns an HTTP middleware that adds security headers.
func (m *HeadersMiddleware) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add security headers before handling the request
			m.addSecurityHeaders(w, r)

			// Create a response writer wrapper to remove headers after the response
			wrapped := &headerRemovingResponseWriter{
				ResponseWriter: w,
				removeHeaders:  m.getHeadersToRemove(),
			}

			next.ServeHTTP(wrapped, r)
		})
	}
}

// addSecurityHeaders adds all configured security headers.
func (m *HeadersMiddleware) addSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	if !m.config.Enabled {
		return
	}

	// Add basic security headers
	if m.config.IsHeadersEnabled() {
		m.addBasicSecurityHeaders(w)
	}

	// Add HSTS header (only for HTTPS)
	if m.config.IsHSTSEnabled() && isSecureRequest(r) {
		m.addHSTSHeader(w)
	}

	// Add CSP header
	if m.config.IsCSPEnabled() {
		m.addCSPHeader(w)
	}

	// Add Permissions Policy header
	if m.config.IsPermissionsPolicyEnabled() {
		m.addPermissionsPolicyHeader(w)
	}

	// Add Referrer-Policy header
	if m.config.ReferrerPolicy != "" {
		w.Header().Set("Referrer-Policy", m.config.ReferrerPolicy)
	}

	// Add Cross-Origin headers
	if m.config.CrossOriginOpenerPolicy != "" {
		w.Header().Set("Cross-Origin-Opener-Policy", m.config.CrossOriginOpenerPolicy)
	}
	if m.config.CrossOriginEmbedderPolicy != "" {
		w.Header().Set("Cross-Origin-Embedder-Policy", m.config.CrossOriginEmbedderPolicy)
	}
	if m.config.CrossOriginResourcePolicy != "" {
		w.Header().Set("Cross-Origin-Resource-Policy", m.config.CrossOriginResourcePolicy)
	}
}

// addBasicSecurityHeaders adds basic security headers.
func (m *HeadersMiddleware) addBasicSecurityHeaders(w http.ResponseWriter) {
	headers := m.config.Headers

	if headers.XFrameOptions != "" {
		w.Header().Set("X-Frame-Options", headers.XFrameOptions)
	}

	if headers.XContentTypeOptions != "" {
		w.Header().Set("X-Content-Type-Options", headers.XContentTypeOptions)
	}

	if headers.XXSSProtection != "" {
		w.Header().Set("X-XSS-Protection", headers.XXSSProtection)
	}

	if headers.CacheControl != "" {
		w.Header().Set("Cache-Control", headers.CacheControl)
	}

	if headers.Pragma != "" {
		w.Header().Set("Pragma", headers.Pragma)
	}

	// Add custom headers
	for name, value := range headers.CustomHeaders {
		w.Header().Set(name, value)
	}
}

// addHSTSHeader adds the Strict-Transport-Security header.
func (m *HeadersMiddleware) addHSTSHeader(w http.ResponseWriter) {
	hsts := m.config.HSTS

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("max-age=%d", hsts.MaxAge))

	if hsts.IncludeSubDomains {
		builder.WriteString("; includeSubDomains")
	}

	if hsts.Preload {
		builder.WriteString("; preload")
	}

	w.Header().Set("Strict-Transport-Security", builder.String())
}

// addCSPHeader adds the Content-Security-Policy header.
func (m *HeadersMiddleware) addCSPHeader(w http.ResponseWriter) {
	csp := m.config.CSP

	var policy string
	if csp.Policy != "" {
		policy = csp.Policy
	} else if csp.Directives != nil {
		policy = m.buildCSPPolicy(csp.Directives)
	}

	if policy == "" {
		return
	}

	// Add report-uri if configured
	if csp.ReportURI != "" && !strings.Contains(policy, "report-uri") {
		policy += fmt.Sprintf("; report-uri %s", csp.ReportURI)
	}

	headerName := "Content-Security-Policy"
	if csp.ReportOnly {
		headerName = "Content-Security-Policy-Report-Only"
	}

	w.Header().Set(headerName, policy)
}

// buildCSPPolicy builds a CSP policy string from directives.
func (m *HeadersMiddleware) buildCSPPolicy(directives *CSPDirectives) string {
	var parts []string

	if len(directives.DefaultSrc) > 0 {
		parts = append(parts, fmt.Sprintf("default-src %s", strings.Join(directives.DefaultSrc, " ")))
	}
	if len(directives.ScriptSrc) > 0 {
		parts = append(parts, fmt.Sprintf("script-src %s", strings.Join(directives.ScriptSrc, " ")))
	}
	if len(directives.StyleSrc) > 0 {
		parts = append(parts, fmt.Sprintf("style-src %s", strings.Join(directives.StyleSrc, " ")))
	}
	if len(directives.ImgSrc) > 0 {
		parts = append(parts, fmt.Sprintf("img-src %s", strings.Join(directives.ImgSrc, " ")))
	}
	if len(directives.FontSrc) > 0 {
		parts = append(parts, fmt.Sprintf("font-src %s", strings.Join(directives.FontSrc, " ")))
	}
	if len(directives.ConnectSrc) > 0 {
		parts = append(parts, fmt.Sprintf("connect-src %s", strings.Join(directives.ConnectSrc, " ")))
	}
	if len(directives.MediaSrc) > 0 {
		parts = append(parts, fmt.Sprintf("media-src %s", strings.Join(directives.MediaSrc, " ")))
	}
	if len(directives.ObjectSrc) > 0 {
		parts = append(parts, fmt.Sprintf("object-src %s", strings.Join(directives.ObjectSrc, " ")))
	}
	if len(directives.FrameSrc) > 0 {
		parts = append(parts, fmt.Sprintf("frame-src %s", strings.Join(directives.FrameSrc, " ")))
	}
	if len(directives.FrameAncestors) > 0 {
		parts = append(parts, fmt.Sprintf("frame-ancestors %s", strings.Join(directives.FrameAncestors, " ")))
	}
	if len(directives.FormAction) > 0 {
		parts = append(parts, fmt.Sprintf("form-action %s", strings.Join(directives.FormAction, " ")))
	}
	if len(directives.BaseURI) > 0 {
		parts = append(parts, fmt.Sprintf("base-uri %s", strings.Join(directives.BaseURI, " ")))
	}
	if directives.UpgradeInsecureRequests {
		parts = append(parts, "upgrade-insecure-requests")
	}
	if directives.BlockAllMixedContent {
		parts = append(parts, "block-all-mixed-content")
	}

	return strings.Join(parts, "; ")
}

// addPermissionsPolicyHeader adds the Permissions-Policy header.
func (m *HeadersMiddleware) addPermissionsPolicyHeader(w http.ResponseWriter) {
	pp := m.config.PermissionsPolicy

	var policy string
	if pp.Policy != "" {
		policy = pp.Policy
	} else if len(pp.Features) > 0 {
		policy = m.buildPermissionsPolicy(pp.Features)
	}

	if policy != "" {
		w.Header().Set("Permissions-Policy", policy)
	}
}

// buildPermissionsPolicy builds a Permissions Policy string from features.
func (m *HeadersMiddleware) buildPermissionsPolicy(features map[string][]string) string {
	var parts []string

	for feature, allowlist := range features {
		if len(allowlist) == 0 {
			parts = append(parts, fmt.Sprintf("%s=()", feature))
		} else {
			parts = append(parts, fmt.Sprintf("%s=(%s)", feature, strings.Join(allowlist, " ")))
		}
	}

	return strings.Join(parts, ", ")
}

// getHeadersToRemove returns the list of headers to remove from responses.
func (m *HeadersMiddleware) getHeadersToRemove() []string {
	if m.config.Headers == nil {
		return nil
	}
	return m.config.Headers.RemoveHeaders
}

// isSecureRequest checks if the request is over HTTPS.
func isSecureRequest(r *http.Request) bool {
	// Check TLS
	if r.TLS != nil {
		return true
	}

	// Check X-Forwarded-Proto header
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return true
	}

	// Check scheme
	if r.URL.Scheme == "https" {
		return true
	}

	return false
}

// headerRemovingResponseWriter wraps http.ResponseWriter to remove specified headers.
type headerRemovingResponseWriter struct {
	http.ResponseWriter
	removeHeaders []string
	wroteHeader   bool
}

// WriteHeader removes specified headers before writing the status code.
func (w *headerRemovingResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		for _, header := range w.removeHeaders {
			w.ResponseWriter.Header().Del(header)
		}
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures headers are processed before writing the body.
func (w *headerRemovingResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter.
func (w *headerRemovingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

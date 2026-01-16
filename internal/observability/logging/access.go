// Package logging provides structured logging for the API Gateway.
package logging

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AccessLogConfig holds configuration for access logging.
type AccessLogConfig struct {
	// Logger is the logger to use.
	Logger *Logger

	// SkipPaths is a list of paths to skip logging.
	SkipPaths []string

	// SkipHealthCheck skips health check endpoints.
	SkipHealthCheck bool

	// LogRequestBody enables logging of request body.
	LogRequestBody bool

	// LogResponseBody enables logging of response body.
	LogResponseBody bool

	// MaxBodySize is the maximum body size to log.
	MaxBodySize int

	// SensitiveHeaders is a list of headers to redact.
	SensitiveHeaders []string

	// SensitiveParams is a list of query parameters to redact.
	SensitiveParams []string

	// SensitiveFields is a list of JSON fields to redact.
	SensitiveFields []string

	// CustomFields is a function to add custom fields.
	CustomFields func(*gin.Context) []zap.Field
}

// DefaultAccessLogConfig returns an AccessLogConfig with default values.
func DefaultAccessLogConfig() *AccessLogConfig {
	return &AccessLogConfig{
		SkipHealthCheck: true,
		MaxBodySize:     1024,
		SensitiveHeaders: []string{
			"Authorization",
			"X-API-Key",
			"Cookie",
			"Set-Cookie",
			"X-Auth-Token",
		},
		SensitiveParams: []string{
			"password",
			"token",
			"secret",
			"api_key",
			"apikey",
			"access_token",
			"refresh_token",
		},
		SensitiveFields: []string{
			"password",
			"secret",
			"token",
			"api_key",
			"apiKey",
			"accessToken",
			"refreshToken",
			"credit_card",
			"creditCard",
			"ssn",
			"social_security",
		},
	}
}

// AccessLogMiddleware returns a Gin middleware for access logging.
func AccessLogMiddleware(logger *Logger) gin.HandlerFunc {
	return AccessLogMiddlewareWithConfig(&AccessLogConfig{
		Logger: logger,
	})
}

// AccessLogMiddlewareWithConfig returns an access log middleware with custom configuration.
func AccessLogMiddlewareWithConfig(config *AccessLogConfig) gin.HandlerFunc {
	config = normalizeAccessLogConfig(config)
	skipPaths, sensitiveParams := buildAccessLogMaps(config)

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if shouldSkipLogging(path, skipPaths, config.SkipHealthCheck) {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()
		latency := time.Since(start)

		fields := buildGinAccessLogFields(c, path, latency, sensitiveParams, config)
		logAccessByStatus(config.Logger, c.Writer.Status(), fields)
	}
}

// normalizeAccessLogConfig ensures config has all required defaults.
func normalizeAccessLogConfig(config *AccessLogConfig) *AccessLogConfig {
	if config == nil {
		config = DefaultAccessLogConfig()
	}
	if config.Logger == nil {
		config.Logger = GetGlobalLogger()
	}
	if config.SensitiveHeaders == nil {
		config.SensitiveHeaders = DefaultAccessLogConfig().SensitiveHeaders
	}
	if config.SensitiveParams == nil {
		config.SensitiveParams = DefaultAccessLogConfig().SensitiveParams
	}
	if config.SensitiveFields == nil {
		config.SensitiveFields = DefaultAccessLogConfig().SensitiveFields
	}
	return config
}

// buildAccessLogMaps creates lookup maps for skip paths and sensitive params.
func buildAccessLogMaps(config *AccessLogConfig) (skipPaths map[string]bool, sensitiveParams map[string]bool) {
	skipPaths = make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	sensitiveParams = make(map[string]bool)
	for _, p := range config.SensitiveParams {
		sensitiveParams[strings.ToLower(p)] = true
	}

	return skipPaths, sensitiveParams
}

// shouldSkipLogging determines if logging should be skipped for the given path.
func shouldSkipLogging(path string, skipPaths map[string]bool, skipHealthCheck bool) bool {
	if skipPaths[path] {
		return true
	}
	if skipHealthCheck && isHealthCheckPath(path) {
		return true
	}
	return false
}

// buildGinAccessLogFields constructs log fields from a Gin context.
func buildGinAccessLogFields(
	c *gin.Context,
	path string,
	latency time.Duration,
	sensitiveParams map[string]bool,
	config *AccessLogConfig,
) []zap.Field {
	fields := []zap.Field{
		Method(c.Request.Method),
		Path(path),
		StatusCode(c.Writer.Status()),
		Latency(latency),
		LatencyMS(latency),
		ClientIP(c.ClientIP()),
		ResponseSize(c.Writer.Size()),
	}

	fields = appendGinOptionalFields(fields, c, sensitiveParams)

	if config.CustomFields != nil {
		fields = append(fields, config.CustomFields(c)...)
	}

	return fields
}

// appendGinOptionalFields adds optional fields from Gin context.
func appendGinOptionalFields(fields []zap.Field, c *gin.Context, sensitiveParams map[string]bool) []zap.Field {
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		fields = append(fields, RequestID(requestID))
	}
	if query := c.Request.URL.RawQuery; query != "" {
		fields = append(fields, Query(redactQueryParams(query, sensitiveParams)))
	}
	if ua := c.Request.UserAgent(); ua != "" {
		fields = append(fields, UserAgent(ua))
	}
	if ct := c.ContentType(); ct != "" {
		fields = append(fields, ContentType(ct))
	}
	if c.Request.ContentLength > 0 {
		fields = append(fields, ContentLength(c.Request.ContentLength))
	}
	if referer := c.Request.Referer(); referer != "" {
		fields = append(fields, String("referer", referer))
	}
	if len(c.Errors) > 0 {
		fields = append(fields, String("errors", c.Errors.String()))
	}
	return fields
}

// logAccessByStatus logs the request with appropriate level based on status code.
func logAccessByStatus(logger *Logger, statusCode int, fields []zap.Field) {
	switch {
	case statusCode >= 500:
		logger.Error("request completed", fields...)
	case statusCode >= 400:
		logger.Warn("request completed", fields...)
	default:
		logger.Info("request completed", fields...)
	}
}

// HTTPAccessLogMiddleware returns an HTTP middleware for access logging.
func HTTPAccessLogMiddleware(logger *Logger) func(http.Handler) http.Handler {
	return HTTPAccessLogMiddlewareWithConfig(&AccessLogConfig{
		Logger: logger,
	})
}

// HTTPAccessLogMiddlewareWithConfig returns an HTTP access log middleware with custom configuration.
func HTTPAccessLogMiddlewareWithConfig(config *AccessLogConfig) func(http.Handler) http.Handler {
	config = normalizeHTTPAccessLogConfig(config)
	skipPaths, sensitiveParams := buildHTTPAccessLogMaps(config)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if shouldSkipLogging(path, skipPaths, config.SkipHealthCheck) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			wrapped := &accessResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(wrapped, r)
			latency := time.Since(start)

			fields := buildHTTPAccessLogFields(r, wrapped, path, latency, sensitiveParams)
			logAccessByStatus(config.Logger, wrapped.statusCode, fields)
		})
	}
}

// normalizeHTTPAccessLogConfig ensures HTTP config has all required defaults.
func normalizeHTTPAccessLogConfig(config *AccessLogConfig) *AccessLogConfig {
	if config == nil {
		config = DefaultAccessLogConfig()
	}
	if config.Logger == nil {
		config.Logger = GetGlobalLogger()
	}
	return config
}

// buildHTTPAccessLogMaps creates lookup maps for HTTP middleware.
func buildHTTPAccessLogMaps(config *AccessLogConfig) (skipPaths map[string]bool, sensitiveParams map[string]bool) {
	skipPaths = make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	sensitiveParams = make(map[string]bool)
	for _, p := range config.SensitiveParams {
		sensitiveParams[strings.ToLower(p)] = true
	}

	return skipPaths, sensitiveParams
}

// buildHTTPAccessLogFields constructs log fields from an HTTP request.
func buildHTTPAccessLogFields(
	r *http.Request,
	wrapped *accessResponseWriter,
	path string,
	latency time.Duration,
	sensitiveParams map[string]bool,
) []zap.Field {
	fields := []zap.Field{
		Method(r.Method),
		Path(path),
		StatusCode(wrapped.statusCode),
		Latency(latency),
		LatencyMS(latency),
		ClientIP(getClientIPFromRequest(r)),
		ResponseSize(wrapped.size),
	}

	return appendHTTPOptionalFields(fields, r, sensitiveParams)
}

// appendHTTPOptionalFields adds optional fields from HTTP request.
func appendHTTPOptionalFields(fields []zap.Field, r *http.Request, sensitiveParams map[string]bool) []zap.Field {
	if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
		fields = append(fields, RequestID(requestID))
	}
	if query := r.URL.RawQuery; query != "" {
		fields = append(fields, Query(redactQueryParams(query, sensitiveParams)))
	}
	if ua := r.UserAgent(); ua != "" {
		fields = append(fields, UserAgent(ua))
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		fields = append(fields, ContentType(ct))
	}
	if r.ContentLength > 0 {
		fields = append(fields, ContentLength(r.ContentLength))
	}
	return fields
}

// accessResponseWriter wraps http.ResponseWriter to capture status code and size.
type accessResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

// WriteHeader captures the status code.
func (rw *accessResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the response size.
func (rw *accessResponseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// Flush implements http.Flusher.
func (rw *accessResponseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// isHealthCheckPath returns true if the path is a health check endpoint.
func isHealthCheckPath(path string) bool {
	healthPaths := []string{
		"/health",
		"/healthz",
		"/ready",
		"/readyz",
		"/livez",
		"/metrics",
	}
	for _, hp := range healthPaths {
		if path == hp {
			return true
		}
	}
	return false
}

// redactQueryParams redacts sensitive query parameters.
func redactQueryParams(query string, sensitiveParams map[string]bool) string {
	if query == "" {
		return query
	}

	parts := strings.Split(query, "&")
	for i, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			if sensitiveParams[strings.ToLower(kv[0])] {
				parts[i] = kv[0] + "=[REDACTED]"
			}
		}
	}
	return strings.Join(parts, "&")
}

// RedactHeaders redacts sensitive headers.
func RedactHeaders(headers http.Header, sensitiveHeaders map[string]bool) http.Header {
	redacted := make(http.Header)
	for k, v := range headers {
		if sensitiveHeaders[strings.ToLower(k)] {
			redacted[k] = []string{"[REDACTED]"}
		} else {
			redacted[k] = v
		}
	}
	return redacted
}

// RedactJSON redacts sensitive fields from JSON data.
func RedactJSON(data string, sensitiveFields []string) string {
	result := data
	for _, field := range sensitiveFields {
		// Match "field": "value" or "field":"value"
		pattern := regexp.MustCompile(`"` + regexp.QuoteMeta(field) + `"\s*:\s*"[^"]*"`)
		result = pattern.ReplaceAllString(result, `"`+field+`":"[REDACTED]"`)

		// Match "field": value (for non-string values)
		pattern = regexp.MustCompile(`"` + regexp.QuoteMeta(field) + `"\s*:\s*[^,}\]]+`)
		result = pattern.ReplaceAllString(result, `"`+field+`":"[REDACTED]"`)
	}
	return result
}

// getClientIPFromRequest extracts the client IP from the request.
func getClientIPFromRequest(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// AccessLogEntry represents a structured access log entry.
type AccessLogEntry struct {
	Timestamp     time.Time         `json:"timestamp"`
	RequestID     string            `json:"request_id,omitempty"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         string            `json:"query,omitempty"`
	StatusCode    int               `json:"status_code"`
	Latency       time.Duration     `json:"latency"`
	LatencyMS     float64           `json:"latency_ms"`
	ClientIP      string            `json:"client_ip"`
	UserAgent     string            `json:"user_agent,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
	ResponseSize  int               `json:"response_size"`
	TraceID       string            `json:"trace_id,omitempty"`
	SpanID        string            `json:"span_id,omitempty"`
	Error         string            `json:"error,omitempty"`
	Extra         map[string]string `json:"extra,omitempty"`
}

// ToZapFields converts the entry to zap fields.
func (e *AccessLogEntry) ToZapFields() []zap.Field {
	fields := []zap.Field{
		zap.Time("timestamp", e.Timestamp),
		zap.String("method", e.Method),
		zap.String("path", e.Path),
		zap.Int("status_code", e.StatusCode),
		zap.Duration("latency", e.Latency),
		zap.Float64("latency_ms", e.LatencyMS),
		zap.String("client_ip", e.ClientIP),
		zap.Int("response_size", e.ResponseSize),
	}

	if e.RequestID != "" {
		fields = append(fields, zap.String("request_id", e.RequestID))
	}
	if e.Query != "" {
		fields = append(fields, zap.String("query", e.Query))
	}
	if e.UserAgent != "" {
		fields = append(fields, zap.String("user_agent", e.UserAgent))
	}
	if e.ContentType != "" {
		fields = append(fields, zap.String("content_type", e.ContentType))
	}
	if e.ContentLength > 0 {
		fields = append(fields, zap.Int64("content_length", e.ContentLength))
	}
	if e.TraceID != "" {
		fields = append(fields, zap.String("trace_id", e.TraceID))
	}
	if e.SpanID != "" {
		fields = append(fields, zap.String("span_id", e.SpanID))
	}
	if e.Error != "" {
		fields = append(fields, zap.String("error", e.Error))
	}
	for k, v := range e.Extra {
		fields = append(fields, zap.String(k, v))
	}

	return fields
}

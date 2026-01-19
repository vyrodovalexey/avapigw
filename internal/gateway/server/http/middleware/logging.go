package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// RequestIDHeader is the header name for request ID.
	RequestIDHeader = "X-Request-ID"
	// RequestIDKey is the context key for request ID.
	RequestIDKey = "requestID"
)

// LoggingConfig holds configuration for the logging middleware.
type LoggingConfig struct {
	Logger          *zap.Logger
	SkipPaths       []string
	SkipHealthCheck bool
}

// Logging returns a middleware that logs HTTP requests.
func Logging(logger *zap.Logger) gin.HandlerFunc {
	return LoggingWithConfig(LoggingConfig{Logger: logger})
}

// isHealthCheckPath checks if the path is a health check endpoint.
func isHealthCheckPath(path string) bool {
	return path == "/health" || path == "/healthz" || path == "/ready" || path == "/readyz"
}

// buildLogFields builds the log fields from request and response data.
func buildLogFields(c *gin.Context, requestID, path string, latency time.Duration, status int) []zap.Field {
	fields := []zap.Field{
		zap.String("requestID", requestID),
		zap.String("method", c.Request.Method),
		zap.String("path", path),
		zap.String("query", c.Request.URL.RawQuery),
		zap.Int("status", status),
		zap.Duration("latency", latency),
		zap.String("clientIP", c.ClientIP()),
		zap.String("userAgent", c.Request.UserAgent()),
		zap.Int("bodySize", c.Writer.Size()),
	}

	// Add error if present
	if len(c.Errors) > 0 {
		fields = append(fields, zap.String("errors", c.Errors.String()))
	}

	return fields
}

// logRequestByStatus logs the request with appropriate level based on status code.
func logRequestByStatus(logger *zap.Logger, status int, fields []zap.Field) {
	switch {
	case status >= 500:
		logger.Error("request completed", fields...)
	case status >= 400:
		logger.Warn("request completed", fields...)
	default:
		logger.Info("request completed", fields...)
	}
}

// LoggingWithConfig returns a logging middleware with custom configuration.
func LoggingWithConfig(config LoggingConfig) gin.HandlerFunc {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	skipPaths := make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip logging for certain paths
		if skipPaths[path] || (config.SkipHealthCheck && isHealthCheckPath(path)) {
			c.Next()
			return
		}

		start := time.Now()

		// Get or generate request ID
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set(RequestIDKey, requestID)
		c.Header(RequestIDHeader, requestID)

		// Process request
		c.Next()

		// Build and log fields
		latency := time.Since(start)
		status := c.Writer.Status()
		fields := buildLogFields(c, requestID, path, latency, status)
		logRequestByStatus(config.Logger, status, fields)
	}
}

// RequestID returns a middleware that generates and sets a request ID.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set(RequestIDKey, requestID)
		c.Header(RequestIDHeader, requestID)
		c.Next()
	}
}

// GetRequestID returns the request ID from the context.
func GetRequestID(c *gin.Context) string {
	if id, exists := c.Get(RequestIDKey); exists {
		if requestID, ok := id.(string); ok {
			return requestID
		}
	}
	return ""
}

// StructuredLogger returns a middleware that provides structured logging context.
func StructuredLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := GetRequestID(c)
		if requestID == "" {
			requestID = uuid.New().String()
			c.Set(RequestIDKey, requestID)
		}

		// Create a logger with request context
		requestLogger := logger.With(
			zap.String("requestID", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
		)

		// Store logger in context
		c.Set("logger", requestLogger)

		c.Next()
	}
}

// GetLogger returns the logger from the context.
func GetLogger(c *gin.Context) *zap.Logger {
	if logger, exists := c.Get("logger"); exists {
		if l, ok := logger.(*zap.Logger); ok {
			return l
		}
	}
	return zap.NewNop()
}

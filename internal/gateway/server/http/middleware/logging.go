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
		// Skip logging for certain paths
		path := c.Request.URL.Path
		if skipPaths[path] {
			c.Next()
			return
		}

		// Skip health check endpoints if configured
		if config.SkipHealthCheck && (path == "/health" || path == "/healthz" || path == "/ready" || path == "/readyz") {
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

		// Calculate latency
		latency := time.Since(start)

		// Get response status
		status := c.Writer.Status()

		// Build log fields
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

		// Log based on status code
		switch {
		case status >= 500:
			config.Logger.Error("request completed", fields...)
		case status >= 400:
			config.Logger.Warn("request completed", fields...)
		default:
			config.Logger.Info("request completed", fields...)
		}
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

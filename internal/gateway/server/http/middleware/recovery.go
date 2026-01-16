package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RecoveryConfig holds configuration for the recovery middleware.
type RecoveryConfig struct {
	Logger           *zap.Logger
	EnableStackTrace bool
	PanicHandler     func(c *gin.Context, err interface{})
}

// Recovery returns a middleware that recovers from panics.
func Recovery(logger *zap.Logger) gin.HandlerFunc {
	return RecoveryWithConfig(RecoveryConfig{
		Logger:           logger,
		EnableStackTrace: true,
	})
}

// RecoveryWithConfig returns a recovery middleware with custom configuration.
func RecoveryWithConfig(config RecoveryConfig) gin.HandlerFunc {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				handlePanicRecovery(c, err, config)
			}
		}()

		c.Next()
	}
}

// handlePanicRecovery handles the recovery from a panic.
func handlePanicRecovery(c *gin.Context, err interface{}, config RecoveryConfig) {
	stack := getStackTrace(config.EnableStackTrace)
	fields := buildPanicLogFields(c, err, stack, config.EnableStackTrace)

	config.Logger.Error("panic recovered", fields...)

	recordPanicInSpan(c, err)

	if config.PanicHandler != nil {
		config.PanicHandler(c, err)
		return
	}

	sendDefaultErrorResponse(c)
}

// getStackTrace returns the stack trace if enabled.
func getStackTrace(enabled bool) []byte {
	if enabled {
		return debug.Stack()
	}
	return nil
}

// buildPanicLogFields builds the log fields for a panic.
func buildPanicLogFields(c *gin.Context, err interface{}, stack []byte, includeStack bool) []zap.Field {
	fields := []zap.Field{
		zap.Any("error", err),
		zap.String("method", c.Request.Method),
		zap.String("path", c.Request.URL.Path),
		zap.String("clientIP", c.ClientIP()),
	}

	if requestID := GetRequestID(c); requestID != "" {
		fields = append(fields, zap.String("requestID", requestID))
	}

	if includeStack && len(stack) > 0 {
		fields = append(fields, zap.ByteString("stack", stack))
	}

	return fields
}

// recordPanicInSpan records the panic error in the tracing span if available.
func recordPanicInSpan(c *gin.Context, err interface{}) {
	span := GetSpan(c)
	if span == nil {
		return
	}
	span.RecordError(fmt.Errorf("panic: %v", err))
}

// sendDefaultErrorResponse sends the default error response for a panic.
func sendDefaultErrorResponse(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
		"error":   "Internal Server Error",
		"message": "An unexpected error occurred",
	})
}

// RecoveryWithWriter returns a recovery middleware that writes to a custom writer.
func RecoveryWithWriter(logger *zap.Logger, handlers ...gin.RecoveryFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				stack := debug.Stack()

				logger.Error("panic recovered",
					zap.Any("error", err),
					zap.ByteString("stack", stack),
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
				)

				// Call custom handlers
				for _, handler := range handlers {
					handler(c, err)
				}

				if !c.IsAborted() {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error":   "Internal Server Error",
						"message": "An unexpected error occurred",
					})
				}
			}
		}()

		c.Next()
	}
}

// CustomRecovery returns a recovery middleware with a custom recovery function.
func CustomRecovery(logger *zap.Logger, handle gin.RecoveryFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				stack := debug.Stack()

				logger.Error("panic recovered",
					zap.Any("error", err),
					zap.ByteString("stack", stack),
				)

				handle(c, err)
			}
		}()

		c.Next()
	}
}

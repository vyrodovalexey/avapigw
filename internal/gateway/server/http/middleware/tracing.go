package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	// TracerName is the name of the tracer.
	TracerName = "avapigw"
	// SpanKey is the context key for the span.
	SpanKey = "otel-span"
)

// TracingConfig holds configuration for the tracing middleware.
type TracingConfig struct {
	TracerProvider trace.TracerProvider
	Propagators    propagation.TextMapPropagator
	ServiceName    string
	SkipPaths      []string
}

// Tracing returns a middleware that creates OpenTelemetry spans for requests.
func Tracing(serviceName string) gin.HandlerFunc {
	return TracingWithConfig(TracingConfig{
		ServiceName: serviceName,
	})
}

// TracingWithConfig returns a tracing middleware with custom configuration.
func TracingWithConfig(config TracingConfig) gin.HandlerFunc {
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}
	if config.Propagators == nil {
		config.Propagators = otel.GetTextMapPropagator()
	}
	if config.ServiceName == "" {
		config.ServiceName = TracerName
	}

	tracer := config.TracerProvider.Tracer(config.ServiceName)

	skipPaths := make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	return func(c *gin.Context) {
		// Skip tracing for certain paths
		path := c.Request.URL.Path
		if skipPaths[path] {
			c.Next()
			return
		}

		// Extract trace context from incoming request
		ctx := config.Propagators.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		// Create span name
		spanName := fmt.Sprintf("%s %s", c.Request.Method, path)

		// Start span
		ctx, span := tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		// Set span attributes
		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.url", c.Request.URL.String()),
			attribute.String("http.target", path),
			attribute.String("http.host", c.Request.Host),
			attribute.String("http.scheme", c.Request.URL.Scheme),
			attribute.String("http.user_agent", c.Request.UserAgent()),
			attribute.String("net.peer.ip", c.ClientIP()),
		)

		// Add request ID if available
		if requestID := GetRequestID(c); requestID != "" {
			span.SetAttributes(attribute.String("request.id", requestID))
		}

		// Store span in context
		c.Set(SpanKey, span)
		c.Request = c.Request.WithContext(ctx)

		// Process request
		c.Next()

		// Set response attributes
		status := c.Writer.Status()
		span.SetAttributes(
			attribute.Int("http.status_code", status),
			attribute.Int("http.response_content_length", c.Writer.Size()),
		)

		// Record errors
		if len(c.Errors) > 0 {
			span.SetAttributes(attribute.String("error", c.Errors.String()))
			span.RecordError(fmt.Errorf("%s", c.Errors.String()))
		}

		// Set span status based on HTTP status code
		if status >= 500 {
			span.SetAttributes(attribute.Bool("error", true))
		}
	}
}

// GetSpan returns the span from the context.
func GetSpan(c *gin.Context) trace.Span {
	if span, exists := c.Get(SpanKey); exists {
		if s, ok := span.(trace.Span); ok {
			return s
		}
	}
	return nil
}

// AddSpanAttribute adds an attribute to the current span.
func AddSpanAttribute(c *gin.Context, key string, value interface{}) {
	span := GetSpan(c)
	if span == nil {
		return
	}

	switch v := value.(type) {
	case string:
		span.SetAttributes(attribute.String(key, v))
	case int:
		span.SetAttributes(attribute.Int(key, v))
	case int64:
		span.SetAttributes(attribute.Int64(key, v))
	case float64:
		span.SetAttributes(attribute.Float64(key, v))
	case bool:
		span.SetAttributes(attribute.Bool(key, v))
	default:
		span.SetAttributes(attribute.String(key, fmt.Sprintf("%v", v)))
	}
}

// AddSpanEvent adds an event to the current span.
func AddSpanEvent(c *gin.Context, name string, attrs ...attribute.KeyValue) {
	span := GetSpan(c)
	if span == nil {
		return
	}
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// RecordSpanError records an error on the current span.
func RecordSpanError(c *gin.Context, err error) {
	span := GetSpan(c)
	if span == nil {
		return
	}
	span.RecordError(err)
}

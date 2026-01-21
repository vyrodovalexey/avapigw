// Package observability provides logging, metrics, and tracing functionality.
package observability

import (
	"context"
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the interface for structured logging.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)
	With(fields ...Field) Logger
	WithContext(ctx context.Context) Logger
	Sync() error
}

// Field represents a log field.
type Field = zap.Field

// Field constructors for convenience.
var (
	String   = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Float64  = zap.Float64
	Bool     = zap.Bool
	Error    = zap.Error
	Any      = zap.Any
	Duration = zap.Duration
	Time     = zap.Time
)

// LogConfig represents logging configuration.
type LogConfig struct {
	Level      string
	Format     string
	Output     string
	TimeFormat string
}

// DefaultLogConfig returns default logging configuration.
func DefaultLogConfig() LogConfig {
	return LogConfig{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		TimeFormat: "2006-01-02T15:04:05.000Z07:00",
	}
}

// zapLogger implements Logger using zap.
type zapLogger struct {
	logger *zap.Logger
	sugar  *zap.SugaredLogger
}

var (
	globalLogger Logger
	globalMu     sync.RWMutex
)

// NewLogger creates a new logger with the given configuration.
func NewLogger(cfg LogConfig) (Logger, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var encoder zapcore.Encoder
	if cfg.Format == "console" {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	var writeSyncer zapcore.WriteSyncer
	switch cfg.Output {
	case "stderr":
		writeSyncer = zapcore.AddSync(os.Stderr)
	default:
		writeSyncer = zapcore.AddSync(os.Stdout)
	}

	core := zapcore.NewCore(encoder, writeSyncer, level)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &zapLogger{
		logger: logger,
		sugar:  logger.Sugar(),
	}, nil
}

// parseLevel parses a log level string.
func parseLevel(level string) (zapcore.Level, error) {
	var l zapcore.Level
	err := l.UnmarshalText([]byte(level))
	return l, err
}

// Debug logs a debug message.
func (l *zapLogger) Debug(msg string, fields ...Field) {
	l.logger.Debug(msg, fields...)
}

// Info logs an info message.
func (l *zapLogger) Info(msg string, fields ...Field) {
	l.logger.Info(msg, fields...)
}

// Warn logs a warning message.
func (l *zapLogger) Warn(msg string, fields ...Field) {
	l.logger.Warn(msg, fields...)
}

// Error logs an error message.
func (l *zapLogger) Error(msg string, fields ...Field) {
	l.logger.Error(msg, fields...)
}

// Fatal logs a fatal message and exits.
func (l *zapLogger) Fatal(msg string, fields ...Field) {
	l.logger.Fatal(msg, fields...)
}

// With returns a logger with additional fields.
func (l *zapLogger) With(fields ...Field) Logger {
	return &zapLogger{
		logger: l.logger.With(fields...),
		sugar:  l.logger.With(fields...).Sugar(),
	}
}

// WithContext returns a logger with context fields (request ID, trace ID).
func (l *zapLogger) WithContext(ctx context.Context) Logger {
	fields := extractContextFields(ctx)
	if len(fields) == 0 {
		return l
	}
	return l.With(fields...)
}

// Sync flushes any buffered log entries.
func (l *zapLogger) Sync() error {
	return l.logger.Sync()
}

// Context keys for logging.
type contextKey string

const (
	requestIDKey contextKey = "request_id"
	traceIDKey   contextKey = "trace_id"
	spanIDKey    contextKey = "span_id"
)

// extractContextFields extracts logging fields from context.
func extractContextFields(ctx context.Context) []Field {
	var fields []Field

	if requestID, ok := ctx.Value(requestIDKey).(string); ok && requestID != "" {
		fields = append(fields, String("request_id", requestID))
	}

	if traceID, ok := ctx.Value(traceIDKey).(string); ok && traceID != "" {
		fields = append(fields, String("trace_id", traceID))
	}

	if spanID, ok := ctx.Value(spanIDKey).(string); ok && spanID != "" {
		fields = append(fields, String("span_id", spanID))
	}

	return fields
}

// ContextWithRequestID adds a request ID to the context.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// RequestIDFromContext extracts the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// ContextWithTraceID adds a trace ID to the context.
func ContextWithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey, traceID)
}

// TraceIDFromContext extracts the trace ID from context.
func TraceIDFromContext(ctx context.Context) string {
	if traceID, ok := ctx.Value(traceIDKey).(string); ok {
		return traceID
	}
	return ""
}

// ContextWithSpanID adds a span ID to the context.
func ContextWithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, spanIDKey, spanID)
}

// SpanIDFromContext extracts the span ID from context.
func SpanIDFromContext(ctx context.Context) string {
	if spanID, ok := ctx.Value(spanIDKey).(string); ok {
		return spanID
	}
	return ""
}

// SetGlobalLogger sets the global logger instance.
func SetGlobalLogger(logger Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = logger
}

// GetGlobalLogger returns the global logger instance.
func GetGlobalLogger() Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	if globalLogger == nil {
		// Return a default logger if none is set
		logger, _ := NewLogger(DefaultLogConfig())
		return logger
	}
	return globalLogger
}

// L returns the global logger (shorthand).
func L() Logger {
	return GetGlobalLogger()
}

// NopLogger returns a logger that discards all output.
func NopLogger() Logger {
	return &zapLogger{
		logger: zap.NewNop(),
		sugar:  zap.NewNop().Sugar(),
	}
}

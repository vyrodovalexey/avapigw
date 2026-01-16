// Package logging provides structured logging for the API Gateway.
package logging

import (
	"context"
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Level represents a log level.
type Level string

const (
	// LevelDebug is the debug log level.
	LevelDebug Level = "debug"
	// LevelInfo is the info log level.
	LevelInfo Level = "info"
	// LevelWarn is the warn log level.
	LevelWarn Level = "warn"
	// LevelError is the error log level.
	LevelError Level = "error"
)

// Format represents a log format.
type Format string

const (
	// FormatJSON outputs logs in JSON format.
	FormatJSON Format = "json"
	// FormatConsole outputs logs in human-readable format.
	FormatConsole Format = "console"
)

// Config holds configuration for the logger.
type Config struct {
	// Level is the minimum log level.
	Level Level

	// Format is the log output format.
	Format Format

	// Output is the output destination (stdout, stderr, or file path).
	Output string

	// Development enables development mode (more verbose).
	Development bool

	// DisableCaller disables caller information in logs.
	DisableCaller bool

	// DisableStacktrace disables stack traces for error logs.
	DisableStacktrace bool

	// Sampling configures log sampling.
	Sampling *SamplingConfig

	// InitialFields are fields added to every log entry.
	InitialFields map[string]interface{}
}

// SamplingConfig holds configuration for log sampling.
type SamplingConfig struct {
	// Initial is the number of messages to log per second initially.
	Initial int

	// Thereafter is the number of messages to log per second after initial.
	Thereafter int
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Level:             LevelInfo,
		Format:            FormatJSON,
		Output:            "stdout",
		Development:       false,
		DisableCaller:     false,
		DisableStacktrace: false,
	}
}

// Logger wraps zap.Logger with additional functionality.
type Logger struct {
	*zap.Logger
	config *Config
	level  zap.AtomicLevel
}

var (
	globalLogger *Logger
	globalMu     sync.RWMutex
)

// NewLogger creates a new Logger with the given configuration.
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}

	level := zap.NewAtomicLevel()
	level.SetLevel(parseLevel(config.Level))

	encoderConfig := buildEncoderConfig(config)
	encoder := buildEncoder(config.Format, encoderConfig)

	output, err := buildOutput(config.Output)
	if err != nil {
		return nil, err
	}

	core := buildCore(encoder, output, level, config.Sampling)
	opts := buildLoggerOptions(config)
	zapLogger := zap.New(core, opts...)

	return &Logger{
		Logger: zapLogger,
		config: config,
		level:  level,
	}, nil
}

// buildEncoderConfig creates the encoder configuration based on config settings.
func buildEncoderConfig(config *Config) zapcore.EncoderConfig {
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

	if config.Development {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	return encoderConfig
}

// buildEncoder creates the appropriate encoder based on format.
func buildEncoder(format Format, encoderConfig zapcore.EncoderConfig) zapcore.Encoder {
	switch format {
	case FormatConsole:
		return zapcore.NewConsoleEncoder(encoderConfig)
	default:
		return zapcore.NewJSONEncoder(encoderConfig)
	}
}

// buildOutput creates the output writer based on the output configuration.
func buildOutput(outputPath string) (zapcore.WriteSyncer, error) {
	switch outputPath {
	case "stdout":
		return zapcore.AddSync(os.Stdout), nil
	case "stderr":
		return zapcore.AddSync(os.Stderr), nil
	default:
		// G302: Log files need to be readable for log aggregation tools, 0o644 is intentional
		//nolint:gosec // log files need broader read permissions
		file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		return zapcore.AddSync(file), nil
	}
}

// buildCore creates the zapcore.Core with optional sampling.
func buildCore(
	encoder zapcore.Encoder,
	output zapcore.WriteSyncer,
	level zap.AtomicLevel,
	sampling *SamplingConfig,
) zapcore.Core {
	core := zapcore.NewCore(encoder, output, level)

	if sampling != nil {
		core = zapcore.NewSamplerWithOptions(core, 1, sampling.Initial, sampling.Thereafter)
	}

	return core
}

// buildLoggerOptions creates zap options based on configuration.
func buildLoggerOptions(config *Config) []zap.Option {
	opts := []zap.Option{}

	if !config.DisableCaller {
		opts = append(opts, zap.AddCaller())
	}
	if !config.DisableStacktrace {
		opts = append(opts, zap.AddStacktrace(zapcore.ErrorLevel))
	}
	if config.Development {
		opts = append(opts, zap.Development())
	}

	if len(config.InitialFields) > 0 {
		fields := make([]zap.Field, 0, len(config.InitialFields))
		for k, v := range config.InitialFields {
			fields = append(fields, zap.Any(k, v))
		}
		opts = append(opts, zap.Fields(fields...))
	}

	return opts
}

// SetLevel sets the log level dynamically.
func (l *Logger) SetLevel(level Level) {
	l.level.SetLevel(parseLevel(level))
}

// GetLevel returns the current log level.
func (l *Logger) GetLevel() Level {
	switch l.level.Level() {
	case zapcore.DebugLevel:
		return LevelDebug
	case zapcore.InfoLevel:
		return LevelInfo
	case zapcore.WarnLevel:
		return LevelWarn
	case zapcore.ErrorLevel:
		return LevelError
	default:
		return LevelInfo
	}
}

// With creates a child logger with the given fields.
func (l *Logger) With(fields ...zap.Field) *Logger {
	return &Logger{
		Logger: l.Logger.With(fields...),
		config: l.config,
		level:  l.level,
	}
}

// WithContext creates a child logger with context fields.
func (l *Logger) WithContext(ctx context.Context) *Logger {
	fields := FieldsFromContext(ctx)
	if len(fields) == 0 {
		return l
	}
	return l.With(fields...)
}

// Named creates a named child logger.
func (l *Logger) Named(name string) *Logger {
	return &Logger{
		Logger: l.Logger.Named(name),
		config: l.config,
		level:  l.level,
	}
}

// Sync flushes any buffered log entries.
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// SetGlobalLogger sets the global logger.
func SetGlobalLogger(logger *Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = logger
}

// GetGlobalLogger returns the global logger.
func GetGlobalLogger() *Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	if globalLogger == nil {
		logger, _ := NewLogger(DefaultConfig())
		return logger
	}
	return globalLogger
}

// L returns the global logger (shorthand for GetGlobalLogger).
func L() *Logger {
	return GetGlobalLogger()
}

// parseLevel parses a Level to zapcore.Level.
func parseLevel(level Level) zapcore.Level {
	switch level {
	case LevelDebug:
		return zapcore.DebugLevel
	case LevelInfo:
		return zapcore.InfoLevel
	case LevelWarn:
		return zapcore.WarnLevel
	case LevelError:
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// Context key for logger
type contextKey struct{}

var loggerContextKey = contextKey{}

// ContextWithLogger returns a new context with the logger.
func ContextWithLogger(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey, logger)
}

// LoggerFromContext returns the logger from the context.
func LoggerFromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerContextKey).(*Logger); ok {
		return logger
	}
	return GetGlobalLogger()
}

// Debug logs a debug message.
func Debug(msg string, fields ...zap.Field) {
	GetGlobalLogger().Debug(msg, fields...)
}

// Info logs an info message.
func Info(msg string, fields ...zap.Field) {
	GetGlobalLogger().Info(msg, fields...)
}

// Warn logs a warning message.
func Warn(msg string, fields ...zap.Field) {
	GetGlobalLogger().Warn(msg, fields...)
}

// Error logs an error message.
func Error(msg string, fields ...zap.Field) {
	GetGlobalLogger().Error(msg, fields...)
}

// Fatal logs a fatal message and exits.
func Fatal(msg string, fields ...zap.Field) {
	GetGlobalLogger().Fatal(msg, fields...)
}

// Panic logs a panic message and panics.
func Panic(msg string, fields ...zap.Field) {
	GetGlobalLogger().Panic(msg, fields...)
}

// DebugContext logs a debug message with context.
func DebugContext(ctx context.Context, msg string, fields ...zap.Field) {
	LoggerFromContext(ctx).WithContext(ctx).Debug(msg, fields...)
}

// InfoContext logs an info message with context.
func InfoContext(ctx context.Context, msg string, fields ...zap.Field) {
	LoggerFromContext(ctx).WithContext(ctx).Info(msg, fields...)
}

// WarnContext logs a warning message with context.
func WarnContext(ctx context.Context, msg string, fields ...zap.Field) {
	LoggerFromContext(ctx).WithContext(ctx).Warn(msg, fields...)
}

// ErrorContext logs an error message with context.
func ErrorContext(ctx context.Context, msg string, fields ...zap.Field) {
	LoggerFromContext(ctx).WithContext(ctx).Error(msg, fields...)
}

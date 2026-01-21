package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLogConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultLogConfig()

	assert.Equal(t, "info", cfg.Level)
	assert.Equal(t, "json", cfg.Format)
	assert.Equal(t, "stdout", cfg.Output)
	assert.NotEmpty(t, cfg.TimeFormat)
}

func TestNewLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  LogConfig
		wantErr bool
	}{
		{
			name:    "default config",
			config:  DefaultLogConfig(),
			wantErr: false,
		},
		{
			name: "console format",
			config: LogConfig{
				Level:  "debug",
				Format: "console",
				Output: "stdout",
			},
			wantErr: false,
		},
		{
			name: "stderr output",
			config: LogConfig{
				Level:  "info",
				Format: "json",
				Output: "stderr",
			},
			wantErr: false,
		},
		{
			name: "invalid level",
			config: LogConfig{
				Level:  "invalid",
				Format: "json",
				Output: "stdout",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger, err := NewLogger(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, logger)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestZapLogger_Methods(t *testing.T) {
	t.Parallel()

	logger, err := NewLogger(LogConfig{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	// These should not panic
	logger.Debug("debug message", String("key", "value"))
	logger.Info("info message", Int("count", 42))
	logger.Warn("warn message", Bool("flag", true))
	logger.Error("error message", Float64("value", 3.14))

	// Sync may return error for stdout/stderr in test environment
	_ = logger.Sync()
}

func TestZapLogger_With(t *testing.T) {
	t.Parallel()

	logger, err := NewLogger(DefaultLogConfig())
	require.NoError(t, err)

	childLogger := logger.With(String("service", "test"))

	assert.NotNil(t, childLogger)
	assert.NotEqual(t, logger, childLogger)
}

func TestZapLogger_WithContext(t *testing.T) {
	t.Parallel()

	logger, err := NewLogger(DefaultLogConfig())
	require.NoError(t, err)

	ctx := context.Background()
	ctx = ContextWithRequestID(ctx, "req-123")
	ctx = ContextWithTraceID(ctx, "trace-456")
	ctx = ContextWithSpanID(ctx, "span-789")

	childLogger := logger.WithContext(ctx)

	assert.NotNil(t, childLogger)
}

func TestZapLogger_WithContext_EmptyContext(t *testing.T) {
	t.Parallel()

	logger, err := NewLogger(DefaultLogConfig())
	require.NoError(t, err)

	ctx := context.Background()
	childLogger := logger.WithContext(ctx)

	// Should return same logger when no context values
	assert.NotNil(t, childLogger)
}

func TestContextWithRequestID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = ContextWithRequestID(ctx, "test-request-id")

	requestID := RequestIDFromContext(ctx)
	assert.Equal(t, "test-request-id", requestID)
}

func TestRequestIDFromContext_Empty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	requestID := RequestIDFromContext(ctx)

	assert.Empty(t, requestID)
}

func TestContextWithTraceID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = ContextWithTraceID(ctx, "test-trace-id")

	traceID := TraceIDFromContext(ctx)
	assert.Equal(t, "test-trace-id", traceID)
}

func TestTraceIDFromContext_Empty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	traceID := TraceIDFromContext(ctx)

	assert.Empty(t, traceID)
}

func TestContextWithSpanID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = ContextWithSpanID(ctx, "test-span-id")

	spanID := SpanIDFromContext(ctx)
	assert.Equal(t, "test-span-id", spanID)
}

func TestSpanIDFromContext_Empty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spanID := SpanIDFromContext(ctx)

	assert.Empty(t, spanID)
}

func TestSetGlobalLogger(t *testing.T) {
	// Not parallel - modifies global state
	logger, err := NewLogger(DefaultLogConfig())
	require.NoError(t, err)

	SetGlobalLogger(logger)

	retrieved := GetGlobalLogger()
	assert.Equal(t, logger, retrieved)

	// Reset global logger
	SetGlobalLogger(nil)
}

func TestGetGlobalLogger_Default(t *testing.T) {
	// Not parallel - modifies global state
	SetGlobalLogger(nil)

	logger := GetGlobalLogger()
	assert.NotNil(t, logger)
}

func TestL(t *testing.T) {
	// Not parallel - modifies global state
	logger, err := NewLogger(DefaultLogConfig())
	require.NoError(t, err)

	SetGlobalLogger(logger)

	retrieved := L()
	assert.Equal(t, logger, retrieved)

	// Reset global logger
	SetGlobalLogger(nil)
}

func TestNopLogger(t *testing.T) {
	t.Parallel()

	logger := NopLogger()

	assert.NotNil(t, logger)

	// These should not panic
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")

	err := logger.Sync()
	assert.NoError(t, err)
}

func TestNopLogger_With(t *testing.T) {
	t.Parallel()

	logger := NopLogger()
	childLogger := logger.With(String("key", "value"))

	assert.NotNil(t, childLogger)
}

func TestNopLogger_WithContext(t *testing.T) {
	t.Parallel()

	logger := NopLogger()
	ctx := ContextWithRequestID(context.Background(), "req-123")
	childLogger := logger.WithContext(ctx)

	assert.NotNil(t, childLogger)
}

func TestExtractContextFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		setupContext  func() context.Context
		expectedCount int
	}{
		{
			name: "all fields present",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = ContextWithRequestID(ctx, "req-123")
				ctx = ContextWithTraceID(ctx, "trace-456")
				ctx = ContextWithSpanID(ctx, "span-789")
				return ctx
			},
			expectedCount: 3,
		},
		{
			name: "only request ID",
			setupContext: func() context.Context {
				return ContextWithRequestID(context.Background(), "req-123")
			},
			expectedCount: 1,
		},
		{
			name: "no fields",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectedCount: 0,
		},
		{
			name: "empty values",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = ContextWithRequestID(ctx, "")
				return ctx
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.setupContext()
			fields := extractContextFields(ctx)

			assert.Len(t, fields, tt.expectedCount)
		})
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		level   string
		wantErr bool
	}{
		{name: "debug", level: "debug", wantErr: false},
		{name: "info", level: "info", wantErr: false},
		{name: "warn", level: "warn", wantErr: false},
		{name: "error", level: "error", wantErr: false},
		{name: "invalid", level: "invalid", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseLevel(tt.level)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFieldConstructors(t *testing.T) {
	t.Parallel()

	// Test that field constructors work
	_ = String("key", "value")
	_ = Int("key", 42)
	_ = Int64("key", int64(42))
	_ = Float64("key", 3.14)
	_ = Bool("key", true)
	_ = Error(assert.AnError)
	_ = Any("key", struct{}{})
	_ = Duration("key", 0)
	_ = Time("key", time.Now())
}

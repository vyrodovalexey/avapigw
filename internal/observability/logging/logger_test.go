// Package logging provides structured logging for the API Gateway.
package logging

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		name     string
		validate func(t *testing.T, cfg *Config)
	}{
		{
			name: "returns non-nil config",
			validate: func(t *testing.T, cfg *Config) {
				assert.NotNil(t, cfg)
			},
		},
		{
			name: "has info level",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, LevelInfo, cfg.Level)
			},
		},
		{
			name: "has JSON format",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, FormatJSON, cfg.Format)
			},
		},
		{
			name: "has stdout output",
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "stdout", cfg.Output)
			},
		},
		{
			name: "has development disabled",
			validate: func(t *testing.T, cfg *Config) {
				assert.False(t, cfg.Development)
			},
		},
		{
			name: "has caller enabled",
			validate: func(t *testing.T, cfg *Config) {
				assert.False(t, cfg.DisableCaller)
			},
		},
		{
			name: "has stacktrace enabled",
			validate: func(t *testing.T, cfg *Config) {
				assert.False(t, cfg.DisableStacktrace)
			},
		},
		{
			name: "has no sampling",
			validate: func(t *testing.T, cfg *Config) {
				assert.Nil(t, cfg.Sampling)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.validate(t, cfg)
		})
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "with nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name: "with JSON format",
			config: &Config{
				Level:  LevelInfo,
				Format: FormatJSON,
				Output: "stdout",
			},
			wantErr: false,
		},
		{
			name: "with console format",
			config: &Config{
				Level:  LevelDebug,
				Format: FormatConsole,
				Output: "stderr",
			},
			wantErr: false,
		},
		{
			name: "with development mode",
			config: &Config{
				Level:       LevelDebug,
				Format:      FormatConsole,
				Output:      "stdout",
				Development: true,
			},
			wantErr: false,
		},
		{
			name: "with disabled caller",
			config: &Config{
				Level:         LevelInfo,
				Format:        FormatJSON,
				Output:        "stdout",
				DisableCaller: true,
			},
			wantErr: false,
		},
		{
			name: "with disabled stacktrace",
			config: &Config{
				Level:             LevelInfo,
				Format:            FormatJSON,
				Output:            "stdout",
				DisableStacktrace: true,
			},
			wantErr: false,
		},
		{
			name: "with sampling",
			config: &Config{
				Level:  LevelInfo,
				Format: FormatJSON,
				Output: "stdout",
				Sampling: &SamplingConfig{
					Initial:    100,
					Thereafter: 100,
				},
			},
			wantErr: false,
		},
		{
			name: "with initial fields",
			config: &Config{
				Level:  LevelInfo,
				Format: FormatJSON,
				Output: "stdout",
				InitialFields: map[string]interface{}{
					"service": "test",
					"version": "1.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "with all log levels",
			config: &Config{
				Level:  LevelError,
				Format: FormatJSON,
				Output: "stdout",
			},
			wantErr: false,
		},
		{
			name: "with warn level",
			config: &Config{
				Level:  LevelWarn,
				Format: FormatJSON,
				Output: "stdout",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, logger)
			assert.NotNil(t, logger.Logger)
		})
	}
}

func TestNewLogger_WithFileOutput(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	config := &Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: logFile,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)
	assert.NotNil(t, logger)

	// Write a log entry
	logger.Info("test message")
	_ = logger.Sync()

	// Verify file was created
	_, err = os.Stat(logFile)
	assert.NoError(t, err)
}

func TestNewLogger_WithInvalidFileOutput(t *testing.T) {
	config := &Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: "/nonexistent/directory/test.log",
	}

	_, err := NewLogger(config)
	assert.Error(t, err)
}

func TestLogger_SetLevel(t *testing.T) {
	tests := []struct {
		name     string
		initial  Level
		newLevel Level
	}{
		{
			name:     "from info to debug",
			initial:  LevelInfo,
			newLevel: LevelDebug,
		},
		{
			name:     "from debug to error",
			initial:  LevelDebug,
			newLevel: LevelError,
		},
		{
			name:     "from error to warn",
			initial:  LevelError,
			newLevel: LevelWarn,
		},
		{
			name:     "from warn to info",
			initial:  LevelWarn,
			newLevel: LevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Level:  tt.initial,
				Format: FormatJSON,
				Output: "stdout",
			}
			logger, err := NewLogger(config)
			require.NoError(t, err)

			logger.SetLevel(tt.newLevel)
			assert.Equal(t, tt.newLevel, logger.GetLevel())
		})
	}
}

func TestLogger_GetLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    Level
		expected Level
	}{
		{
			name:     "debug level",
			level:    LevelDebug,
			expected: LevelDebug,
		},
		{
			name:     "info level",
			level:    LevelInfo,
			expected: LevelInfo,
		},
		{
			name:     "warn level",
			level:    LevelWarn,
			expected: LevelWarn,
		},
		{
			name:     "error level",
			level:    LevelError,
			expected: LevelError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Level:  tt.level,
				Format: FormatJSON,
				Output: "stdout",
			}
			logger, err := NewLogger(config)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, logger.GetLevel())
		})
	}
}

func TestLogger_With(t *testing.T) {
	tests := []struct {
		name       string
		fields     []zap.Field
		expectSame bool
	}{
		{
			name:       "with single field",
			fields:     []zap.Field{zap.String("key", "value")},
			expectSame: false,
		},
		{
			name: "with multiple fields",
			fields: []zap.Field{
				zap.String("key1", "value1"),
				zap.Int("key2", 42),
				zap.Bool("key3", true),
			},
			expectSame: false,
		},
		{
			name:       "with no fields",
			fields:     []zap.Field{},
			expectSame: true, // zap returns same logger for empty fields
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(nil)
			require.NoError(t, err)

			childLogger := logger.With(tt.fields...)
			assert.NotNil(t, childLogger)
			if tt.expectSame {
				assert.Same(t, logger.Logger, childLogger.Logger)
			} else {
				assert.NotSame(t, logger.Logger, childLogger.Logger)
			}
		})
	}
}

func TestLogger_WithContext(t *testing.T) {
	tests := []struct {
		name      string
		setupCtx  func() context.Context
		expectNew bool
	}{
		{
			name: "with context fields",
			setupCtx: func() context.Context {
				cf := NewContextFields()
				cf.Set("request_id", "123")
				return ContextWithFields(context.Background(), cf)
			},
			expectNew: true,
		},
		{
			name: "without context fields",
			setupCtx: func() context.Context {
				return context.Background()
			},
			expectNew: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(nil)
			require.NoError(t, err)

			ctx := tt.setupCtx()
			childLogger := logger.WithContext(ctx)
			assert.NotNil(t, childLogger)

			if tt.expectNew {
				assert.NotSame(t, logger.Logger, childLogger.Logger)
			} else {
				assert.Same(t, logger, childLogger)
			}
		})
	}
}

func TestLogger_Named(t *testing.T) {
	tests := []struct {
		name       string
		loggerName string
		expectSame bool
	}{
		{
			name:       "with simple name",
			loggerName: "mylogger",
			expectSame: false,
		},
		{
			name:       "with dotted name",
			loggerName: "my.logger.name",
			expectSame: false,
		},
		{
			name:       "with empty name",
			loggerName: "",
			expectSame: true, // zap returns same logger for empty name
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(nil)
			require.NoError(t, err)

			namedLogger := logger.Named(tt.loggerName)
			assert.NotNil(t, namedLogger)
			if tt.expectSame {
				assert.Same(t, logger.Logger, namedLogger.Logger)
			} else {
				assert.NotSame(t, logger.Logger, namedLogger.Logger)
			}
		})
	}
}

func TestSetGlobalLogger(t *testing.T) {
	// Save original global logger
	originalLogger := globalLogger
	defer func() {
		globalLogger = originalLogger
	}()

	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	SetGlobalLogger(logger)

	// Verify global logger was set
	globalMu.RLock()
	assert.Same(t, logger, globalLogger)
	globalMu.RUnlock()
}

func TestGetGlobalLogger(t *testing.T) {
	tests := []struct {
		name      string
		setup     func()
		expectNil bool
	}{
		{
			name: "returns set logger",
			setup: func() {
				logger, _ := NewLogger(nil)
				SetGlobalLogger(logger)
			},
			expectNil: false,
		},
		{
			name: "returns default when nil",
			setup: func() {
				globalMu.Lock()
				globalLogger = nil
				globalMu.Unlock()
			},
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			logger := GetGlobalLogger()
			if tt.expectNil {
				assert.Nil(t, logger)
			} else {
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestL(t *testing.T) {
	// L() is a shorthand for GetGlobalLogger()
	logger, err := NewLogger(nil)
	require.NoError(t, err)
	SetGlobalLogger(logger)

	result := L()
	assert.NotNil(t, result)
	assert.Equal(t, GetGlobalLogger(), result)
}

func TestContextWithLogger(t *testing.T) {
	logger, err := NewLogger(nil)
	require.NoError(t, err)

	ctx := context.Background()
	ctxWithLogger := ContextWithLogger(ctx, logger)

	assert.NotNil(t, ctxWithLogger)
	assert.NotEqual(t, ctx, ctxWithLogger)
}

func TestLoggerFromContext(t *testing.T) {
	tests := []struct {
		name     string
		setupCtx func() context.Context
		wantSame bool
	}{
		{
			name: "returns logger from context",
			setupCtx: func() context.Context {
				logger, _ := NewLogger(nil)
				return ContextWithLogger(context.Background(), logger)
			},
			wantSame: true,
		},
		{
			name: "returns global logger when not in context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantSame: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			logger := LoggerFromContext(ctx)
			assert.NotNil(t, logger)
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    Level
		expected string
	}{
		{
			name:     "debug level",
			level:    LevelDebug,
			expected: "debug",
		},
		{
			name:     "info level",
			level:    LevelInfo,
			expected: "info",
		},
		{
			name:     "warn level",
			level:    LevelWarn,
			expected: "warn",
		},
		{
			name:     "error level",
			level:    LevelError,
			expected: "error",
		},
		{
			name:     "unknown level defaults to info",
			level:    Level("unknown"),
			expected: "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zapLevel := parseLevel(tt.level)
			assert.Equal(t, tt.expected, zapLevel.String())
		})
	}
}

func TestGlobalLogFunctions(t *testing.T) {
	// Setup a logger
	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)
	SetGlobalLogger(logger)

	// Test that global functions don't panic
	t.Run("Debug", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Debug("debug message", zap.String("key", "value"))
		})
	})

	t.Run("Info", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Info("info message", zap.Int("count", 42))
		})
	})

	t.Run("Warn", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Warn("warn message", zap.Bool("flag", true))
		})
	})

	t.Run("Error", func(t *testing.T) {
		assert.NotPanics(t, func() {
			Error("error message", zap.Error(nil))
		})
	})
}

func TestContextLogFunctions(t *testing.T) {
	// Setup a logger
	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)
	SetGlobalLogger(logger)

	ctx := context.Background()

	t.Run("DebugContext", func(t *testing.T) {
		assert.NotPanics(t, func() {
			DebugContext(ctx, "debug message", zap.String("key", "value"))
		})
	})

	t.Run("InfoContext", func(t *testing.T) {
		assert.NotPanics(t, func() {
			InfoContext(ctx, "info message", zap.Int("count", 42))
		})
	})

	t.Run("WarnContext", func(t *testing.T) {
		assert.NotPanics(t, func() {
			WarnContext(ctx, "warn message", zap.Bool("flag", true))
		})
	})

	t.Run("ErrorContext", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ErrorContext(ctx, "error message", zap.Error(nil))
		})
	})
}

func TestContextLogFunctions_WithContextFields(t *testing.T) {
	// Setup a logger
	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)
	SetGlobalLogger(logger)

	// Create context with fields
	cf := NewContextFields()
	cf.Set("request_id", "test-123")
	cf.Set("user_id", "user-456")
	ctx := ContextWithFields(context.Background(), cf)

	t.Run("DebugContext with fields", func(t *testing.T) {
		assert.NotPanics(t, func() {
			DebugContext(ctx, "debug message")
		})
	})

	t.Run("InfoContext with fields", func(t *testing.T) {
		assert.NotPanics(t, func() {
			InfoContext(ctx, "info message")
		})
	})

	t.Run("WarnContext with fields", func(t *testing.T) {
		assert.NotPanics(t, func() {
			WarnContext(ctx, "warn message")
		})
	})

	t.Run("ErrorContext with fields", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ErrorContext(ctx, "error message")
		})
	})
}

func TestLogger_Sync(t *testing.T) {
	logger, err := NewLogger(&Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	// Sync should not panic (may return error for stdout/stderr)
	assert.NotPanics(t, func() {
		_ = logger.Sync()
	})
}

func TestLogger_LogMethods(t *testing.T) {
	logger, err := NewLogger(&Config{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: "stdout",
	})
	require.NoError(t, err)

	t.Run("Debug method", func(t *testing.T) {
		assert.NotPanics(t, func() {
			logger.Debug("debug message", zap.String("key", "value"))
		})
	})

	t.Run("Info method", func(t *testing.T) {
		assert.NotPanics(t, func() {
			logger.Info("info message", zap.Int("count", 42))
		})
	})

	t.Run("Warn method", func(t *testing.T) {
		assert.NotPanics(t, func() {
			logger.Warn("warn message", zap.Bool("flag", true))
		})
	})

	t.Run("Error method", func(t *testing.T) {
		assert.NotPanics(t, func() {
			logger.Error("error message", zap.Error(nil))
		})
	})
}

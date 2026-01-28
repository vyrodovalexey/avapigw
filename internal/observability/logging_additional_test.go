package observability

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetGlobalLogger_Concurrent tests concurrent access to GetGlobalLogger.
func TestGetGlobalLogger_Concurrent(t *testing.T) {
	// Not parallel - modifies global state

	// Reset global logger state
	globalMu.Lock()
	globalLogger = nil
	globalMu.Unlock()

	defaultLoggerMu.Lock()
	defaultLoggerVal = nil
	defaultLoggerMu.Unlock()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	loggers := make([]Logger, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			loggers[idx] = GetGlobalLogger()
		}(i)
	}

	wg.Wait()

	// All goroutines should get a non-nil logger
	for i, logger := range loggers {
		assert.NotNil(t, logger, "logger %d should not be nil", i)
	}

	// All loggers should be the same instance (the default logger)
	firstLogger := loggers[0]
	for i, logger := range loggers[1:] {
		assert.Equal(t, firstLogger, logger, "logger %d should be the same as logger 0", i+1)
	}

	// Reset global logger
	SetGlobalLogger(nil)
}

// TestGetGlobalLogger_ConcurrentWithSet tests concurrent GetGlobalLogger and SetGlobalLogger.
func TestGetGlobalLogger_ConcurrentWithSet(t *testing.T) {
	// Not parallel - modifies global state

	// Reset global logger state
	SetGlobalLogger(nil)

	defaultLoggerMu.Lock()
	defaultLoggerVal = nil
	defaultLoggerMu.Unlock()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Create a custom logger
	customLogger, err := NewLogger(LogConfig{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Half the goroutines will get the logger
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			logger := GetGlobalLogger()
			assert.NotNil(t, logger)
		}()
	}

	// Half the goroutines will set the logger
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			SetGlobalLogger(customLogger)
		}()
	}

	wg.Wait()

	// Reset global logger
	SetGlobalLogger(nil)
}

// TestGetGlobalLogger_DefaultLoggerFallback tests the default logger creation fallback.
func TestGetGlobalLogger_DefaultLoggerFallback(t *testing.T) {
	// Not parallel - modifies global state

	// Reset global logger state
	globalMu.Lock()
	globalLogger = nil
	globalMu.Unlock()

	defaultLoggerMu.Lock()
	defaultLoggerVal = nil
	defaultLoggerMu.Unlock()

	// Get the global logger - should create a default logger
	logger := GetGlobalLogger()
	assert.NotNil(t, logger)

	// Getting it again should return the same instance
	logger2 := GetGlobalLogger()
	assert.Equal(t, logger, logger2)

	// Reset global logger
	SetGlobalLogger(nil)
}

// TestGetGlobalLogger_WithSetLogger tests GetGlobalLogger after SetGlobalLogger.
func TestGetGlobalLogger_WithSetLogger(t *testing.T) {
	// Not parallel - modifies global state

	// Create a custom logger
	customLogger, err := NewLogger(LogConfig{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Set the global logger
	SetGlobalLogger(customLogger)

	// Get should return the custom logger
	logger := GetGlobalLogger()
	assert.Equal(t, customLogger, logger)

	// Reset global logger
	SetGlobalLogger(nil)
}

// TestL_Concurrent tests concurrent access to L().
func TestL_Concurrent(t *testing.T) {
	// Not parallel - modifies global state

	// Reset global logger state
	SetGlobalLogger(nil)

	defaultLoggerMu.Lock()
	defaultLoggerVal = nil
	defaultLoggerMu.Unlock()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	loggers := make([]Logger, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			loggers[idx] = L()
		}(i)
	}

	wg.Wait()

	// All goroutines should get a non-nil logger
	for i, logger := range loggers {
		assert.NotNil(t, logger, "logger %d should not be nil", i)
	}

	// Reset global logger
	SetGlobalLogger(nil)
}

// TestSetGlobalLogger_Concurrent tests concurrent SetGlobalLogger calls.
func TestSetGlobalLogger_Concurrent(t *testing.T) {
	// Not parallel - modifies global state

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	loggers := make([]Logger, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		var err error
		loggers[i], err = NewLogger(LogConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		})
		require.NoError(t, err)
	}

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			SetGlobalLogger(loggers[idx])
		}(i)
	}

	wg.Wait()

	// The global logger should be one of the loggers we set
	globalLogger := GetGlobalLogger()
	assert.NotNil(t, globalLogger)

	// Reset global logger
	SetGlobalLogger(nil)
}

// TestNopLogger_Concurrent tests concurrent use of NopLogger.
func TestNopLogger_Concurrent(t *testing.T) {
	t.Parallel()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			logger := NopLogger()
			assert.NotNil(t, logger)

			// Use the logger
			logger.Debug("debug message")
			logger.Info("info message")
			logger.Warn("warn message")
			logger.Error("error message")

			// Create child loggers
			child := logger.With(String("key", "value"))
			assert.NotNil(t, child)
		}()
	}

	wg.Wait()
}

// TestZapLogger_Concurrent tests concurrent use of zapLogger.
func TestZapLogger_Concurrent(t *testing.T) {
	t.Parallel()

	logger, err := NewLogger(LogConfig{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})
	require.NoError(t, err)

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Use the logger
			logger.Debug("debug message", Int("idx", idx))
			logger.Info("info message", Int("idx", idx))
			logger.Warn("warn message", Int("idx", idx))
			logger.Error("error message", Int("idx", idx))

			// Create child loggers
			child := logger.With(String("goroutine", "test"))
			assert.NotNil(t, child)
		}(i)
	}

	wg.Wait()
}

// TestDefaultLoggerVal_DoubleCheckedLocking tests the double-checked locking pattern.
func TestDefaultLoggerVal_DoubleCheckedLocking(t *testing.T) {
	// Not parallel - modifies global state

	// Reset global logger state
	globalMu.Lock()
	globalLogger = nil
	globalMu.Unlock()

	defaultLoggerMu.Lock()
	defaultLoggerVal = nil
	defaultLoggerMu.Unlock()

	// First call should create the default logger
	logger1 := GetGlobalLogger()
	assert.NotNil(t, logger1)

	// Second call should return the same logger (from defaultLoggerVal)
	logger2 := GetGlobalLogger()
	assert.Equal(t, logger1, logger2)

	// Reset global logger
	SetGlobalLogger(nil)
}

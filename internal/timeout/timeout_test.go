// Package timeout provides timeout management for the API Gateway.
package timeout

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTimeout(t *testing.T) {
	tests := []struct {
		name    string
		request time.Duration
		backend time.Duration
		idle    time.Duration
	}{
		{
			name:    "positive values",
			request: 10 * time.Second,
			backend: 20 * time.Second,
			idle:    60 * time.Second,
		},
		{
			name:    "zero values",
			request: 0,
			backend: 0,
			idle:    0,
		},
		{
			name:    "negative values",
			request: -5 * time.Second,
			backend: -10 * time.Second,
			idle:    -30 * time.Second,
		},
		{
			name:    "mixed values",
			request: 5 * time.Second,
			backend: 0,
			idle:    -10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			timeout := NewTimeout(tt.request, tt.backend, tt.idle)

			// Assert
			require.NotNil(t, timeout)
			assert.Equal(t, tt.request, timeout.request)
			assert.Equal(t, tt.backend, timeout.backend)
			assert.Equal(t, tt.idle, timeout.idle)
			// connect, read, write should be zero (not set by NewTimeout)
			assert.Equal(t, time.Duration(0), timeout.connect)
			assert.Equal(t, time.Duration(0), timeout.read)
			assert.Equal(t, time.Duration(0), timeout.write)
		})
	}
}

func TestNewTimeoutWithDefaults(t *testing.T) {
	// Act
	timeout := NewTimeoutWithDefaults()

	// Assert
	require.NotNil(t, timeout)
	assert.Equal(t, 30*time.Second, timeout.request, "request should be 30s")
	assert.Equal(t, 30*time.Second, timeout.backend, "backend should be 30s")
	assert.Equal(t, 120*time.Second, timeout.idle, "idle should be 120s")
	assert.Equal(t, 10*time.Second, timeout.connect, "connect should be 10s")
	assert.Equal(t, 30*time.Second, timeout.read, "read should be 30s")
	assert.Equal(t, 30*time.Second, timeout.write, "write should be 30s")
}

func TestTimeout_RequestContext(t *testing.T) {
	tests := []struct {
		name            string
		request         time.Duration
		expectDeadline  bool
		expectCancelNop bool
	}{
		{
			name:            "positive timeout creates deadline",
			request:         5 * time.Second,
			expectDeadline:  true,
			expectCancelNop: false,
		},
		{
			name:            "zero timeout no deadline",
			request:         0,
			expectDeadline:  false,
			expectCancelNop: true,
		},
		{
			name:            "negative timeout no deadline",
			request:         -5 * time.Second,
			expectDeadline:  false,
			expectCancelNop: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{request: tt.request}
			parentCtx := context.Background()

			// Act
			ctx, cancel := timeout.RequestContext(parentCtx)
			defer cancel()

			// Assert
			_, hasDeadline := ctx.Deadline()
			assert.Equal(t, tt.expectDeadline, hasDeadline)

			if tt.expectDeadline {
				// Verify the deadline is approximately correct
				deadline, _ := ctx.Deadline()
				expectedDeadline := time.Now().Add(tt.request)
				assert.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond)
			}
		})
	}
}

func TestTimeout_RequestContext_Cancellation(t *testing.T) {
	// Arrange
	timeout := &Timeout{request: 50 * time.Millisecond}
	parentCtx := context.Background()

	// Act
	ctx, cancel := timeout.RequestContext(parentCtx)
	defer cancel()

	// Assert - context should be cancelled after timeout
	select {
	case <-ctx.Done():
		assert.Equal(t, context.DeadlineExceeded, ctx.Err())
	case <-time.After(200 * time.Millisecond):
		t.Fatal("context should have been cancelled by timeout")
	}
}

func TestTimeout_BackendContext(t *testing.T) {
	tests := []struct {
		name           string
		backend        time.Duration
		expectDeadline bool
	}{
		{
			name:           "positive timeout creates deadline",
			backend:        5 * time.Second,
			expectDeadline: true,
		},
		{
			name:           "zero timeout no deadline",
			backend:        0,
			expectDeadline: false,
		},
		{
			name:           "negative timeout no deadline",
			backend:        -5 * time.Second,
			expectDeadline: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{backend: tt.backend}
			parentCtx := context.Background()

			// Act
			ctx, cancel := timeout.BackendContext(parentCtx)
			defer cancel()

			// Assert
			_, hasDeadline := ctx.Deadline()
			assert.Equal(t, tt.expectDeadline, hasDeadline)

			if tt.expectDeadline {
				deadline, _ := ctx.Deadline()
				expectedDeadline := time.Now().Add(tt.backend)
				assert.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond)
			}
		})
	}
}

func TestTimeout_BackendContext_Cancellation(t *testing.T) {
	// Arrange
	timeout := &Timeout{backend: 50 * time.Millisecond}
	parentCtx := context.Background()

	// Act
	ctx, cancel := timeout.BackendContext(parentCtx)
	defer cancel()

	// Assert
	select {
	case <-ctx.Done():
		assert.Equal(t, context.DeadlineExceeded, ctx.Err())
	case <-time.After(200 * time.Millisecond):
		t.Fatal("context should have been cancelled by timeout")
	}
}

func TestTimeout_ConnectContext(t *testing.T) {
	tests := []struct {
		name           string
		connect        time.Duration
		expectDeadline bool
	}{
		{
			name:           "positive timeout creates deadline",
			connect:        5 * time.Second,
			expectDeadline: true,
		},
		{
			name:           "zero timeout no deadline",
			connect:        0,
			expectDeadline: false,
		},
		{
			name:           "negative timeout no deadline",
			connect:        -5 * time.Second,
			expectDeadline: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{connect: tt.connect}
			parentCtx := context.Background()

			// Act
			ctx, cancel := timeout.ConnectContext(parentCtx)
			defer cancel()

			// Assert
			_, hasDeadline := ctx.Deadline()
			assert.Equal(t, tt.expectDeadline, hasDeadline)

			if tt.expectDeadline {
				deadline, _ := ctx.Deadline()
				expectedDeadline := time.Now().Add(tt.connect)
				assert.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond)
			}
		})
	}
}

func TestTimeout_ConnectContext_Cancellation(t *testing.T) {
	// Arrange
	timeout := &Timeout{connect: 50 * time.Millisecond}
	parentCtx := context.Background()

	// Act
	ctx, cancel := timeout.ConnectContext(parentCtx)
	defer cancel()

	// Assert
	select {
	case <-ctx.Done():
		assert.Equal(t, context.DeadlineExceeded, ctx.Err())
	case <-time.After(200 * time.Millisecond):
		t.Fatal("context should have been cancelled by timeout")
	}
}

func TestTimeout_Getters(t *testing.T) {
	// Arrange
	timeout := &Timeout{
		request: 10 * time.Second,
		backend: 20 * time.Second,
		idle:    30 * time.Second,
		connect: 5 * time.Second,
		read:    15 * time.Second,
		write:   25 * time.Second,
	}

	// Act & Assert
	assert.Equal(t, 10*time.Second, timeout.Request())
	assert.Equal(t, 20*time.Second, timeout.Backend())
	assert.Equal(t, 30*time.Second, timeout.Idle())
	assert.Equal(t, 5*time.Second, timeout.Connect())
	assert.Equal(t, 15*time.Second, timeout.Read())
	assert.Equal(t, 25*time.Second, timeout.Write())
}

func TestTimeout_Getters_ZeroValues(t *testing.T) {
	// Arrange
	timeout := &Timeout{}

	// Act & Assert
	assert.Equal(t, time.Duration(0), timeout.Request())
	assert.Equal(t, time.Duration(0), timeout.Backend())
	assert.Equal(t, time.Duration(0), timeout.Idle())
	assert.Equal(t, time.Duration(0), timeout.Connect())
	assert.Equal(t, time.Duration(0), timeout.Read())
	assert.Equal(t, time.Duration(0), timeout.Write())
}

func TestTimeout_WithRequest(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"positive duration", 10 * time.Second},
		{"zero duration", 0},
		{"negative duration", -5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{}

			// Act
			result := timeout.WithRequest(tt.duration)

			// Assert
			assert.Same(t, timeout, result, "should return self for chaining")
			assert.Equal(t, tt.duration, timeout.request)
		})
	}
}

func TestTimeout_WithBackend(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"positive duration", 20 * time.Second},
		{"zero duration", 0},
		{"negative duration", -10 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{}

			// Act
			result := timeout.WithBackend(tt.duration)

			// Assert
			assert.Same(t, timeout, result, "should return self for chaining")
			assert.Equal(t, tt.duration, timeout.backend)
		})
	}
}

func TestTimeout_WithIdle(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"positive duration", 60 * time.Second},
		{"zero duration", 0},
		{"negative duration", -30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{}

			// Act
			result := timeout.WithIdle(tt.duration)

			// Assert
			assert.Same(t, timeout, result, "should return self for chaining")
			assert.Equal(t, tt.duration, timeout.idle)
		})
	}
}

func TestTimeout_WithConnect(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"positive duration", 5 * time.Second},
		{"zero duration", 0},
		{"negative duration", -2 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{}

			// Act
			result := timeout.WithConnect(tt.duration)

			// Assert
			assert.Same(t, timeout, result, "should return self for chaining")
			assert.Equal(t, tt.duration, timeout.connect)
		})
	}
}

func TestTimeout_WithRead(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"positive duration", 15 * time.Second},
		{"zero duration", 0},
		{"negative duration", -7 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{}

			// Act
			result := timeout.WithRead(tt.duration)

			// Assert
			assert.Same(t, timeout, result, "should return self for chaining")
			assert.Equal(t, tt.duration, timeout.read)
		})
	}
}

func TestTimeout_WithWrite(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"positive duration", 25 * time.Second},
		{"zero duration", 0},
		{"negative duration", -12 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			timeout := &Timeout{}

			// Act
			result := timeout.WithWrite(tt.duration)

			// Assert
			assert.Same(t, timeout, result, "should return self for chaining")
			assert.Equal(t, tt.duration, timeout.write)
		})
	}
}

func TestTimeout_WithMethods_Chaining(t *testing.T) {
	// Arrange & Act
	timeout := (&Timeout{}).
		WithRequest(10 * time.Second).
		WithBackend(20 * time.Second).
		WithIdle(60 * time.Second).
		WithConnect(5 * time.Second).
		WithRead(15 * time.Second).
		WithWrite(25 * time.Second)

	// Assert
	assert.Equal(t, 10*time.Second, timeout.Request())
	assert.Equal(t, 20*time.Second, timeout.Backend())
	assert.Equal(t, 60*time.Second, timeout.Idle())
	assert.Equal(t, 5*time.Second, timeout.Connect())
	assert.Equal(t, 15*time.Second, timeout.Read())
	assert.Equal(t, 25*time.Second, timeout.Write())
}

func TestDefaultConfig(t *testing.T) {
	// Act
	cfg := DefaultConfig()

	// Assert
	require.NotNil(t, cfg)
	assert.Equal(t, 30*time.Second, cfg.Request, "Request should be 30s")
	assert.Equal(t, 30*time.Second, cfg.Backend, "Backend should be 30s")
	assert.Equal(t, 120*time.Second, cfg.Idle, "Idle should be 120s")
	assert.Equal(t, 10*time.Second, cfg.Connect, "Connect should be 10s")
	assert.Equal(t, 30*time.Second, cfg.Read, "Read should be 30s")
	assert.Equal(t, 30*time.Second, cfg.Write, "Write should be 30s")
}

func TestNewTimeoutFromConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         *Config
		expectedResult *Timeout
	}{
		{
			name: "valid config",
			config: &Config{
				Request: 10 * time.Second,
				Backend: 20 * time.Second,
				Idle:    60 * time.Second,
				Connect: 5 * time.Second,
				Read:    15 * time.Second,
				Write:   25 * time.Second,
			},
			expectedResult: &Timeout{
				request: 10 * time.Second,
				backend: 20 * time.Second,
				idle:    60 * time.Second,
				connect: 5 * time.Second,
				read:    15 * time.Second,
				write:   25 * time.Second,
			},
		},
		{
			name:   "nil config uses defaults",
			config: nil,
			expectedResult: &Timeout{
				request: 30 * time.Second,
				backend: 30 * time.Second,
				idle:    120 * time.Second,
				connect: 10 * time.Second,
				read:    30 * time.Second,
				write:   30 * time.Second,
			},
		},
		{
			name: "zero values config",
			config: &Config{
				Request: 0,
				Backend: 0,
				Idle:    0,
				Connect: 0,
				Read:    0,
				Write:   0,
			},
			expectedResult: &Timeout{
				request: 0,
				backend: 0,
				idle:    0,
				connect: 0,
				read:    0,
				write:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result := NewTimeoutFromConfig(tt.config)

			// Assert
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedResult.request, result.request)
			assert.Equal(t, tt.expectedResult.backend, result.backend)
			assert.Equal(t, tt.expectedResult.idle, result.idle)
			assert.Equal(t, tt.expectedResult.connect, result.connect)
			assert.Equal(t, tt.expectedResult.read, result.read)
			assert.Equal(t, tt.expectedResult.write, result.write)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected *Config
	}{
		{
			name: "all zero values should set defaults",
			config: &Config{
				Request: 0,
				Backend: 0,
				Idle:    0,
				Connect: 0,
				Read:    0,
				Write:   0,
			},
			expected: &Config{
				Request: 30 * time.Second,
				Backend: 30 * time.Second,
				Idle:    120 * time.Second,
				Connect: 10 * time.Second,
				Read:    30 * time.Second,
				Write:   30 * time.Second,
			},
		},
		{
			name: "all negative values should set defaults",
			config: &Config{
				Request: -10 * time.Second,
				Backend: -20 * time.Second,
				Idle:    -60 * time.Second,
				Connect: -5 * time.Second,
				Read:    -15 * time.Second,
				Write:   -25 * time.Second,
			},
			expected: &Config{
				Request: 30 * time.Second,
				Backend: 30 * time.Second,
				Idle:    120 * time.Second,
				Connect: 10 * time.Second,
				Read:    30 * time.Second,
				Write:   30 * time.Second,
			},
		},
		{
			name: "valid values should be kept",
			config: &Config{
				Request: 10 * time.Second,
				Backend: 20 * time.Second,
				Idle:    60 * time.Second,
				Connect: 5 * time.Second,
				Read:    15 * time.Second,
				Write:   25 * time.Second,
			},
			expected: &Config{
				Request: 10 * time.Second,
				Backend: 20 * time.Second,
				Idle:    60 * time.Second,
				Connect: 5 * time.Second,
				Read:    15 * time.Second,
				Write:   25 * time.Second,
			},
		},
		{
			name: "partial invalid values",
			config: &Config{
				Request: 10 * time.Second,  // valid
				Backend: 0,                 // invalid
				Idle:    -30 * time.Second, // invalid
				Connect: 5 * time.Second,   // valid
				Read:    0,                 // invalid
				Write:   25 * time.Second,  // valid
			},
			expected: &Config{
				Request: 10 * time.Second,
				Backend: 30 * time.Second,  // default
				Idle:    120 * time.Second, // default
				Connect: 5 * time.Second,
				Read:    30 * time.Second, // default
				Write:   25 * time.Second,
			},
		},
		{
			name: "minimum positive values should be kept",
			config: &Config{
				Request: 1 * time.Nanosecond,
				Backend: 1 * time.Nanosecond,
				Idle:    1 * time.Nanosecond,
				Connect: 1 * time.Nanosecond,
				Read:    1 * time.Nanosecond,
				Write:   1 * time.Nanosecond,
			},
			expected: &Config{
				Request: 1 * time.Nanosecond,
				Backend: 1 * time.Nanosecond,
				Idle:    1 * time.Nanosecond,
				Connect: 1 * time.Nanosecond,
				Read:    1 * time.Nanosecond,
				Write:   1 * time.Nanosecond,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			tt.config.Validate()

			// Assert
			assert.Equal(t, tt.expected.Request, tt.config.Request)
			assert.Equal(t, tt.expected.Backend, tt.config.Backend)
			assert.Equal(t, tt.expected.Idle, tt.config.Idle)
			assert.Equal(t, tt.expected.Connect, tt.config.Connect)
			assert.Equal(t, tt.expected.Read, tt.config.Read)
			assert.Equal(t, tt.expected.Write, tt.config.Write)
		})
	}
}

func TestTimeoutError_Error(t *testing.T) {
	tests := []struct {
		name     string
		phase    string
		timeout  time.Duration
		expected string
	}{
		{
			name:     "request timeout",
			phase:    "request",
			timeout:  30 * time.Second,
			expected: "request timeout after 30s",
		},
		{
			name:     "backend timeout",
			phase:    "backend",
			timeout:  20 * time.Second,
			expected: "backend timeout after 20s",
		},
		{
			name:     "connect timeout",
			phase:    "connect",
			timeout:  5 * time.Second,
			expected: "connect timeout after 5s",
		},
		{
			name:     "read timeout",
			phase:    "read",
			timeout:  15 * time.Second,
			expected: "read timeout after 15s",
		},
		{
			name:     "write timeout",
			phase:    "write",
			timeout:  25 * time.Second,
			expected: "write timeout after 25s",
		},
		{
			name:     "idle timeout",
			phase:    "idle",
			timeout:  120 * time.Second,
			expected: "idle timeout after 2m0s",
		},
		{
			name:     "millisecond timeout",
			phase:    "connect",
			timeout:  500 * time.Millisecond,
			expected: "connect timeout after 500ms",
		},
		{
			name:     "empty phase",
			phase:    "",
			timeout:  10 * time.Second,
			expected: " timeout after 10s",
		},
		{
			name:     "zero timeout",
			phase:    "request",
			timeout:  0,
			expected: "request timeout after 0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			err := &TimeoutError{
				Phase:   tt.phase,
				Timeout: tt.timeout,
			}

			// Act
			result := err.Error()

			// Assert
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "TimeoutError returns true",
			err:      &TimeoutError{Phase: "request", Timeout: 30 * time.Second},
			expected: true,
		},
		{
			name:     "TimeoutError with empty phase returns true",
			err:      &TimeoutError{Phase: "", Timeout: 0},
			expected: true,
		},
		{
			name:     "generic error returns false",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "nil error returns false",
			err:      nil,
			expected: false,
		},
		{
			name:     "context.DeadlineExceeded returns false",
			err:      context.DeadlineExceeded,
			expected: false,
		},
		{
			name:     "context.Canceled returns false",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "wrapped error returns false",
			err:      errors.New("wrapped: timeout"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result := IsTimeout(tt.err)

			// Assert
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTimeoutError_ImplementsError(t *testing.T) {
	// Verify TimeoutError implements the error interface
	var _ error = &TimeoutError{}
}

func TestTimeout_ContextMethods_WithParentContext(t *testing.T) {
	// Test that context methods properly inherit from parent context
	t.Run("RequestContext inherits parent values", func(t *testing.T) {
		// Arrange
		type ctxKey string
		key := ctxKey("test-key")
		parentCtx := context.WithValue(context.Background(), key, "test-value")
		timeout := &Timeout{request: 5 * time.Second}

		// Act
		ctx, cancel := timeout.RequestContext(parentCtx)
		defer cancel()

		// Assert
		assert.Equal(t, "test-value", ctx.Value(key))
	})

	t.Run("BackendContext inherits parent values", func(t *testing.T) {
		// Arrange
		type ctxKey string
		key := ctxKey("test-key")
		parentCtx := context.WithValue(context.Background(), key, "test-value")
		timeout := &Timeout{backend: 5 * time.Second}

		// Act
		ctx, cancel := timeout.BackendContext(parentCtx)
		defer cancel()

		// Assert
		assert.Equal(t, "test-value", ctx.Value(key))
	})

	t.Run("ConnectContext inherits parent values", func(t *testing.T) {
		// Arrange
		type ctxKey string
		key := ctxKey("test-key")
		parentCtx := context.WithValue(context.Background(), key, "test-value")
		timeout := &Timeout{connect: 5 * time.Second}

		// Act
		ctx, cancel := timeout.ConnectContext(parentCtx)
		defer cancel()

		// Assert
		assert.Equal(t, "test-value", ctx.Value(key))
	})
}

func TestTimeout_ContextMethods_CancelFunctionWorks(t *testing.T) {
	t.Run("RequestContext cancel function works", func(t *testing.T) {
		// Arrange
		timeout := &Timeout{request: 5 * time.Second}

		// Act
		ctx, cancel := timeout.RequestContext(context.Background())
		cancel()

		// Assert
		assert.Error(t, ctx.Err())
		assert.Equal(t, context.Canceled, ctx.Err())
	})

	t.Run("BackendContext cancel function works", func(t *testing.T) {
		// Arrange
		timeout := &Timeout{backend: 5 * time.Second}

		// Act
		ctx, cancel := timeout.BackendContext(context.Background())
		cancel()

		// Assert
		assert.Error(t, ctx.Err())
		assert.Equal(t, context.Canceled, ctx.Err())
	})

	t.Run("ConnectContext cancel function works", func(t *testing.T) {
		// Arrange
		timeout := &Timeout{connect: 5 * time.Second}

		// Act
		ctx, cancel := timeout.ConnectContext(context.Background())
		cancel()

		// Assert
		assert.Error(t, ctx.Err())
		assert.Equal(t, context.Canceled, ctx.Err())
	})
}

func TestTimeout_ContextMethods_NopCancelFunction(t *testing.T) {
	// Test that nop cancel functions don't panic
	t.Run("RequestContext nop cancel doesn't panic", func(t *testing.T) {
		timeout := &Timeout{request: 0}
		ctx, cancel := timeout.RequestContext(context.Background())
		assert.NotPanics(t, func() { cancel() })
		assert.NoError(t, ctx.Err())
	})

	t.Run("BackendContext nop cancel doesn't panic", func(t *testing.T) {
		timeout := &Timeout{backend: 0}
		ctx, cancel := timeout.BackendContext(context.Background())
		assert.NotPanics(t, func() { cancel() })
		assert.NoError(t, ctx.Err())
	})

	t.Run("ConnectContext nop cancel doesn't panic", func(t *testing.T) {
		timeout := &Timeout{connect: 0}
		ctx, cancel := timeout.ConnectContext(context.Background())
		assert.NotPanics(t, func() { cancel() })
		assert.NoError(t, ctx.Err())
	})
}

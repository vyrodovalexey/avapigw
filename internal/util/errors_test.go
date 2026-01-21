package util

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		field          string
		message        string
		cause          error
		expectedString string
	}{
		{
			name:           "with field",
			field:          "spec.listeners",
			message:        "at least one listener required",
			cause:          nil,
			expectedString: "config error at spec.listeners: at least one listener required",
		},
		{
			name:           "without field",
			field:          "",
			message:        "invalid configuration",
			cause:          nil,
			expectedString: "config error: invalid configuration",
		},
		{
			name:           "with cause",
			field:          "spec.port",
			message:        "invalid port",
			cause:          errors.New("port out of range"),
			expectedString: "config error at spec.port: invalid port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var err *ConfigError
			if tt.cause != nil {
				err = NewConfigErrorWithCause(tt.field, tt.message, tt.cause)
			} else {
				err = NewConfigError(tt.field, tt.message)
			}

			assert.Equal(t, tt.expectedString, err.Error())
			assert.Equal(t, tt.field, err.Field)
			assert.Equal(t, tt.message, err.Message)
			assert.Equal(t, tt.cause, err.Unwrap())
		})
	}
}

func TestConfigError_Is(t *testing.T) {
	t.Parallel()

	err := NewConfigError("field", "message")

	assert.True(t, err.Is(&ConfigError{}))
	assert.False(t, err.Is(errors.New("other error")))

	errWithCause := NewConfigErrorWithCause("field", "message", ErrInvalidInput)
	assert.True(t, errors.Is(errWithCause, ErrInvalidInput))
}

func TestValidationError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		message        string
		fields         map[string]string
		expectedString string
	}{
		{
			name:           "without fields",
			message:        "validation failed",
			fields:         nil,
			expectedString: "validation error: validation failed",
		},
		{
			name:           "with empty fields",
			message:        "validation failed",
			fields:         map[string]string{},
			expectedString: "validation error: validation failed",
		},
		{
			name:    "with fields",
			message: "validation failed",
			fields:  map[string]string{"name": "required"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var err *ValidationError
			if tt.fields != nil && len(tt.fields) > 0 {
				err = NewValidationErrorWithFields(tt.message, tt.fields)
				assert.Contains(t, err.Error(), "validation error:")
				assert.Contains(t, err.Error(), "fields:")
			} else {
				err = NewValidationError(tt.message)
				assert.Equal(t, tt.expectedString, err.Error())
			}

			assert.Equal(t, tt.message, err.Message)
		})
	}
}

func TestValidationError_AddField(t *testing.T) {
	t.Parallel()

	err := NewValidationError("validation failed")
	err.AddField("name", "required")
	err.AddField("email", "invalid format")

	assert.Equal(t, "required", err.Fields["name"])
	assert.Equal(t, "invalid format", err.Fields["email"])
}

func TestValidationError_AddField_NilFields(t *testing.T) {
	t.Parallel()

	err := &ValidationError{Message: "test"}
	err.AddField("name", "required")

	assert.NotNil(t, err.Fields)
	assert.Equal(t, "required", err.Fields["name"])
}

func TestValidationError_Is(t *testing.T) {
	t.Parallel()

	err := NewValidationError("test")
	assert.True(t, err.Is(&ValidationError{}))
	assert.False(t, err.Is(errors.New("other")))
}

func TestRouteNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		expectedString string
	}{
		{
			name:           "GET request",
			method:         "GET",
			path:           "/api/users",
			expectedString: "no route found for GET /api/users",
		},
		{
			name:           "POST request",
			method:         "POST",
			path:           "/api/orders",
			expectedString: "no route found for POST /api/orders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewRouteNotFoundError(tt.method, tt.path)
			assert.Equal(t, tt.expectedString, err.Error())
			assert.Equal(t, tt.method, err.Method)
			assert.Equal(t, tt.path, err.Path)
		})
	}
}

func TestRouteNotFoundError_Is(t *testing.T) {
	t.Parallel()

	err := NewRouteNotFoundError("GET", "/test")

	assert.True(t, err.Is(ErrNotFound))
	assert.True(t, err.Is(&RouteNotFoundError{}))
	assert.False(t, err.Is(errors.New("other")))
}

func TestBackendError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		backend        string
		message        string
		cause          error
		expectedString string
	}{
		{
			name:           "without cause",
			backend:        "user-service",
			message:        "connection refused",
			cause:          nil,
			expectedString: "backend user-service error: connection refused",
		},
		{
			name:           "with cause",
			backend:        "order-service",
			message:        "timeout",
			cause:          errors.New("context deadline exceeded"),
			expectedString: "backend order-service error: timeout: context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var err *BackendError
			if tt.cause != nil {
				err = NewBackendErrorWithCause(tt.backend, tt.message, tt.cause)
			} else {
				err = NewBackendError(tt.backend, tt.message)
			}

			assert.Equal(t, tt.expectedString, err.Error())
			assert.Equal(t, tt.backend, err.Backend)
			assert.Equal(t, tt.message, err.Message)
			assert.Equal(t, tt.cause, err.Unwrap())
		})
	}
}

func TestBackendError_Is(t *testing.T) {
	t.Parallel()

	err := NewBackendError("test", "error")
	assert.True(t, err.Is(ErrBackendUnavail))
	assert.True(t, err.Is(&BackendError{}))
	assert.False(t, err.Is(errors.New("other")))

	errWithCause := NewBackendErrorWithCause("test", "error", ErrTimeout)
	assert.True(t, errors.Is(errWithCause, ErrTimeout))
}

func TestTimeoutError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		operation      string
		duration       time.Duration
		expectedString string
	}{
		{
			name:           "proxy timeout",
			operation:      "proxy request",
			duration:       30 * time.Second,
			expectedString: "timeout after 30s during proxy request",
		},
		{
			name:           "health check timeout",
			operation:      "health check",
			duration:       5 * time.Second,
			expectedString: "timeout after 5s during health check",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewTimeoutError(tt.operation, tt.duration)
			assert.Equal(t, tt.expectedString, err.Error())
			assert.Equal(t, tt.operation, err.Operation)
			assert.Equal(t, tt.duration, err.Duration)
		})
	}
}

func TestTimeoutError_Is(t *testing.T) {
	t.Parallel()

	err := NewTimeoutError("test", time.Second)
	assert.True(t, err.Is(ErrTimeout))
	assert.True(t, err.Is(&TimeoutError{}))
	assert.False(t, err.Is(errors.New("other")))
}

func TestRateLimitError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		limit      int
		retryAfter time.Duration
	}{
		{
			name:       "standard limit",
			limit:      100,
			retryAfter: time.Second,
		},
		{
			name:       "high limit",
			limit:      10000,
			retryAfter: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewRateLimitError(tt.limit, tt.retryAfter)
			assert.Contains(t, err.Error(), "rate limit exceeded")
			assert.Equal(t, tt.limit, err.Limit)
			assert.Equal(t, tt.retryAfter, err.RetryAfter)
		})
	}
}

func TestRateLimitError_Is(t *testing.T) {
	t.Parallel()

	err := NewRateLimitError(100, time.Second)
	assert.True(t, err.Is(ErrRateLimited))
	assert.True(t, err.Is(&RateLimitError{}))
	assert.False(t, err.Is(errors.New("other")))
}

func TestCircuitOpenError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cbName         string
		state          string
		expectedString string
	}{
		{
			name:           "open state",
			cbName:         "user-service",
			state:          "open",
			expectedString: "circuit breaker user-service is open",
		},
		{
			name:           "half-open state",
			cbName:         "order-service",
			state:          "half-open",
			expectedString: "circuit breaker order-service is half-open",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewCircuitOpenError(tt.cbName, tt.state)
			assert.Equal(t, tt.expectedString, err.Error())
			assert.Equal(t, tt.cbName, err.Name)
			assert.Equal(t, tt.state, err.State)
		})
	}
}

func TestCircuitOpenError_Is(t *testing.T) {
	t.Parallel()

	err := NewCircuitOpenError("test", "open")
	assert.True(t, err.Is(ErrCircuitOpen))
	assert.True(t, err.Is(&CircuitOpenError{}))
	assert.False(t, err.Is(errors.New("other")))
}

func TestWrapError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		message  string
		expected string
	}{
		{
			name:     "wrap error",
			err:      errors.New("original error"),
			message:  "context",
			expected: "context: original error",
		},
		{
			name:     "nil error",
			err:      nil,
			message:  "context",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := WrapError(tt.err, tt.message)
			if tt.err == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected, result.Error())
			}
		})
	}
}

func TestIsRetryable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "timeout error",
			err:      ErrTimeout,
			expected: true,
		},
		{
			name:     "backend unavailable",
			err:      ErrBackendUnavail,
			expected: true,
		},
		{
			name:     "timeout error type",
			err:      NewTimeoutError("test", time.Second),
			expected: true,
		},
		{
			name:     "backend error type",
			err:      NewBackendError("test", "error"),
			expected: true,
		},
		{
			name:     "not found error",
			err:      ErrNotFound,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("generic"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsRetryable(tt.err))
		})
	}
}

func TestIsClientError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "not found",
			err:      ErrNotFound,
			expected: true,
		},
		{
			name:     "invalid input",
			err:      ErrInvalidInput,
			expected: true,
		},
		{
			name:     "rate limited",
			err:      ErrRateLimited,
			expected: true,
		},
		{
			name:     "timeout",
			err:      ErrTimeout,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("generic"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsClientError(tt.err))
		})
	}
}

func TestIsServerError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "backend unavailable",
			err:      ErrBackendUnavail,
			expected: true,
		},
		{
			name:     "circuit open",
			err:      ErrCircuitOpen,
			expected: true,
		},
		{
			name:     "timeout",
			err:      ErrTimeout,
			expected: true,
		},
		{
			name:     "not found",
			err:      ErrNotFound,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("generic"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsServerError(tt.err))
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	// Verify sentinel errors are distinct
	sentinelErrors := []error{
		ErrNotFound,
		ErrInvalidInput,
		ErrTimeout,
		ErrCircuitOpen,
		ErrRateLimited,
		ErrBackendUnavail,
		ErrConfigInvalid,
	}

	for i, err1 := range sentinelErrors {
		for j, err2 := range sentinelErrors {
			if i == j {
				assert.True(t, errors.Is(err1, err2))
			} else {
				assert.False(t, errors.Is(err1, err2))
			}
		}
	}
}

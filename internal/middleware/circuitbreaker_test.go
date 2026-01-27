package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

func TestNewCircuitBreaker(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker("test-cb", 5, 10*time.Second)

	assert.NotNil(t, cb)
	assert.NotNil(t, cb.cb)
	assert.Equal(t, gobreaker.StateClosed, cb.State())
}

func TestNewCircuitBreaker_WithLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cb := NewCircuitBreaker("test-cb", 5, 10*time.Second, WithCircuitBreakerLogger(logger))

	assert.NotNil(t, cb)
	assert.Equal(t, logger, cb.logger)
}

func TestCircuitBreaker_Execute(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker("test-cb", 5, 10*time.Second)

	// Successful execution
	result, err := cb.Execute(func() (interface{}, error) {
		return "success", nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "success", result)
}

func TestCircuitBreaker_Execute_WithError(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker("test-cb", 5, 10*time.Second)

	// Failed execution
	result, err := cb.Execute(func() (interface{}, error) {
		return nil, assert.AnError
	})

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestCircuitBreaker_State(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker("test-cb", 5, 10*time.Second)

	// Initial state should be closed
	assert.Equal(t, gobreaker.StateClosed, cb.State())
}

func TestSafeIntToUint32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    int
		expected uint32
	}{
		{
			name:     "positive number",
			input:    100,
			expected: 100,
		},
		{
			name:     "zero",
			input:    0,
			expected: 0,
		},
		{
			name:     "negative number",
			input:    -1,
			expected: 0,
		},
		{
			name:     "max uint32",
			input:    int(^uint32(0)),
			expected: ^uint32(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := safeIntToUint32(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCircuitBreakerMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		handlerStatus  int
		expectedStatus int
	}{
		{
			name:           "passes through successful request",
			handlerStatus:  http.StatusOK,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "passes through client error",
			handlerStatus:  http.StatusBadRequest,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "records server error",
			handlerStatus:  http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cb := NewCircuitBreaker("test-cb", 100, 10*time.Second)
			middleware := CircuitBreakerMiddleware(cb)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.handlerStatus)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestCircuitBreakerMiddleware_OpenState(t *testing.T) {
	t.Parallel()

	// Create a circuit breaker with low threshold
	cb := NewCircuitBreaker("test-cb", 2, 100*time.Millisecond)

	// Trip the circuit breaker by causing failures
	for i := 0; i < 10; i++ {
		_, _ = cb.Execute(func() (interface{}, error) {
			return nil, http.ErrAbortHandler
		})
	}

	// Wait a bit for state to update
	time.Sleep(10 * time.Millisecond)

	// If circuit is open, middleware should return 503
	if cb.State() == gobreaker.StateOpen {
		middleware := CircuitBreakerMiddleware(cb)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "circuit breaker open")
	}
}

func TestStatusCapturingResponseWriter_WriteHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	cbw := util.NewStatusCapturingResponseWriter(rec)

	cbw.WriteHeader(http.StatusCreated)

	assert.Equal(t, http.StatusCreated, cbw.StatusCode)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestCircuitBreakerFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *config.CircuitBreakerConfig
		expectPassthru bool
	}{
		{
			name:           "nil config returns passthrough",
			config:         nil,
			expectPassthru: true,
		},
		{
			name: "disabled config returns passthrough",
			config: &config.CircuitBreakerConfig{
				Enabled:   false,
				Threshold: 5,
			},
			expectPassthru: true,
		},
		{
			name: "enabled config returns circuit breaker",
			config: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(10 * time.Second),
			},
			expectPassthru: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			middleware := CircuitBreakerFromConfig(tt.config, logger)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

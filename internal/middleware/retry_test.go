package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
)

func TestDefaultRetryConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultRetryConfig()

	assert.Equal(t, 3, cfg.Attempts)
	assert.Equal(t, 10*time.Second, cfg.PerTryTimeout)
	assert.Contains(t, cfg.RetryOn, "5xx")
	assert.Equal(t, 100*time.Millisecond, cfg.BackoffBase)
	assert.Equal(t, 10*time.Second, cfg.BackoffMax)
}

func TestRetry_SuccessfulRequest(t *testing.T) {
	t.Parallel()

	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"5xx"},
		BackoffBase: 1 * time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	middleware := Retry(cfg, logger)

	callCount := 0
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, callCount) // Should only be called once
	assert.Equal(t, "success", rec.Body.String())
}

func TestRetry_RetriesOn5xx(t *testing.T) {
	t.Parallel()

	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"5xx"},
		BackoffBase: 1 * time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	middleware := Retry(cfg, logger)

	callCount := 0
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 3, callCount) // Should be called 3 times
}

func TestRetry_ExhaustsRetries(t *testing.T) {
	t.Parallel()

	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"5xx"},
		BackoffBase: 1 * time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	middleware := Retry(cfg, logger)

	callCount := 0
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Equal(t, 3, callCount) // Should be called 3 times
	assert.Contains(t, rec.Body.String(), "all retries exhausted")
}

func TestRetry_DoesNotRetryOn4xx(t *testing.T) {
	t.Parallel()

	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"5xx"},
		BackoffBase: 1 * time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	middleware := Retry(cfg, logger)

	callCount := 0
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, 1, callCount) // Should only be called once
}

func TestRetry_RetriesOnRetriable4xx(t *testing.T) {
	t.Parallel()

	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"retriable-4xx"},
		BackoffBase: 1 * time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	middleware := Retry(cfg, logger)

	callCount := 0
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 2 {
			w.WriteHeader(http.StatusTooManyRequests) // 429
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 2, callCount)
}

func TestRetry_PreservesRequestBody(t *testing.T) {
	t.Parallel()

	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"5xx"},
		BackoffBase: 1 * time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	middleware := Retry(cfg, logger)

	callCount := 0
	var capturedBodies []string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		capturedBodies = append(capturedBodies, string(body))
		if callCount < 2 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("request body"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 2, callCount)
	// Body should be preserved across retries
	for _, body := range capturedBodies {
		assert.Equal(t, "request body", body)
	}
}

func TestShouldRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		retryOn  []string
		expected bool
	}{
		{
			name:     "5xx matches 500",
			status:   500,
			retryOn:  []string{"5xx"},
			expected: true,
		},
		{
			name:     "5xx matches 503",
			status:   503,
			retryOn:  []string{"5xx"},
			expected: true,
		},
		{
			name:     "5xx does not match 400",
			status:   400,
			retryOn:  []string{"5xx"},
			expected: false,
		},
		{
			name:     "retriable-4xx matches 429",
			status:   429,
			retryOn:  []string{"retriable-4xx"},
			expected: true,
		},
		{
			name:     "retriable-4xx matches 408",
			status:   408,
			retryOn:  []string{"retriable-4xx"},
			expected: true,
		},
		{
			name:     "retriable-4xx does not match 404",
			status:   404,
			retryOn:  []string{"retriable-4xx"},
			expected: false,
		},
		{
			name:     "empty retryOn",
			status:   500,
			retryOn:  []string{},
			expected: false,
		},
		{
			name:     "unknown condition",
			status:   500,
			retryOn:  []string{"unknown"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := shouldRetry(tt.status, tt.retryOn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchRetryCondition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    int
		condition string
		expected  bool
	}{
		{
			name:      "5xx matches 500",
			status:    500,
			condition: "5xx",
			expected:  true,
		},
		{
			name:      "5xx matches 599",
			status:    599,
			condition: "5xx",
			expected:  true,
		},
		{
			name:      "5xx does not match 600",
			status:    600,
			condition: "5xx",
			expected:  false,
		},
		{
			name:      "retriable-4xx matches 408",
			status:    408,
			condition: "retriable-4xx",
			expected:  true,
		},
		{
			name:      "retriable-4xx matches 429",
			status:    429,
			condition: "retriable-4xx",
			expected:  true,
		},
		{
			name:      "retriable-4xx does not match 400",
			status:    400,
			condition: "retriable-4xx",
			expected:  false,
		},
		{
			name:      "unknown condition",
			status:    500,
			condition: "unknown",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := matchRetryCondition(tt.status, tt.condition)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateBackoff(t *testing.T) {
	t.Parallel()

	base := 100 * time.Millisecond
	maxBackoff := 10 * time.Second
	jitter := retry.DefaultJitterFactor

	// First attempt
	backoff0 := retry.CalculateBackoff(0, base, maxBackoff, jitter)
	assert.GreaterOrEqual(t, backoff0, base)
	assert.LessOrEqual(t, backoff0, base+base/4) // With jitter

	// Second attempt (should be roughly 2x)
	backoff1 := retry.CalculateBackoff(1, base, maxBackoff, jitter)
	assert.GreaterOrEqual(t, backoff1, 2*base)

	// High attempt should be capped at max
	backoff10 := retry.CalculateBackoff(10, base, maxBackoff, jitter)
	assert.LessOrEqual(t, backoff10, maxBackoff)
}

func TestReadRequestBodyWithLimit(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	tests := []struct {
		name      string
		body      io.Reader
		maxSize   int64
		expected  []byte
		canRetry  bool
		nilResult bool
	}{
		{
			name:     "reads body within limit",
			body:     strings.NewReader("test body"),
			maxSize:  1024,
			expected: []byte("test body"),
			canRetry: true,
		},
		{
			name:     "nil body (becomes http.NoBody)",
			body:     nil,
			maxSize:  1024,
			expected: []byte{}, // httptest.NewRequest converts nil to http.NoBody
			canRetry: true,
		},
		{
			name:     "empty body",
			body:     strings.NewReader(""),
			maxSize:  1024,
			expected: []byte{},
			canRetry: true,
		},
		{
			name:      "body exceeds limit",
			body:      strings.NewReader("this is a long body that exceeds the limit"),
			maxSize:   10,
			nilResult: true,
			canRetry:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/test", tt.body)
			result, canRetry := readRequestBodyWithLimit(req, tt.maxSize, logger)

			assert.Equal(t, tt.canRetry, canRetry)
			if tt.nilResult {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestRetryResponseWriter(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           &bytes.Buffer{},
		status:         http.StatusOK,
	}

	rw.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, rw.status)

	n, err := rw.Write([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, "test", rw.body.String())
}

func TestRetry_ContextCancelledDuringBackoff(t *testing.T) {
	t.Parallel()

	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"5xx"},
		BackoffBase: 5 * time.Second, // Long backoff to ensure context cancels first
		BackoffMax:  10 * time.Second,
	}
	logger := observability.NopLogger()
	middleware := Retry(cfg, logger)

	callCount := 0
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))

	// Create a request with a context that will be cancelled quickly
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	// Cancel the context after a short delay (during backoff)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	handler.ServeHTTP(rec, req)

	// Should have been called once (first attempt), then context cancelled during backoff
	assert.Equal(t, 1, callCount, "should only be called once before context cancellation")
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestMatchRetryCondition_Reset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		expected bool
	}{
		{
			name:     "reset matches 502",
			status:   http.StatusBadGateway,
			expected: true,
		},
		{
			name:     "reset does not match 503",
			status:   http.StatusServiceUnavailable,
			expected: false,
		},
		{
			name:     "reset does not match 500",
			status:   http.StatusInternalServerError,
			expected: false,
		},
		{
			name:     "reset does not match 200",
			status:   http.StatusOK,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := matchRetryCondition(tt.status, "reset")
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchRetryCondition_ConnectFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		expected bool
	}{
		{
			name:     "connect-failure matches 502",
			status:   http.StatusBadGateway,
			expected: true,
		},
		{
			name:     "connect-failure matches 503",
			status:   http.StatusServiceUnavailable,
			expected: true,
		},
		{
			name:     "connect-failure does not match 500",
			status:   http.StatusInternalServerError,
			expected: false,
		},
		{
			name:     "connect-failure does not match 200",
			status:   http.StatusOK,
			expected: false,
		},
		{
			name:     "connect-failure does not match 404",
			status:   http.StatusNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := matchRetryCondition(tt.status, "connect-failure")
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRetryResponseWriter_Flush(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           &bytes.Buffer{},
		status:         http.StatusOK,
	}

	// Flush should be a no-op and not panic
	rw.Flush()
}

func TestRetryFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *config.RetryPolicy
		expectPassthru bool
	}{
		{
			name:           "nil config returns passthrough",
			config:         nil,
			expectPassthru: true,
		},
		{
			name: "zero attempts returns passthrough",
			config: &config.RetryPolicy{
				Attempts: 0,
			},
			expectPassthru: true,
		},
		{
			name: "negative attempts returns passthrough",
			config: &config.RetryPolicy{
				Attempts: -1,
			},
			expectPassthru: true,
		},
		{
			name: "valid config returns retry middleware",
			config: &config.RetryPolicy{
				Attempts:      3,
				PerTryTimeout: config.Duration(5 * time.Second),
				RetryOn:       "5xx,retriable-4xx",
			},
			expectPassthru: false,
		},
		{
			name: "empty retryOn uses defaults",
			config: &config.RetryPolicy{
				Attempts: 3,
				RetryOn:  "",
			},
			expectPassthru: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			middleware := RetryFromConfig(tt.config, logger)

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

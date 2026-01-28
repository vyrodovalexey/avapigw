package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		timeout        time.Duration
		handlerDelay   time.Duration
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "request completes before timeout",
			timeout:        500 * time.Millisecond,
			handlerDelay:   10 * time.Millisecond,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "request times out",
			timeout:        50 * time.Millisecond,
			handlerDelay:   200 * time.Millisecond,
			expectedStatus: http.StatusGatewayTimeout,
			expectedBody:   `{"error":"gateway timeout"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not parallel due to timing sensitivity

			logger := observability.NopLogger()
			middleware := Timeout(tt.timeout, logger)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(tt.handlerDelay):
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("success"))
				case <-r.Context().Done():
					// Context cancelled
					return
				}
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, rec.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestTimeout_ContentType(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	middleware := Timeout(10*time.Millisecond, logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(100 * time.Millisecond):
			// Should not reach here
		case <-r.Context().Done():
			return
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestTimeout_ContextCancellation(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	middleware := Timeout(100*time.Millisecond, logger)

	var contextCancelled atomic.Bool
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(200 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
			contextCancelled.Store(true)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Give some time for the goroutine to detect cancellation
	time.Sleep(50 * time.Millisecond)

	assert.True(t, contextCancelled.Load())
}

func TestTimeoutWriter_WriteHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	tw := &timeoutWriter{
		ResponseWriter: rec,
		done:           done,
		written:        false,
	}

	tw.WriteHeader(http.StatusCreated)

	assert.True(t, tw.written)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestTimeoutWriter_Write(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	tw := &timeoutWriter{
		ResponseWriter: rec,
		done:           done,
		written:        false,
	}

	n, err := tw.Write([]byte("test"))

	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.True(t, tw.written)
	assert.Equal(t, "test", rec.Body.String())
}

func TestTimeout_ResponseAlreadyStarted(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	middleware := Timeout(50*time.Millisecond, logger)

	// Use a channel to signal when handler has finished writing
	handlerDone := make(chan struct{})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write response immediately
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("started"))
		// Signal that writing is complete
		close(handlerDone)
		// Then wait, checking for context cancellation
		select {
		case <-time.After(100 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Wait for handler to finish writing before reading the response
	<-handlerDone

	// Should get the original response since it was already started
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "started")
}

func TestTimeout_ZeroTimeout(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	// Zero timeout means immediate timeout
	middleware := Timeout(0, logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if context is already done
		select {
		case <-r.Context().Done():
			return
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// With zero timeout, context should be immediately cancelled
	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
}

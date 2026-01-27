package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestTimeoutWriter_WriteHeader_AfterTimeout tests WriteHeader after timeout.
func TestTimeoutWriter_WriteHeader_AfterTimeout(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tw := &timeoutWriter{
		ResponseWriter: rec,
		done:           done,
		written:        false,
		timedOut:       true, // Simulate timeout already occurred
		ctx:            ctx,
	}

	// WriteHeader should be a no-op after timeout
	tw.WriteHeader(http.StatusCreated)

	// written should still be false since we didn't actually write
	assert.False(t, tw.written)
}

// TestTimeoutWriter_Write_AfterTimeout tests Write after timeout.
func TestTimeoutWriter_Write_AfterTimeout(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context to simulate timeout

	tw := &timeoutWriter{
		ResponseWriter: rec,
		done:           done,
		written:        false,
		timedOut:       true, // Simulate timeout already occurred
		ctx:            ctx,
	}

	// Write should return context error after timeout
	n, err := tw.Write([]byte("test"))

	assert.Equal(t, 0, n)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestTimeout_PanicRecovery tests that panics in handlers are recovered.
func TestTimeout_PanicRecovery(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	middleware := Timeout(500*time.Millisecond, logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Should not panic
	assert.NotPanics(t, func() {
		handler.ServeHTTP(rec, req)
	})
}

// TestTimeout_ContextAlreadyCancelled tests behavior when context is already cancelled.
func TestTimeout_ContextAlreadyCancelled(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	middleware := Timeout(100*time.Millisecond, logger)

	var handlerCalled atomic.Bool
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if context is done
		select {
		case <-r.Context().Done():
			handlerCalled.Store(true)
			return
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))

	// Create a request with an already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// The handler should detect the cancelled context
	// Either timeout response or handler detected cancellation
	assert.True(t, rec.Code == http.StatusGatewayTimeout || handlerCalled.Load())
}

// TestTimeout_LongRunningHandler tests timeout with a long-running handler.
func TestTimeout_LongRunningHandler(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	middleware := Timeout(50*time.Millisecond, logger)

	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(handlerStarted)
		select {
		case <-time.After(500 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
			// Context cancelled
		}
		close(handlerDone)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Wait for handler to start
	<-handlerStarted

	// Should get timeout response
	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)

	// Wait for handler goroutine to finish
	select {
	case <-handlerDone:
		// Handler finished
	case <-time.After(200 * time.Millisecond):
		// Grace period should have allowed handler to finish
	}
}

// TestTimeout_WriteBeforeTimeout tests that writes before timeout are preserved.
func TestTimeout_WriteBeforeTimeout(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	middleware := Timeout(200*time.Millisecond, logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write immediately
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("accepted"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should get the original response
	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Contains(t, rec.Body.String(), "accepted")
}

// TestTimeout_MultipleWrites tests multiple writes within timeout.
func TestTimeout_MultipleWrites(t *testing.T) {
	// Not parallel due to timing sensitivity

	logger := observability.NopLogger()
	middleware := Timeout(200*time.Millisecond, logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("part1"))
		_, _ = w.Write([]byte("part2"))
		_, _ = w.Write([]byte("part3"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "part1part2part3", rec.Body.String())
}

// TestRecoverAndSignalDone_AlreadyClosed tests recoverAndSignalDone when channel is already closed.
func TestRecoverAndSignalDone_AlreadyClosed(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	done := make(chan struct{})
	close(done) // Close the channel first

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	// Should not panic when channel is already closed
	assert.NotPanics(t, func() {
		recoverAndSignalDone(done, req, logger)
	})
}

// TestWaitForGoroutine_ImmediateCompletion tests waitForGoroutine with immediate completion.
func TestWaitForGoroutine_ImmediateCompletion(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	close(done) // Close immediately

	// Should return immediately
	start := time.Now()
	waitForGoroutine(done)
	elapsed := time.Since(start)

	// Should be very fast (less than grace period)
	assert.Less(t, elapsed, timeoutGracePeriod)
}

// TestWaitForGoroutine_GracePeriodExpires tests waitForGoroutine when grace period expires.
func TestWaitForGoroutine_GracePeriodExpires(t *testing.T) {
	// Not parallel due to timing sensitivity

	done := make(chan struct{})
	// Don't close the channel

	start := time.Now()
	waitForGoroutine(done)
	elapsed := time.Since(start)

	// Should wait approximately the grace period
	assert.GreaterOrEqual(t, elapsed, timeoutGracePeriod)
	assert.Less(t, elapsed, timeoutGracePeriod+50*time.Millisecond)
}

// TestRunWithTimeout_ContextAlreadyDone tests runWithTimeout when context is already done.
func TestRunWithTimeout_ContextAlreadyDone(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	tw := &timeoutWriter{
		ResponseWriter: rec,
		done:           done,
		ctx:            ctx,
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

	var handlerCalled atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled.Store(true)
	})

	runWithTimeout(ctx, tw, req, next, done, logger)

	// Handler should not be called when context is already done
	assert.False(t, handlerCalled.Load())
}

// TestHandleTimeoutResult_NormalCompletion tests handleTimeoutResult with normal completion.
func TestHandleTimeoutResult_NormalCompletion(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	ctx := context.Background()

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	close(done) // Signal completion

	tw := &timeoutWriter{
		ResponseWriter: rec,
		done:           done,
		ctx:            ctx,
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	// Should return immediately without writing timeout response
	handleTimeoutResult(ctx, done, tw, rec, req, 100*time.Millisecond, logger)

	// When done is closed, handleTimeoutResult returns immediately
	// The response code depends on whether the handler wrote anything
	// In this case, httptest.NewRecorder defaults to 200 when accessed
	assert.NotEqual(t, http.StatusGatewayTimeout, rec.Code)
}

// TestHandleTimeout_ResponseAlreadyStarted tests handleTimeout when response already started.
func TestHandleTimeout_ResponseAlreadyStarted(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	close(done) // Close to prevent blocking

	tw := &timeoutWriter{
		ResponseWriter: rec,
		done:           done,
		written:        true, // Response already started
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	handleTimeout(tw, rec, req, 100*time.Millisecond, done, logger)

	// Should not write timeout response since response already started
	assert.NotEqual(t, http.StatusGatewayTimeout, rec.Code)
}

// TestWriteTimeoutResponse tests writeTimeoutResponse directly.
func TestWriteTimeoutResponse(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	writeTimeoutResponse(rec, req, 100*time.Millisecond, logger)

	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
	assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))
	assert.Equal(t, ErrGatewayTimeout, rec.Body.String())
}

package middleware

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// timeoutGracePeriod is the grace period to wait for goroutine completion after timeout.
const timeoutGracePeriod = 100 * time.Millisecond

// Timeout returns a middleware that adds a timeout to requests.
// The middleware properly handles goroutine cleanup when timeout occurs.
func Timeout(timeout time.Duration, logger observability.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.WithContext(ctx)
			done := make(chan struct{})

			tw := &timeoutWriter{
				ResponseWriter: w,
				done:           done,
				ctx:            ctx,
			}

			go runWithTimeout(ctx, tw, r, next, done, logger)

			handleTimeoutResult(ctx, done, tw, w, r, timeout, logger)
		})
	}
}

// runWithTimeout executes the handler with panic recovery and context checking.
func runWithTimeout(
	ctx context.Context,
	tw *timeoutWriter,
	r *http.Request,
	next http.Handler,
	done chan struct{},
	logger observability.Logger,
) {
	defer recoverAndSignalDone(done, r, logger)

	// Check if context is already canceled before starting
	select {
	case <-ctx.Done():
		return
	default:
	}

	next.ServeHTTP(tw, r)
}

// recoverAndSignalDone handles panic recovery and signals completion.
func recoverAndSignalDone(done chan struct{}, r *http.Request, logger observability.Logger) {
	if rec := recover(); rec != nil {
		logger.Error("panic in timeout handler",
			observability.String("path", r.URL.Path),
			observability.Any("panic", rec),
		)
	}
	// Always signal completion, even on panic
	select {
	case <-done:
		// Already closed
	default:
		close(done)
	}
}

// handleTimeoutResult handles the result of the timeout operation.
func handleTimeoutResult(
	ctx context.Context,
	done chan struct{},
	tw *timeoutWriter,
	w http.ResponseWriter,
	r *http.Request,
	timeout time.Duration,
	logger observability.Logger,
) {
	select {
	case <-done:
		// Request completed normally
	case <-ctx.Done():
		handleTimeout(tw, w, r, timeout, done, logger)
	}
}

// handleTimeout handles the timeout case.
func handleTimeout(
	tw *timeoutWriter,
	w http.ResponseWriter,
	r *http.Request,
	timeout time.Duration,
	done chan struct{},
	logger observability.Logger,
) {
	tw.mu.Lock()
	timedOut := !tw.written
	tw.timedOut = true
	tw.mu.Unlock()

	if timedOut {
		writeTimeoutResponse(w, r, timeout, logger)
	}

	waitForGoroutine(done)
}

// writeTimeoutResponse writes the timeout error response.
func writeTimeoutResponse(
	w http.ResponseWriter,
	r *http.Request,
	timeout time.Duration,
	logger observability.Logger,
) {
	logger.Warn("request timeout",
		observability.String("path", r.URL.Path),
		observability.String("method", r.Method),
		observability.Duration("timeout", timeout),
	)

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusGatewayTimeout)
	_, _ = io.WriteString(w, ErrGatewayTimeout)
}

// waitForGoroutine waits for the goroutine to finish with a grace period.
func waitForGoroutine(done chan struct{}) {
	select {
	case <-done:
		// Goroutine finished
	case <-time.After(timeoutGracePeriod):
		// Grace period expired
	}
}

// timeoutWriter wraps http.ResponseWriter to track if response has started.
type timeoutWriter struct {
	http.ResponseWriter
	done     chan struct{}
	written  bool
	timedOut bool
	ctx      context.Context
	mu       sync.Mutex
}

// WriteHeader tracks that response has started.
// It prevents writing after timeout has occurred.
func (tw *timeoutWriter) WriteHeader(code int) {
	tw.mu.Lock()
	if tw.timedOut {
		tw.mu.Unlock()
		return // Don't write after timeout
	}
	tw.written = true
	tw.mu.Unlock()
	tw.ResponseWriter.WriteHeader(code)
}

// Write tracks that response has started.
// It prevents writing after timeout has occurred.
func (tw *timeoutWriter) Write(b []byte) (int, error) {
	tw.mu.Lock()
	if tw.timedOut {
		tw.mu.Unlock()
		return 0, tw.ctx.Err() // Return context error after timeout
	}
	tw.written = true
	tw.mu.Unlock()
	return tw.ResponseWriter.Write(b)
}

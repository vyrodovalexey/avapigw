package middleware

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Timeout returns a middleware that adds a timeout to requests.
func Timeout(timeout time.Duration, logger observability.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.WithContext(ctx)

			// Create a channel to signal completion
			done := make(chan struct{})

			// Wrap response writer to detect if response has started
			tw := &timeoutWriter{
				ResponseWriter: w,
				done:           done,
			}

			go func() {
				next.ServeHTTP(tw, r)
				close(done)
			}()

			select {
			case <-done:
				// Request completed normally
			case <-ctx.Done():
				// Timeout occurred
				tw.mu.Lock()
				defer tw.mu.Unlock()

				if !tw.written {
					logger.Warn("request timeout",
						observability.String("path", r.URL.Path),
						observability.String("method", r.Method),
						observability.Duration("timeout", timeout),
					)

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusGatewayTimeout)
					_, _ = io.WriteString(w, `{"error":"gateway timeout"}`)
				}
			}
		})
	}
}

// timeoutWriter wraps http.ResponseWriter to track if response has started.
type timeoutWriter struct {
	http.ResponseWriter
	done    chan struct{}
	written bool
	mu      sync.Mutex
}

// WriteHeader tracks that response has started.
func (tw *timeoutWriter) WriteHeader(code int) {
	tw.mu.Lock()
	tw.written = true
	tw.mu.Unlock()
	tw.ResponseWriter.WriteHeader(code)
}

// Write tracks that response has started.
func (tw *timeoutWriter) Write(b []byte) (int, error) {
	tw.mu.Lock()
	tw.written = true
	tw.mu.Unlock()
	return tw.ResponseWriter.Write(b)
}

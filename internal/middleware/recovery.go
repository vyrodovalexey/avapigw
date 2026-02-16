// Package middleware provides HTTP middleware for the API Gateway.
package middleware

import (
	"fmt"
	"io"
	"net/http"
	"runtime/debug"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Recovery returns a middleware that recovers from panics.
func Recovery(logger observability.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					stack := debug.Stack()

					logger.Error("panic recovered",
						observability.String("path", r.URL.Path),
						observability.String("method", r.Method),
						observability.Any("error", err),
						observability.String("stack", string(stack)),
					)

					GetMiddlewareMetrics().panicsRecovered.Inc()

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, `{"error":"internal server error"}`)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// RecoveryWithWriter returns a middleware that recovers from panics and writes to a custom writer.
func RecoveryWithWriter(logger observability.Logger, out io.Writer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					stack := debug.Stack()

					logger.Error("panic recovered",
						observability.String("path", r.URL.Path),
						observability.String("method", r.Method),
						observability.Any("error", err),
						observability.String("stack", string(stack)),
					)

					// Write to custom writer
					_, _ = fmt.Fprintf(out, "panic: %v\n%s\n", err, stack)

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, `{"error":"internal server error"}`)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

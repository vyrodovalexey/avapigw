package middleware

import (
	"io"
	"net/http"
	"time"

	"github.com/sony/gobreaker"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// CircuitBreaker wraps gobreaker.CircuitBreaker.
type CircuitBreaker struct {
	cb     *gobreaker.CircuitBreaker
	logger observability.Logger
}

// CircuitBreakerOption is a functional option for configuring the circuit breaker.
type CircuitBreakerOption func(*CircuitBreaker)

// WithCircuitBreakerLogger sets the logger for the circuit breaker.
func WithCircuitBreakerLogger(logger observability.Logger) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		cb.logger = logger
	}
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(
	name string,
	threshold int,
	timeout time.Duration,
	opts ...CircuitBreakerOption,
) *CircuitBreaker {
	cb := &CircuitBreaker{
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(cb)
	}

	thresholdU32 := safeIntToUint32(threshold)

	settings := gobreaker.Settings{
		Name:        name,
		MaxRequests: thresholdU32,
		Interval:    timeout,
		Timeout:     timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= thresholdU32 && failureRatio >= 0.5
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			cb.logger.Info("circuit breaker state change",
				observability.String("name", name),
				observability.String("from", from.String()),
				observability.String("to", to.String()),
			)
		},
	}

	cb.cb = gobreaker.NewCircuitBreaker(settings)
	return cb
}

// safeIntToUint32 safely converts int to uint32.
func safeIntToUint32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > int(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(n) //nolint:gosec // bounds checked above
}

// Execute executes a function with circuit breaker protection.
func (cb *CircuitBreaker) Execute(fn func() (interface{}, error)) (interface{}, error) {
	return cb.cb.Execute(fn)
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() gobreaker.State {
	return cb.cb.State()
}

// CircuitBreakerMiddleware returns a middleware that applies circuit breaker.
func CircuitBreakerMiddleware(cb *CircuitBreaker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cb.State() == gobreaker.StateOpen {
				cb.logger.Warn("circuit breaker open",
					observability.String("path", r.URL.Path),
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":"service unavailable","message":"circuit breaker open"}`)
				return
			}

			rw := &circuitBreakerWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			next.ServeHTTP(rw, r)

			if rw.status >= 500 {
				_, _ = cb.Execute(func() (interface{}, error) {
					return nil, http.ErrAbortHandler
				})
			} else {
				_, _ = cb.Execute(func() (interface{}, error) {
					return nil, nil
				})
			}
		})
	}
}

// circuitBreakerWriter wraps http.ResponseWriter to track status.
type circuitBreakerWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code.
func (w *circuitBreakerWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// CircuitBreakerFromConfig creates circuit breaker middleware from gateway config.
func CircuitBreakerFromConfig(
	cfg *config.CircuitBreakerConfig,
	logger observability.Logger,
) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	cb := NewCircuitBreaker(
		"gateway",
		cfg.Threshold,
		cfg.Timeout.Duration(),
		WithCircuitBreakerLogger(logger),
	)

	return CircuitBreakerMiddleware(cb)
}

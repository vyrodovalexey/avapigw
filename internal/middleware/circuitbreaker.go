package middleware

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/sony/gobreaker"

	"github.com/vyrodovalexey/avapigw/internal/config"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// CircuitBreakerStateFunc is called when the circuit breaker changes state.
// Parameters: name (circuit breaker name), state (0=closed, 1=half-open, 2=open).
type CircuitBreakerStateFunc func(name string, state int)

// CircuitBreaker wraps gobreaker.CircuitBreaker.
type CircuitBreaker struct {
	cb            *gobreaker.CircuitBreaker
	logger        observability.Logger
	stateCallback CircuitBreakerStateFunc
}

// CircuitBreakerOption is a functional option for configuring the circuit breaker.
type CircuitBreakerOption func(*CircuitBreaker)

// WithCircuitBreakerLogger sets the logger for the circuit breaker.
func WithCircuitBreakerLogger(logger observability.Logger) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		cb.logger = logger
	}
}

// WithCircuitBreakerStateCallback sets a callback for circuit breaker state changes.
func WithCircuitBreakerStateCallback(fn CircuitBreakerStateFunc) CircuitBreakerOption {
	return func(cb *CircuitBreaker) {
		cb.stateCallback = fn
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

			mm := GetMiddlewareMetrics()
			mm.circuitBreakerTransitions.WithLabelValues(
				name, from.String(), to.String(),
			).Inc()

			// Intentionally no OTEL span here: OnStateChange runs
			// outside any request context, so a span started from
			// context.Background() would be an orphan root span that
			// can never join the trace that triggered the transition.
			// The transition is already observable through the Info
			// log above and the circuit_breaker_transitions_total
			// metric.

			// Record route-level circuit breaker trip when
			// transitioning to open state
			if to == gobreaker.StateOpen {
				routepkg.GetRouteMetrics().
					CircuitBreakerTripsTotal.
					WithLabelValues(name).Inc()
			}

			if cb.stateCallback != nil {
				cb.stateCallback(name, int(to))
			}
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
// It uses the circuit breaker's Execute method to ensure atomic state checks and execution.
func CircuitBreakerMiddleware(cb *CircuitBreaker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip circuit breaker for WebSocket upgrade requests
			// WebSocket connections require direct access to the underlying connection (Hijacker)
			// and cannot be wrapped by the circuit breaker's response recorder
			if isWebSocketUpgrade(r) {
				next.ServeHTTP(w, r)
				return
			}

			mm := GetMiddlewareMetrics()

			rw := util.NewStatusCapturingResponseWriter(w)

			// Execute the request through the circuit breaker for atomic state check
			_, err := cb.Execute(func() (interface{}, error) {
				// Read the state inside Execute so the metric label
				// reflects the state under which this request was
				// actually admitted. A value captured before Execute
				// could go stale if the breaker transitions in between.
				mm.circuitBreakerRequests.WithLabelValues(
					"gateway", cb.State().String(),
				).Inc()

				next.ServeHTTP(rw, r)

				// Return error for 5xx responses to trigger circuit breaker
				if rw.StatusCode >= 500 {
					return nil, util.NewServerError(rw.StatusCode)
				}
				return nil, nil
			})

			// Handle circuit breaker open state
			if err != nil {
				// Check if it's a circuit breaker open error
				if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
					mm.circuitBreakerRequests.WithLabelValues(
						"gateway", "open",
					).Inc()

					cb.logger.Warn("circuit breaker rejected request",
						observability.String("path", r.URL.Path),
						observability.String("state", cb.State().String()),
					)

					// Only write error response if we haven't written anything yet
					if !rw.HeaderWritten {
						w.Header().Set(HeaderContentType, ContentTypeJSON)
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = io.WriteString(w, ErrServiceUnavailable)
					}
					return
				}
				// For server errors, the response was already written by the handler
			}
		})
	}
}

// CircuitBreakerFromConfig creates circuit breaker middleware from gateway config.
// Additional CircuitBreakerOption values are forwarded to NewCircuitBreaker.
func CircuitBreakerFromConfig(
	cfg *config.CircuitBreakerConfig,
	logger observability.Logger,
	opts ...CircuitBreakerOption,
) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	allOpts := append(
		[]CircuitBreakerOption{WithCircuitBreakerLogger(logger)},
		opts...,
	)

	cb := NewCircuitBreaker(
		"gateway",
		cfg.Threshold,
		cfg.Timeout.Duration(),
		allOpts...,
	)

	return CircuitBreakerMiddleware(cb)
}

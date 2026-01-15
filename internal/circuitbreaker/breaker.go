package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
)

// State represents the state of a circuit breaker.
type State int

const (
	// StateClosed indicates the circuit is closed and requests are allowed.
	StateClosed State = iota

	// StateOpen indicates the circuit is open and requests are rejected.
	StateOpen

	// StateHalfOpen indicates the circuit is testing if the backend is healthy.
	StateHalfOpen
)

// String returns the string representation of the state.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// ErrTooManyRequests is returned when too many requests are made in half-open state.
var ErrTooManyRequests = errors.New("too many requests in half-open state")

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	name   string
	config *Config
	logger *zap.Logger

	mu    sync.RWMutex
	state State

	// Counters
	failures         int
	successes        int
	consecutiveFails int
	totalRequests    int

	// Half-open state tracking
	halfOpenRequests int

	// Timestamps
	lastFailure     time.Time
	lastStateChange time.Time
	samplingStart   time.Time
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(name string, config *Config, logger *zap.Logger) *CircuitBreaker {
	if config == nil {
		config = DefaultConfig()
	}
	config.Validate()

	if logger == nil {
		logger = zap.NewNop()
	}

	now := time.Now()
	return &CircuitBreaker{
		name:            name,
		config:          config,
		logger:          logger,
		state:           StateClosed,
		lastStateChange: now,
		samplingStart:   now,
	}
}

// Execute executes the given function with circuit breaker protection.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	if !cb.Allow() {
		return ErrCircuitOpen
	}

	// Execute the function
	err := fn()

	// Record the result
	if cb.isSuccessful(err) {
		cb.RecordSuccess()
	} else {
		cb.RecordFailure()
	}

	return err
}

// ExecuteWithFallback executes the function with a fallback on circuit open.
func (cb *CircuitBreaker) ExecuteWithFallback(ctx context.Context, fn func() error, fallback func(error) error) error {
	err := cb.Execute(ctx, fn)
	if errors.Is(err, ErrCircuitOpen) || errors.Is(err, ErrTooManyRequests) {
		return fallback(err)
	}
	return err
}

// Allow checks if a request is allowed through the circuit breaker.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	var allowed bool

	switch cb.state {
	case StateClosed:
		allowed = true

	case StateOpen:
		// Check if timeout has passed
		if now.Sub(cb.lastStateChange) >= cb.config.Timeout {
			cb.transitionTo(StateHalfOpen)
			cb.halfOpenRequests = 1
			allowed = true
		} else {
			allowed = false
		}

	case StateHalfOpen:
		// Allow limited requests in half-open state
		if cb.halfOpenRequests < cb.config.HalfOpenMax {
			cb.halfOpenRequests++
			allowed = true
		} else {
			allowed = false
		}

	default:
		allowed = false
	}

	// Record request metric
	RecordRequest(cb.name, allowed)

	return allowed
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.successes++
	cb.consecutiveFails = 0
	cb.totalRequests++

	// Record success metric
	RecordSuccess(cb.name)

	switch cb.state {
	case StateHalfOpen:
		// Check if we have enough successes to close the circuit
		if cb.successes >= cb.config.SuccessThreshold {
			cb.transitionTo(StateClosed)
		}

	case StateClosed:
		// Reset sampling window if needed
		if time.Since(cb.samplingStart) >= cb.config.SamplingDuration {
			cb.resetCounters()
		}
	}
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.consecutiveFails++
	cb.totalRequests++
	cb.lastFailure = time.Now()

	// Record failure metric
	RecordFailure(cb.name)

	switch cb.state {
	case StateClosed:
		// Check if we should open the circuit
		if cb.shouldOpen() {
			cb.transitionTo(StateOpen)
		}

	case StateHalfOpen:
		// Any failure in half-open state opens the circuit
		cb.transitionTo(StateOpen)
	}
}

// shouldOpen determines if the circuit should open.
func (cb *CircuitBreaker) shouldOpen() bool {
	// Check consecutive failures
	if cb.consecutiveFails >= cb.config.MaxFailures {
		return true
	}

	// Check failure ratio if configured
	if cb.config.FailureRatio > 0 && cb.totalRequests >= cb.config.MinRequests {
		ratio := float64(cb.failures) / float64(cb.totalRequests)
		if ratio >= cb.config.FailureRatio {
			return true
		}
	}

	return false
}

// transitionTo transitions the circuit breaker to a new state.
func (cb *CircuitBreaker) transitionTo(newState State) {
	oldState := cb.state
	cb.state = newState
	cb.lastStateChange = time.Now()

	// Reset counters on state change
	cb.resetCounters()

	// Record state change metric
	RecordStateChange(cb.name, oldState, newState)

	cb.logger.Info("circuit breaker state changed",
		zap.String("name", cb.name),
		zap.String("from", oldState.String()),
		zap.String("to", newState.String()),
	)

	// Call state change callback
	if cb.config.OnStateChange != nil {
		go cb.config.OnStateChange(cb.name, oldState, newState)
	}
}

// resetCounters resets the failure and success counters.
func (cb *CircuitBreaker) resetCounters() {
	cb.failures = 0
	cb.successes = 0
	cb.consecutiveFails = 0
	cb.totalRequests = 0
	cb.halfOpenRequests = 0
	cb.samplingStart = time.Now()
}

// isSuccessful determines if the error should be counted as a success.
func (cb *CircuitBreaker) isSuccessful(err error) bool {
	if cb.config.IsSuccessful != nil {
		return cb.config.IsSuccessful(err)
	}
	return err == nil
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.resetCounters()
	cb.lastStateChange = time.Now()

	cb.logger.Info("circuit breaker reset",
		zap.String("name", cb.name),
	)
}

// Name returns the name of the circuit breaker.
func (cb *CircuitBreaker) Name() string {
	return cb.name
}

// Stats returns the current statistics of the circuit breaker.
func (cb *CircuitBreaker) Stats() Stats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return Stats{
		State:            cb.state,
		Failures:         cb.failures,
		Successes:        cb.successes,
		ConsecutiveFails: cb.consecutiveFails,
		TotalRequests:    cb.totalRequests,
		LastFailure:      cb.lastFailure,
		LastStateChange:  cb.lastStateChange,
	}
}

// Stats holds circuit breaker statistics.
type Stats struct {
	State            State
	Failures         int
	Successes        int
	ConsecutiveFails int
	TotalRequests    int
	LastFailure      time.Time
	LastStateChange  time.Time
}

// FailureRatio returns the current failure ratio.
func (s Stats) FailureRatio() float64 {
	if s.TotalRequests == 0 {
		return 0
	}
	return float64(s.Failures) / float64(s.TotalRequests)
}

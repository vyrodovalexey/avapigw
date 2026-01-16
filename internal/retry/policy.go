// Package retry provides retry functionality with configurable backoff strategies.
package retry

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Policy defines the retry policy configuration.
type Policy struct {
	// MaxRetries is the maximum number of retry attempts.
	MaxRetries int

	// InitialBackoff is the initial backoff duration.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration.
	MaxBackoff time.Duration

	// BackoffFactor is the multiplier for exponential backoff.
	BackoffFactor float64

	// Jitter is the random jitter factor (0.0 to 1.0).
	Jitter float64

	// RetryOn is a list of conditions that trigger a retry.
	RetryOn []RetryCondition

	// Logger for logging retry attempts.
	Logger *zap.Logger
}

// RetryCondition defines when a retry should be attempted.
type RetryCondition interface {
	// ShouldRetry returns true if the request should be retried.
	ShouldRetry(err error, statusCode int) bool
}

// DefaultPolicy returns a Policy with default values.
func DefaultPolicy() *Policy {
	return &Policy{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		BackoffFactor:  2.0,
		Jitter:         0.1,
		RetryOn:        []RetryCondition{RetryOnNetworkErrors()},
	}
}

// Validate validates and normalizes the policy.
func (p *Policy) Validate() {
	if p.MaxRetries < 0 {
		p.MaxRetries = 0
	}
	if p.InitialBackoff <= 0 {
		p.InitialBackoff = 100 * time.Millisecond
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = 10 * time.Second
	}
	if p.BackoffFactor <= 0 {
		p.BackoffFactor = 2.0
	}
	if p.Jitter < 0 || p.Jitter > 1 {
		p.Jitter = 0.1
	}
}

// Execute executes the function with retry logic.
func (p *Policy) Execute(ctx context.Context, fn func() (interface{}, error)) (interface{}, error) {
	p.Validate()

	backoff := NewExponentialBackoff(p.InitialBackoff, p.MaxBackoff, p.BackoffFactor, p.Jitter)

	var lastErr error
	for attempt := 0; attempt <= p.MaxRetries; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Execute the function
		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Check if we should retry
		if attempt < p.MaxRetries && p.shouldRetry(err, 0) {
			waitDuration := backoff.Next(attempt)

			if p.Logger != nil {
				p.Logger.Debug("retrying request",
					zap.Int("attempt", attempt+1),
					zap.Int("max_retries", p.MaxRetries),
					zap.Duration("wait", waitDuration),
					zap.Error(err),
				)
			}

			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitDuration):
			}
		}
	}

	return nil, lastErr
}

// ExecuteWithStatusCode executes the function with retry logic, considering HTTP status codes.
// Returns the result, HTTP status code, and any error.
func (p *Policy) ExecuteWithStatusCode(
	ctx context.Context,
	fn func() (interface{}, int, error),
) (result interface{}, statusCode int, err error) {
	p.Validate()

	backoff := NewExponentialBackoff(p.InitialBackoff, p.MaxBackoff, p.BackoffFactor, p.Jitter)

	var lastErr error
	var lastStatusCode int

	for attempt := 0; attempt <= p.MaxRetries; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}

		// Execute the function
		result, statusCode, err := fn()
		if err == nil && !p.isRetryableStatusCode(statusCode) {
			return result, statusCode, nil
		}

		lastErr = err
		lastStatusCode = statusCode

		// Check if we should retry
		if attempt < p.MaxRetries && p.shouldRetry(err, statusCode) {
			waitDuration := backoff.Next(attempt)

			if p.Logger != nil {
				p.Logger.Debug("retrying request",
					zap.Int("attempt", attempt+1),
					zap.Int("max_retries", p.MaxRetries),
					zap.Int("status_code", statusCode),
					zap.Duration("wait", waitDuration),
					zap.Error(err),
				)
			}

			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(waitDuration):
			}
		}
	}

	return nil, lastStatusCode, lastErr
}

// shouldRetry checks if the request should be retried.
func (p *Policy) shouldRetry(err error, statusCode int) bool {
	if len(p.RetryOn) == 0 {
		// Default: retry on any error
		return err != nil
	}

	for _, condition := range p.RetryOn {
		if condition.ShouldRetry(err, statusCode) {
			return true
		}
	}

	return false
}

// isRetryableStatusCode checks if the status code is retryable.
func (p *Policy) isRetryableStatusCode(statusCode int) bool {
	for _, condition := range p.RetryOn {
		if condition.ShouldRetry(nil, statusCode) {
			return true
		}
	}
	return false
}

// WithMaxRetries sets the maximum retries.
func (p *Policy) WithMaxRetries(n int) *Policy {
	p.MaxRetries = n
	return p
}

// WithInitialBackoff sets the initial backoff.
func (p *Policy) WithInitialBackoff(d time.Duration) *Policy {
	p.InitialBackoff = d
	return p
}

// WithMaxBackoff sets the maximum backoff.
func (p *Policy) WithMaxBackoff(d time.Duration) *Policy {
	p.MaxBackoff = d
	return p
}

// WithBackoffFactor sets the backoff factor.
func (p *Policy) WithBackoffFactor(f float64) *Policy {
	p.BackoffFactor = f
	return p
}

// WithJitter sets the jitter factor.
func (p *Policy) WithJitter(j float64) *Policy {
	p.Jitter = j
	return p
}

// WithRetryOn sets the retry conditions.
func (p *Policy) WithRetryOn(conditions ...RetryCondition) *Policy {
	p.RetryOn = conditions
	return p
}

// WithLogger sets the logger.
func (p *Policy) WithLogger(logger *zap.Logger) *Policy {
	p.Logger = logger
	return p
}

// NoRetryPolicy returns a policy that never retries.
func NoRetryPolicy() *Policy {
	return &Policy{
		MaxRetries: 0,
	}
}

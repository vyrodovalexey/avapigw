// Package retry provides exponential backoff retry functionality.
package retry

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

// Default retry configuration constants.
const (
	// DefaultMaxRetries is the default maximum number of retry attempts.
	DefaultMaxRetries = 3

	// DefaultInitialBackoff is the default initial backoff duration.
	DefaultInitialBackoff = 100 * time.Millisecond

	// DefaultMaxBackoff is the default maximum backoff duration.
	DefaultMaxBackoff = 30 * time.Second

	// DefaultJitterFactor is the default jitter factor (25%).
	DefaultJitterFactor = 0.25

	// MaxJitterFactor is the maximum allowed jitter factor.
	MaxJitterFactor = 1.0
)

// Config contains retry configuration parameters.
type Config struct {
	// MaxRetries is the maximum number of retry attempts.
	// Default is 3.
	MaxRetries int

	// InitialBackoff is the initial backoff duration.
	// Default is 100ms.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration.
	// Default is 30s.
	MaxBackoff time.Duration

	// JitterFactor is the jitter factor (0.0 to 1.0) to add randomness to backoff.
	// Default is 0.25 (25% jitter).
	JitterFactor float64
}

// DefaultConfig returns the default retry configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxRetries:     DefaultMaxRetries,
		InitialBackoff: DefaultInitialBackoff,
		MaxBackoff:     DefaultMaxBackoff,
		JitterFactor:   DefaultJitterFactor,
	}
}

// GetMaxRetries returns the effective max retries.
func (c *Config) GetMaxRetries() int {
	if c == nil || c.MaxRetries <= 0 {
		return DefaultMaxRetries
	}
	return c.MaxRetries
}

// GetInitialBackoff returns the effective initial backoff.
func (c *Config) GetInitialBackoff() time.Duration {
	if c == nil || c.InitialBackoff <= 0 {
		return DefaultInitialBackoff
	}
	return c.InitialBackoff
}

// GetMaxBackoff returns the effective max backoff.
func (c *Config) GetMaxBackoff() time.Duration {
	if c == nil || c.MaxBackoff <= 0 {
		return DefaultMaxBackoff
	}
	return c.MaxBackoff
}

// GetJitterFactor returns the effective jitter factor.
func (c *Config) GetJitterFactor() float64 {
	if c == nil || c.JitterFactor <= 0 {
		return DefaultJitterFactor
	}
	if c.JitterFactor > MaxJitterFactor {
		return MaxJitterFactor
	}
	return c.JitterFactor
}

// RetryableFunc is a function that can be retried.
type RetryableFunc func() error

// ShouldRetryFunc determines if an error should trigger a retry.
type ShouldRetryFunc func(error) bool

// OnRetryFunc is called before each retry attempt.
type OnRetryFunc func(attempt int, err error, backoff time.Duration)

// Options contains optional retry behavior configuration.
type Options struct {
	// ShouldRetry determines if an error should trigger a retry.
	// If nil, all errors are retried.
	ShouldRetry ShouldRetryFunc

	// OnRetry is called before each retry attempt.
	OnRetry OnRetryFunc
}

// Do executes a function with retry logic.
func Do(ctx context.Context, cfg *Config, fn RetryableFunc, opts *Options) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	maxRetries := cfg.GetMaxRetries()
	initialBackoff := cfg.GetInitialBackoff()
	maxBackoff := cfg.GetMaxBackoff()
	jitterFactor := cfg.GetJitterFactor()

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Check if error is retryable
		if opts != nil && opts.ShouldRetry != nil && !opts.ShouldRetry(lastErr) {
			return lastErr
		}

		// Don't sleep after the last attempt
		if attempt < maxRetries {
			backoff := CalculateBackoff(attempt, initialBackoff, maxBackoff, jitterFactor)

			// Call OnRetry callback if provided
			if opts != nil && opts.OnRetry != nil {
				opts.OnRetry(attempt+1, lastErr, backoff)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return lastErr
}

// CalculateBackoff calculates the backoff duration for a given attempt.
func CalculateBackoff(attempt int, initialBackoff, maxBackoff time.Duration, jitterFactor float64) time.Duration {
	// Exponential backoff
	backoff := float64(initialBackoff) * math.Pow(2, float64(attempt))

	// Add jitter to prevent thundering herd
	// Using math/rand is acceptable here as this is for timing, not security
	//nolint:gosec // G404: jitter for retry timing is not security-sensitive
	jitter := backoff * jitterFactor * rand.Float64()
	backoff += jitter

	// Cap at maxBackoff
	if backoff > float64(maxBackoff) {
		backoff = float64(maxBackoff)
	}

	return time.Duration(backoff)
}

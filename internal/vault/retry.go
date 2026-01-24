package vault

import (
	"context"
	"math"
	"math/rand/v2"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// executeWithRetry executes a function with retry logic.
func (c *vaultClient) executeWithRetry(ctx context.Context, fn func() error) error {
	cfg := c.getRetryConfig()
	maxRetries := cfg.GetMaxRetries()
	backoffBase := cfg.GetBackoffBase()
	backoffMax := cfg.GetBackoffMax()

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
		if !IsRetryable(lastErr) {
			return lastErr
		}

		// Don't sleep after the last attempt
		if attempt < maxRetries {
			backoff := calculateBackoff(attempt, backoffBase, backoffMax)
			c.logger.Debug("retrying vault operation",
				observability.Int("attempt", attempt+1),
				observability.Int("max_retries", maxRetries),
				observability.Duration("backoff", backoff),
				observability.Error(lastErr),
			)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return lastErr
}

// calculateBackoff calculates the backoff duration for a given attempt.
func calculateBackoff(attempt int, base, maxBackoff time.Duration) time.Duration {
	// Exponential backoff with jitter
	backoff := float64(base) * math.Pow(2, float64(attempt))

	// Add jitter (0-25% of backoff) using crypto/rand would be overkill here
	// as this is just for retry timing, not security-sensitive
	jitter := backoff * 0.25 * rand.Float64() //nolint:gosec // G404: jitter for retry timing is not security-sensitive
	backoff += jitter

	// Cap at maxBackoff
	if backoff > float64(maxBackoff) {
		backoff = float64(maxBackoff)
	}

	return time.Duration(backoff)
}

// RetryableFunc is a function that can be retried.
type RetryableFunc func() error

// Retry executes a function with retry logic using the provided configuration.
func Retry(ctx context.Context, cfg *RetryConfig, fn RetryableFunc) error {
	if cfg == nil {
		cfg = DefaultRetryConfig()
	}

	maxRetries := cfg.GetMaxRetries()
	backoffBase := cfg.GetBackoffBase()
	backoffMax := cfg.GetBackoffMax()

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
		if !IsRetryable(lastErr) {
			return lastErr
		}

		// Don't sleep after the last attempt
		if attempt < maxRetries {
			backoff := calculateBackoff(attempt, backoffBase, backoffMax)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return lastErr
}

package vault

import (
	"context"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
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
			backoff := retry.CalculateBackoff(
				attempt, backoffBase, backoffMax,
				retry.DefaultJitterFactor,
			)
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
			backoff := retry.CalculateBackoff(
				attempt, backoffBase, backoffMax,
				retry.DefaultJitterFactor,
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

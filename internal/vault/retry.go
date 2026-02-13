package vault

import (
	"context"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
)

// toRetryConfig converts a vault RetryConfig to an internal retry.Config.
func toRetryConfig(cfg *RetryConfig) *retry.Config {
	if cfg == nil {
		cfg = DefaultRetryConfig()
	}
	return &retry.Config{
		MaxRetries:     cfg.GetMaxRetries(),
		InitialBackoff: cfg.GetBackoffBase(),
		MaxBackoff:     cfg.GetBackoffMax(),
		JitterFactor:   retry.DefaultJitterFactor,
	}
}

// executeWithRetry executes a function with retry logic.
func (c *vaultClient) executeWithRetry(ctx context.Context, fn func() error) error {
	cfg := c.getRetryConfig()
	retryCfg := toRetryConfig(cfg)

	return retry.Do(ctx, retryCfg, func() error {
		return fn()
	}, &retry.Options{
		ShouldRetry: IsRetryable,
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			c.logger.Debug("retrying vault operation",
				observability.Int("attempt", attempt),
				observability.Int("max_retries", retryCfg.MaxRetries),
				observability.Duration("backoff", backoff),
				observability.Error(err),
			)
		},
	})
}

// RetryableFunc is a function that can be retried.
type RetryableFunc func() error

// Retry executes a function with retry logic using the provided configuration.
// It is a thin wrapper around internal/retry.Do with vault-specific IsRetryable check.
func Retry(ctx context.Context, cfg *RetryConfig, fn RetryableFunc) error {
	retryCfg := toRetryConfig(cfg)

	return retry.Do(ctx, retryCfg, func() error {
		return fn()
	}, &retry.Options{
		ShouldRetry: IsRetryable,
	})
}

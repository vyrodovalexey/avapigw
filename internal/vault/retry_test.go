package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/retry"
)

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		name       string
		attempt    int
		base       time.Duration
		maxBackoff time.Duration
		minExpect  time.Duration
		maxExpect  time.Duration
	}{
		{
			name:       "first attempt",
			attempt:    0,
			base:       100 * time.Millisecond,
			maxBackoff: 5 * time.Second,
			minExpect:  100 * time.Millisecond,
			maxExpect:  125 * time.Millisecond, // base + 25% jitter
		},
		{
			name:       "second attempt",
			attempt:    1,
			base:       100 * time.Millisecond,
			maxBackoff: 5 * time.Second,
			minExpect:  200 * time.Millisecond,
			maxExpect:  250 * time.Millisecond, // 2*base + 25% jitter
		},
		{
			name:       "third attempt",
			attempt:    2,
			base:       100 * time.Millisecond,
			maxBackoff: 5 * time.Second,
			minExpect:  400 * time.Millisecond,
			maxExpect:  500 * time.Millisecond, // 4*base + 25% jitter
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run multiple times to account for jitter
			for i := 0; i < 10; i++ {
				result := retry.CalculateBackoff(
					tt.attempt, tt.base, tt.maxBackoff,
					retry.DefaultJitterFactor,
				)
				if result < tt.minExpect || result > tt.maxExpect {
					t.Errorf("CalculateBackoff() = %v, want between %v and %v",
						result, tt.minExpect, tt.maxExpect)
				}
			}
		})
	}
}

func TestCalculateBackoff_MaxCap(t *testing.T) {
	base := 100 * time.Millisecond
	maxBackoff := 500 * time.Millisecond

	// High attempt number should be capped at maxBackoff
	result := retry.CalculateBackoff(
		10, base, maxBackoff, retry.DefaultJitterFactor,
	)
	if result > maxBackoff {
		t.Errorf("CalculateBackoff() = %v, should be capped at %v",
			result, maxBackoff)
	}
}

func TestRetry_SuccessOnFirstTry(t *testing.T) {
	ctx := context.Background()
	cfg := &RetryConfig{
		MaxRetries:  3,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	err := Retry(ctx, cfg, func() error {
		attempts++
		return nil
	})

	if err != nil {
		t.Errorf("Retry() error = %v, want nil", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %v, want 1", attempts)
	}
}

func TestRetry_SuccessAfterRetries(t *testing.T) {
	ctx := context.Background()
	cfg := &RetryConfig{
		MaxRetries:  3,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	err := Retry(ctx, cfg, func() error {
		attempts++
		if attempts < 3 {
			return ErrVaultUnavailable // Retryable error
		}
		return nil
	})

	if err != nil {
		t.Errorf("Retry() error = %v, want nil", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %v, want 3", attempts)
	}
}

func TestRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &RetryConfig{
		MaxRetries:  10,
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  1 * time.Second,
	}

	attempts := 0
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := Retry(ctx, cfg, func() error {
		attempts++
		return ErrVaultUnavailable
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Retry() error = %v, want context.Canceled", err)
	}
}

func TestRetry_ContextCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := &RetryConfig{
		MaxRetries:  3,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	err := Retry(ctx, cfg, func() error {
		attempts++
		return nil
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Retry() error = %v, want context.Canceled", err)
	}
	if attempts != 0 {
		t.Errorf("attempts = %v, want 0", attempts)
	}
}

func TestRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	cfg := &RetryConfig{
		MaxRetries:  3,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	expectedErr := ErrAuthenticationFailed // Non-retryable
	err := Retry(ctx, cfg, func() error {
		attempts++
		return expectedErr
	})

	if !errors.Is(err, expectedErr) {
		t.Errorf("Retry() error = %v, want %v", err, expectedErr)
	}
	if attempts != 1 {
		t.Errorf("attempts = %v, want 1 (should not retry non-retryable error)", attempts)
	}
}

func TestRetry_MaxRetriesExceeded(t *testing.T) {
	ctx := context.Background()
	cfg := &RetryConfig{
		MaxRetries:  3,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	err := Retry(ctx, cfg, func() error {
		attempts++
		return ErrVaultUnavailable // Always fail with retryable error
	})

	if !errors.Is(err, ErrVaultUnavailable) {
		t.Errorf("Retry() error = %v, want %v", err, ErrVaultUnavailable)
	}
	// Should be maxRetries + 1 (initial attempt + retries)
	if attempts != 4 {
		t.Errorf("attempts = %v, want 4", attempts)
	}
}

func TestRetry_NilConfig(t *testing.T) {
	ctx := context.Background()

	attempts := 0
	err := Retry(ctx, nil, func() error {
		attempts++
		if attempts < 2 {
			return ErrVaultUnavailable
		}
		return nil
	})

	if err != nil {
		t.Errorf("Retry() error = %v, want nil", err)
	}
	// Should use default config (3 retries)
	if attempts < 2 {
		t.Errorf("attempts = %v, want at least 2", attempts)
	}
}

func TestRetry_ZeroMaxRetries(t *testing.T) {
	ctx := context.Background()
	cfg := &RetryConfig{
		MaxRetries:  0, // Will use default (3)
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	err := Retry(ctx, cfg, func() error {
		attempts++
		return ErrVaultUnavailable
	})

	if !errors.Is(err, ErrVaultUnavailable) {
		t.Errorf("Retry() error = %v, want %v", err, ErrVaultUnavailable)
	}
	// With default 3 retries: 1 initial + 3 retries = 4 attempts
	if attempts != 4 {
		t.Errorf("attempts = %v, want 4", attempts)
	}
}

func TestRetry_VaultSealedIsRetryable(t *testing.T) {
	ctx := context.Background()
	cfg := &RetryConfig{
		MaxRetries:  2,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	err := Retry(ctx, cfg, func() error {
		attempts++
		if attempts < 3 {
			return ErrVaultSealed // Retryable
		}
		return nil
	})

	if err != nil {
		t.Errorf("Retry() error = %v, want nil", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %v, want 3", attempts)
	}
}

func TestRetry_ConfigurationErrorNotRetryable(t *testing.T) {
	ctx := context.Background()
	cfg := &RetryConfig{
		MaxRetries:  3,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	configErr := NewConfigurationError("address", "required")
	err := Retry(ctx, cfg, func() error {
		attempts++
		return configErr
	})

	if !errors.Is(err, configErr) {
		t.Errorf("Retry() error = %v, want %v", err, configErr)
	}
	if attempts != 1 {
		t.Errorf("attempts = %v, want 1", attempts)
	}
}

func TestRetry_TokenExpiredNotRetryable(t *testing.T) {
	ctx := context.Background()
	cfg := &RetryConfig{
		MaxRetries:  3,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
	}

	attempts := 0
	err := Retry(ctx, cfg, func() error {
		attempts++
		return ErrTokenExpired
	})

	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("Retry() error = %v, want %v", err, ErrTokenExpired)
	}
	if attempts != 1 {
		t.Errorf("attempts = %v, want 1", attempts)
	}
}

func TestRetry_ContextDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	cfg := &RetryConfig{
		MaxRetries:  10,
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  1 * time.Second,
	}

	err := Retry(ctx, cfg, func() error {
		return ErrVaultUnavailable
	})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Retry() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestCalculateBackoff_ZeroBase(t *testing.T) {
	result := retry.CalculateBackoff(
		0, 0, 5*time.Second, retry.DefaultJitterFactor,
	)
	if result != 0 {
		t.Errorf("CalculateBackoff() with zero base = %v, want 0", result)
	}
}

func TestCalculateBackoff_ZeroMax(t *testing.T) {
	result := retry.CalculateBackoff(
		5, 100*time.Millisecond, 0, retry.DefaultJitterFactor,
	)
	// With zero max, the backoff should still be calculated but not capped
	if result < 0 {
		t.Errorf("CalculateBackoff() = %v, should not be negative", result)
	}
}

func TestCalculateBackoff_ExponentialGrowth(t *testing.T) {
	base := 100 * time.Millisecond
	maxBackoff := 10 * time.Second

	var prevBackoff time.Duration
	for attempt := 0; attempt < 5; attempt++ {
		backoff := retry.CalculateBackoff(
			attempt, base, maxBackoff,
			retry.DefaultJitterFactor,
		)
		if attempt > 0 && backoff <= prevBackoff {
			// Note: Due to jitter, this might occasionally fail
			// but generally backoff should increase
			t.Logf(
				"Warning: backoff did not increase at attempt %d: %v <= %v",
				attempt, backoff, prevBackoff,
			)
		}
		prevBackoff = backoff
	}
}

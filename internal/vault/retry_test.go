package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 500*time.Millisecond, config.WaitMin)
	assert.Equal(t, 30*time.Second, config.WaitMax) // Updated for better exponential backoff
	assert.Equal(t, BackoffTypeDecorrelatedJitter, config.BackoffType)
	assert.Equal(t, 2.0, config.BackoffMultiplier)
	assert.Equal(t, 0.2, config.Jitter)
	assert.Equal(t, "vault_operation", config.OperationName)
}

func TestExternalServiceRetryConfig(t *testing.T) {
	config := ExternalServiceRetryConfig()

	assert.Equal(t, 5, config.MaxRetries)
	assert.Equal(t, 500*time.Millisecond, config.WaitMin)
	assert.Equal(t, 60*time.Second, config.WaitMax)
	assert.Equal(t, BackoffTypeDecorrelatedJitter, config.BackoffType)
	assert.Equal(t, 2.0, config.BackoffMultiplier)
	assert.Equal(t, 0.3, config.Jitter)
	assert.Equal(t, "external_service", config.OperationName)
}

func TestWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxRetries: 3,
		WaitMin:    10 * time.Millisecond,
		WaitMax:    100 * time.Millisecond,
	}

	attempts := 0
	err := WithRetry(ctx, config, func() error {
		attempts++
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 1, attempts)
}

func TestWithRetry_SuccessAfterRetries(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxRetries: 3,
		WaitMin:    10 * time.Millisecond,
		WaitMax:    100 * time.Millisecond,
		RetryIf: func(err error) bool {
			return true // Always retry
		},
	}

	attempts := 0
	err := WithRetry(ctx, config, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary error")
		}
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 3, attempts)
}

func TestWithRetry_ExhaustedRetries(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxRetries: 2,
		WaitMin:    10 * time.Millisecond,
		WaitMax:    100 * time.Millisecond,
		RetryIf: func(err error) bool {
			return true // Always retry
		},
	}

	attempts := 0
	err := WithRetry(ctx, config, func() error {
		attempts++
		return errors.New("persistent error")
	})

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrRetryExhausted))
	assert.Equal(t, 3, attempts) // Initial + 2 retries
}

func TestWithRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	config := &RetryConfig{
		MaxRetries: 3,
		WaitMin:    10 * time.Millisecond,
		WaitMax:    100 * time.Millisecond,
		RetryIf: func(err error) bool {
			return false // Never retry
		},
	}

	attempts := 0
	expectedErr := errors.New("non-retryable error")
	err := WithRetry(ctx, config, func() error {
		attempts++
		return expectedErr
	})

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, 1, attempts)
}

func TestWithRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := &RetryConfig{
		MaxRetries: 10,
		WaitMin:    100 * time.Millisecond,
		WaitMax:    1 * time.Second,
		RetryIf: func(err error) bool {
			return true
		},
	}

	attempts := 0
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := WithRetry(ctx, config, func() error {
		attempts++
		return errors.New("error")
	})

	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
}

func TestWithRetry_NilConfig(t *testing.T) {
	ctx := context.Background()

	err := WithRetry(ctx, nil, func() error {
		return nil
	})

	assert.NoError(t, err)
}

func TestExponentialBackoffWithJitter(t *testing.T) {
	backoff := ExponentialBackoffWithJitter(100*time.Millisecond, 10*time.Second, 2.0, 0.1)

	// Test that backoff increases
	prev := time.Duration(0)
	for i := 0; i < 5; i++ {
		d := backoff(i)
		// Due to jitter, we can't assert exact values, but general trend should be increasing
		t.Logf("Attempt %d: %v", i, d)
		if i > 0 {
			// Allow for jitter variance
			assert.True(t, d >= 90*time.Millisecond, "backoff should be at least min")
		}
		prev = d
	}
	_ = prev // Silence unused variable warning
}

func TestConstantBackoff(t *testing.T) {
	backoff := ConstantBackoff(500 * time.Millisecond)

	for i := 0; i < 5; i++ {
		assert.Equal(t, 500*time.Millisecond, backoff(i))
	}
}

func TestLinearBackoff(t *testing.T) {
	backoff := LinearBackoff(100*time.Millisecond, 100*time.Millisecond, 500*time.Millisecond)

	assert.Equal(t, 100*time.Millisecond, backoff(0))
	assert.Equal(t, 200*time.Millisecond, backoff(1))
	assert.Equal(t, 300*time.Millisecond, backoff(2))
	assert.Equal(t, 400*time.Millisecond, backoff(3))
	assert.Equal(t, 500*time.Millisecond, backoff(4))
	assert.Equal(t, 500*time.Millisecond, backoff(5)) // Capped at max
}

func TestDecorrelatedJitterBackoff(t *testing.T) {
	backoff := DecorrelatedJitterBackoff(100*time.Millisecond, 10*time.Second)

	// First attempt should return initial value
	d0 := backoff(0)
	assert.Equal(t, 100*time.Millisecond, d0)

	// Subsequent attempts should be within bounds
	for i := 1; i < 10; i++ {
		d := backoff(i)
		t.Logf("Attempt %d: %v", i, d)
		assert.True(t, d >= 100*time.Millisecond, "backoff should be at least min")
		assert.True(t, d <= 10*time.Second, "backoff should be at most max")
	}
}

func TestFullJitterBackoff(t *testing.T) {
	backoff := FullJitterBackoff(100*time.Millisecond, 10*time.Second)

	// Test multiple attempts
	for i := 0; i < 10; i++ {
		d := backoff(i)
		t.Logf("Attempt %d: %v", i, d)
		assert.True(t, d >= 100*time.Millisecond, "backoff should be at least min")
		assert.True(t, d <= 10*time.Second, "backoff should be at most max")
	}
}

func TestEqualJitterBackoff(t *testing.T) {
	backoff := EqualJitterBackoff(100*time.Millisecond, 10*time.Second)

	// Test multiple attempts
	for i := 0; i < 10; i++ {
		d := backoff(i)
		t.Logf("Attempt %d: %v", i, d)
		// Equal jitter should be at least half of the exponential backoff
		assert.True(t, d >= 50*time.Millisecond, "backoff should be at least half of min")
		assert.True(t, d <= 10*time.Second, "backoff should be at most max")
	}
}

func TestCreateBackoffFunc(t *testing.T) {
	tests := []struct {
		name        string
		backoffType BackoffType
	}{
		{"exponential", BackoffTypeExponential},
		{"decorrelated_jitter", BackoffTypeDecorrelatedJitter},
		{"full_jitter", BackoffTypeFullJitter},
		{"equal_jitter", BackoffTypeEqualJitter},
		{"constant", BackoffTypeConstant},
		{"linear", BackoffTypeLinear},
		{"unknown", BackoffType("unknown")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &RetryConfig{
				WaitMin:           100 * time.Millisecond,
				WaitMax:           10 * time.Second,
				BackoffType:       tt.backoffType,
				BackoffMultiplier: 2.0,
				Jitter:            0.2,
			}

			backoff := createBackoffFunc(config)
			require.NotNil(t, backoff)

			// Test that backoff function works
			d := backoff(0)
			assert.True(t, d >= 0, "backoff should be non-negative")
		})
	}
}

func TestRetryableOperation(t *testing.T) {
	config := &RetryConfig{
		MaxRetries: 2,
		WaitMin:    10 * time.Millisecond,
		WaitMax:    100 * time.Millisecond,
	}

	op := NewRetryableOperation(config)
	require.NotNil(t, op)

	attempts := 0
	err := op.Do(context.Background(), func() error {
		attempts++
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 1, attempts)
}

func TestDoWithResult(t *testing.T) {
	config := &RetryConfig{
		MaxRetries: 2,
		WaitMin:    10 * time.Millisecond,
		WaitMax:    100 * time.Millisecond,
	}

	t.Run("success", func(t *testing.T) {
		result, err := DoWithResult(context.Background(), config, func() (string, error) {
			return "success", nil
		})

		assert.NoError(t, err)
		assert.Equal(t, "success", result)
	})

	t.Run("success after retry", func(t *testing.T) {
		attempts := 0
		config.RetryIf = func(err error) bool { return true }

		result, err := DoWithResult(context.Background(), config, func() (int, error) {
			attempts++
			if attempts < 2 {
				return 0, errors.New("temporary error")
			}
			return 42, nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 42, result)
	})
}

// ============================================================================
// Exponential Backoff Timing Tests
// ============================================================================

func TestExponentialBackoff_Timing(t *testing.T) {
	t.Run("backoff increases exponentially", func(t *testing.T) {
		backoff := ExponentialBackoffWithJitter(100*time.Millisecond, 10*time.Second, 2.0, 0.0)

		// Without jitter, backoff should be exactly exponential
		d0 := backoff(0)
		d1 := backoff(1)
		d2 := backoff(2)

		// d0 should be around 100ms
		assert.True(t, d0 >= 100*time.Millisecond && d0 <= 120*time.Millisecond,
			"d0 should be around 100ms, got %v", d0)

		// d1 should be around 200ms (100 * 2^1)
		assert.True(t, d1 >= 180*time.Millisecond && d1 <= 220*time.Millisecond,
			"d1 should be around 200ms, got %v", d1)

		// d2 should be around 400ms (100 * 2^2)
		assert.True(t, d2 >= 380*time.Millisecond && d2 <= 420*time.Millisecond,
			"d2 should be around 400ms, got %v", d2)
	})

	t.Run("backoff respects max wait", func(t *testing.T) {
		backoff := ExponentialBackoffWithJitter(100*time.Millisecond, 500*time.Millisecond, 2.0, 0.0)

		// After several attempts, should be capped at max
		d10 := backoff(10)
		assert.True(t, d10 <= 500*time.Millisecond,
			"backoff should be capped at max, got %v", d10)
	})
}

// ============================================================================
// Decorrelated Jitter Tests
// ============================================================================

func TestDecorrelatedJitter(t *testing.T) {
	t.Run("first attempt returns min wait", func(t *testing.T) {
		backoff := DecorrelatedJitterBackoff(100*time.Millisecond, 10*time.Second)

		d0 := backoff(0)
		assert.Equal(t, 100*time.Millisecond, d0)
	})

	t.Run("subsequent attempts are within bounds", func(t *testing.T) {
		backoff := DecorrelatedJitterBackoff(100*time.Millisecond, 10*time.Second)

		// Reset by calling with 0
		_ = backoff(0)

		for i := 1; i < 20; i++ {
			d := backoff(i)
			assert.True(t, d >= 100*time.Millisecond, "backoff should be at least min")
			assert.True(t, d <= 10*time.Second, "backoff should be at most max")
		}
	})

	t.Run("produces varied results", func(t *testing.T) {
		backoff := DecorrelatedJitterBackoff(100*time.Millisecond, 10*time.Second)

		// Collect multiple samples
		samples := make(map[time.Duration]bool)
		for i := 0; i < 10; i++ {
			// Reset
			_ = backoff(0)
			for j := 1; j < 5; j++ {
				d := backoff(j)
				samples[d] = true
			}
		}

		// Should have some variety (not all the same)
		assert.True(t, len(samples) > 1, "decorrelated jitter should produce varied results")
	})
}

// ============================================================================
// Max Retries Tests
// ============================================================================

func TestMaxRetries(t *testing.T) {
	t.Run("stops after max retries", func(t *testing.T) {
		config := &RetryConfig{
			MaxRetries: 3,
			WaitMin:    1 * time.Millisecond,
			WaitMax:    10 * time.Millisecond,
			RetryIf:    func(err error) bool { return true },
		}

		attempts := 0
		err := WithRetry(context.Background(), config, func() error {
			attempts++
			return errors.New("always fails")
		})

		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrRetryExhausted))
		assert.Equal(t, 4, attempts) // Initial + 3 retries
	})

	t.Run("zero max retries means no retries", func(t *testing.T) {
		config := &RetryConfig{
			MaxRetries: 0,
			WaitMin:    1 * time.Millisecond,
			WaitMax:    10 * time.Millisecond,
			RetryIf:    func(err error) bool { return true },
		}

		attempts := 0
		err := WithRetry(context.Background(), config, func() error {
			attempts++
			return errors.New("always fails")
		})

		assert.Error(t, err)
		assert.Equal(t, 1, attempts) // Only initial attempt
	})
}

// ============================================================================
// Context Cancellation During Retry Tests
// ============================================================================

func TestContextCancellation(t *testing.T) {
	t.Run("cancellation before first attempt", func(t *testing.T) {
		config := &RetryConfig{
			MaxRetries: 10,
			WaitMin:    100 * time.Millisecond,
			WaitMax:    1 * time.Second,
			RetryIf:    func(err error) bool { return true },
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		attempts := 0
		err := WithRetry(ctx, config, func() error {
			attempts++
			return errors.New("error")
		})

		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
		assert.Equal(t, 0, attempts) // Should not even attempt
	})

	t.Run("cancellation during backoff wait", func(t *testing.T) {
		config := &RetryConfig{
			MaxRetries: 10,
			WaitMin:    500 * time.Millisecond,
			WaitMax:    1 * time.Second,
			RetryIf:    func(err error) bool { return true },
		}

		ctx, cancel := context.WithCancel(context.Background())

		attempts := 0
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := WithRetry(ctx, config, func() error {
			attempts++
			return errors.New("error")
		})

		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
		// Should have attempted at least once before cancellation
		assert.GreaterOrEqual(t, attempts, 1)
	})

	t.Run("timeout context", func(t *testing.T) {
		config := &RetryConfig{
			MaxRetries: 100,
			WaitMin:    100 * time.Millisecond,
			WaitMax:    1 * time.Second,
			RetryIf:    func(err error) bool { return true },
		}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		err := WithRetry(ctx, config, func() error {
			return errors.New("error")
		})

		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.DeadlineExceeded))
	})
}

// ============================================================================
// Retry With Transient Errors Tests
// ============================================================================

func TestRetryWithTransientErrors(t *testing.T) {
	t.Run("retries on transient errors", func(t *testing.T) {
		config := &RetryConfig{
			MaxRetries: 5,
			WaitMin:    1 * time.Millisecond,
			WaitMax:    10 * time.Millisecond,
			RetryIf: func(err error) bool {
				return err.Error() == "transient"
			},
		}

		attempts := 0
		err := WithRetry(context.Background(), config, func() error {
			attempts++
			if attempts < 3 {
				return errors.New("transient")
			}
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 3, attempts)
	})
}

// ============================================================================
// No Retry For Permanent Errors Tests
// ============================================================================

func TestNoRetryForPermanentErrors(t *testing.T) {
	t.Run("does not retry permanent errors", func(t *testing.T) {
		permanentErr := errors.New("permanent error")

		config := &RetryConfig{
			MaxRetries: 5,
			WaitMin:    1 * time.Millisecond,
			WaitMax:    10 * time.Millisecond,
			RetryIf: func(err error) bool {
				return err.Error() != "permanent error"
			},
		}

		attempts := 0
		err := WithRetry(context.Background(), config, func() error {
			attempts++
			return permanentErr
		})

		assert.Error(t, err)
		assert.Equal(t, permanentErr, err)
		assert.Equal(t, 1, attempts) // Only one attempt
	})

	t.Run("uses IsRetryable by default", func(t *testing.T) {
		config := &RetryConfig{
			MaxRetries: 3,
			WaitMin:    1 * time.Millisecond,
			WaitMax:    10 * time.Millisecond,
			// RetryIf is nil, so IsRetryable will be used
		}

		attempts := 0
		err := WithRetry(context.Background(), config, func() error {
			attempts++
			return errors.New("non-retryable error")
		})

		assert.Error(t, err)
		// IsRetryable returns false for generic errors, so no retry
		assert.Equal(t, 1, attempts)
	})
}

// ============================================================================
// Full Jitter Backoff Tests
// ============================================================================

func TestFullJitterBackoff_NegativeAttempt(t *testing.T) {
	backoff := FullJitterBackoff(100*time.Millisecond, 10*time.Second)

	// Negative attempt should be treated as 0
	d := backoff(-1)
	assert.True(t, d >= 100*time.Millisecond, "backoff should be at least min")
	assert.True(t, d <= 10*time.Second, "backoff should be at most max")
}

// ============================================================================
// Equal Jitter Backoff Tests
// ============================================================================

func TestEqualJitterBackoff_NegativeAttempt(t *testing.T) {
	backoff := EqualJitterBackoff(100*time.Millisecond, 10*time.Second)

	// Negative attempt should be treated as 0
	d := backoff(-1)
	assert.True(t, d >= 50*time.Millisecond, "backoff should be at least half of min")
	assert.True(t, d <= 10*time.Second, "backoff should be at most max")
}

// ============================================================================
// CreateBackoffFunc Edge Cases Tests
// ============================================================================

func TestCreateBackoffFunc_EdgeCases(t *testing.T) {
	t.Run("zero multiplier uses default", func(t *testing.T) {
		config := &RetryConfig{
			WaitMin:           100 * time.Millisecond,
			WaitMax:           10 * time.Second,
			BackoffType:       BackoffTypeExponential,
			BackoffMultiplier: 0, // Should use default 2.0
			Jitter:            0.2,
		}

		backoff := createBackoffFunc(config)
		require.NotNil(t, backoff)

		d := backoff(0)
		assert.True(t, d >= 80*time.Millisecond, "backoff should be reasonable")
	})

	t.Run("negative jitter uses default", func(t *testing.T) {
		config := &RetryConfig{
			WaitMin:           100 * time.Millisecond,
			WaitMax:           10 * time.Second,
			BackoffType:       BackoffTypeExponential,
			BackoffMultiplier: 2.0,
			Jitter:            -0.5, // Should use default 0.2
		}

		backoff := createBackoffFunc(config)
		require.NotNil(t, backoff)

		d := backoff(0)
		assert.True(t, d >= 80*time.Millisecond, "backoff should be reasonable")
	})

	t.Run("jitter greater than 1 uses default", func(t *testing.T) {
		config := &RetryConfig{
			WaitMin:           100 * time.Millisecond,
			WaitMax:           10 * time.Second,
			BackoffType:       BackoffTypeExponential,
			BackoffMultiplier: 2.0,
			Jitter:            1.5, // Should use default 0.2
		}

		backoff := createBackoffFunc(config)
		require.NotNil(t, backoff)

		d := backoff(0)
		assert.True(t, d >= 80*time.Millisecond, "backoff should be reasonable")
	})
}

// ============================================================================
// NewRetryableOperation Tests
// ============================================================================

func TestNewRetryableOperation_NilConfig(t *testing.T) {
	op := NewRetryableOperation(nil)
	require.NotNil(t, op)
	require.NotNil(t, op.config)

	// Should use default config
	assert.Equal(t, 3, op.config.MaxRetries)
}

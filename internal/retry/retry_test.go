package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, cfg.InitialBackoff)
	assert.Equal(t, 30*time.Second, cfg.MaxBackoff)
	assert.Equal(t, 0.25, cfg.JitterFactor)
}

func TestConfig_GetMaxRetries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Config
		expected int
	}{
		{"nil config", nil, 3},
		{"zero value", &Config{MaxRetries: 0}, 3},
		{"negative value", &Config{MaxRetries: -1}, 3},
		{"custom value", &Config{MaxRetries: 5}, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetMaxRetries())
		})
	}
}

func TestConfig_GetInitialBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Config
		expected time.Duration
	}{
		{"nil config", nil, 100 * time.Millisecond},
		{"zero value", &Config{InitialBackoff: 0}, 100 * time.Millisecond},
		{"custom value", &Config{InitialBackoff: 500 * time.Millisecond}, 500 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetInitialBackoff())
		})
	}
}

func TestConfig_GetMaxBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Config
		expected time.Duration
	}{
		{"nil config", nil, 30 * time.Second},
		{"zero value", &Config{MaxBackoff: 0}, 30 * time.Second},
		{"custom value", &Config{MaxBackoff: 1 * time.Minute}, 1 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetMaxBackoff())
		})
	}
}

func TestConfig_GetJitterFactor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Config
		expected float64
	}{
		{"nil config", nil, 0.25},
		{"zero value", &Config{JitterFactor: 0}, 0.25},
		{"negative value", &Config{JitterFactor: -0.5}, 0.25},
		{"custom value", &Config{JitterFactor: 0.5}, 0.5},
		{"capped at 1.0", &Config{JitterFactor: 1.5}, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetJitterFactor())
		})
	}
}

func TestDo_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := &Config{
		MaxRetries:     3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	}

	callCount := 0
	err := Do(ctx, cfg, func() error {
		callCount++
		return nil
	}, nil)

	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestDo_RetryThenSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := &Config{
		MaxRetries:     3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	}

	callCount := 0
	err := Do(ctx, cfg, func() error {
		callCount++
		if callCount < 3 {
			return errors.New("temporary error")
		}
		return nil
	}, nil)

	assert.NoError(t, err)
	assert.Equal(t, 3, callCount)
}

func TestDo_AllRetriesFail(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := &Config{
		MaxRetries:     2,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	}

	expectedErr := errors.New("persistent error")
	callCount := 0
	err := Do(ctx, cfg, func() error {
		callCount++
		return expectedErr
	}, nil)

	assert.ErrorIs(t, err, expectedErr)
	assert.Equal(t, 3, callCount) // Initial + 2 retries
}

func TestDo_ContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := &Config{
		MaxRetries:     5,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
	}

	callCount := 0
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := Do(ctx, cfg, func() error {
		callCount++
		return errors.New("error")
	}, nil)

	assert.ErrorIs(t, err, context.Canceled)
}

func TestDo_ShouldRetryFunc(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := &Config{
		MaxRetries:     3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	}

	retryableErr := errors.New("retryable")
	nonRetryableErr := errors.New("non-retryable")

	callCount := 0
	err := Do(ctx, cfg, func() error {
		callCount++
		if callCount == 1 {
			return retryableErr
		}
		return nonRetryableErr
	}, &Options{
		ShouldRetry: func(err error) bool {
			return errors.Is(err, retryableErr)
		},
	})

	assert.ErrorIs(t, err, nonRetryableErr)
	assert.Equal(t, 2, callCount) // First call + one retry
}

func TestDo_OnRetryCallback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := &Config{
		MaxRetries:     2,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	}

	retryAttempts := []int{}
	err := Do(ctx, cfg, func() error {
		return errors.New("error")
	}, &Options{
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			retryAttempts = append(retryAttempts, attempt)
		},
	})

	assert.Error(t, err)
	assert.Equal(t, []int{1, 2}, retryAttempts)
}

func TestDo_NilConfig(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	callCount := 0
	err := Do(ctx, nil, func() error {
		callCount++
		return nil
	}, nil)

	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestCalculateBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		attempt        int
		initialBackoff time.Duration
		maxBackoff     time.Duration
		jitterFactor   float64
	}{
		{
			name:           "first attempt",
			attempt:        0,
			initialBackoff: 100 * time.Millisecond,
			maxBackoff:     10 * time.Second,
			jitterFactor:   0.25,
		},
		{
			name:           "second attempt",
			attempt:        1,
			initialBackoff: 100 * time.Millisecond,
			maxBackoff:     10 * time.Second,
			jitterFactor:   0.25,
		},
		{
			name:           "capped at max",
			attempt:        10,
			initialBackoff: 100 * time.Millisecond,
			maxBackoff:     1 * time.Second,
			jitterFactor:   0.25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backoff := CalculateBackoff(tt.attempt, tt.initialBackoff, tt.maxBackoff, tt.jitterFactor)

			// Backoff should be positive
			assert.Greater(t, backoff, time.Duration(0))

			// Backoff should not exceed max (with jitter)
			maxWithJitter := time.Duration(float64(tt.maxBackoff) * (1 + tt.jitterFactor))
			assert.LessOrEqual(t, backoff, maxWithJitter)
		})
	}
}

func TestCalculateBackoff_ExponentialGrowth(t *testing.T) {
	t.Parallel()

	initialBackoff := 100 * time.Millisecond
	maxBackoff := 10 * time.Second
	jitterFactor := 0.0 // No jitter for predictable testing

	backoff0 := CalculateBackoff(0, initialBackoff, maxBackoff, jitterFactor)
	backoff1 := CalculateBackoff(1, initialBackoff, maxBackoff, jitterFactor)
	backoff2 := CalculateBackoff(2, initialBackoff, maxBackoff, jitterFactor)

	// Each backoff should be approximately double the previous
	assert.Equal(t, 100*time.Millisecond, backoff0)
	assert.Equal(t, 200*time.Millisecond, backoff1)
	assert.Equal(t, 400*time.Millisecond, backoff2)
}

func TestDo_ContextCanceledBeforeFirstAttempt(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := DefaultConfig()

	callCount := 0
	err := Do(ctx, cfg, func() error {
		callCount++
		return nil
	}, nil)

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, callCount)
}

func TestDo_ContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	cfg := &Config{
		MaxRetries:     10,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
	}

	err := Do(ctx, cfg, func() error {
		return errors.New("error")
	}, nil)

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
}

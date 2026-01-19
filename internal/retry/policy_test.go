package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy_Execute_Success(t *testing.T) {
	policy := DefaultPolicy()

	callCount := 0
	result, err := policy.Execute(context.Background(), func() (interface{}, error) {
		callCount++
		return "success", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "success", result)
	assert.Equal(t, 1, callCount)
}

func TestPolicy_Execute_RetryOnError(t *testing.T) {
	policy := &Policy{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		BackoffFactor:  2.0,
		RetryOn:        []RetryCondition{AlwaysRetry()},
	}

	callCount := 0
	expectedErr := errors.New("test error")

	result, err := policy.Execute(context.Background(), func() (interface{}, error) {
		callCount++
		if callCount < 3 {
			return nil, expectedErr
		}
		return "success", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "success", result)
	assert.Equal(t, 3, callCount)
}

func TestPolicy_Execute_AllRetriesFail(t *testing.T) {
	policy := &Policy{
		MaxRetries:     2,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		BackoffFactor:  2.0,
		RetryOn:        []RetryCondition{AlwaysRetry()},
	}

	callCount := 0
	expectedErr := errors.New("persistent error")

	result, err := policy.Execute(context.Background(), func() (interface{}, error) {
		callCount++
		return nil, expectedErr
	})

	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
	assert.Equal(t, 3, callCount) // 1 initial + 2 retries
}

func TestPolicy_Execute_ContextCancellation(t *testing.T) {
	policy := &Policy{
		MaxRetries:     10,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
		BackoffFactor:  2.0,
		RetryOn:        []RetryCondition{AlwaysRetry()},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	callCount := 0
	_, err := policy.Execute(ctx, func() (interface{}, error) {
		callCount++
		return nil, errors.New("error")
	})

	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || callCount <= 2)
}

func TestPolicy_Execute_NoRetryOnSuccess(t *testing.T) {
	policy := DefaultPolicy()

	callCount := 0
	result, err := policy.Execute(context.Background(), func() (interface{}, error) {
		callCount++
		return "immediate success", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "immediate success", result)
	assert.Equal(t, 1, callCount)
}

func TestPolicy_Execute_NoRetryConditions(t *testing.T) {
	policy := &Policy{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		BackoffFactor:  2.0,
		RetryOn:        nil, // No conditions - will retry on any error
	}

	callCount := 0
	_, err := policy.Execute(context.Background(), func() (interface{}, error) {
		callCount++
		return nil, errors.New("error")
	})

	assert.Error(t, err)
	assert.Equal(t, 4, callCount) // 1 initial + 3 retries
}

func TestNoRetryPolicy(t *testing.T) {
	policy := NoRetryPolicy()

	callCount := 0
	_, err := policy.Execute(context.Background(), func() (interface{}, error) {
		callCount++
		return nil, errors.New("error")
	})

	assert.Error(t, err)
	assert.Equal(t, 1, callCount)
}

func TestPolicy_ExecuteWithStatusCode(t *testing.T) {
	policy := &Policy{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		BackoffFactor:  2.0,
		RetryOn:        []RetryCondition{RetryOn5xx()},
	}

	callCount := 0
	result, statusCode, err := policy.ExecuteWithStatusCode(context.Background(), func() (interface{}, int, error) {
		callCount++
		if callCount < 3 {
			return nil, 503, nil
		}
		return "success", 200, nil
	})

	require.NoError(t, err)
	assert.Equal(t, "success", result)
	assert.Equal(t, 200, statusCode)
	assert.Equal(t, 3, callCount)
}

func TestPolicy_Validate(t *testing.T) {
	policy := &Policy{
		MaxRetries:     -1,
		InitialBackoff: 0,
		MaxBackoff:     0,
		BackoffFactor:  0,
		Jitter:         2.0,
	}

	policy.Validate()

	assert.Equal(t, 0, policy.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, policy.InitialBackoff)
	assert.Equal(t, 10*time.Second, policy.MaxBackoff)
	assert.Equal(t, 2.0, policy.BackoffFactor)
	assert.Equal(t, 0.1, policy.Jitter)
}

func TestPolicy_WithMethods(t *testing.T) {
	policy := DefaultPolicy().
		WithMaxRetries(5).
		WithInitialBackoff(50 * time.Millisecond).
		WithMaxBackoff(5 * time.Second).
		WithBackoffFactor(3.0).
		WithJitter(0.2).
		WithRetryOn(RetryOn5xx())

	assert.Equal(t, 5, policy.MaxRetries)
	assert.Equal(t, 50*time.Millisecond, policy.InitialBackoff)
	assert.Equal(t, 5*time.Second, policy.MaxBackoff)
	assert.Equal(t, 3.0, policy.BackoffFactor)
	assert.Equal(t, 0.2, policy.Jitter)
	assert.Len(t, policy.RetryOn, 1)
}

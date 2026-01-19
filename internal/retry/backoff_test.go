package retry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Cases for ExponentialBackoff
// ============================================================================

func TestExponentialBackoff_FirstAttemptReturnsInitialInterval(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second
	factor := 2.0
	jitter := 0.0 // No jitter for deterministic test

	backoff := NewExponentialBackoff(initial, max, factor, jitter)

	result := backoff.Next(0)
	assert.Equal(t, initial, result)
}

func TestExponentialBackoff_SubsequentAttemptsIncreaseExponentially(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second
	factor := 2.0
	jitter := 0.0 // No jitter for deterministic test

	backoff := NewExponentialBackoff(initial, max, factor, jitter)

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 100 * time.Millisecond},  // 100 * 2^0 = 100
		{1, 200 * time.Millisecond},  // 100 * 2^1 = 200
		{2, 400 * time.Millisecond},  // 100 * 2^2 = 400
		{3, 800 * time.Millisecond},  // 100 * 2^3 = 800
		{4, 1600 * time.Millisecond}, // 100 * 2^4 = 1600
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := backoff.Next(tt.attempt)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExponentialBackoff_MaxIntervalIsRespected(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 500 * time.Millisecond
	factor := 2.0
	jitter := 0.0

	backoff := NewExponentialBackoff(initial, max, factor, jitter)

	// Attempt 10 would be 100 * 2^10 = 102400ms, but should be capped at 500ms
	result := backoff.Next(10)
	assert.Equal(t, max, result)
}

func TestExponentialBackoff_JitterIsApplied(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second
	factor := 2.0
	jitter := 0.5 // 50% jitter

	backoff := NewExponentialBackoff(initial, max, factor, jitter)

	// Run multiple times to verify jitter produces different values
	results := make(map[time.Duration]bool)
	for i := 0; i < 100; i++ {
		result := backoff.Next(0)
		results[result] = true

		// With 50% jitter on 100ms, result should be between 50ms and 150ms
		assert.GreaterOrEqual(t, result, 50*time.Millisecond)
		assert.LessOrEqual(t, result, 150*time.Millisecond)
	}

	// Should have some variation (not all the same value)
	assert.Greater(t, len(results), 1, "Jitter should produce different values")
}

func TestExponentialBackoff_NegativeAttemptIsTreatedAsZero(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second
	factor := 2.0
	jitter := 0.0

	backoff := NewExponentialBackoff(initial, max, factor, jitter)

	result := backoff.Next(-5)
	assert.Equal(t, initial, result)
}

func TestExponentialBackoff_Reset(t *testing.T) {
	backoff := NewExponentialBackoff(100*time.Millisecond, 10*time.Second, 2.0, 0.0)

	// Make some calls
	_ = backoff.Next(0)
	_ = backoff.Next(1)
	_ = backoff.Next(2)

	// Reset is a no-op for ExponentialBackoff (stateless)
	backoff.Reset()

	// Should still work correctly after reset
	result := backoff.Next(0)
	assert.Equal(t, 100*time.Millisecond, result)
}

// ============================================================================
// Test Cases for ConstantBackoff
// ============================================================================

func TestConstantBackoff_AlwaysReturnsSameInterval(t *testing.T) {
	interval := 500 * time.Millisecond
	backoff := NewConstantBackoff(interval)

	tests := []int{0, 1, 5, 10, 100}
	for _, attempt := range tests {
		t.Run("", func(t *testing.T) {
			result := backoff.Next(attempt)
			assert.Equal(t, interval, result)
		})
	}
}

func TestConstantBackoff_Reset(t *testing.T) {
	backoff := NewConstantBackoff(500 * time.Millisecond)

	// Make some calls
	_ = backoff.Next(0)
	_ = backoff.Next(1)

	// Reset is a no-op for ConstantBackoff (stateless)
	backoff.Reset()

	// Should still work correctly after reset
	result := backoff.Next(0)
	assert.Equal(t, 500*time.Millisecond, result)
}

// ============================================================================
// Test Cases for LinearBackoff
// ============================================================================

func TestLinearBackoff_FirstAttemptReturnsInitialInterval(t *testing.T) {
	initial := 100 * time.Millisecond
	increment := 50 * time.Millisecond
	max := 1 * time.Second

	backoff := NewLinearBackoff(initial, increment, max)

	result := backoff.Next(0)
	assert.Equal(t, initial, result)
}

func TestLinearBackoff_SubsequentAttemptsIncreaseLinearly(t *testing.T) {
	initial := 100 * time.Millisecond
	increment := 50 * time.Millisecond
	max := 1 * time.Second

	backoff := NewLinearBackoff(initial, increment, max)

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 100 * time.Millisecond}, // 100 + 0*50 = 100
		{1, 150 * time.Millisecond}, // 100 + 1*50 = 150
		{2, 200 * time.Millisecond}, // 100 + 2*50 = 200
		{3, 250 * time.Millisecond}, // 100 + 3*50 = 250
		{4, 300 * time.Millisecond}, // 100 + 4*50 = 300
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := backoff.Next(tt.attempt)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLinearBackoff_MaxIntervalIsRespected(t *testing.T) {
	initial := 100 * time.Millisecond
	increment := 50 * time.Millisecond
	max := 200 * time.Millisecond

	backoff := NewLinearBackoff(initial, increment, max)

	// Attempt 10 would be 100 + 10*50 = 600ms, but should be capped at 200ms
	result := backoff.Next(10)
	assert.Equal(t, max, result)
}

func TestLinearBackoff_NegativeAttemptIsTreatedAsZero(t *testing.T) {
	initial := 100 * time.Millisecond
	increment := 50 * time.Millisecond
	max := 1 * time.Second

	backoff := NewLinearBackoff(initial, increment, max)

	result := backoff.Next(-5)
	assert.Equal(t, initial, result)
}

func TestLinearBackoff_Reset(t *testing.T) {
	backoff := NewLinearBackoff(100*time.Millisecond, 50*time.Millisecond, 1*time.Second)

	// Make some calls
	_ = backoff.Next(0)
	_ = backoff.Next(1)
	_ = backoff.Next(2)

	// Reset is a no-op for LinearBackoff (stateless)
	backoff.Reset()

	// Should still work correctly after reset
	result := backoff.Next(0)
	assert.Equal(t, 100*time.Millisecond, result)
}

// ============================================================================
// Test Cases for FibonacciBackoff
// ============================================================================

func TestFibonacciBackoff_SequenceIsCorrect(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewFibonacciBackoff(initial, max)

	// Fibonacci sequence: 1, 1, 2, 3, 5, 8, 13, 21...
	// For attempt n, we use fibonacci(n+1)
	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 100 * time.Millisecond},  // fib(1) = 1, 1 * 100 = 100
		{1, 100 * time.Millisecond},  // fib(2) = 1, 1 * 100 = 100
		{2, 200 * time.Millisecond},  // fib(3) = 2, 2 * 100 = 200
		{3, 300 * time.Millisecond},  // fib(4) = 3, 3 * 100 = 300
		{4, 500 * time.Millisecond},  // fib(5) = 5, 5 * 100 = 500
		{5, 800 * time.Millisecond},  // fib(6) = 8, 8 * 100 = 800
		{6, 1300 * time.Millisecond}, // fib(7) = 13, 13 * 100 = 1300
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := backoff.Next(tt.attempt)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFibonacciBackoff_MaxIntervalIsRespected(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 500 * time.Millisecond

	backoff := NewFibonacciBackoff(initial, max)

	// Attempt 10 would be fib(11) * 100 = 89 * 100 = 8900ms, but should be capped at 500ms
	result := backoff.Next(10)
	assert.Equal(t, max, result)
}

func TestFibonacciBackoff_NegativeAttemptIsTreatedAsZero(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewFibonacciBackoff(initial, max)

	result := backoff.Next(-5)
	// fib(1) = 1, 1 * 100 = 100
	assert.Equal(t, 100*time.Millisecond, result)
}

func TestFibonacciBackoff_Reset(t *testing.T) {
	backoff := NewFibonacciBackoff(100*time.Millisecond, 10*time.Second)

	// Make some calls
	_ = backoff.Next(0)
	_ = backoff.Next(1)
	_ = backoff.Next(2)

	// Reset is a no-op for FibonacciBackoff (stateless)
	backoff.Reset()

	// Should still work correctly after reset
	result := backoff.Next(0)
	assert.Equal(t, 100*time.Millisecond, result)
}

// ============================================================================
// Test Cases for fibonacci() helper function
// ============================================================================

func TestFibonacci_NEqualsZeroReturnsZero(t *testing.T) {
	result := fibonacci(0)
	assert.Equal(t, 0, result)
}

func TestFibonacci_NEqualsOneReturnsOne(t *testing.T) {
	result := fibonacci(1)
	assert.Equal(t, 1, result)
}

func TestFibonacci_SequenceIsCorrect(t *testing.T) {
	// Fibonacci sequence: 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55...
	tests := []struct {
		n        int
		expected int
	}{
		{0, 0},
		{1, 1},
		{2, 1},
		{3, 2},
		{4, 3},
		{5, 5},
		{6, 8},
		{7, 13},
		{8, 21},
		{9, 34},
		{10, 55},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := fibonacci(tt.n)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFibonacci_NegativeReturnsZero(t *testing.T) {
	result := fibonacci(-5)
	assert.Equal(t, 0, result)
}

// ============================================================================
// Test Cases for DecorrelatedJitterBackoff
// ============================================================================

func TestDecorrelatedJitterBackoff_FirstAttemptReturnsInitialInterval(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewDecorrelatedJitterBackoff(initial, max)

	result := backoff.Next(0)
	assert.Equal(t, initial, result)
}

func TestDecorrelatedJitterBackoff_SubsequentAttemptsAreWithinExpectedRange(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewDecorrelatedJitterBackoff(initial, max)

	// First call to set current
	_ = backoff.Next(0)

	// Subsequent calls should be between initial and current*3
	for i := 1; i < 10; i++ {
		result := backoff.Next(i)
		// Result should be >= initial and <= max
		assert.GreaterOrEqual(t, result, initial)
		assert.LessOrEqual(t, result, max)
	}
}

func TestDecorrelatedJitterBackoff_MaxIntervalIsRespected(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 200 * time.Millisecond

	backoff := NewDecorrelatedJitterBackoff(initial, max)

	// Run many iterations to ensure max is never exceeded
	for i := 0; i < 100; i++ {
		result := backoff.Next(i)
		assert.LessOrEqual(t, result, max)
	}
}

func TestDecorrelatedJitterBackoff_ResetResetsCurrentToInitial(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewDecorrelatedJitterBackoff(initial, max)

	// Make some calls to change current
	_ = backoff.Next(0)
	_ = backoff.Next(1)
	_ = backoff.Next(2)

	// Reset
	backoff.Reset()

	// After reset, first call should return initial
	result := backoff.Next(0)
	assert.Equal(t, initial, result)
}

// ============================================================================
// Test Cases for FullJitterBackoff
// ============================================================================

func TestFullJitterBackoff_ReturnsValueBetweenZeroAndCeiling(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewFullJitterBackoff(initial, max)

	for attempt := 0; attempt < 5; attempt++ {
		// Calculate expected ceiling: initial * 2^attempt
		ceiling := time.Duration(float64(initial) * float64(int(1)<<attempt))
		if ceiling > max {
			ceiling = max
		}

		for i := 0; i < 50; i++ {
			result := backoff.Next(attempt)
			// Full jitter: result should be between 0 and ceiling
			assert.GreaterOrEqual(t, result, time.Duration(0))
			assert.LessOrEqual(t, result, ceiling)
		}
	}
}

func TestFullJitterBackoff_MaxIntervalIsRespected(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 200 * time.Millisecond

	backoff := NewFullJitterBackoff(initial, max)

	// Run many iterations with high attempt to ensure max is never exceeded
	for i := 0; i < 100; i++ {
		result := backoff.Next(10)
		assert.LessOrEqual(t, result, max)
	}
}

func TestFullJitterBackoff_NegativeAttemptIsTreatedAsZero(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewFullJitterBackoff(initial, max)

	for i := 0; i < 50; i++ {
		result := backoff.Next(-5)
		// Should be between 0 and initial (ceiling for attempt 0)
		assert.GreaterOrEqual(t, result, time.Duration(0))
		assert.LessOrEqual(t, result, initial)
	}
}

func TestFullJitterBackoff_Reset(t *testing.T) {
	backoff := NewFullJitterBackoff(100*time.Millisecond, 10*time.Second)

	// Make some calls
	_ = backoff.Next(0)
	_ = backoff.Next(1)
	_ = backoff.Next(2)

	// Reset is a no-op for FullJitterBackoff (stateless)
	backoff.Reset()

	// Should still work correctly after reset
	result := backoff.Next(0)
	assert.GreaterOrEqual(t, result, time.Duration(0))
	assert.LessOrEqual(t, result, 100*time.Millisecond)
}

// ============================================================================
// Test Cases for EqualJitterBackoff
// ============================================================================

func TestEqualJitterBackoff_ReturnsValueBetweenHalfAndFullCeiling(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewEqualJitterBackoff(initial, max)

	for attempt := 0; attempt < 5; attempt++ {
		// Calculate expected ceiling: initial * 2^attempt
		ceiling := time.Duration(float64(initial) * float64(int(1)<<attempt))
		if ceiling > max {
			ceiling = max
		}
		halfCeiling := ceiling / 2

		for i := 0; i < 50; i++ {
			result := backoff.Next(attempt)
			// Equal jitter: result should be between half and full ceiling
			assert.GreaterOrEqual(t, result, halfCeiling)
			assert.LessOrEqual(t, result, ceiling)
		}
	}
}

func TestEqualJitterBackoff_MaxIntervalIsRespected(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 200 * time.Millisecond

	backoff := NewEqualJitterBackoff(initial, max)

	// Run many iterations with high attempt to ensure max is never exceeded
	for i := 0; i < 100; i++ {
		result := backoff.Next(10)
		assert.LessOrEqual(t, result, max)
	}
}

func TestEqualJitterBackoff_NegativeAttemptIsTreatedAsZero(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 10 * time.Second

	backoff := NewEqualJitterBackoff(initial, max)

	for i := 0; i < 50; i++ {
		result := backoff.Next(-5)
		// Should be between half and full initial (ceiling for attempt 0)
		assert.GreaterOrEqual(t, result, initial/2)
		assert.LessOrEqual(t, result, initial)
	}
}

func TestEqualJitterBackoff_Reset(t *testing.T) {
	backoff := NewEqualJitterBackoff(100*time.Millisecond, 10*time.Second)

	// Make some calls
	_ = backoff.Next(0)
	_ = backoff.Next(1)
	_ = backoff.Next(2)

	// Reset is a no-op for EqualJitterBackoff (stateless)
	backoff.Reset()

	// Should still work correctly after reset
	result := backoff.Next(0)
	assert.GreaterOrEqual(t, result, 50*time.Millisecond)
	assert.LessOrEqual(t, result, 100*time.Millisecond)
}

// ============================================================================
// Test Cases for DefaultBackoffConfig
// ============================================================================

func TestDefaultBackoffConfig_ReturnsExpectedDefaultValues(t *testing.T) {
	config := DefaultBackoffConfig()

	assert.Equal(t, BackoffTypeDecorrelatedJitter, config.Type)
	assert.Equal(t, 100*time.Millisecond, config.InitialInterval)
	assert.Equal(t, 30*time.Second, config.MaxInterval)
	assert.Equal(t, 2.0, config.Multiplier)
	assert.Equal(t, 0.2, config.Jitter)
	assert.Equal(t, 100*time.Millisecond, config.Increment)
}

// ============================================================================
// Test Cases for ExternalServiceBackoffConfig
// ============================================================================

func TestExternalServiceBackoffConfig_ReturnsExpectedValues(t *testing.T) {
	config := ExternalServiceBackoffConfig()

	assert.Equal(t, BackoffTypeDecorrelatedJitter, config.Type)
	assert.Equal(t, 500*time.Millisecond, config.InitialInterval)
	assert.Equal(t, 60*time.Second, config.MaxInterval)
	assert.Equal(t, 2.0, config.Multiplier)
	assert.Equal(t, 0.3, config.Jitter)
}

// ============================================================================
// Test Cases for NewBackoffFromConfig
// ============================================================================

func TestNewBackoffFromConfig_NilConfigUsesDefaults(t *testing.T) {
	backoff := NewBackoffFromConfig(nil)

	require.NotNil(t, backoff)
	// Should be DecorrelatedJitterBackoff (default type)
	_, ok := backoff.(*DecorrelatedJitterBackoff)
	assert.True(t, ok, "Expected DecorrelatedJitterBackoff for nil config")
}

func TestNewBackoffFromConfig_ExponentialType(t *testing.T) {
	config := &BackoffConfig{
		Type:            BackoffTypeExponential,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:          0.1,
	}

	backoff := NewBackoffFromConfig(config)

	require.NotNil(t, backoff)
	_, ok := backoff.(*ExponentialBackoff)
	assert.True(t, ok, "Expected ExponentialBackoff")
}

func TestNewBackoffFromConfig_DecorrelatedJitterType(t *testing.T) {
	config := &BackoffConfig{
		Type:            BackoffTypeDecorrelatedJitter,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     10 * time.Second,
	}

	backoff := NewBackoffFromConfig(config)

	require.NotNil(t, backoff)
	_, ok := backoff.(*DecorrelatedJitterBackoff)
	assert.True(t, ok, "Expected DecorrelatedJitterBackoff")
}

func TestNewBackoffFromConfig_ConstantType(t *testing.T) {
	config := &BackoffConfig{
		Type:            BackoffTypeConstant,
		InitialInterval: 500 * time.Millisecond,
	}

	backoff := NewBackoffFromConfig(config)

	require.NotNil(t, backoff)
	_, ok := backoff.(*ConstantBackoff)
	assert.True(t, ok, "Expected ConstantBackoff")

	// Verify it returns the correct interval
	result := backoff.Next(0)
	assert.Equal(t, 500*time.Millisecond, result)
}

func TestNewBackoffFromConfig_LinearType(t *testing.T) {
	config := &BackoffConfig{
		Type:            BackoffTypeLinear,
		InitialInterval: 100 * time.Millisecond,
		Increment:       50 * time.Millisecond,
		MaxInterval:     1 * time.Second,
	}

	backoff := NewBackoffFromConfig(config)

	require.NotNil(t, backoff)
	_, ok := backoff.(*LinearBackoff)
	assert.True(t, ok, "Expected LinearBackoff")
}

func TestNewBackoffFromConfig_FibonacciType(t *testing.T) {
	config := &BackoffConfig{
		Type:            BackoffTypeFibonacci,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     10 * time.Second,
	}

	backoff := NewBackoffFromConfig(config)

	require.NotNil(t, backoff)
	_, ok := backoff.(*FibonacciBackoff)
	assert.True(t, ok, "Expected FibonacciBackoff")
}

func TestNewBackoffFromConfig_UnknownTypeDefaultsToDecorrelatedJitter(t *testing.T) {
	config := &BackoffConfig{
		Type:            BackoffType("unknown"),
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     10 * time.Second,
	}

	backoff := NewBackoffFromConfig(config)

	require.NotNil(t, backoff)
	_, ok := backoff.(*DecorrelatedJitterBackoff)
	assert.True(t, ok, "Expected DecorrelatedJitterBackoff for unknown type")
}

// ============================================================================
// Test Cases for Backoff Interface Compliance
// ============================================================================

func TestBackoffInterfaceCompliance(t *testing.T) {
	// Verify all backoff types implement the Backoff interface
	var _ Backoff = &ExponentialBackoff{}
	var _ Backoff = &ConstantBackoff{}
	var _ Backoff = &LinearBackoff{}
	var _ Backoff = &FibonacciBackoff{}
	var _ Backoff = &DecorrelatedJitterBackoff{}
	var _ Backoff = &FullJitterBackoff{}
	var _ Backoff = &EqualJitterBackoff{}
}

// ============================================================================
// Test Cases for Concurrent Access
// ============================================================================

func TestExponentialBackoff_ConcurrentAccess(t *testing.T) {
	backoff := NewExponentialBackoff(100*time.Millisecond, 10*time.Second, 2.0, 0.5)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(attempt int) {
			for j := 0; j < 100; j++ {
				_ = backoff.Next(attempt)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestDecorrelatedJitterBackoff_ConcurrentAccess(t *testing.T) {
	backoff := NewDecorrelatedJitterBackoff(100*time.Millisecond, 10*time.Second)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(attempt int) {
			for j := 0; j < 100; j++ {
				_ = backoff.Next(attempt)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestFullJitterBackoff_ConcurrentAccess(t *testing.T) {
	backoff := NewFullJitterBackoff(100*time.Millisecond, 10*time.Second)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(attempt int) {
			for j := 0; j < 100; j++ {
				_ = backoff.Next(attempt)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestEqualJitterBackoff_ConcurrentAccess(t *testing.T) {
	backoff := NewEqualJitterBackoff(100*time.Millisecond, 10*time.Second)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(attempt int) {
			for j := 0; j < 100; j++ {
				_ = backoff.Next(attempt)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// ============================================================================
// Table-Driven Tests
// ============================================================================

func TestBackoffTypes_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		backoffType BackoffType
		expected    interface{}
	}{
		{
			name:        "Exponential",
			backoffType: BackoffTypeExponential,
			expected:    &ExponentialBackoff{},
		},
		{
			name:        "DecorrelatedJitter",
			backoffType: BackoffTypeDecorrelatedJitter,
			expected:    &DecorrelatedJitterBackoff{},
		},
		{
			name:        "Constant",
			backoffType: BackoffTypeConstant,
			expected:    &ConstantBackoff{},
		},
		{
			name:        "Linear",
			backoffType: BackoffTypeLinear,
			expected:    &LinearBackoff{},
		},
		{
			name:        "Fibonacci",
			backoffType: BackoffTypeFibonacci,
			expected:    &FibonacciBackoff{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &BackoffConfig{
				Type:            tt.backoffType,
				InitialInterval: 100 * time.Millisecond,
				MaxInterval:     10 * time.Second,
				Multiplier:      2.0,
				Jitter:          0.1,
				Increment:       50 * time.Millisecond,
			}

			backoff := NewBackoffFromConfig(config)
			require.NotNil(t, backoff)

			// Verify the backoff works
			result := backoff.Next(0)
			assert.GreaterOrEqual(t, result, time.Duration(0))
		})
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestExponentialBackoff_ZeroJitter(t *testing.T) {
	backoff := NewExponentialBackoff(100*time.Millisecond, 10*time.Second, 2.0, 0.0)

	// With zero jitter, results should be deterministic
	result1 := backoff.Next(0)
	result2 := backoff.Next(0)
	assert.Equal(t, result1, result2)
}

func TestExponentialBackoff_LargeAttempt(t *testing.T) {
	backoff := NewExponentialBackoff(100*time.Millisecond, 1*time.Second, 2.0, 0.0)

	// Very large attempt should be capped at max
	result := backoff.Next(1000)
	assert.Equal(t, 1*time.Second, result)
}

func TestLinearBackoff_ZeroIncrement(t *testing.T) {
	backoff := NewLinearBackoff(100*time.Millisecond, 0, 1*time.Second)

	// With zero increment, all attempts should return initial
	for i := 0; i < 10; i++ {
		result := backoff.Next(i)
		assert.Equal(t, 100*time.Millisecond, result)
	}
}

func TestConstantBackoff_ZeroInterval(t *testing.T) {
	backoff := NewConstantBackoff(0)

	result := backoff.Next(0)
	assert.Equal(t, time.Duration(0), result)
}

func TestExponentialBackoff_HighJitterEnsuresNonNegative(t *testing.T) {
	// Use very high jitter (2.0 = 200%) which could make backoff negative
	// The implementation should ensure non-negative result
	initial := 10 * time.Millisecond
	max := 10 * time.Second
	factor := 2.0
	jitter := 2.0 // 200% jitter - can definitely make backoff negative

	backoff := NewExponentialBackoff(initial, max, factor, jitter)

	// Run many iterations to try to trigger the negative case
	// With 200% jitter, there's a good chance of hitting negative values
	for i := 0; i < 10000; i++ {
		result := backoff.Next(0)
		assert.GreaterOrEqual(t, result, time.Duration(0), "Backoff should never be negative")
	}
}

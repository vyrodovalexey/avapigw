package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// ============================================================================
// Test Cases for Metrics Recording on Success
// ============================================================================

func TestCircuitBreaker_RecordSuccess(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-success", DefaultConfig(), logger)

	// Record initial success
	initialStats := cb.Stats()
	assert.Equal(t, 0, initialStats.Successes)

	// Record a success
	cb.RecordSuccess()

	stats := cb.Stats()
	assert.Equal(t, 1, stats.Successes)
	assert.Equal(t, 0, stats.ConsecutiveFails)
	assert.Equal(t, 1, stats.TotalRequests)
}

func TestCircuitBreaker_RecordSuccess_ClosesHalfOpenCircuit(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1
	config.Timeout = 10 * time.Millisecond
	config.SuccessThreshold = 1

	cb := NewCircuitBreaker("test-halfopen-success", config, logger)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Allow request to transition to half-open
	assert.True(t, cb.Allow())
	assert.Equal(t, StateHalfOpen, cb.State())

	// Record success - should close the circuit
	cb.RecordSuccess()

	assert.Equal(t, StateClosed, cb.State())
}

// ============================================================================
// Test Cases for Metrics Recording on Failure
// ============================================================================

func TestCircuitBreaker_RecordFailure(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-failure", DefaultConfig(), logger)

	// Record initial state
	initialStats := cb.Stats()
	assert.Equal(t, 0, initialStats.Failures)

	// Record a failure
	cb.RecordFailure()

	stats := cb.Stats()
	assert.Equal(t, 1, stats.Failures)
	assert.Equal(t, 1, stats.ConsecutiveFails)
	assert.Equal(t, 1, stats.TotalRequests)
}

func TestCircuitBreaker_RecordFailure_OpensCircuit(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 3

	cb := NewCircuitBreaker("test-open", config, logger)

	// Record failures until circuit opens
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	assert.Equal(t, StateOpen, cb.State())
	// Note: Counters are reset when state transitions to Open
	// This is expected behavior - counters track the current state's metrics
	assert.Equal(t, 0, cb.Stats().Failures)
	assert.Equal(t, 0, cb.Stats().ConsecutiveFails)
}

func TestCircuitBreaker_RecordFailure_OpensHalfOpenCircuit(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1
	config.Timeout = 10 * time.Millisecond

	cb := NewCircuitBreaker("test-halfopen-fail", config, logger)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Allow request to transition to half-open
	assert.True(t, cb.Allow())
	assert.Equal(t, StateHalfOpen, cb.State())

	// Record failure in half-open state - should open circuit again
	cb.RecordFailure()

	assert.Equal(t, StateOpen, cb.State())
}

// ============================================================================
// Test Cases for Metrics Recording on State Change
// ============================================================================

func TestCircuitBreaker_StateChange_OpenOnFailure(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1

	cb := NewCircuitBreaker("test-state-change", config, logger)

	assert.Equal(t, StateClosed, cb.State())

	// Open the circuit
	cb.RecordFailure()

	assert.Equal(t, StateOpen, cb.State())
	assert.False(t, cb.Allow())
}

func TestCircuitBreaker_StateChange_HalfOpenAfterTimeout(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1
	config.Timeout = 10 * time.Millisecond

	cb := NewCircuitBreaker("test-timeout", config, logger)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Should transition to half-open on next Allow
	assert.True(t, cb.Allow())
	assert.Equal(t, StateHalfOpen, cb.State())
}

func TestCircuitBreaker_StateChange_CloseOnSuccess(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1
	config.Timeout = 10 * time.Millisecond
	config.SuccessThreshold = 1

	cb := NewCircuitBreaker("test-close", config, logger)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Transition to half-open
	cb.Allow()
	assert.Equal(t, StateHalfOpen, cb.State())

	// Record success - should close circuit
	cb.RecordSuccess()

	assert.Equal(t, StateClosed, cb.State())
}

// ============================================================================
// Test Cases for Metrics Recording on Request Allow/Deny
// ============================================================================

func TestCircuitBreaker_Allow_ClosedState(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-allow-closed", DefaultConfig(), logger)

	// Should allow in closed state
	assert.True(t, cb.Allow())
	assert.Equal(t, StateClosed, cb.State())
}

func TestCircuitBreaker_Allow_OpenState(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1

	cb := NewCircuitBreaker("test-allow-open", config, logger)

	// Open the circuit
	cb.RecordFailure()

	// Should deny in open state
	assert.False(t, cb.Allow())
	assert.Equal(t, StateOpen, cb.State())
}

func TestCircuitBreaker_Allow_HalfOpenState(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1
	config.Timeout = 10 * time.Millisecond
	config.HalfOpenMax = 2

	cb := NewCircuitBreaker("test-allow-halfopen", config, logger)

	// Open the circuit
	cb.RecordFailure()

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// First request should be allowed (transitions to half-open)
	assert.True(t, cb.Allow())
	assert.Equal(t, StateHalfOpen, cb.State())

	// Second request should also be allowed
	assert.True(t, cb.Allow())

	// Third request should be denied (exceeded half-open max)
	assert.False(t, cb.Allow())
}

// ============================================================================
// Test Cases for Execute with Metrics
// ============================================================================

func TestCircuitBreaker_Execute_Success(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-exec-success", DefaultConfig(), logger)

	// Execute a successful function
	err := cb.Execute(context.Background(), func() error {
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, StateClosed, cb.State())
	assert.Equal(t, 1, cb.Stats().Successes)
}

func TestCircuitBreaker_Execute_Failure(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-exec-fail", DefaultConfig(), logger)

	testErr := errors.New("test error")

	// Execute a failing function
	err := cb.Execute(context.Background(), func() error {
		return testErr
	})

	assert.Equal(t, testErr, err)
	assert.Equal(t, StateClosed, cb.State())
	assert.Equal(t, 1, cb.Stats().Failures)
}

func TestCircuitBreaker_Execute_CircuitOpen(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1

	cb := NewCircuitBreaker("test-exec-open", config, logger)

	// Open the circuit
	cb.RecordFailure()

	// Execute should return circuit open error
	err := cb.Execute(context.Background(), func() error {
		return nil
	})

	assert.Equal(t, ErrCircuitOpen, err)
	assert.Equal(t, StateOpen, cb.State())
}

// ============================================================================
// Test Cases for ExecuteWithFallback
// ============================================================================

func TestCircuitBreaker_ExecuteWithFallback_CircuitOpen(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1

	cb := NewCircuitBreaker("test-fallback", config, logger)

	// Open the circuit
	cb.RecordFailure()

	// Execute with fallback
	fallbackCalled := false
	err := cb.ExecuteWithFallback(context.Background(), func() error {
		return nil
	}, func(e error) error {
		fallbackCalled = true
		return e
	})

	assert.True(t, fallbackCalled)
	assert.Equal(t, ErrCircuitOpen, err)
}

func TestCircuitBreaker_ExecuteWithFallback_Success(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-fallback-success", DefaultConfig(), logger)

	// Execute with fallback - should not call fallback
	fallbackCalled := false
	err := cb.ExecuteWithFallback(context.Background(), func() error {
		return nil
	}, func(e error) error {
		fallbackCalled = true
		return e
	})

	assert.False(t, fallbackCalled)
	assert.NoError(t, err)
}

// ============================================================================
// Test Cases for Reset
// ============================================================================

func TestCircuitBreaker_Reset(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1

	cb := NewCircuitBreaker("test-reset", config, logger)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())
	// Note: Counters are reset when state transitions to Open
	// So failures will be 0 after the transition
	assert.Equal(t, 0, cb.Stats().Failures)

	// Reset
	cb.Reset()

	// Should be closed with reset counters
	assert.Equal(t, StateClosed, cb.State())
	assert.Equal(t, 0, cb.Stats().Failures)
	assert.Equal(t, 0, cb.Stats().Successes)
	assert.Equal(t, 0, cb.Stats().ConsecutiveFails)
}

// ============================================================================
// Test Cases for Stats
// ============================================================================

func TestCircuitBreaker_Stats(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-stats", DefaultConfig(), logger)

	// Initial stats
	stats := cb.Stats()
	assert.Equal(t, StateClosed, stats.State)
	assert.Equal(t, 0, stats.Failures)
	assert.Equal(t, 0, stats.Successes)
	assert.Equal(t, 0, stats.TotalRequests)

	// Record some operations
	cb.RecordSuccess()
	cb.RecordSuccess()
	cb.RecordFailure()

	stats = cb.Stats()
	assert.Equal(t, 1, stats.Failures)
	assert.Equal(t, 2, stats.Successes)
	assert.Equal(t, 3, stats.TotalRequests)
}

func TestCircuitBreaker_FailureRatio(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-ratio", DefaultConfig(), logger)

	// Record failures and successes
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	for i := 0; i < 7; i++ {
		cb.RecordSuccess()
	}

	stats := cb.Stats()
	assert.Equal(t, float64(3)/float64(10), stats.FailureRatio())
}

// ============================================================================
// Test Cases for IsSuccessful
// ============================================================================

func TestCircuitBreaker_IsSuccessful_Default(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("test-default-success", DefaultConfig(), logger)

	// nil error should be success
	assert.True(t, cb.isSuccessful(nil))

	// non-nil error should be failure
	assert.False(t, cb.isSuccessful(errors.New("error")))
}

func TestCircuitBreaker_IsSuccessful_Custom(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.IsSuccessful = func(err error) bool {
		return err == nil || err.Error() == "non-critical"
	}

	cb := NewCircuitBreaker("test-custom-success", config, logger)

	// nil error should be success
	assert.True(t, cb.isSuccessful(nil))

	// "non-critical" error should be success
	assert.True(t, cb.isSuccessful(errors.New("non-critical")))

	// "critical" error should be failure
	assert.False(t, cb.isSuccessful(errors.New("critical")))
}

// ============================================================================
// Test Cases for Thread Safety
// ============================================================================

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Use a high MaxFailures to prevent state transitions during the test
	config := DefaultConfig()
	config.MaxFailures = 10000 // Prevent circuit from opening

	cb := NewCircuitBreaker("test-concurrent", config, logger)

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent Allow calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				cb.Allow()
			}
		}()
	}

	// Concurrent RecordSuccess calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				cb.RecordSuccess()
			}
		}()
	}

	// Concurrent RecordFailure calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				cb.RecordFailure()
			}
		}()
	}

	wg.Wait()

	// All operations should complete without race conditions
	// TotalRequests = RecordSuccess calls + RecordFailure calls
	// = 100 * 10 + 100 * 10 = 2000
	// Note: Allow() does not increment TotalRequests
	stats := cb.Stats()
	assert.Equal(t, 2000, stats.TotalRequests)
	assert.Equal(t, 1000, stats.Successes)
	assert.Equal(t, 1000, stats.Failures)
}

// ============================================================================
// Test Cases for Name
// ============================================================================

func TestCircuitBreaker_Name(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker("my-test-breaker", DefaultConfig(), logger)

	assert.Equal(t, "my-test-breaker", cb.Name())
}

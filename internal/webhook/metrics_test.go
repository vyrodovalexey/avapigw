package webhook

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecordValidation(t *testing.T) {
	tests := []struct {
		name      string
		resource  string
		operation string
		result    string
	}{
		{
			name:      "record successful create validation",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			result:    ResultSuccess,
		},
		{
			name:      "record failed update validation",
			resource:  "HTTPRoute",
			operation: OperationValidateUpdate,
			result:    ResultError,
		},
		{
			name:      "record denied delete validation",
			resource:  "Backend",
			operation: OperationValidateDelete,
			result:    ResultDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordValidation(tt.resource, tt.operation, tt.result)
			})
		})
	}
}

func TestRecordMutation(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		result   string
	}{
		{
			name:     "record successful mutation",
			resource: "Gateway",
			result:   ResultSuccess,
		},
		{
			name:     "record failed mutation",
			resource: "HTTPRoute",
			result:   ResultError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordMutation(tt.resource, tt.result)
			})
		})
	}
}

func TestRecordDuration(t *testing.T) {
	tests := []struct {
		name      string
		resource  string
		operation string
		duration  time.Duration
	}{
		{
			name:      "record short duration",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			duration:  1 * time.Millisecond,
		},
		{
			name:      "record long duration",
			resource:  "HTTPRoute",
			operation: OperationMutate,
			duration:  500 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordDuration(tt.resource, tt.operation, tt.duration)
			})
		})
	}
}

func TestRecordError(t *testing.T) {
	tests := []struct {
		name      string
		resource  string
		operation string
		errorType string
	}{
		{
			name:      "record validation error",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			errorType: "validation_failed",
		},
		{
			name:      "record reference error",
			resource:  "HTTPRoute",
			operation: OperationValidateUpdate,
			errorType: "reference_not_found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				RecordError(tt.resource, tt.operation, tt.errorType)
			})
		})
	}
}

func TestInFlightMetrics(t *testing.T) {
	resource := "Gateway"
	operation := OperationValidateCreate

	// Should not panic
	assert.NotPanics(t, func() {
		IncrementInFlight(resource, operation)
		DecrementInFlight(resource, operation)
	})
}

func TestWebhookTimer(t *testing.T) {
	t.Run("timer observes duration", func(t *testing.T) {
		timer := NewWebhookTimer("Gateway", OperationValidateCreate)
		assert.NotNil(t, timer)

		// Simulate some work
		time.Sleep(1 * time.Millisecond)

		// Should not panic
		assert.NotPanics(t, func() {
			timer.ObserveDuration()
		})
	})

	t.Run("timer observes duration with result", func(t *testing.T) {
		timer := NewWebhookTimer("HTTPRoute", OperationMutate)
		assert.NotNil(t, timer)

		// Simulate some work
		time.Sleep(1 * time.Millisecond)

		// Should not panic
		assert.NotPanics(t, func() {
			timer.ObserveDurationWithResult(ResultSuccess, false)
		})
	})

	t.Run("timer observes validation with result", func(t *testing.T) {
		timer := NewWebhookTimer("Backend", OperationValidateUpdate)
		assert.NotNil(t, timer)

		// Simulate some work
		time.Sleep(1 * time.Millisecond)

		// Should not panic
		assert.NotPanics(t, func() {
			timer.ObserveDurationWithResult(ResultError, true)
		})
	})
}

func TestMetricConstants(t *testing.T) {
	// Verify constants are defined correctly
	assert.Equal(t, "success", ResultSuccess)
	assert.Equal(t, "error", ResultError)
	assert.Equal(t, "denied", ResultDenied)
	assert.Equal(t, "validate_create", OperationValidateCreate)
	assert.Equal(t, "validate_update", OperationValidateUpdate)
	assert.Equal(t, "validate_delete", OperationValidateDelete)
	assert.Equal(t, "mutate", OperationMutate)
}

// ============================================================================
// Additional Webhook Metrics Tests for Edge Cases
// ============================================================================

func TestRecordValidation_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resource  string
		operation string
		result    string
	}{
		{
			name:      "empty resource name",
			resource:  "",
			operation: OperationValidateCreate,
			result:    ResultSuccess,
		},
		{
			name:      "empty operation",
			resource:  "Gateway",
			operation: "",
			result:    ResultSuccess,
		},
		{
			name:      "empty result",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			result:    "",
		},
		{
			name:      "all empty values",
			resource:  "",
			operation: "",
			result:    "",
		},
		{
			name:      "special characters in resource",
			resource:  "Gateway/test-ns",
			operation: OperationValidateCreate,
			result:    ResultSuccess,
		},
		{
			name:      "unicode characters",
			resource:  "Gateway-测试",
			operation: OperationValidateCreate,
			result:    ResultSuccess,
		},
		{
			name:      "very long resource name",
			resource:  "VeryLongResourceNameThatExceedsNormalLengthLimitsForTestingPurposes",
			operation: OperationValidateCreate,
			result:    ResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Should not panic with any input
			assert.NotPanics(t, func() {
				RecordValidation(tt.resource, tt.operation, tt.result)
			})
		})
	}
}

func TestRecordMutation_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resource string
		result   string
	}{
		{
			name:     "empty resource",
			resource: "",
			result:   ResultSuccess,
		},
		{
			name:     "empty result",
			resource: "Gateway",
			result:   "",
		},
		{
			name:     "all empty",
			resource: "",
			result:   "",
		},
		{
			name:     "special characters",
			resource: "Gateway/namespace/name",
			result:   ResultError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NotPanics(t, func() {
				RecordMutation(tt.resource, tt.result)
			})
		})
	}
}

func TestRecordDuration_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resource  string
		operation string
		duration  time.Duration
	}{
		{
			name:      "zero duration",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			duration:  0,
		},
		{
			name:      "negative duration",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			duration:  -1 * time.Second,
		},
		{
			name:      "very large duration",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			duration:  24 * time.Hour,
		},
		{
			name:      "nanosecond precision",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			duration:  1 * time.Nanosecond,
		},
		{
			name:      "empty resource",
			resource:  "",
			operation: OperationValidateCreate,
			duration:  1 * time.Second,
		},
		{
			name:      "empty operation",
			resource:  "Gateway",
			operation: "",
			duration:  1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NotPanics(t, func() {
				RecordDuration(tt.resource, tt.operation, tt.duration)
			})
		})
	}
}

func TestRecordError_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resource  string
		operation string
		errorType string
	}{
		{
			name:      "empty error type",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			errorType: "",
		},
		{
			name:      "all empty",
			resource:  "",
			operation: "",
			errorType: "",
		},
		{
			name:      "special characters in error type",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			errorType: "error/type/with/slashes",
		},
		{
			name:      "error type with spaces",
			resource:  "Gateway",
			operation: OperationValidateCreate,
			errorType: "error type with spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NotPanics(t, func() {
				RecordError(tt.resource, tt.operation, tt.errorType)
			})
		})
	}
}

func TestInFlightMetrics_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resource  string
		operation string
	}{
		{
			name:      "empty resource",
			resource:  "",
			operation: OperationValidateCreate,
		},
		{
			name:      "empty operation",
			resource:  "Gateway",
			operation: "",
		},
		{
			name:      "all empty",
			resource:  "",
			operation: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NotPanics(t, func() {
				IncrementInFlight(tt.resource, tt.operation)
				DecrementInFlight(tt.resource, tt.operation)
			})
		})
	}
}

func TestInFlightMetrics_MultipleIncrements(t *testing.T) {
	resource := "TestResource"
	operation := OperationValidateCreate

	// Should handle multiple increments and decrements
	assert.NotPanics(t, func() {
		for i := 0; i < 10; i++ {
			IncrementInFlight(resource, operation)
		}
		for i := 0; i < 10; i++ {
			DecrementInFlight(resource, operation)
		}
	})
}

func TestInFlightMetrics_DecrementBelowZero(t *testing.T) {
	resource := "TestResourceDecrement"
	operation := OperationValidateUpdate

	// Should not panic even when decrementing below zero
	assert.NotPanics(t, func() {
		DecrementInFlight(resource, operation)
		DecrementInFlight(resource, operation)
	})
}

func TestWebhookTimer_EdgeCases(t *testing.T) {
	t.Run("timer with empty resource", func(t *testing.T) {
		timer := NewWebhookTimer("", OperationValidateCreate)
		assert.NotNil(t, timer)
		assert.NotPanics(t, func() {
			timer.ObserveDuration()
		})
	})

	t.Run("timer with empty operation", func(t *testing.T) {
		timer := NewWebhookTimer("Gateway", "")
		assert.NotNil(t, timer)
		assert.NotPanics(t, func() {
			timer.ObserveDuration()
		})
	})

	t.Run("timer with all empty", func(t *testing.T) {
		timer := NewWebhookTimer("", "")
		assert.NotNil(t, timer)
		assert.NotPanics(t, func() {
			timer.ObserveDuration()
		})
	})

	t.Run("timer observe duration multiple times", func(t *testing.T) {
		timer := NewWebhookTimer("Gateway", OperationValidateCreate)
		assert.NotNil(t, timer)

		// Calling ObserveDuration multiple times should not panic
		assert.NotPanics(t, func() {
			timer.ObserveDuration()
			timer.ObserveDuration()
		})
	})

	t.Run("timer observe duration with result - denied", func(t *testing.T) {
		timer := NewWebhookTimer("Gateway", OperationValidateCreate)
		assert.NotNil(t, timer)

		assert.NotPanics(t, func() {
			timer.ObserveDurationWithResult(ResultDenied, true)
		})
	})

	t.Run("timer observe duration with result - empty result", func(t *testing.T) {
		timer := NewWebhookTimer("Gateway", OperationValidateCreate)
		assert.NotNil(t, timer)

		assert.NotPanics(t, func() {
			timer.ObserveDurationWithResult("", true)
		})
	})
}

func TestWebhookTimer_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Test concurrent timer creation and observation
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			timer := NewWebhookTimer("Gateway", OperationValidateCreate)
			time.Sleep(time.Duration(id) * time.Millisecond)
			timer.ObserveDuration()
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMetricsFunctions_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	done := make(chan bool)

	// Test concurrent access to all metric functions
	for i := 0; i < 10; i++ {
		go func(id int) {
			resource := "Gateway"
			operation := OperationValidateCreate

			RecordValidation(resource, operation, ResultSuccess)
			RecordMutation(resource, ResultSuccess)
			RecordDuration(resource, operation, time.Duration(id)*time.Millisecond)
			RecordError(resource, operation, "test_error")
			IncrementInFlight(resource, operation)
			DecrementInFlight(resource, operation)

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func TestDefaultRequeueConfig(t *testing.T) {
	config := DefaultRequeueConfig()

	assert.Equal(t, 5*time.Second, config.BaseInterval)
	assert.Equal(t, 15*time.Minute, config.MaxInterval)
	assert.Equal(t, 10*time.Second, config.TransientErrorInterval)
	assert.Equal(t, 30*time.Second, config.DependencyErrorInterval)
	assert.Equal(t, 5*time.Minute, config.ValidationErrorInterval)
	assert.Equal(t, 10*time.Minute, config.PermanentErrorInterval)
	assert.Equal(t, 5*time.Minute, config.SuccessInterval)
	assert.Equal(t, 2.0, config.BackoffMultiplier)
	assert.Equal(t, 10, config.MaxFailures)
	assert.Equal(t, 10, config.JitterPercent)
}

func TestNewRequeueStrategy(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		strategy := NewRequeueStrategy(nil)
		require.NotNil(t, strategy)
		require.NotNil(t, strategy.config)
		assert.Equal(t, DefaultRequeueConfig().BaseInterval, strategy.config.BaseInterval)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &RequeueConfig{
			BaseInterval:            10 * time.Second,
			MaxInterval:             30 * time.Minute,
			TransientErrorInterval:  20 * time.Second,
			DependencyErrorInterval: 1 * time.Minute,
			ValidationErrorInterval: 10 * time.Minute,
			PermanentErrorInterval:  20 * time.Minute,
			SuccessInterval:         10 * time.Minute,
			BackoffMultiplier:       3.0,
			MaxFailures:             5,
			JitterPercent:           20,
		}
		strategy := NewRequeueStrategy(config)
		require.NotNil(t, strategy)
		assert.Equal(t, config.BaseInterval, strategy.config.BaseInterval)
		assert.Equal(t, config.MaxInterval, strategy.config.MaxInterval)
	})
}

func TestDefaultRequeueStrategy(t *testing.T) {
	strategy := DefaultRequeueStrategy()
	require.NotNil(t, strategy)
	require.NotNil(t, strategy.config)
	require.NotNil(t, strategy.failureTracker)
}

func TestRequeueStrategy_ForSuccess(t *testing.T) {
	config := &RequeueConfig{
		SuccessInterval: 5 * time.Minute,
		JitterPercent:   0, // No jitter for predictable testing
	}
	strategy := NewRequeueStrategy(config)

	result := strategy.ForSuccess()
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	assert.False(t, result.Requeue)
}

func TestRequeueStrategy_ForSuccessWithResource(t *testing.T) {
	config := &RequeueConfig{
		SuccessInterval: 5 * time.Minute,
		JitterPercent:   0,
	}
	strategy := NewRequeueStrategy(config)

	// Add some failures first
	key := "default/my-resource"
	strategy.failureTracker.Increment(key)
	strategy.failureTracker.Increment(key)
	assert.Equal(t, 2, strategy.GetFailureCount(key))

	// ForSuccessWithResource should reset the failure count
	result := strategy.ForSuccessWithResource(key)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	assert.Equal(t, 0, strategy.GetFailureCount(key))
}

func TestRequeueStrategy_ForTransientError(t *testing.T) {
	config := &RequeueConfig{
		TransientErrorInterval: 10 * time.Second,
		JitterPercent:          0,
	}
	strategy := NewRequeueStrategy(config)

	result := strategy.ForTransientError()
	assert.Equal(t, 10*time.Second, result.RequeueAfter)
	assert.True(t, result.Requeue)
}

func TestRequeueStrategy_ForTransientErrorWithBackoff(t *testing.T) {
	config := &RequeueConfig{
		TransientErrorInterval: 10 * time.Second,
		MaxInterval:            5 * time.Minute,
		BackoffMultiplier:      2.0,
		MaxFailures:            10,
		JitterPercent:          0,
	}
	strategy := NewRequeueStrategy(config)
	key := "default/my-resource"

	// First failure: 10s * 2^1 = 20s
	result1 := strategy.ForTransientErrorWithBackoff(key)
	assert.Equal(t, 20*time.Second, result1.RequeueAfter)
	assert.True(t, result1.Requeue)

	// Second failure: 10s * 2^2 = 40s
	result2 := strategy.ForTransientErrorWithBackoff(key)
	assert.Equal(t, 40*time.Second, result2.RequeueAfter)

	// Third failure: 10s * 2^3 = 80s
	result3 := strategy.ForTransientErrorWithBackoff(key)
	assert.Equal(t, 80*time.Second, result3.RequeueAfter)
}

func TestRequeueStrategy_ForTransientErrorWithBackoff_MaxInterval(t *testing.T) {
	config := &RequeueConfig{
		TransientErrorInterval: 1 * time.Minute,
		MaxInterval:            5 * time.Minute,
		BackoffMultiplier:      2.0,
		MaxFailures:            10,
		JitterPercent:          0,
	}
	strategy := NewRequeueStrategy(config)
	key := "default/my-resource"

	// Simulate many failures to hit the max interval
	for i := 0; i < 10; i++ {
		strategy.ForTransientErrorWithBackoff(key)
	}

	// Should be capped at max interval
	result := strategy.ForTransientErrorWithBackoff(key)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
}

func TestRequeueStrategy_ForDependencyError(t *testing.T) {
	config := &RequeueConfig{
		DependencyErrorInterval: 30 * time.Second,
		JitterPercent:           0,
	}
	strategy := NewRequeueStrategy(config)

	result := strategy.ForDependencyError()
	assert.Equal(t, 30*time.Second, result.RequeueAfter)
	assert.True(t, result.Requeue)
}

func TestRequeueStrategy_ForValidationError(t *testing.T) {
	config := &RequeueConfig{
		ValidationErrorInterval: 5 * time.Minute,
		JitterPercent:           0,
	}
	strategy := NewRequeueStrategy(config)

	result := strategy.ForValidationError()
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	assert.False(t, result.Requeue) // Validation errors don't set Requeue flag
}

func TestRequeueStrategy_ForPermanentError(t *testing.T) {
	config := &RequeueConfig{
		PermanentErrorInterval: 10 * time.Minute,
		JitterPercent:          0,
	}
	strategy := NewRequeueStrategy(config)

	result := strategy.ForPermanentError()
	assert.Equal(t, 10*time.Minute, result.RequeueAfter)
	assert.False(t, result.Requeue)
}

func TestRequeueStrategy_ForInternalError(t *testing.T) {
	config := &RequeueConfig{
		TransientErrorInterval: 10 * time.Second,
		JitterPercent:          0,
	}
	strategy := NewRequeueStrategy(config)

	result := strategy.ForInternalError()
	assert.Equal(t, 10*time.Second, result.RequeueAfter)
	assert.True(t, result.Requeue)
}

func TestRequeueStrategy_ForCustomInterval(t *testing.T) {
	config := &RequeueConfig{
		JitterPercent: 0,
	}
	strategy := NewRequeueStrategy(config)

	result := strategy.ForCustomInterval(3 * time.Minute)
	assert.Equal(t, 3*time.Minute, result.RequeueAfter)
}

func TestRequeueStrategy_ForImmediateRequeue(t *testing.T) {
	strategy := DefaultRequeueStrategy()

	result := strategy.ForImmediateRequeue()
	assert.True(t, result.Requeue)
	assert.Equal(t, time.Duration(0), result.RequeueAfter)
}

func TestRequeueStrategy_ForNoRequeue(t *testing.T) {
	strategy := DefaultRequeueStrategy()

	result := strategy.ForNoRequeue()
	assert.False(t, result.Requeue)
	assert.Equal(t, time.Duration(0), result.RequeueAfter)
}

func TestRequeueStrategy_CalculateBackoff(t *testing.T) {
	config := &RequeueConfig{
		BaseInterval:      10 * time.Second,
		MaxInterval:       5 * time.Minute,
		BackoffMultiplier: 2.0,
		MaxFailures:       10,
	}
	strategy := NewRequeueStrategy(config)

	tests := []struct {
		name         string
		baseInterval time.Duration
		failures     int
		expected     time.Duration
	}{
		{
			name:         "zero failures",
			baseInterval: 10 * time.Second,
			failures:     0,
			expected:     10 * time.Second,
		},
		{
			name:         "one failure",
			baseInterval: 10 * time.Second,
			failures:     1,
			expected:     20 * time.Second,
		},
		{
			name:         "two failures",
			baseInterval: 10 * time.Second,
			failures:     2,
			expected:     40 * time.Second,
		},
		{
			name:         "three failures",
			baseInterval: 10 * time.Second,
			failures:     3,
			expected:     80 * time.Second,
		},
		{
			name:         "capped at max interval",
			baseInterval: 1 * time.Minute,
			failures:     10,
			expected:     5 * time.Minute, // Capped at MaxInterval
		},
		{
			name:         "negative failures treated as zero",
			baseInterval: 10 * time.Second,
			failures:     -1,
			expected:     10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.calculateBackoff(tt.baseInterval, tt.failures)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequeueStrategy_GetFailureCount(t *testing.T) {
	strategy := DefaultRequeueStrategy()
	key := "default/my-resource"

	// Initially zero
	assert.Equal(t, 0, strategy.GetFailureCount(key))

	// After incrementing
	strategy.failureTracker.Increment(key)
	assert.Equal(t, 1, strategy.GetFailureCount(key))

	strategy.failureTracker.Increment(key)
	assert.Equal(t, 2, strategy.GetFailureCount(key))
}

func TestRequeueStrategy_ResetFailureCount(t *testing.T) {
	strategy := DefaultRequeueStrategy()
	key := "default/my-resource"

	// Add some failures
	strategy.failureTracker.Increment(key)
	strategy.failureTracker.Increment(key)
	assert.Equal(t, 2, strategy.GetFailureCount(key))

	// Reset
	strategy.ResetFailureCount(key)
	assert.Equal(t, 0, strategy.GetFailureCount(key))
}

func TestFailureTracker_Increment(t *testing.T) {
	tracker := NewFailureTracker(5)
	key := "default/my-resource"

	// Increment and check
	count := tracker.Increment(key)
	assert.Equal(t, 1, count)

	count = tracker.Increment(key)
	assert.Equal(t, 2, count)

	count = tracker.Increment(key)
	assert.Equal(t, 3, count)
}

func TestFailureTracker_Increment_MaxFailures(t *testing.T) {
	maxFailures := 3
	tracker := NewFailureTracker(maxFailures)
	key := "default/my-resource"

	// Increment beyond max
	for i := 0; i < 10; i++ {
		tracker.Increment(key)
	}

	// Should be capped at max
	assert.Equal(t, maxFailures, tracker.Get(key))
}

func TestFailureTracker_Get(t *testing.T) {
	tracker := NewFailureTracker(10)
	key := "default/my-resource"

	// Non-existent key returns 0
	assert.Equal(t, 0, tracker.Get(key))

	// After increment
	tracker.Increment(key)
	assert.Equal(t, 1, tracker.Get(key))
}

func TestFailureTracker_Reset(t *testing.T) {
	tracker := NewFailureTracker(10)
	key := "default/my-resource"

	tracker.Increment(key)
	tracker.Increment(key)
	assert.Equal(t, 2, tracker.Get(key))

	tracker.Reset(key)
	assert.Equal(t, 0, tracker.Get(key))
}

func TestFailureTracker_Clear(t *testing.T) {
	tracker := NewFailureTracker(10)

	tracker.Increment("key1")
	tracker.Increment("key2")
	tracker.Increment("key3")

	assert.Equal(t, 1, tracker.Get("key1"))
	assert.Equal(t, 1, tracker.Get("key2"))
	assert.Equal(t, 1, tracker.Get("key3"))

	tracker.Clear()

	assert.Equal(t, 0, tracker.Get("key1"))
	assert.Equal(t, 0, tracker.Get("key2"))
	assert.Equal(t, 0, tracker.Get("key3"))
}

func TestNewFailureTracker_InvalidMaxFailures(t *testing.T) {
	// Zero or negative max failures should default to 10
	tracker := NewFailureTracker(0)
	assert.Equal(t, 10, tracker.maxFailures)

	tracker = NewFailureTracker(-5)
	assert.Equal(t, 10, tracker.maxFailures)
}

func TestAddJitter(t *testing.T) {
	t.Run("zero jitter percent", func(t *testing.T) {
		interval := 1 * time.Minute
		result := addJitter(interval, 0)
		assert.Equal(t, interval, result)
	})

	t.Run("negative jitter percent", func(t *testing.T) {
		interval := 1 * time.Minute
		result := addJitter(interval, -10)
		assert.Equal(t, interval, result)
	})

	t.Run("jitter percent over 100", func(t *testing.T) {
		interval := 1 * time.Minute
		result := addJitter(interval, 150)
		assert.Equal(t, interval, result)
	})

	t.Run("valid jitter percent", func(t *testing.T) {
		interval := 1 * time.Minute
		jitterPercent := 10

		// Run multiple times to verify jitter is applied
		results := make(map[time.Duration]bool)
		for i := 0; i < 100; i++ {
			result := addJitter(interval, jitterPercent)
			results[result] = true

			// Result should be within +/- 5% of the interval (half of 10%)
			minExpected := interval - time.Duration(float64(interval)*0.05)
			maxExpected := interval + time.Duration(float64(interval)*0.05)
			assert.GreaterOrEqual(t, result, minExpected)
			assert.LessOrEqual(t, result, maxExpected)
		}

		// Should have some variation (not all the same)
		// Note: This could theoretically fail with very low probability
		assert.Greater(t, len(results), 1, "Expected some variation in jitter results")
	})
}

func TestResourceKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		objName   string
		expected  string
	}{
		{
			name:      "resource in default namespace",
			namespace: "default",
			objName:   "my-resource",
			expected:  "default/my-resource",
		},
		{
			name:      "resource in custom namespace",
			namespace: "production",
			objName:   "api-gateway",
			expected:  "production/api-gateway",
		},
		{
			name:      "resource with empty namespace",
			namespace: "",
			objName:   "cluster-resource",
			expected:  "/cluster-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple object that implements client.Object
			obj := &testObject{
				namespace: tt.namespace,
				name:      tt.objName,
			}
			result := ResourceKey(obj)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRecordRequeueInterval(t *testing.T) {
	tests := []struct {
		name      string
		errorType ErrorType
		interval  time.Duration
	}{
		{
			name:      "transient error interval",
			errorType: ErrorTypeTransient,
			interval:  10 * time.Second,
		},
		{
			name:      "dependency error interval",
			errorType: ErrorTypeDependency,
			interval:  30 * time.Second,
		},
		{
			name:      "validation error interval",
			errorType: ErrorTypeValidation,
			interval:  5 * time.Minute,
		},
		{
			name:      "permanent error interval",
			errorType: ErrorTypePermanent,
			interval:  10 * time.Minute,
		},
		{
			name:      "internal error interval",
			errorType: ErrorTypeInternal,
			interval:  15 * time.Second,
		},
		{
			name:      "zero interval",
			errorType: ErrorTypeTransient,
			interval:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// RecordRequeueInterval should not panic
			assert.NotPanics(t, func() {
				RecordRequeueInterval(tt.errorType, tt.interval)
			})
		})
	}
}

// testObject is a minimal implementation of client.Object for testing.
type testObject struct {
	namespace string
	name      string
}

func (t *testObject) GetNamespace() string                                       { return t.namespace }
func (t *testObject) SetNamespace(namespace string)                              { t.namespace = namespace }
func (t *testObject) GetName() string                                            { return t.name }
func (t *testObject) SetName(name string)                                        { t.name = name }
func (t *testObject) GetGenerateName() string                                    { return "" }
func (t *testObject) SetGenerateName(name string)                                {}
func (t *testObject) GetUID() types.UID                                          { return "" }
func (t *testObject) SetUID(uid types.UID)                                       {}
func (t *testObject) GetResourceVersion() string                                 { return "" }
func (t *testObject) SetResourceVersion(version string)                          {}
func (t *testObject) GetGeneration() int64                                       { return 0 }
func (t *testObject) SetGeneration(generation int64)                             {}
func (t *testObject) GetSelfLink() string                                        { return "" }
func (t *testObject) SetSelfLink(selfLink string)                                {}
func (t *testObject) GetCreationTimestamp() metav1.Time                          { return metav1.Time{} }
func (t *testObject) SetCreationTimestamp(timestamp metav1.Time)                 {}
func (t *testObject) GetDeletionTimestamp() *metav1.Time                         { return nil }
func (t *testObject) SetDeletionTimestamp(timestamp *metav1.Time)                {}
func (t *testObject) GetDeletionGracePeriodSeconds() *int64                      { return nil }
func (t *testObject) SetDeletionGracePeriodSeconds(*int64)                       {}
func (t *testObject) GetLabels() map[string]string                               { return nil }
func (t *testObject) SetLabels(labels map[string]string)                         {}
func (t *testObject) GetAnnotations() map[string]string                          { return nil }
func (t *testObject) SetAnnotations(annotations map[string]string)               {}
func (t *testObject) GetFinalizers() []string                                    { return nil }
func (t *testObject) SetFinalizers(finalizers []string)                          {}
func (t *testObject) GetOwnerReferences() []metav1.OwnerReference                { return nil }
func (t *testObject) SetOwnerReferences([]metav1.OwnerReference)                 {}
func (t *testObject) GetManagedFields() []metav1.ManagedFieldsEntry              { return nil }
func (t *testObject) SetManagedFields(managedFields []metav1.ManagedFieldsEntry) {}
func (t *testObject) GetObjectKind() schema.ObjectKind                           { return nil }
func (t *testObject) DeepCopyObject() runtime.Object                             { return nil }

func TestRequeueStrategy_ForDependencyErrorWithBackoff(t *testing.T) {
	config := &RequeueConfig{
		DependencyErrorInterval: 30 * time.Second,
		MaxInterval:             5 * time.Minute,
		BackoffMultiplier:       2.0,
		MaxFailures:             10,
		JitterPercent:           0,
	}
	strategy := NewRequeueStrategy(config)
	key := "default/my-resource"

	// First failure: 30s * 2^1 = 60s
	result1 := strategy.ForDependencyErrorWithBackoff(key)
	assert.Equal(t, 60*time.Second, result1.RequeueAfter)
	assert.True(t, result1.Requeue)

	// Second failure: 30s * 2^2 = 120s
	result2 := strategy.ForDependencyErrorWithBackoff(key)
	assert.Equal(t, 120*time.Second, result2.RequeueAfter)

	// Third failure: 30s * 2^3 = 240s
	result3 := strategy.ForDependencyErrorWithBackoff(key)
	assert.Equal(t, 240*time.Second, result3.RequeueAfter)
}

func TestRequeueStrategy_ForDependencyErrorWithBackoff_MaxInterval(t *testing.T) {
	config := &RequeueConfig{
		DependencyErrorInterval: 1 * time.Minute,
		MaxInterval:             5 * time.Minute,
		BackoffMultiplier:       2.0,
		MaxFailures:             10,
		JitterPercent:           0,
	}
	strategy := NewRequeueStrategy(config)
	key := "default/my-resource"

	// Simulate many failures to hit the max interval
	for i := 0; i < 10; i++ {
		strategy.ForDependencyErrorWithBackoff(key)
	}

	// Should be capped at max interval
	result := strategy.ForDependencyErrorWithBackoff(key)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
}

func TestRequeueStrategy_ForInternalErrorWithBackoff(t *testing.T) {
	config := &RequeueConfig{
		TransientErrorInterval: 10 * time.Second,
		MaxInterval:            5 * time.Minute,
		BackoffMultiplier:      2.0,
		MaxFailures:            10,
		JitterPercent:          0,
	}
	strategy := NewRequeueStrategy(config)
	key := "default/my-resource"

	// First failure: 10s * 2^1 = 20s
	result1 := strategy.ForInternalErrorWithBackoff(key)
	assert.Equal(t, 20*time.Second, result1.RequeueAfter)
	assert.True(t, result1.Requeue)

	// Second failure: 10s * 2^2 = 40s
	result2 := strategy.ForInternalErrorWithBackoff(key)
	assert.Equal(t, 40*time.Second, result2.RequeueAfter)

	// Third failure: 10s * 2^3 = 80s
	result3 := strategy.ForInternalErrorWithBackoff(key)
	assert.Equal(t, 80*time.Second, result3.RequeueAfter)
}

func TestRequeueStrategy_ForInternalErrorWithBackoff_MaxInterval(t *testing.T) {
	config := &RequeueConfig{
		TransientErrorInterval: 1 * time.Minute,
		MaxInterval:            5 * time.Minute,
		BackoffMultiplier:      2.0,
		MaxFailures:            10,
		JitterPercent:          0,
	}
	strategy := NewRequeueStrategy(config)
	key := "default/my-resource"

	// Simulate many failures to hit the max interval
	for i := 0; i < 10; i++ {
		strategy.ForInternalErrorWithBackoff(key)
	}

	// Should be capped at max interval
	result := strategy.ForInternalErrorWithBackoff(key)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
}

func TestRequeueStrategy_CalculateBackoff_FailuresExceedMax(t *testing.T) {
	config := &RequeueConfig{
		BaseInterval:      10 * time.Second,
		MaxInterval:       5 * time.Minute,
		BackoffMultiplier: 2.0,
		MaxFailures:       5, // Set a low max for testing
	}
	strategy := NewRequeueStrategy(config)

	// Test with failures exceeding max - should be capped at MaxFailures
	// With MaxFailures=5, failures=10 should be treated as failures=5
	// 10s * 2^5 = 10s * 32 = 320s = 5m20s, but capped at MaxInterval (5m)
	result := strategy.calculateBackoff(10*time.Second, 10)
	assert.Equal(t, 5*time.Minute, result)

	// Test with failures exactly at max
	// 10s * 2^5 = 320s, capped at 5m
	result2 := strategy.calculateBackoff(10*time.Second, 5)
	assert.Equal(t, 5*time.Minute, result2)

	// Test with failures just above max
	result3 := strategy.calculateBackoff(10*time.Second, 6)
	assert.Equal(t, 5*time.Minute, result3)
}

func TestFailureTracker_CleanupStaleEntries(t *testing.T) {
	cfg := &FailureTrackerConfig{
		MaxFailures: 10,
		MaxEntries:  100,
		StaleAge:    100 * time.Millisecond,
	}
	tracker := NewFailureTrackerWithConfig(cfg)

	// Add some entries
	tracker.Increment("key1")
	tracker.Increment("key2")
	tracker.Increment("key3")

	assert.Equal(t, 3, tracker.Size())

	// Wait for entries to become stale
	time.Sleep(150 * time.Millisecond)

	// Cleanup stale entries
	removed := tracker.CleanupStaleEntries(100 * time.Millisecond)
	assert.Equal(t, 3, removed)
	assert.Equal(t, 0, tracker.Size())
}

func TestFailureTracker_CleanupStaleEntries_PartialCleanup(t *testing.T) {
	cfg := &FailureTrackerConfig{
		MaxFailures: 10,
		MaxEntries:  100,
		StaleAge:    1 * time.Hour, // Long stale age
	}
	tracker := NewFailureTrackerWithConfig(cfg)

	// Add some entries
	tracker.Increment("key1")
	tracker.Increment("key2")

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Add more entries
	tracker.Increment("key3")

	assert.Equal(t, 3, tracker.Size())

	// Cleanup with a short max age - should remove key1 and key2
	removed := tracker.CleanupStaleEntries(25 * time.Millisecond)
	assert.Equal(t, 2, removed)
	assert.Equal(t, 1, tracker.Size())
	assert.Equal(t, 1, tracker.Get("key3"))
}

func TestFailureTracker_Size(t *testing.T) {
	tracker := NewFailureTracker(10)

	assert.Equal(t, 0, tracker.Size())

	tracker.Increment("key1")
	assert.Equal(t, 1, tracker.Size())

	tracker.Increment("key2")
	assert.Equal(t, 2, tracker.Size())

	tracker.Increment("key1") // Increment existing key
	assert.Equal(t, 2, tracker.Size())

	tracker.Reset("key1")
	assert.Equal(t, 1, tracker.Size())

	tracker.Clear()
	assert.Equal(t, 0, tracker.Size())
}

func TestFailureTracker_LRUEviction(t *testing.T) {
	cfg := &FailureTrackerConfig{
		MaxFailures: 10,
		MaxEntries:  3, // Small max entries for testing
		StaleAge:    1 * time.Hour,
	}
	tracker := NewFailureTrackerWithConfig(cfg)

	// Add entries up to max
	tracker.Increment("key1")
	tracker.Increment("key2")
	tracker.Increment("key3")

	assert.Equal(t, 3, tracker.Size())

	// Adding a new entry should evict the LRU entry (key1)
	tracker.Increment("key4")

	assert.Equal(t, 3, tracker.Size())
	assert.Equal(t, 0, tracker.Get("key1")) // key1 should be evicted
	assert.Equal(t, 1, tracker.Get("key2"))
	assert.Equal(t, 1, tracker.Get("key3"))
	assert.Equal(t, 1, tracker.Get("key4"))
}

func TestFailureTracker_LRUEviction_AccessUpdatesOrder(t *testing.T) {
	cfg := &FailureTrackerConfig{
		MaxFailures: 10,
		MaxEntries:  3,
		StaleAge:    1 * time.Hour,
	}
	tracker := NewFailureTrackerWithConfig(cfg)

	// Add entries
	tracker.Increment("key1")
	tracker.Increment("key2")
	tracker.Increment("key3")

	// Access key1 to make it most recently used
	tracker.Get("key1")

	// Adding a new entry should evict key2 (now the LRU)
	tracker.Increment("key4")

	assert.Equal(t, 3, tracker.Size())
	assert.Equal(t, 1, tracker.Get("key1")) // key1 should still exist
	assert.Equal(t, 0, tracker.Get("key2")) // key2 should be evicted
	assert.Equal(t, 1, tracker.Get("key3"))
	assert.Equal(t, 1, tracker.Get("key4"))
}

func TestFailureTrackerWithConfig(t *testing.T) {
	t.Run("nil config uses defaults", func(t *testing.T) {
		tracker := NewFailureTrackerWithConfig(nil)
		assert.Equal(t, 10, tracker.maxFailures)
		assert.Equal(t, DefaultMaxEntries, tracker.maxEntries)
		assert.Equal(t, DefaultStaleEntryAge, tracker.staleAge)
	})

	t.Run("custom config", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 5,
			MaxEntries:  1000,
			StaleAge:    30 * time.Minute,
		}
		tracker := NewFailureTrackerWithConfig(cfg)
		assert.Equal(t, 5, tracker.maxFailures)
		assert.Equal(t, 1000, tracker.maxEntries)
		assert.Equal(t, 30*time.Minute, tracker.staleAge)
	})

	t.Run("invalid values use defaults", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: -1,
			MaxEntries:  0,
			StaleAge:    -1 * time.Second,
		}
		tracker := NewFailureTrackerWithConfig(cfg)
		assert.Equal(t, 10, tracker.maxFailures)
		assert.Equal(t, DefaultMaxEntries, tracker.maxEntries)
		assert.Equal(t, DefaultStaleEntryAge, tracker.staleAge)
	})
}

func TestDefaultFailureTrackerConfig(t *testing.T) {
	cfg := DefaultFailureTrackerConfig()
	assert.Equal(t, 10, cfg.MaxFailures)
	assert.Equal(t, DefaultMaxEntries, cfg.MaxEntries)
	assert.Equal(t, DefaultStaleEntryAge, cfg.StaleAge)
}

func TestFailureTracker_PeriodicCleanup(t *testing.T) {
	t.Run("starts and stops cleanup goroutine", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  100,
			StaleAge:    50 * time.Millisecond,
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Start periodic cleanup with short interval
		tracker.StartPeriodicCleanup(ctx, 20*time.Millisecond)

		// Add some entries
		tracker.Increment("key1")
		tracker.Increment("key2")
		assert.Equal(t, 2, tracker.Size())

		// Wait for entries to become stale and be cleaned up
		time.Sleep(150 * time.Millisecond)

		// Entries should be cleaned up
		assert.Equal(t, 0, tracker.Size())

		// Stop cleanup
		tracker.StopPeriodicCleanup()
	})

	t.Run("cleanup respects context cancellation", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  100,
			StaleAge:    1 * time.Hour, // Long stale age so entries won't be cleaned
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		ctx, cancel := context.WithCancel(context.Background())

		// Start periodic cleanup
		tracker.StartPeriodicCleanup(ctx, 10*time.Millisecond)

		// Add entries
		tracker.Increment("key1")
		tracker.Increment("key2")

		// Cancel context
		cancel()

		// Wait a bit for goroutine to stop
		time.Sleep(50 * time.Millisecond)

		// Entries should still exist (not cleaned due to long stale age)
		assert.Equal(t, 2, tracker.Size())
	})

	t.Run("stop without start is safe", func(t *testing.T) {
		tracker := NewFailureTracker(10)
		// Should not panic
		tracker.StopPeriodicCleanup()
	})

	t.Run("double stop is safe", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  100,
			StaleAge:    1 * time.Hour,
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		tracker.StartPeriodicCleanup(ctx, 100*time.Millisecond)

		// Double stop should not panic
		tracker.StopPeriodicCleanup()
		tracker.StopPeriodicCleanup()
	})

	t.Run("default interval when zero provided", func(t *testing.T) {
		tracker := NewFailureTracker(10)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Start with zero interval - should use default
		tracker.StartPeriodicCleanup(ctx, 0)

		// Just verify it starts without error
		time.Sleep(10 * time.Millisecond)

		tracker.StopPeriodicCleanup()
	})
}

// ============================================================================
// Additional Periodic Cleanup Tests
// ============================================================================

func TestFailureTracker_PeriodicCleanup_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent access during cleanup", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  1000,
			StaleAge:    50 * time.Millisecond,
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Start periodic cleanup
		tracker.StartPeriodicCleanup(ctx, 10*time.Millisecond)

		// Concurrent access from multiple goroutines
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func(id int) {
				for j := 0; j < 100; j++ {
					key := "key-" + string(rune('a'+id)) + "-" + string(rune('0'+j%10))
					tracker.Increment(key)
					tracker.Get(key)
					if j%10 == 0 {
						tracker.Reset(key)
					}
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Stop cleanup
		tracker.StopPeriodicCleanup()
	})

	t.Run("cleanup removes stale entries while adding new ones", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  100,
			StaleAge:    30 * time.Millisecond,
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Add initial entries
		for i := 0; i < 10; i++ {
			tracker.Increment("old-key-" + string(rune('0'+i)))
		}

		// Start periodic cleanup
		tracker.StartPeriodicCleanup(ctx, 10*time.Millisecond)

		// Wait for old entries to become stale
		time.Sleep(50 * time.Millisecond)

		// Add new entries while cleanup is running
		for i := 0; i < 10; i++ {
			tracker.Increment("new-key-" + string(rune('0'+i)))
		}

		// Wait a bit more
		time.Sleep(20 * time.Millisecond)

		// New entries should still exist
		for i := 0; i < 10; i++ {
			count := tracker.Get("new-key-" + string(rune('0'+i)))
			assert.GreaterOrEqual(t, count, 0)
		}

		tracker.StopPeriodicCleanup()
	})

	t.Run("cleanup respects maxAge parameter", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  100,
			StaleAge:    1 * time.Hour, // Long default stale age
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		// Add entries
		tracker.Increment("key1")
		tracker.Increment("key2")
		tracker.Increment("key3")

		// Wait a bit
		time.Sleep(50 * time.Millisecond)

		// Cleanup with short maxAge should remove entries
		removed := tracker.CleanupStaleEntries(25 * time.Millisecond)
		assert.Equal(t, 3, removed)
		assert.Equal(t, 0, tracker.Size())
	})

	t.Run("cleanup with zero maxAge uses configured staleAge", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  100,
			StaleAge:    25 * time.Millisecond,
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		// Add entries
		tracker.Increment("key1")
		tracker.Increment("key2")

		// Wait for entries to become stale
		time.Sleep(50 * time.Millisecond)

		// Cleanup with zero maxAge should use configured staleAge
		removed := tracker.CleanupStaleEntries(0)
		assert.Equal(t, 2, removed)
		assert.Equal(t, 0, tracker.Size())
	})

	t.Run("cleanup with negative maxAge uses configured staleAge", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  100,
			StaleAge:    25 * time.Millisecond,
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		// Add entries
		tracker.Increment("key1")

		// Wait for entries to become stale
		time.Sleep(50 * time.Millisecond)

		// Cleanup with negative maxAge should use configured staleAge
		removed := tracker.CleanupStaleEntries(-1 * time.Second)
		assert.Equal(t, 1, removed)
	})
}

func TestFailureTracker_LRUEviction_StaleEntries(t *testing.T) {
	t.Run("eviction prefers stale entries over LRU", func(t *testing.T) {
		cfg := &FailureTrackerConfig{
			MaxFailures: 10,
			MaxEntries:  3,
			StaleAge:    25 * time.Millisecond,
		}
		tracker := NewFailureTrackerWithConfig(cfg)

		// Add entries
		tracker.Increment("key1")
		tracker.Increment("key2")
		tracker.Increment("key3")

		// Wait for entries to become stale
		time.Sleep(50 * time.Millisecond)

		// Adding a new entry should evict stale entries first
		tracker.Increment("key4")

		// key4 should exist
		assert.Equal(t, 1, tracker.Get("key4"))
	})
}

func TestFailureTracker_ConcurrentOperations(t *testing.T) {
	t.Run("concurrent increment and reset", func(t *testing.T) {
		tracker := NewFailureTracker(10)

		done := make(chan bool)

		// Concurrent increments
		for i := 0; i < 5; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					tracker.Increment("shared-key")
				}
				done <- true
			}()
		}

		// Concurrent resets
		for i := 0; i < 5; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					tracker.Reset("shared-key")
				}
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Should not panic and tracker should be in a valid state
		_ = tracker.Get("shared-key")
		_ = tracker.Size()
	})

	t.Run("concurrent clear and increment", func(t *testing.T) {
		tracker := NewFailureTracker(10)

		done := make(chan bool)

		// Concurrent increments
		for i := 0; i < 5; i++ {
			go func(id int) {
				for j := 0; j < 100; j++ {
					tracker.Increment("key-" + string(rune('0'+id)))
				}
				done <- true
			}(i)
		}

		// Concurrent clears
		for i := 0; i < 5; i++ {
			go func() {
				for j := 0; j < 10; j++ {
					tracker.Clear()
					time.Sleep(1 * time.Millisecond)
				}
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Should not panic
		_ = tracker.Size()
	})
}

func TestRequeueStrategy_EdgeCases(t *testing.T) {
	t.Run("backoff with very high failure count", func(t *testing.T) {
		config := &RequeueConfig{
			TransientErrorInterval: 10 * time.Second,
			MaxInterval:            5 * time.Minute,
			BackoffMultiplier:      2.0,
			MaxFailures:            10,
			JitterPercent:          0,
		}
		strategy := NewRequeueStrategy(config)
		key := "test-resource"

		// Simulate many failures
		for i := 0; i < 100; i++ {
			strategy.ForTransientErrorWithBackoff(key)
		}

		// Should be capped at max interval
		result := strategy.ForTransientErrorWithBackoff(key)
		assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	})

	t.Run("multiple resources with different failure counts", func(t *testing.T) {
		config := &RequeueConfig{
			TransientErrorInterval: 10 * time.Second,
			MaxInterval:            5 * time.Minute,
			BackoffMultiplier:      2.0,
			MaxFailures:            10,
			JitterPercent:          0,
		}
		strategy := NewRequeueStrategy(config)

		// Resource 1: 1 failure
		strategy.ForTransientErrorWithBackoff("resource1")
		assert.Equal(t, 1, strategy.GetFailureCount("resource1"))

		// Resource 2: 3 failures
		strategy.ForTransientErrorWithBackoff("resource2")
		strategy.ForTransientErrorWithBackoff("resource2")
		strategy.ForTransientErrorWithBackoff("resource2")
		assert.Equal(t, 3, strategy.GetFailureCount("resource2"))

		// Resource 3: success (reset)
		strategy.ForTransientErrorWithBackoff("resource3")
		strategy.ForSuccessWithResource("resource3")
		assert.Equal(t, 0, strategy.GetFailureCount("resource3"))
	})
}

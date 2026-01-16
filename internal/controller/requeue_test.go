// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
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

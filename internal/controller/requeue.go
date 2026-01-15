// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"math"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// ============================================================================
// Requeue Strategy Configuration
// ============================================================================

// RequeueConfig holds configuration for requeue timing.
type RequeueConfig struct {
	// BaseInterval is the starting interval for requeue.
	BaseInterval time.Duration

	// MaxInterval is the maximum interval for requeue (cap for exponential backoff).
	MaxInterval time.Duration

	// TransientErrorInterval is the interval for transient errors.
	TransientErrorInterval time.Duration

	// DependencyErrorInterval is the interval for dependency errors.
	DependencyErrorInterval time.Duration

	// ValidationErrorInterval is the interval for validation errors.
	// These are typically longer since user intervention is required.
	ValidationErrorInterval time.Duration

	// PermanentErrorInterval is the interval for permanent errors.
	// These are typically longer since user intervention is required.
	PermanentErrorInterval time.Duration

	// SuccessInterval is the interval for successful reconciliation.
	SuccessInterval time.Duration

	// BackoffMultiplier is the multiplier for exponential backoff.
	BackoffMultiplier float64

	// MaxFailures is the maximum number of failures to track for backoff.
	MaxFailures int

	// JitterPercent is the percentage of jitter to add to intervals (0-100).
	JitterPercent int
}

// DefaultRequeueConfig returns the default requeue configuration.
func DefaultRequeueConfig() *RequeueConfig {
	return &RequeueConfig{
		BaseInterval:            5 * time.Second,
		MaxInterval:             15 * time.Minute,
		TransientErrorInterval:  10 * time.Second,
		DependencyErrorInterval: 30 * time.Second,
		ValidationErrorInterval: 5 * time.Minute,
		PermanentErrorInterval:  10 * time.Minute,
		SuccessInterval:         5 * time.Minute,
		BackoffMultiplier:       2.0,
		MaxFailures:             10,
		JitterPercent:           10,
	}
}

// ============================================================================
// Requeue Strategy
// ============================================================================

// RequeueStrategy manages requeue timing with exponential backoff.
type RequeueStrategy struct {
	config *RequeueConfig

	// failureTracker tracks failure counts per resource for backoff calculation.
	failureTracker *FailureTracker
}

// NewRequeueStrategy creates a new RequeueStrategy with the given configuration.
func NewRequeueStrategy(config *RequeueConfig) *RequeueStrategy {
	if config == nil {
		config = DefaultRequeueConfig()
	}
	return &RequeueStrategy{
		config:         config,
		failureTracker: NewFailureTracker(config.MaxFailures),
	}
}

// DefaultRequeueStrategy returns a RequeueStrategy with default configuration.
func DefaultRequeueStrategy() *RequeueStrategy {
	return NewRequeueStrategy(nil)
}

// ForSuccess returns the Result for a successful reconciliation.
// Resets the failure count for the resource.
func (s *RequeueStrategy) ForSuccess() ctrl.Result {
	return ctrl.Result{
		RequeueAfter: addJitter(s.config.SuccessInterval, s.config.JitterPercent),
	}
}

// ForSuccessWithResource returns the Result for a successful reconciliation
// and resets the failure count for the specific resource.
func (s *RequeueStrategy) ForSuccessWithResource(key string) ctrl.Result {
	s.failureTracker.Reset(key)
	return s.ForSuccess()
}

// ForTransientError returns the Result for a transient error.
// Uses exponential backoff based on failure count.
func (s *RequeueStrategy) ForTransientError() ctrl.Result {
	return ctrl.Result{
		RequeueAfter: addJitter(s.config.TransientErrorInterval, s.config.JitterPercent),
		Requeue:      true,
	}
}

// ForTransientErrorWithBackoff returns the Result for a transient error
// with exponential backoff based on the resource's failure count.
func (s *RequeueStrategy) ForTransientErrorWithBackoff(key string) ctrl.Result {
	failures := s.failureTracker.Increment(key)
	interval := s.calculateBackoff(s.config.TransientErrorInterval, failures)
	return ctrl.Result{
		RequeueAfter: addJitter(interval, s.config.JitterPercent),
		Requeue:      true,
	}
}

// ForDependencyError returns the Result for a dependency error.
// Uses a moderate interval as dependencies may be created soon.
func (s *RequeueStrategy) ForDependencyError() ctrl.Result {
	return ctrl.Result{
		RequeueAfter: addJitter(s.config.DependencyErrorInterval, s.config.JitterPercent),
		Requeue:      true,
	}
}

// ForDependencyErrorWithBackoff returns the Result for a dependency error
// with exponential backoff based on the resource's failure count.
func (s *RequeueStrategy) ForDependencyErrorWithBackoff(key string) ctrl.Result {
	failures := s.failureTracker.Increment(key)
	interval := s.calculateBackoff(s.config.DependencyErrorInterval, failures)
	return ctrl.Result{
		RequeueAfter: addJitter(interval, s.config.JitterPercent),
		Requeue:      true,
	}
}

// ForValidationError returns the Result for a validation error.
// Uses a longer interval as user intervention is required.
func (s *RequeueStrategy) ForValidationError() ctrl.Result {
	return ctrl.Result{
		RequeueAfter: addJitter(s.config.ValidationErrorInterval, s.config.JitterPercent),
	}
}

// ForPermanentError returns the Result for a permanent error.
// Uses a longer interval as user intervention is required.
func (s *RequeueStrategy) ForPermanentError() ctrl.Result {
	return ctrl.Result{
		RequeueAfter: addJitter(s.config.PermanentErrorInterval, s.config.JitterPercent),
	}
}

// ForInternalError returns the Result for an internal error.
// Uses exponential backoff with a moderate starting interval.
func (s *RequeueStrategy) ForInternalError() ctrl.Result {
	return ctrl.Result{
		RequeueAfter: addJitter(s.config.TransientErrorInterval, s.config.JitterPercent),
		Requeue:      true,
	}
}

// ForInternalErrorWithBackoff returns the Result for an internal error
// with exponential backoff based on the resource's failure count.
func (s *RequeueStrategy) ForInternalErrorWithBackoff(key string) ctrl.Result {
	failures := s.failureTracker.Increment(key)
	interval := s.calculateBackoff(s.config.TransientErrorInterval, failures)
	return ctrl.Result{
		RequeueAfter: addJitter(interval, s.config.JitterPercent),
		Requeue:      true,
	}
}

// ForCustomInterval returns a Result with a custom interval.
func (s *RequeueStrategy) ForCustomInterval(interval time.Duration) ctrl.Result {
	return ctrl.Result{
		RequeueAfter: addJitter(interval, s.config.JitterPercent),
	}
}

// ForImmediateRequeue returns a Result for immediate requeue.
func (s *RequeueStrategy) ForImmediateRequeue() ctrl.Result {
	return ctrl.Result{Requeue: true}
}

// ForNoRequeue returns a Result that does not requeue.
func (s *RequeueStrategy) ForNoRequeue() ctrl.Result {
	return ctrl.Result{}
}

// calculateBackoff calculates the backoff interval using exponential backoff.
// Formula: min(maxInterval, baseInterval * multiplier^failures)
func (s *RequeueStrategy) calculateBackoff(baseInterval time.Duration, failures int) time.Duration {
	if failures <= 0 {
		return baseInterval
	}

	// Cap failures to prevent overflow
	if failures > s.config.MaxFailures {
		failures = s.config.MaxFailures
	}

	// Calculate exponential backoff
	multiplier := math.Pow(s.config.BackoffMultiplier, float64(failures))
	interval := time.Duration(float64(baseInterval) * multiplier)

	// Cap at max interval
	if interval > s.config.MaxInterval {
		interval = s.config.MaxInterval
	}

	return interval
}

// GetFailureCount returns the current failure count for a resource.
func (s *RequeueStrategy) GetFailureCount(key string) int {
	return s.failureTracker.Get(key)
}

// ResetFailureCount resets the failure count for a resource.
func (s *RequeueStrategy) ResetFailureCount(key string) {
	s.failureTracker.Reset(key)
}

// ============================================================================
// Failure Tracker
// ============================================================================

// FailureTracker tracks failure counts per resource for backoff calculation.
type FailureTracker struct {
	mu          sync.RWMutex
	failures    map[string]int
	maxFailures int
}

// NewFailureTracker creates a new FailureTracker.
func NewFailureTracker(maxFailures int) *FailureTracker {
	if maxFailures <= 0 {
		maxFailures = 10
	}
	return &FailureTracker{
		failures:    make(map[string]int),
		maxFailures: maxFailures,
	}
}

// Increment increments the failure count for a resource and returns the new count.
func (t *FailureTracker) Increment(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.failures[key]++
	if t.failures[key] > t.maxFailures {
		t.failures[key] = t.maxFailures
	}

	// Record metric
	requeueFailureCount.WithLabelValues(key).Set(float64(t.failures[key]))

	return t.failures[key]
}

// Get returns the current failure count for a resource.
func (t *FailureTracker) Get(key string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.failures[key]
}

// Reset resets the failure count for a resource.
func (t *FailureTracker) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, key)

	// Record metric
	requeueFailureCount.WithLabelValues(key).Set(0)
}

// Clear clears all failure counts.
func (t *FailureTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures = make(map[string]int)
}

// ============================================================================
// Jitter Calculation
// ============================================================================

// addJitter adds random jitter to an interval.
// Jitter is calculated as a percentage of the interval, applied as +/- half the jitter.
func addJitter(interval time.Duration, jitterPercent int) time.Duration {
	if jitterPercent <= 0 || jitterPercent > 100 {
		return interval
	}

	jitterMu.Lock()
	defer jitterMu.Unlock()

	// Calculate jitter range
	jitterRange := float64(interval) * float64(jitterPercent) / 100.0

	// Generate random jitter between -jitterRange/2 and +jitterRange/2
	jitterValue := jitterRand.Float64()*jitterRange - jitterRange/2

	return interval + time.Duration(jitterValue)
}

// ============================================================================
// Resource Key Helpers
// ============================================================================

// ResourceKey returns a string key for a resource suitable for failure tracking.
func ResourceKey(obj client.Object) string {
	return client.ObjectKeyFromObject(obj).String()
}

// ============================================================================
// Metrics
// ============================================================================

var (
	requeueFailureCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "requeue_failure_count",
			Help:      "Current failure count for resources (used for backoff calculation)",
		},
		[]string{"resource"},
	)

	requeueIntervalHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "requeue_interval_seconds",
			Help:      "Distribution of requeue intervals in seconds",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 900},
		},
		[]string{"error_type"},
	)
)

func init() {
	metrics.Registry.MustRegister(requeueFailureCount)
	metrics.Registry.MustRegister(requeueIntervalHistogram)
}

// RecordRequeueInterval records a requeue interval metric.
func RecordRequeueInterval(errorType ErrorType, interval time.Duration) {
	requeueIntervalHistogram.WithLabelValues(string(errorType)).Observe(interval.Seconds())
}

// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
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

// FailureTracker configuration constants.
const (
	// DefaultMaxEntries is the default maximum number of entries in the failure tracker.
	DefaultMaxEntries = 10000
	// DefaultStaleEntryAge is the default age after which entries are considered stale.
	DefaultStaleEntryAge = 1 * time.Hour
	// DefaultCleanupInterval is the default interval for automatic cleanup.
	DefaultCleanupInterval = 5 * time.Minute
)

// failureEntry holds failure count and access timestamp for LRU eviction.
type failureEntry struct {
	count        int
	lastAccessed time.Time
}

// FailureTracker tracks failure counts per resource for backoff calculation.
// It implements LRU eviction and stale entry cleanup to prevent unbounded memory growth.
type FailureTracker struct {
	mu          sync.RWMutex
	failures    map[string]*failureEntry
	maxFailures int
	maxEntries  int
	staleAge    time.Duration

	// accessOrder maintains LRU order for eviction (most recently accessed at end)
	accessOrder []string

	// cleanupCancel is used to stop the periodic cleanup goroutine
	cleanupCancel context.CancelFunc
	// cleanupDone signals when the cleanup goroutine has finished
	cleanupDone chan struct{}
	// logger for cleanup operations
	logger logr.Logger
}

// FailureTrackerConfig holds configuration for FailureTracker.
type FailureTrackerConfig struct {
	// MaxFailures is the maximum failure count to track (caps backoff calculation).
	MaxFailures int
	// MaxEntries is the maximum number of entries before LRU eviction.
	MaxEntries int
	// StaleAge is the duration after which entries are considered stale.
	StaleAge time.Duration
}

// DefaultFailureTrackerConfig returns the default configuration.
func DefaultFailureTrackerConfig() *FailureTrackerConfig {
	return &FailureTrackerConfig{
		MaxFailures: 10,
		MaxEntries:  DefaultMaxEntries,
		StaleAge:    DefaultStaleEntryAge,
	}
}

// NewFailureTracker creates a new FailureTracker with default configuration.
func NewFailureTracker(maxFailures int) *FailureTracker {
	cfg := DefaultFailureTrackerConfig()
	if maxFailures > 0 {
		cfg.MaxFailures = maxFailures
	}
	return NewFailureTrackerWithConfig(cfg)
}

// NewFailureTrackerWithConfig creates a new FailureTracker with the given configuration.
func NewFailureTrackerWithConfig(cfg *FailureTrackerConfig) *FailureTracker {
	if cfg == nil {
		cfg = DefaultFailureTrackerConfig()
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 10
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.StaleAge <= 0 {
		cfg.StaleAge = DefaultStaleEntryAge
	}
	return &FailureTracker{
		failures:    make(map[string]*failureEntry),
		maxFailures: cfg.MaxFailures,
		maxEntries:  cfg.MaxEntries,
		staleAge:    cfg.StaleAge,
		accessOrder: make([]string, 0),
	}
}

// Increment increments the failure count for a resource and returns the new count.
// It also updates the last accessed time and performs LRU eviction if needed.
func (t *FailureTracker) Increment(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	entry, exists := t.failures[key]
	if !exists {
		// Check if we need to evict before adding
		t.evictIfNeededLocked()

		entry = &failureEntry{
			count:        0,
			lastAccessed: now,
		}
		t.failures[key] = entry
		t.accessOrder = append(t.accessOrder, key)
	}

	entry.count++
	if entry.count > t.maxFailures {
		entry.count = t.maxFailures
	}
	entry.lastAccessed = now

	// Update access order (move to end for LRU)
	t.updateAccessOrderLocked(key)

	// Record metric
	requeueFailureCount.WithLabelValues(key).Set(float64(entry.count))

	return entry.count
}

// Get returns the current failure count for a resource.
// It also updates the last accessed time.
func (t *FailureTracker) Get(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.failures[key]
	if !exists {
		return 0
	}

	entry.lastAccessed = time.Now()
	t.updateAccessOrderLocked(key)

	return entry.count
}

// Reset resets the failure count for a resource.
func (t *FailureTracker) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.failures, key)
	t.removeFromAccessOrderLocked(key)

	// Record metric
	requeueFailureCount.WithLabelValues(key).Set(0)
}

// Clear clears all failure counts.
func (t *FailureTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.failures = make(map[string]*failureEntry)
	t.accessOrder = make([]string, 0)
}

// CleanupStaleEntries removes entries that haven't been accessed within maxAge.
// Returns the number of entries removed.
func (t *FailureTracker) CleanupStaleEntries(maxAge time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	if maxAge <= 0 {
		maxAge = t.staleAge
	}

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for key, entry := range t.failures {
		if entry.lastAccessed.Before(cutoff) {
			delete(t.failures, key)
			t.removeFromAccessOrderLocked(key)
			requeueFailureCount.WithLabelValues(key).Set(0)
			removed++
		}
	}

	return removed
}

// Size returns the current number of tracked entries.
func (t *FailureTracker) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.failures)
}

// evictIfNeededLocked evicts the least recently used entry if at capacity.
// Must be called with lock held.
func (t *FailureTracker) evictIfNeededLocked() {
	if len(t.failures) < t.maxEntries {
		return
	}

	// First, try to remove stale entries
	cutoff := time.Now().Add(-t.staleAge)
	for key, entry := range t.failures {
		if entry.lastAccessed.Before(cutoff) {
			delete(t.failures, key)
			t.removeFromAccessOrderLocked(key)
			requeueFailureCount.WithLabelValues(key).Set(0)
			if len(t.failures) < t.maxEntries {
				return
			}
		}
	}

	// If still at capacity, evict LRU entry
	if len(t.accessOrder) > 0 && len(t.failures) >= t.maxEntries {
		lruKey := t.accessOrder[0]
		delete(t.failures, lruKey)
		t.accessOrder = t.accessOrder[1:]
		requeueFailureCount.WithLabelValues(lruKey).Set(0)
	}
}

// updateAccessOrderLocked moves a key to the end of the access order (most recently used).
// Must be called with lock held.
func (t *FailureTracker) updateAccessOrderLocked(key string) {
	// Find and remove the key from its current position
	for i, k := range t.accessOrder {
		if k == key {
			t.accessOrder = append(t.accessOrder[:i], t.accessOrder[i+1:]...)
			break
		}
	}
	// Add to end (most recently used)
	t.accessOrder = append(t.accessOrder, key)
}

// removeFromAccessOrderLocked removes a key from the access order.
// Must be called with lock held.
func (t *FailureTracker) removeFromAccessOrderLocked(key string) {
	for i, k := range t.accessOrder {
		if k == key {
			t.accessOrder = append(t.accessOrder[:i], t.accessOrder[i+1:]...)
			return
		}
	}
}

// StartPeriodicCleanup starts a background goroutine that periodically cleans up stale entries.
// The cleanup runs at the specified interval and removes entries older than the configured staleAge.
// Call StopPeriodicCleanup to stop the background goroutine gracefully.
func (t *FailureTracker) StartPeriodicCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}

	// Create a cancellable context for the cleanup goroutine
	cleanupCtx, cancel := context.WithCancel(ctx)
	t.cleanupCancel = cancel
	t.cleanupDone = make(chan struct{})
	t.logger = log.FromContext(ctx).WithName("failure-tracker-cleanup")

	go t.runPeriodicCleanup(cleanupCtx, interval)
}

// StopPeriodicCleanup stops the periodic cleanup goroutine gracefully.
// It waits for the cleanup goroutine to finish before returning.
func (t *FailureTracker) StopPeriodicCleanup() {
	if t.cleanupCancel != nil {
		t.cleanupCancel()
		// Wait for the cleanup goroutine to finish
		if t.cleanupDone != nil {
			<-t.cleanupDone
		}
		t.cleanupCancel = nil
		t.cleanupDone = nil
	}
}

// runPeriodicCleanup runs the periodic cleanup loop.
func (t *FailureTracker) runPeriodicCleanup(ctx context.Context, interval time.Duration) {
	defer close(t.cleanupDone)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	t.logger.Info("started periodic cleanup", "interval", interval, "staleAge", t.staleAge)

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("stopping periodic cleanup")
			return
		case <-ticker.C:
			removed := t.CleanupStaleEntries(0) // Use configured staleAge
			if removed > 0 {
				t.logger.V(1).Info("cleaned up stale entries", "removed", removed, "remaining", t.Size())
			}
		}
	}
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

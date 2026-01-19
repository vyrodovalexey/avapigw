package retry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RetryAttemptsTotal counts total retry attempts.
	RetryAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "retry_attempts_total",
			Help: "Total number of retry attempts",
		},
		[]string{"operation", "attempt"},
	)

	// RetrySuccessTotal counts successful retries.
	RetrySuccessTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "retry_success_total",
			Help: "Total number of successful operations after retry",
		},
		[]string{"operation"},
	)

	// RetryFailureTotal counts failed retries (all attempts exhausted).
	RetryFailureTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "retry_failure_total",
			Help: "Total number of operations that failed after all retry attempts",
		},
		[]string{"operation"},
	)

	// RetryDuration measures the total duration of retry operations.
	RetryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "retry_duration_seconds",
			Help:    "Total duration of retry operations in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation", "result"},
	)

	// RetryBackoffDuration measures backoff wait times.
	RetryBackoffDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "retry_backoff_duration_seconds",
			Help:    "Duration of backoff waits in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"operation", "attempt"},
	)
)

// RecordRetryAttempt records a retry attempt.
func RecordRetryAttempt(operation string, attempt int) {
	RetryAttemptsTotal.WithLabelValues(operation, string(rune('0'+attempt))).Inc()
}

// RecordRetrySuccess records a successful retry.
func RecordRetrySuccess(operation string) {
	RetrySuccessTotal.WithLabelValues(operation).Inc()
}

// RecordRetryFailure records a failed retry (all attempts exhausted).
func RecordRetryFailure(operation string) {
	RetryFailureTotal.WithLabelValues(operation).Inc()
}

// RecordRetryDuration records the total duration of a retry operation.
func RecordRetryDuration(operation string, success bool, durationSeconds float64) {
	result := "success"
	if !success {
		result = "failure"
	}
	RetryDuration.WithLabelValues(operation, result).Observe(durationSeconds)
}

// RecordBackoffDuration records a backoff wait duration.
func RecordBackoffDuration(operation string, attempt int, durationSeconds float64) {
	RetryBackoffDuration.WithLabelValues(operation, string(rune('0'+attempt))).Observe(durationSeconds)
}

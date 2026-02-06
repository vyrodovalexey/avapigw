// Package controller provides Kubernetes controllers for the operator.
package controller

import "time"

// Requeue duration constants for controller reconciliation.
// These constants define the time intervals for requeuing reconciliation
// requests in various scenarios.
const (
	// RequeueAfterReconcileFailure is the duration to wait before retrying
	// after a reconciliation failure.
	RequeueAfterReconcileFailure = 30 * time.Second

	// RequeueAfterStatusUpdateFailure is the duration to wait before retrying
	// after a status update failure.
	RequeueAfterStatusUpdateFailure = 5 * time.Second

	// RequeueAfterCleanupFailure is the duration to wait before retrying
	// after a cleanup failure during deletion.
	RequeueAfterCleanupFailure = 10 * time.Second

	// RateLimiterBaseDelay is the base delay for the exponential backoff rate limiter.
	RateLimiterBaseDelay = time.Second

	// RateLimiterMaxDelay is the maximum delay for the exponential backoff rate limiter.
	RateLimiterMaxDelay = 30 * time.Second

	// MaxConcurrentReconciles is the maximum number of concurrent reconciles
	// allowed per controller.
	MaxConcurrentReconciles = 3
)

// Status messages for controller reconciliation.
const (
	// MessageRouteApplied is the message when a route is successfully applied.
	MessageRouteApplied = "Route successfully applied"

	// MessageRouteDeleted is the message when a route is successfully deleted.
	MessageRouteDeleted = "Route successfully deleted"

	// MessageBackendApplied is the message when a backend is successfully applied.
	MessageBackendApplied = "Backend successfully applied"

	// MessageBackendDeleted is the message when a backend is successfully deleted.
	MessageBackendDeleted = "Backend successfully deleted"

	// MessageReconcileFailed is the message when reconciliation fails.
	MessageReconcileFailed = "Reconciliation failed"

	// MessageCleanupFailed is the message when cleanup fails.
	MessageCleanupFailed = "Cleanup failed"
)

// Event reasons for controller events.
const (
	// EventReasonReconciled is the event reason when a resource is successfully reconciled.
	EventReasonReconciled = "Reconciled"

	// EventReasonReconcileFailed is the event reason when reconciliation fails.
	EventReasonReconcileFailed = "ReconcileFailed"

	// EventReasonDeleted is the event reason when a resource is successfully deleted.
	EventReasonDeleted = "Deleted"

	// EventReasonCleanupFailed is the event reason when cleanup fails.
	EventReasonCleanupFailed = "CleanupFailed"
)

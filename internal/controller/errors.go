// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ============================================================================
// Error Types
// ============================================================================

// ErrorType represents the classification of an error for handling purposes.
type ErrorType string

const (
	// ErrorTypeTransient indicates a temporary error that should be retried.
	// Examples: network timeouts, temporary API unavailability, rate limiting.
	ErrorTypeTransient ErrorType = "Transient"

	// ErrorTypePermanent indicates an error that won't be resolved by retrying.
	// Examples: invalid configuration, missing required fields, invalid references.
	ErrorTypePermanent ErrorType = "Permanent"

	// ErrorTypeValidation indicates a validation error in the resource spec.
	// These errors require user intervention to fix the resource.
	ErrorTypeValidation ErrorType = "Validation"

	// ErrorTypeDependency indicates a missing or invalid dependency.
	// Examples: referenced Secret not found, Gateway not found.
	ErrorTypeDependency ErrorType = "Dependency"

	// ErrorTypeInternal indicates an internal error in the controller.
	// These are unexpected errors that may indicate bugs.
	ErrorTypeInternal ErrorType = "Internal"
)

// ReconcileError represents a structured error for controller reconciliation.
// It provides context about the error type, severity, and whether it should be retried.
type ReconcileError struct {
	// Type classifies the error for handling decisions.
	Type ErrorType

	// Op is the operation that failed (e.g., "validateTLSConfig", "syncSecret").
	Op string

	// Resource identifies the resource being reconciled.
	Resource string

	// Err is the underlying error.
	Err error

	// Message provides additional context about the error.
	Message string

	// Retryable indicates whether the error should trigger a retry.
	Retryable bool

	// UserActionRequired indicates whether user intervention is needed.
	UserActionRequired bool
}

// Error implements the error interface.
// Error messages follow Go conventions: lowercase, no trailing punctuation, include context.
func (e *ReconcileError) Error() string {
	errType := strings.ToLower(string(e.Type))
	if e.Resource != "" {
		return fmt.Sprintf("%s error during %s for %s: %v", errType, e.Op, e.Resource, e.Err)
	}
	return fmt.Sprintf("%s error during %s: %v", errType, e.Op, e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *ReconcileError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is for ReconcileError.
func (e *ReconcileError) Is(target error) bool {
	if t, ok := target.(*ReconcileError); ok {
		return e.Type == t.Type
	}
	return errors.Is(e.Err, target)
}

// ============================================================================
// Error Constructors
// ============================================================================

// NewTransientError creates a new transient error that should be retried.
// Use for temporary failures like network issues or rate limiting.
func NewTransientError(op, resource string, err error) *ReconcileError {
	return &ReconcileError{
		Type:               ErrorTypeTransient,
		Op:                 op,
		Resource:           resource,
		Err:                err,
		Message:            "temporary error, will retry",
		Retryable:          true,
		UserActionRequired: false,
	}
}

// NewPermanentError creates a new permanent error that should not be retried.
// Use for errors that require user intervention or configuration changes.
func NewPermanentError(op, resource string, err error) *ReconcileError {
	return &ReconcileError{
		Type:               ErrorTypePermanent,
		Op:                 op,
		Resource:           resource,
		Err:                err,
		Message:            "permanent error, requires intervention",
		Retryable:          false,
		UserActionRequired: true,
	}
}

// NewValidationError creates a new validation error.
// Use for spec validation failures that require user to fix the resource.
func NewValidationError(op, resource string, err error) *ReconcileError {
	return &ReconcileError{
		Type:               ErrorTypeValidation,
		Op:                 op,
		Resource:           resource,
		Err:                err,
		Message:            "validation failed",
		Retryable:          false,
		UserActionRequired: true,
	}
}

// NewDependencyError creates a new dependency error.
// Use when a referenced resource is not found or invalid.
// These are retryable as the dependency might be created later.
func NewDependencyError(op, resource string, err error) *ReconcileError {
	return &ReconcileError{
		Type:               ErrorTypeDependency,
		Op:                 op,
		Resource:           resource,
		Err:                err,
		Message:            "dependency not satisfied",
		Retryable:          true,
		UserActionRequired: false,
	}
}

// NewInternalError creates a new internal error.
// Use for unexpected errors that may indicate bugs.
func NewInternalError(op, resource string, err error) *ReconcileError {
	return &ReconcileError{
		Type:               ErrorTypeInternal,
		Op:                 op,
		Resource:           resource,
		Err:                err,
		Message:            "internal error",
		Retryable:          true,
		UserActionRequired: false,
	}
}

// ============================================================================
// Error Classification
// ============================================================================

// ClassifyError analyzes an error and returns a properly typed ReconcileError.
// This function examines the error to determine if it's transient, permanent, etc.
func ClassifyError(op, resource string, err error) *ReconcileError {
	if err == nil {
		return nil
	}

	// Check if it's already a ReconcileError
	var reconcileErr *ReconcileError
	if errors.As(err, &reconcileErr) {
		return reconcileErr
	}

	// Check for Kubernetes API errors
	if classified := classifyKubernetesAPIError(op, resource, err); classified != nil {
		return classified
	}

	// Check for network errors (transient)
	if isNetworkError(err) {
		return NewTransientError(op, resource, err)
	}

	// Check for context errors
	if isContextError(err) {
		return NewTransientError(op, resource, err)
	}

	// Default to internal error for unknown errors
	return NewInternalError(op, resource, err)
}

// classifyKubernetesAPIError classifies Kubernetes API errors.
func classifyKubernetesAPIError(op, resource string, err error) *ReconcileError {
	// Dependency errors
	if apierrors.IsNotFound(err) {
		return NewDependencyError(op, resource, err)
	}

	// Transient errors
	if isTransientAPIError(err) {
		return NewTransientError(op, resource, err)
	}

	// Validation errors
	if isValidationAPIError(err) {
		return NewValidationError(op, resource, err)
	}

	// Permanent errors
	if isPermanentAPIError(err) {
		return NewPermanentError(op, resource, err)
	}

	return nil
}

// isTransientAPIError checks if the error is a transient Kubernetes API error.
func isTransientAPIError(err error) bool {
	return apierrors.IsConflict(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsTimeout(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err)
}

// isValidationAPIError checks if the error is a validation Kubernetes API error.
func isValidationAPIError(err error) bool {
	return apierrors.IsBadRequest(err) || apierrors.IsInvalid(err)
}

// isPermanentAPIError checks if the error is a permanent Kubernetes API error.
func isPermanentAPIError(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err)
}

// isContextError checks if the error is a context-related error.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// isNetworkError checks if the error is a network-related error.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for net.Error
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// Check for specific syscall errors
	var syscallErr *net.OpError
	if errors.As(err, &syscallErr) {
		return true
	}

	// Check for connection refused
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}

	// Check for common network error messages
	errMsg := err.Error()
	networkIndicators := []string{
		"connection refused",
		"connection reset",
		"connection timed out",
		"no such host",
		"network is unreachable",
		"i/o timeout",
		"EOF",
		"broken pipe",
	}
	for _, indicator := range networkIndicators {
		if strings.Contains(strings.ToLower(errMsg), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// IsRetryable returns true if the error should trigger a retry.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	var reconcileErr *ReconcileError
	if errors.As(err, &reconcileErr) {
		return reconcileErr.Retryable
	}

	// For non-ReconcileError, classify and check
	classified := ClassifyError("unknown", "", err)
	return classified.Retryable
}

// IsTransient returns true if the error is transient.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}

	var reconcileErr *ReconcileError
	if errors.As(err, &reconcileErr) {
		return reconcileErr.Type == ErrorTypeTransient
	}

	return false
}

// IsPermanent returns true if the error is permanent.
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}

	var reconcileErr *ReconcileError
	if errors.As(err, &reconcileErr) {
		return reconcileErr.Type == ErrorTypePermanent
	}

	return false
}

// IsValidation returns true if the error is a validation error.
func IsValidation(err error) bool {
	if err == nil {
		return false
	}

	var reconcileErr *ReconcileError
	if errors.As(err, &reconcileErr) {
		return reconcileErr.Type == ErrorTypeValidation
	}

	return false
}

// IsDependency returns true if the error is a dependency error.
func IsDependency(err error) bool {
	if err == nil {
		return false
	}

	var reconcileErr *ReconcileError
	if errors.As(err, &reconcileErr) {
		return reconcileErr.Type == ErrorTypeDependency
	}

	return false
}

// ============================================================================
// Error Handling Helpers
// ============================================================================

// ErrorHandler provides utilities for consistent error handling in controllers.
type ErrorHandler struct {
	logger   logr.Logger
	recorder record.EventRecorder
}

// NewErrorHandler creates a new ErrorHandler.
func NewErrorHandler(logger logr.Logger, recorder record.EventRecorder) *ErrorHandler {
	return &ErrorHandler{
		logger:   logger,
		recorder: recorder,
	}
}

// HandleError processes an error and returns the appropriate Result.
// It logs the error, records events, and determines the requeue strategy.
func (h *ErrorHandler) HandleError(obj client.Object, err error, strategy *RequeueStrategy) (ctrl.Result, error) {
	if err == nil {
		return ctrl.Result{}, nil
	}

	// Classify the error if not already classified
	reconcileErr := ClassifyError("reconcile", client.ObjectKeyFromObject(obj).String(), err)

	// Log with structured fields
	h.logError(obj, reconcileErr)

	// Record event
	h.recordEvent(obj, reconcileErr)

	// Determine requeue strategy
	return h.determineResult(reconcileErr, strategy), reconcileErr
}

// logError logs the error with appropriate level and structured fields.
func (h *ErrorHandler) logError(obj client.Object, err *ReconcileError) {
	fields := []interface{}{
		"errorType", err.Type,
		"operation", err.Op,
		"resource", client.ObjectKeyFromObject(obj).String(),
		"retryable", err.Retryable,
		"userActionRequired", err.UserActionRequired,
	}

	switch err.Type {
	case ErrorTypeValidation, ErrorTypePermanent:
		h.logger.Error(err.Err, err.Message, fields...)
	case ErrorTypeTransient, ErrorTypeDependency:
		h.logger.Info("Transient error occurred, will retry", fields...)
	case ErrorTypeInternal:
		h.logger.Error(err.Err, "Internal error occurred", fields...)
	default:
		h.logger.Error(err.Err, "Unknown error type", fields...)
	}
}

// recordEvent records a Kubernetes event for the error.
func (h *ErrorHandler) recordEvent(obj client.Object, err *ReconcileError) {
	if h.recorder == nil {
		return
	}

	eventType := corev1.EventTypeWarning
	reason := string(err.Type) + "Error"
	message := err.Error()

	// Truncate message if too long
	if len(message) > 1024 {
		message = message[:1021] + "..."
	}

	h.recorder.Event(obj, eventType, reason, message)
}

// determineResult determines the ctrl.Result based on error type and strategy.
func (h *ErrorHandler) determineResult(err *ReconcileError, strategy *RequeueStrategy) ctrl.Result {
	if strategy == nil {
		strategy = DefaultRequeueStrategy()
	}

	switch err.Type {
	case ErrorTypeTransient:
		return strategy.ForTransientError()
	case ErrorTypePermanent:
		return strategy.ForPermanentError()
	case ErrorTypeValidation:
		return strategy.ForValidationError()
	case ErrorTypeDependency:
		return strategy.ForDependencyError()
	case ErrorTypeInternal:
		return strategy.ForInternalError()
	default:
		return strategy.ForTransientError()
	}
}

// ============================================================================
// Common Error Messages
// ============================================================================

// Common error messages for consistent error reporting.
// Error messages follow Go conventions:
// - lowercase
// - no trailing punctuation
// - include relevant context
const (
	ErrMsgResourceNotFound     = "resource not found"
	ErrMsgInvalidConfiguration = "configuration is invalid"
	ErrMsgReferenceNotFound    = "referenced resource not found"
	ErrMsgAuthenticationFailed = "authentication failed"
	ErrMsgConnectionFailed     = "failed to establish connection"
	ErrMsgTimeout              = "operation timed out"
	ErrMsgRateLimited          = "request rate limited"
	ErrMsgInternalError        = "internal error occurred"
)

// Metric result labels for controller reconciliation.
const (
	MetricResultSuccess = "success"
	MetricResultError   = "error"
)

// Backend reference kinds.
const (
	BackendKindService = "Service"
	BackendKindBackend = "Backend"
)

// WrapWithContext wraps an error with additional context.
// Uses consistent formatting: "ctx: operation for resource: error"
func WrapWithContext(err error, op, resource, ctx string) error {
	if err == nil {
		return nil
	}
	if resource != "" {
		return fmt.Errorf("%s: %s for %s: %w", ctx, op, resource, err)
	}
	return fmt.Errorf("%s: %s: %w", ctx, op, err)
}

// ============================================================================
// Safe Type Conversions
// ============================================================================

// safeIntToInt32 safely converts an int to int32, clamping to max int32 if needed.
// This prevents integer overflow when converting slice lengths to int32 for status fields.
func safeIntToInt32(v int) int32 {
	const maxInt32 = int32(^uint32(0) >> 1) // 2147483647
	if v < 0 {
		return 0
	}
	if v > int(maxInt32) {
		return maxInt32
	}
	return int32(v)
}

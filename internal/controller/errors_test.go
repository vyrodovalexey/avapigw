// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
)

func TestNewTransientError(t *testing.T) {
	err := errors.New("connection timeout")
	reconcileErr := NewTransientError("syncSecret", "default/my-secret", err)

	assert.Equal(t, ErrorTypeTransient, reconcileErr.Type)
	assert.Equal(t, "syncSecret", reconcileErr.Op)
	assert.Equal(t, "default/my-secret", reconcileErr.Resource)
	assert.True(t, reconcileErr.Retryable)
	assert.False(t, reconcileErr.UserActionRequired)
	assert.Contains(t, reconcileErr.Error(), "transient")
	assert.Contains(t, reconcileErr.Error(), "syncSecret")
	assert.Contains(t, reconcileErr.Error(), "default/my-secret")
}

func TestNewPermanentError(t *testing.T) {
	err := errors.New("invalid configuration")
	reconcileErr := NewPermanentError("validateConfig", "default/my-gateway", err)

	assert.Equal(t, ErrorTypePermanent, reconcileErr.Type)
	assert.Equal(t, "validateConfig", reconcileErr.Op)
	assert.Equal(t, "default/my-gateway", reconcileErr.Resource)
	assert.False(t, reconcileErr.Retryable)
	assert.True(t, reconcileErr.UserActionRequired)
}

func TestNewValidationError(t *testing.T) {
	err := errors.New("invalid TLS configuration")
	reconcileErr := NewValidationError("validateTLS", "default/my-gateway", err)

	assert.Equal(t, ErrorTypeValidation, reconcileErr.Type)
	assert.False(t, reconcileErr.Retryable)
	assert.True(t, reconcileErr.UserActionRequired)
}

func TestNewDependencyError(t *testing.T) {
	err := errors.New("secret not found")
	reconcileErr := NewDependencyError("getSecret", "default/my-secret", err)

	assert.Equal(t, ErrorTypeDependency, reconcileErr.Type)
	assert.True(t, reconcileErr.Retryable)
	assert.False(t, reconcileErr.UserActionRequired)
}

func TestNewInternalError(t *testing.T) {
	err := errors.New("unexpected nil pointer")
	reconcileErr := NewInternalError("processRoute", "default/my-route", err)

	assert.Equal(t, ErrorTypeInternal, reconcileErr.Type)
	assert.True(t, reconcileErr.Retryable)
	assert.False(t, reconcileErr.UserActionRequired)
}

func TestReconcileError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ReconcileError
		contains []string
	}{
		{
			name: "with resource",
			err: &ReconcileError{
				Type:     ErrorTypeTransient,
				Op:       "syncSecret",
				Resource: "default/my-secret",
				Err:      errors.New("timeout"),
			},
			contains: []string{"transient", "syncSecret", "default/my-secret", "timeout"},
		},
		{
			name: "without resource",
			err: &ReconcileError{
				Type: ErrorTypePermanent,
				Op:   "validateConfig",
				Err:  errors.New("invalid"),
			},
			contains: []string{"permanent", "validateConfig", "invalid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, errStr, s)
			}
		})
	}
}

func TestReconcileError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	reconcileErr := NewTransientError("op", "resource", originalErr)

	unwrapped := reconcileErr.Unwrap()
	assert.Equal(t, originalErr, unwrapped)
}

func TestReconcileError_Is(t *testing.T) {
	originalErr := errors.New("original error")
	reconcileErr := NewTransientError("op", "resource", originalErr)

	// Should match the underlying error
	assert.True(t, errors.Is(reconcileErr, originalErr))

	// Should match another ReconcileError of the same type
	anotherTransient := &ReconcileError{Type: ErrorTypeTransient}
	assert.True(t, reconcileErr.Is(anotherTransient))

	// Should not match a different type
	permanent := &ReconcileError{Type: ErrorTypePermanent}
	assert.False(t, reconcileErr.Is(permanent))
}

func TestClassifyError_KubernetesErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedType ErrorType
		retryable    bool
	}{
		{
			name:         "not found",
			err:          apierrors.NewNotFound(schema.GroupResource{Group: "", Resource: "secrets"}, "my-secret"),
			expectedType: ErrorTypeDependency,
			retryable:    true,
		},
		{
			name:         "conflict",
			err:          apierrors.NewConflict(schema.GroupResource{Group: "", Resource: "gateways"}, "my-gateway", errors.New("conflict")),
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
		{
			name:         "server timeout",
			err:          apierrors.NewServerTimeout(schema.GroupResource{Group: "", Resource: "pods"}, "get", 30),
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
		{
			name:         "too many requests",
			err:          apierrors.NewTooManyRequests("rate limited", 60),
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
		{
			name:         "service unavailable",
			err:          apierrors.NewServiceUnavailable("service unavailable"),
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
		{
			name:         "internal error",
			err:          apierrors.NewInternalError(errors.New("internal")),
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
		{
			name:         "bad request",
			err:          apierrors.NewBadRequest("bad request"),
			expectedType: ErrorTypeValidation,
			retryable:    false,
		},
		{
			name:         "forbidden",
			err:          apierrors.NewForbidden(schema.GroupResource{Group: "", Resource: "secrets"}, "my-secret", errors.New("forbidden")),
			expectedType: ErrorTypePermanent,
			retryable:    false,
		},
		{
			name:         "unauthorized",
			err:          apierrors.NewUnauthorized("unauthorized"),
			expectedType: ErrorTypePermanent,
			retryable:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError("testOp", "testResource", tt.err)
			assert.Equal(t, tt.expectedType, result.Type)
			assert.Equal(t, tt.retryable, result.Retryable)
		})
	}
}

func TestClassifyError_NetworkErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "connection refused",
			err:  &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
		},
		{
			name: "connection refused message",
			err:  errors.New("connection refused"),
		},
		{
			name: "connection reset",
			err:  errors.New("connection reset by peer"),
		},
		{
			name: "timeout",
			err:  errors.New("i/o timeout"),
		},
		{
			name: "no such host",
			err:  errors.New("no such host"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError("testOp", "testResource", tt.err)
			assert.Equal(t, ErrorTypeTransient, result.Type)
			assert.True(t, result.Retryable)
		})
	}
}

func TestClassifyError_AlreadyReconcileError(t *testing.T) {
	original := NewValidationError("validate", "resource", errors.New("invalid"))
	result := ClassifyError("anotherOp", "anotherResource", original)

	// Should return the original error unchanged
	assert.Equal(t, original, result)
	assert.Equal(t, ErrorTypeValidation, result.Type)
}

func TestClassifyError_NilError(t *testing.T) {
	result := ClassifyError("op", "resource", nil)
	assert.Nil(t, result)
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "transient error",
			err:       NewTransientError("op", "resource", errors.New("timeout")),
			retryable: true,
		},
		{
			name:      "permanent error",
			err:       NewPermanentError("op", "resource", errors.New("invalid")),
			retryable: false,
		},
		{
			name:      "validation error",
			err:       NewValidationError("op", "resource", errors.New("invalid")),
			retryable: false,
		},
		{
			name:      "dependency error",
			err:       NewDependencyError("op", "resource", errors.New("not found")),
			retryable: true,
		},
		{
			name:      "internal error",
			err:       NewInternalError("op", "resource", errors.New("unexpected")),
			retryable: true,
		},
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
		{
			name:      "regular error - classified as internal",
			err:       errors.New("some error"),
			retryable: true, // Internal errors are retryable
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			assert.Equal(t, tt.retryable, result)
		})
	}
}

func TestIsTransient(t *testing.T) {
	assert.True(t, IsTransient(NewTransientError("op", "resource", errors.New("err"))))
	assert.False(t, IsTransient(NewPermanentError("op", "resource", errors.New("err"))))
	assert.False(t, IsTransient(nil))
}

func TestIsPermanent(t *testing.T) {
	assert.True(t, IsPermanent(NewPermanentError("op", "resource", errors.New("err"))))
	assert.False(t, IsPermanent(NewTransientError("op", "resource", errors.New("err"))))
	assert.False(t, IsPermanent(nil))
}

func TestIsValidation(t *testing.T) {
	assert.True(t, IsValidation(NewValidationError("op", "resource", errors.New("err"))))
	assert.False(t, IsValidation(NewTransientError("op", "resource", errors.New("err"))))
	assert.False(t, IsValidation(nil))
}

func TestIsDependency(t *testing.T) {
	assert.True(t, IsDependency(NewDependencyError("op", "resource", errors.New("err"))))
	assert.False(t, IsDependency(NewTransientError("op", "resource", errors.New("err"))))
	assert.False(t, IsDependency(nil))
}

func TestWrapWithContext(t *testing.T) {
	originalErr := errors.New("original error")
	wrapped := WrapWithContext(originalErr, "syncSecret", "default/my-secret", "failed to sync")

	require.NotNil(t, wrapped)
	assert.Contains(t, wrapped.Error(), "failed to sync")
	assert.Contains(t, wrapped.Error(), "syncSecret")
	assert.Contains(t, wrapped.Error(), "default/my-secret")
	assert.True(t, errors.Is(wrapped, originalErr))
}

func TestWrapWithContext_NilError(t *testing.T) {
	wrapped := WrapWithContext(nil, "op", "resource", "context")
	assert.Nil(t, wrapped)
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "connection refused message",
			err:      errors.New("dial tcp: connection refused"),
			expected: true,
		},
		{
			name:     "connection reset message",
			err:      errors.New("read: connection reset by peer"),
			expected: true,
		},
		{
			name:     "timeout message",
			err:      errors.New("i/o timeout"),
			expected: true,
		},
		{
			name:     "EOF message",
			err:      errors.New("unexpected EOF"),
			expected: true,
		},
		{
			name:     "broken pipe message",
			err:      errors.New("write: broken pipe"),
			expected: true,
		},
		{
			name:     "net.OpError",
			err:      &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNetworkError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestClassifyError_ContextCanceled tests that context.Canceled errors are
// classified as transient errors, allowing the controller to retry when
// the context is no longer cancelled.
func TestClassifyError_ContextCanceled(t *testing.T) {
	err := ClassifyError("test", "resource", context.Canceled)

	require.NotNil(t, err)
	assert.Equal(t, ErrorTypeTransient, err.Type)
	assert.True(t, err.Retryable)
	assert.False(t, err.UserActionRequired)
	assert.Equal(t, "test", err.Op)
	assert.Equal(t, "resource", err.Resource)
	assert.True(t, errors.Is(err, context.Canceled))
}

// TestClassifyError_ContextDeadlineExceeded tests that context.DeadlineExceeded
// errors are classified as transient errors, allowing the controller to retry
// with a fresh context.
func TestClassifyError_ContextDeadlineExceeded(t *testing.T) {
	err := ClassifyError("test", "resource", context.DeadlineExceeded)

	require.NotNil(t, err)
	assert.Equal(t, ErrorTypeTransient, err.Type)
	assert.True(t, err.Retryable)
	assert.False(t, err.UserActionRequired)
	assert.Equal(t, "test", err.Op)
	assert.Equal(t, "resource", err.Resource)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

// TestClassifyError_WrappedContextErrors tests that wrapped context errors
// are correctly identified and classified as transient.
func TestClassifyError_WrappedContextErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "wrapped context.Canceled",
			err:  fmt.Errorf("operation failed: %w", context.Canceled),
		},
		{
			name: "wrapped context.DeadlineExceeded",
			err:  fmt.Errorf("operation failed: %w", context.DeadlineExceeded),
		},
		{
			name: "double wrapped context.Canceled",
			err:  fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", context.Canceled)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError("testOp", "testResource", tt.err)
			assert.Equal(t, ErrorTypeTransient, result.Type)
			assert.True(t, result.Retryable)
		})
	}
}

// TestClassifyError_ContextErrorsTableDriven provides comprehensive table-driven
// tests for context error classification.
func TestClassifyError_ContextErrorsTableDriven(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedType ErrorType
		retryable    bool
	}{
		{
			name:         "context.Canceled",
			err:          context.Canceled,
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
		{
			name:         "context.DeadlineExceeded",
			err:          context.DeadlineExceeded,
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
		{
			name:         "wrapped context.Canceled",
			err:          fmt.Errorf("failed: %w", context.Canceled),
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
		{
			name:         "wrapped context.DeadlineExceeded",
			err:          fmt.Errorf("timeout: %w", context.DeadlineExceeded),
			expectedType: ErrorTypeTransient,
			retryable:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError("testOp", "testResource", tt.err)
			assert.Equal(t, tt.expectedType, result.Type)
			assert.Equal(t, tt.retryable, result.Retryable)
		})
	}
}

// ============================================================================
// ErrorHandler Tests
// ============================================================================

func TestNewErrorHandler(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)

	handler := NewErrorHandler(logger, recorder)

	require.NotNil(t, handler)
	assert.Equal(t, logger, handler.logger)
}

func TestErrorHandler_HandleError_NilError(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	result, err := handler.HandleError(obj, nil, nil)

	assert.NoError(t, err)
	assert.False(t, result.Requeue)
}

func TestErrorHandler_HandleError_TransientError(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	testErr := NewTransientError("syncSecret", "default/test-resource", errors.New("connection timeout"))
	strategy := DefaultRequeueStrategy()

	result, err := handler.HandleError(obj, testErr, strategy)

	assert.Error(t, err)
	assert.True(t, result.Requeue)
}

func TestErrorHandler_HandleError_PermanentError(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	testErr := NewPermanentError("validateConfig", "default/test-resource", errors.New("invalid configuration"))
	strategy := DefaultRequeueStrategy()

	result, err := handler.HandleError(obj, testErr, strategy)

	assert.Error(t, err)
	assert.False(t, result.Requeue)
}

func TestErrorHandler_HandleError_ValidationError(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	testErr := NewValidationError("validateTLS", "default/test-resource", errors.New("invalid TLS config"))
	strategy := DefaultRequeueStrategy()

	result, err := handler.HandleError(obj, testErr, strategy)

	assert.Error(t, err)
	assert.False(t, result.Requeue)
}

func TestErrorHandler_HandleError_DependencyError(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	testErr := NewDependencyError("getSecret", "default/test-resource", errors.New("secret not found"))
	strategy := DefaultRequeueStrategy()

	result, err := handler.HandleError(obj, testErr, strategy)

	assert.Error(t, err)
	assert.True(t, result.Requeue)
}

func TestErrorHandler_HandleError_InternalError(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	testErr := NewInternalError("processRoute", "default/test-resource", errors.New("unexpected nil pointer"))
	strategy := DefaultRequeueStrategy()

	result, err := handler.HandleError(obj, testErr, strategy)

	assert.Error(t, err)
	assert.True(t, result.Requeue)
}

func TestErrorHandler_HandleError_NilStrategy(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	testErr := NewTransientError("syncSecret", "default/test-resource", errors.New("timeout"))

	// Pass nil strategy - should use default
	result, err := handler.HandleError(obj, testErr, nil)

	assert.Error(t, err)
	assert.True(t, result.Requeue)
}

func TestErrorHandler_HandleError_NilRecorder(t *testing.T) {
	logger := logr.Discard()
	handler := NewErrorHandler(logger, nil) // nil recorder

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	testErr := NewTransientError("syncSecret", "default/test-resource", errors.New("timeout"))
	strategy := DefaultRequeueStrategy()

	// Should not panic with nil recorder
	result, err := handler.HandleError(obj, testErr, strategy)

	assert.Error(t, err)
	assert.True(t, result.Requeue)
}

func TestErrorHandler_HandleError_LongMessage(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	// Create an error with a very long message
	longMessage := ""
	for i := 0; i < 2000; i++ {
		longMessage += "x"
	}
	testErr := NewTransientError("syncSecret", "default/test-resource", errors.New(longMessage))
	strategy := DefaultRequeueStrategy()

	result, err := handler.HandleError(obj, testErr, strategy)

	assert.Error(t, err)
	assert.True(t, result.Requeue)
}

func TestErrorHandler_HandleError_UnclassifiedError(t *testing.T) {
	logger := logr.Discard()
	recorder := record.NewFakeRecorder(10)
	handler := NewErrorHandler(logger, recorder)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	// Pass a regular error (not a ReconcileError)
	testErr := errors.New("some random error")
	strategy := DefaultRequeueStrategy()

	result, err := handler.HandleError(obj, testErr, strategy)

	assert.Error(t, err)
	// Unclassified errors should be classified as internal (retryable)
	assert.True(t, result.Requeue)
}

func TestErrorHandler_DetermineResult_AllErrorTypes(t *testing.T) {
	logger := logr.Discard()
	handler := NewErrorHandler(logger, nil)
	strategy := DefaultRequeueStrategy()

	tests := []struct {
		name          string
		errorType     ErrorType
		expectRequeue bool
	}{
		{
			name:          "transient",
			errorType:     ErrorTypeTransient,
			expectRequeue: true,
		},
		{
			name:          "permanent",
			errorType:     ErrorTypePermanent,
			expectRequeue: false,
		},
		{
			name:          "validation",
			errorType:     ErrorTypeValidation,
			expectRequeue: false,
		},
		{
			name:          "dependency",
			errorType:     ErrorTypeDependency,
			expectRequeue: true,
		},
		{
			name:          "internal",
			errorType:     ErrorTypeInternal,
			expectRequeue: true,
		},
		{
			name:          "unknown",
			errorType:     ErrorType("unknown"),
			expectRequeue: true, // defaults to transient behavior
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ReconcileError{
				Type:     tt.errorType,
				Op:       "test",
				Resource: "default/test",
				Err:      errors.New("test error"),
			}
			result := handler.determineResult(err, strategy)
			assert.Equal(t, tt.expectRequeue, result.Requeue)
		})
	}
}

// ============================================================================
// safeIntToInt32 Tests
// ============================================================================

func TestSafeIntToInt32(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int32
	}{
		{
			name:     "zero",
			input:    0,
			expected: 0,
		},
		{
			name:     "positive small number",
			input:    100,
			expected: 100,
		},
		{
			name:     "negative number returns zero",
			input:    -1,
			expected: 0,
		},
		{
			name:     "negative large number returns zero",
			input:    -1000000,
			expected: 0,
		},
		{
			name:     "max int32",
			input:    2147483647,
			expected: 2147483647,
		},
		{
			name:     "overflow - larger than max int32",
			input:    2147483648, // max int32 + 1
			expected: 2147483647, // clamped to max int32
		},
		{
			name:     "very large number",
			input:    9999999999,
			expected: 2147483647, // clamped to max int32
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeIntToInt32(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// IsTransient/IsPermanent/IsValidation/IsDependency with non-ReconcileError Tests
// ============================================================================

func TestIsTransient_NonReconcileError(t *testing.T) {
	// Test with a regular error (not ReconcileError)
	regularErr := errors.New("some regular error")
	assert.False(t, IsTransient(regularErr))
}

func TestIsPermanent_NonReconcileError(t *testing.T) {
	// Test with a regular error (not ReconcileError)
	regularErr := errors.New("some regular error")
	assert.False(t, IsPermanent(regularErr))
}

func TestIsValidation_NonReconcileError(t *testing.T) {
	// Test with a regular error (not ReconcileError)
	regularErr := errors.New("some regular error")
	assert.False(t, IsValidation(regularErr))
}

func TestIsDependency_NonReconcileError(t *testing.T) {
	// Test with a regular error (not ReconcileError)
	regularErr := errors.New("some regular error")
	assert.False(t, IsDependency(regularErr))
}

// ============================================================================
// isNetworkError Additional Tests
// ============================================================================

func TestIsNetworkError_SyscallECONNREFUSED(t *testing.T) {
	// Test with syscall.ECONNREFUSED directly
	err := syscall.ECONNREFUSED
	assert.True(t, isNetworkError(err))
}

func TestIsNetworkError_NetError(t *testing.T) {
	// Test with a net.Error implementation
	netErr := &net.DNSError{
		Err:         "no such host",
		Name:        "example.com",
		IsTemporary: true,
	}
	assert.True(t, isNetworkError(netErr))
}

func TestIsNetworkError_NetworkUnreachable(t *testing.T) {
	// Test with "network is unreachable" message
	err := errors.New("dial tcp: network is unreachable")
	assert.True(t, isNetworkError(err))
}

func TestIsNetworkError_ConnectionTimedOut(t *testing.T) {
	// Test with "connection timed out" message
	err := errors.New("dial tcp: connection timed out")
	assert.True(t, isNetworkError(err))
}

// ============================================================================
// logError Additional Tests
// ============================================================================

func TestErrorHandler_LogError_AllErrorTypes(t *testing.T) {
	logger := logr.Discard()
	handler := NewErrorHandler(logger, nil)

	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}

	tests := []struct {
		name      string
		errorType ErrorType
	}{
		{name: "transient", errorType: ErrorTypeTransient},
		{name: "permanent", errorType: ErrorTypePermanent},
		{name: "validation", errorType: ErrorTypeValidation},
		{name: "dependency", errorType: ErrorTypeDependency},
		{name: "internal", errorType: ErrorTypeInternal},
		{name: "unknown", errorType: ErrorType("unknown")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ReconcileError{
				Type:               tt.errorType,
				Op:                 "test",
				Resource:           "default/test",
				Err:                errors.New("test error"),
				Message:            "test message",
				Retryable:          true,
				UserActionRequired: false,
			}
			// Should not panic
			handler.logError(obj, err)
		})
	}
}

// ============================================================================
// ClassifyError Additional Tests
// ============================================================================

func TestClassifyError_InvalidAPIError(t *testing.T) {
	// Test with apierrors.IsInvalid
	invalidErr := apierrors.NewInvalid(
		schema.GroupKind{Group: "", Kind: "Secret"},
		"my-secret",
		nil,
	)
	result := ClassifyError("testOp", "testResource", invalidErr)
	assert.Equal(t, ErrorTypeValidation, result.Type)
	assert.False(t, result.Retryable)
}

func TestClassifyError_TimeoutAPIError(t *testing.T) {
	// Test with apierrors.IsTimeout
	timeoutErr := apierrors.NewTimeoutError("timeout", 30)
	result := ClassifyError("testOp", "testResource", timeoutErr)
	assert.Equal(t, ErrorTypeTransient, result.Type)
	assert.True(t, result.Retryable)
}

// ============================================================================
// TASK-007: Tests for Error Formatting
// ============================================================================

func TestReconcileError_Error_LowercaseFormat(t *testing.T) {
	tests := []struct {
		name         string
		errorType    ErrorType
		op           string
		resource     string
		err          error
		wantContains []string
	}{
		{
			name:      "transient error is lowercase",
			errorType: ErrorTypeTransient,
			op:        "syncSecret",
			resource:  "default/my-secret",
			err:       errors.New("connection timeout"),
			wantContains: []string{
				"transient", // lowercase error type
				"syncSecret",
				"default/my-secret",
				"connection timeout",
			},
		},
		{
			name:      "permanent error is lowercase",
			errorType: ErrorTypePermanent,
			op:        "validateConfig",
			resource:  "default/my-gateway",
			err:       errors.New("invalid configuration"),
			wantContains: []string{
				"permanent", // lowercase error type
				"validateConfig",
				"default/my-gateway",
				"invalid configuration",
			},
		},
		{
			name:      "validation error is lowercase",
			errorType: ErrorTypeValidation,
			op:        "validateTLS",
			resource:  "default/my-gateway",
			err:       errors.New("invalid TLS config"),
			wantContains: []string{
				"validation", // lowercase error type
				"validateTLS",
				"default/my-gateway",
				"invalid TLS config",
			},
		},
		{
			name:      "dependency error is lowercase",
			errorType: ErrorTypeDependency,
			op:        "getSecret",
			resource:  "default/my-secret",
			err:       errors.New("secret not found"),
			wantContains: []string{
				"dependency", // lowercase error type
				"getSecret",
				"default/my-secret",
				"secret not found",
			},
		},
		{
			name:      "internal error is lowercase",
			errorType: ErrorTypeInternal,
			op:        "processRoute",
			resource:  "default/my-route",
			err:       errors.New("unexpected nil pointer"),
			wantContains: []string{
				"internal", // lowercase error type
				"processRoute",
				"default/my-route",
				"unexpected nil pointer",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconcileErr := &ReconcileError{
				Type:     tt.errorType,
				Op:       tt.op,
				Resource: tt.resource,
				Err:      tt.err,
			}

			errStr := reconcileErr.Error()

			for _, want := range tt.wantContains {
				assert.Contains(t, errStr, want)
			}

			// Verify the error type is lowercase in the output
			assert.NotContains(t, errStr, string(tt.errorType), "error type should be lowercase")
		})
	}
}

func TestWrapWithContext_EmptyResource(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		op           string
		resource     string
		ctx          string
		wantContains []string
		wantFormat   string
	}{
		{
			name:     "with empty resource",
			err:      errors.New("original error"),
			op:       "syncSecret",
			resource: "",
			ctx:      "failed to sync",
			wantContains: []string{
				"failed to sync",
				"syncSecret",
				"original error",
			},
			wantFormat: "failed to sync: syncSecret: original error",
		},
		{
			name:     "with resource",
			err:      errors.New("original error"),
			op:       "syncSecret",
			resource: "default/my-secret",
			ctx:      "failed to sync",
			wantContains: []string{
				"failed to sync",
				"syncSecret",
				"default/my-secret",
				"original error",
			},
			wantFormat: "failed to sync: syncSecret for default/my-secret: original error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := WrapWithContext(tt.err, tt.op, tt.resource, tt.ctx)

			require.NotNil(t, wrapped)

			for _, want := range tt.wantContains {
				assert.Contains(t, wrapped.Error(), want)
			}

			// Verify exact format
			assert.Equal(t, tt.wantFormat, wrapped.Error())

			// Verify the original error is still accessible
			assert.True(t, errors.Is(wrapped, tt.err))
		})
	}
}

func TestReconcileError_Error_WithoutResource(t *testing.T) {
	reconcileErr := &ReconcileError{
		Type:     ErrorTypeTransient,
		Op:       "syncSecret",
		Resource: "", // empty resource
		Err:      errors.New("timeout"),
	}

	errStr := reconcileErr.Error()

	// Should not contain "for" when resource is empty
	assert.Contains(t, errStr, "transient error during syncSecret: timeout")
	assert.NotContains(t, errStr, "for")
}

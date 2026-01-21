// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"errors"
	"fmt"
)

// Common transformation errors.
var (
	// ErrNilMessage indicates that the input message is nil.
	ErrNilMessage = errors.New("message is nil")

	// ErrNilConfig indicates that the transformation config is nil.
	ErrNilConfig = errors.New("transformation config is nil")

	// ErrInvalidFieldPath indicates that a field path is invalid.
	ErrInvalidFieldPath = errors.New("invalid field path")

	// ErrFieldNotFound indicates that a required field was not found.
	ErrFieldNotFound = errors.New("field not found")

	// ErrInvalidFieldType indicates that a field has an unexpected type.
	ErrInvalidFieldType = errors.New("invalid field type")

	// ErrInvalidFieldMask indicates that the FieldMask is invalid.
	ErrInvalidFieldMask = errors.New("invalid field mask")

	// ErrMessageTimeout indicates that a message timeout occurred.
	ErrMessageTimeout = errors.New("message timeout exceeded")

	// ErrRateLimitExceeded indicates that the rate limit was exceeded.
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// ErrStreamClosed indicates that the stream has been closed.
	ErrStreamClosed = errors.New("stream closed")

	// ErrInvalidOperation indicates an invalid operation was requested.
	ErrInvalidOperation = errors.New("invalid operation")

	// ErrValueExtraction indicates a failure to extract a value from source.
	ErrValueExtraction = errors.New("failed to extract value")
)

// TransformError represents a transformation-specific error with context.
type TransformError struct {
	Operation string
	Field     string
	Message   string
	Cause     error
}

// Error implements the error interface.
func (e *TransformError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("transform error in %s at field %s: %s", e.Operation, e.Field, e.Message)
	}
	return fmt.Sprintf("transform error in %s: %s", e.Operation, e.Message)
}

// Unwrap returns the underlying error.
func (e *TransformError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *TransformError) Is(target error) bool {
	_, ok := target.(*TransformError)
	return ok || errors.Is(e.Cause, target)
}

// NewTransformError creates a new TransformError.
func NewTransformError(operation, field, message string) *TransformError {
	return &TransformError{
		Operation: operation,
		Field:     field,
		Message:   message,
	}
}

// NewTransformErrorWithCause creates a new TransformError with a cause.
func NewTransformErrorWithCause(operation, field, message string, cause error) *TransformError {
	return &TransformError{
		Operation: operation,
		Field:     field,
		Message:   message,
		Cause:     cause,
	}
}

// FieldMaskError represents a FieldMask validation error.
type FieldMaskError struct {
	Path    string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *FieldMaskError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("field mask error at path %s: %s", e.Path, e.Message)
	}
	return fmt.Sprintf("field mask error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *FieldMaskError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *FieldMaskError) Is(target error) bool {
	if target == ErrInvalidFieldMask {
		return true
	}
	_, ok := target.(*FieldMaskError)
	return ok || errors.Is(e.Cause, target)
}

// NewFieldMaskError creates a new FieldMaskError.
func NewFieldMaskError(path, message string) *FieldMaskError {
	return &FieldMaskError{
		Path:    path,
		Message: message,
	}
}

// NewFieldMaskErrorWithCause creates a new FieldMaskError with a cause.
func NewFieldMaskErrorWithCause(path, message string, cause error) *FieldMaskError {
	return &FieldMaskError{
		Path:    path,
		Message: message,
		Cause:   cause,
	}
}

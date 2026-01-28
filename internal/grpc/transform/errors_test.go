// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommonErrors(t *testing.T) {
	// Test that all common errors are defined
	assert.NotNil(t, ErrNilMessage)
	assert.NotNil(t, ErrNilConfig)
	assert.NotNil(t, ErrInvalidFieldPath)
	assert.NotNil(t, ErrFieldNotFound)
	assert.NotNil(t, ErrInvalidFieldType)
	assert.NotNil(t, ErrInvalidFieldMask)
	assert.NotNil(t, ErrMessageTimeout)
	assert.NotNil(t, ErrRateLimitExceeded)
	assert.NotNil(t, ErrStreamClosed)
	assert.NotNil(t, ErrInvalidOperation)
	assert.NotNil(t, ErrValueExtraction)

	// Test error messages contain expected content
	assert.Contains(t, ErrNilMessage.Error(), "nil")
	assert.Contains(t, ErrNilConfig.Error(), "nil")
	assert.Contains(t, ErrFieldNotFound.Error(), "not found")
	assert.Contains(t, ErrMessageTimeout.Error(), "timeout")
	assert.Contains(t, ErrRateLimitExceeded.Error(), "rate limit")
	assert.Contains(t, ErrStreamClosed.Error(), "closed")
}

func TestTransformError_Error(t *testing.T) {
	tests := []struct {
		name      string
		err       *TransformError
		wantParts []string
	}{
		{
			name: "with field",
			err: &TransformError{
				Operation: "rename",
				Field:     "user.name",
				Message:   "field not found",
			},
			wantParts: []string{"rename", "user.name", "field not found"},
		},
		{
			name: "without field",
			err: &TransformError{
				Operation: "transform",
				Field:     "",
				Message:   "general error",
			},
			wantParts: []string{"transform", "general error"},
		},
		{
			name: "with all fields",
			err: &TransformError{
				Operation: "filter",
				Field:     "items",
				Message:   "invalid filter condition",
				Cause:     errors.New("underlying error"),
			},
			wantParts: []string{"filter", "items", "invalid filter condition"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, part := range tt.wantParts {
				assert.Contains(t, errMsg, part)
			}
		})
	}
}

func TestTransformError_Unwrap(t *testing.T) {
	cause := errors.New("underlying cause")
	err := &TransformError{
		Operation: "test",
		Message:   "test error",
		Cause:     cause,
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
}

func TestTransformError_Unwrap_NilCause(t *testing.T) {
	err := &TransformError{
		Operation: "test",
		Message:   "test error",
		Cause:     nil,
	}

	unwrapped := err.Unwrap()
	assert.Nil(t, unwrapped)
}

func TestTransformError_Is(t *testing.T) {
	cause := ErrFieldNotFound
	err := &TransformError{
		Operation: "test",
		Message:   "test error",
		Cause:     cause,
	}

	// Should match TransformError type
	assert.True(t, err.Is(&TransformError{}))

	// Should match underlying cause
	assert.True(t, errors.Is(err, ErrFieldNotFound))

	// Should not match unrelated errors
	assert.False(t, errors.Is(err, ErrNilMessage))
}

func TestNewTransformError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		field     string
		message   string
	}{
		{
			name:      "with all fields",
			operation: "rename",
			field:     "user.name",
			message:   "field not found",
		},
		{
			name:      "without field",
			operation: "transform",
			field:     "",
			message:   "general error",
		},
		{
			name:      "empty values",
			operation: "",
			field:     "",
			message:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewTransformError(tt.operation, tt.field, tt.message)

			assert.NotNil(t, err)
			assert.Equal(t, tt.operation, err.Operation)
			assert.Equal(t, tt.field, err.Field)
			assert.Equal(t, tt.message, err.Message)
			assert.Nil(t, err.Cause)
		})
	}
}

func TestNewTransformErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewTransformErrorWithCause("operation", "field", "message", cause)

	assert.NotNil(t, err)
	assert.Equal(t, "operation", err.Operation)
	assert.Equal(t, "field", err.Field)
	assert.Equal(t, "message", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestFieldMaskError_Error(t *testing.T) {
	tests := []struct {
		name      string
		err       *FieldMaskError
		wantParts []string
	}{
		{
			name: "with path",
			err: &FieldMaskError{
				Path:    "user.name",
				Message: "invalid path",
			},
			wantParts: []string{"user.name", "invalid path"},
		},
		{
			name: "without path",
			err: &FieldMaskError{
				Path:    "",
				Message: "general error",
			},
			wantParts: []string{"field mask error", "general error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, part := range tt.wantParts {
				assert.Contains(t, errMsg, part)
			}
		})
	}
}

func TestFieldMaskError_Unwrap(t *testing.T) {
	cause := errors.New("underlying cause")
	err := &FieldMaskError{
		Path:    "test",
		Message: "test error",
		Cause:   cause,
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
}

func TestFieldMaskError_Is(t *testing.T) {
	err := &FieldMaskError{
		Path:    "test",
		Message: "test error",
	}

	// Should match ErrInvalidFieldMask
	assert.True(t, err.Is(ErrInvalidFieldMask))

	// Should match FieldMaskError type
	assert.True(t, err.Is(&FieldMaskError{}))

	// Should not match unrelated errors
	assert.False(t, err.Is(ErrNilMessage))
}

func TestFieldMaskError_Is_WithCause(t *testing.T) {
	cause := ErrFieldNotFound
	err := &FieldMaskError{
		Path:    "test",
		Message: "test error",
		Cause:   cause,
	}

	// Should match underlying cause
	assert.True(t, errors.Is(err, ErrFieldNotFound))
}

func TestNewFieldMaskError(t *testing.T) {
	err := NewFieldMaskError("user.name", "invalid path")

	assert.NotNil(t, err)
	assert.Equal(t, "user.name", err.Path)
	assert.Equal(t, "invalid path", err.Message)
	assert.Nil(t, err.Cause)
}

func TestNewFieldMaskErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewFieldMaskErrorWithCause("user.name", "invalid path", cause)

	assert.NotNil(t, err)
	assert.Equal(t, "user.name", err.Path)
	assert.Equal(t, "invalid path", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestErrorsAreDistinct(t *testing.T) {
	// Ensure all error variables are distinct
	errs := []error{
		ErrNilMessage,
		ErrNilConfig,
		ErrInvalidFieldPath,
		ErrFieldNotFound,
		ErrInvalidFieldType,
		ErrInvalidFieldMask,
		ErrMessageTimeout,
		ErrRateLimitExceeded,
		ErrStreamClosed,
		ErrInvalidOperation,
		ErrValueExtraction,
	}

	for i, err1 := range errs {
		for j, err2 := range errs {
			if i != j {
				assert.NotEqual(t, err1, err2, "errors at index %d and %d should be distinct", i, j)
			}
		}
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that errors can be properly wrapped and unwrapped
	baseErr := ErrFieldNotFound
	transformErr := NewTransformErrorWithCause("test", "field", "message", baseErr)

	// errors.Is should work through the chain
	assert.True(t, errors.Is(transformErr, ErrFieldNotFound))

	// errors.Unwrap should return the cause
	assert.Equal(t, baseErr, errors.Unwrap(transformErr))
}

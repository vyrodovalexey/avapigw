// Package validator provides validation logic for CRD webhooks.
package validator

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		expected string
	}{
		{
			name:     "error with field",
			err:      &ValidationError{Field: "spec.name", Message: "is required"},
			expected: "spec.name: is required",
		},
		{
			name:     "error without field",
			err:      &ValidationError{Field: "", Message: "validation failed"},
			expected: "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestNewValidationError(t *testing.T) {
	err := NewValidationError("spec.field", "invalid value")
	require.NotNil(t, err)
	assert.Equal(t, "spec.field", err.Field)
	assert.Equal(t, "invalid value", err.Message)
}

func TestValidationErrors_Error(t *testing.T) {
	tests := []struct {
		name     string
		errs     *ValidationErrors
		expected string
	}{
		{
			name:     "no errors",
			errs:     &ValidationErrors{Errors: []*ValidationError{}},
			expected: "",
		},
		{
			name: "single error",
			errs: &ValidationErrors{
				Errors: []*ValidationError{
					{Field: "spec.name", Message: "is required"},
				},
			},
			expected: "spec.name: is required",
		},
		{
			name: "multiple errors",
			errs: &ValidationErrors{
				Errors: []*ValidationError{
					{Field: "spec.name", Message: "is required"},
					{Field: "spec.port", Message: "must be positive"},
				},
			},
			expected: "multiple validation errors: [spec.name: is required; spec.port: must be positive]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.errs.Error())
		})
	}
}

func TestValidationErrors_Add(t *testing.T) {
	errs := NewValidationErrors()
	assert.Empty(t, errs.Errors)

	errs.Add("spec.name", "is required")
	require.Len(t, errs.Errors, 1)
	assert.Equal(t, "spec.name", errs.Errors[0].Field)
	assert.Equal(t, "is required", errs.Errors[0].Message)

	errs.Add("spec.port", "must be positive")
	require.Len(t, errs.Errors, 2)
}

func TestValidationErrors_AddError(t *testing.T) {
	errs := NewValidationErrors()
	ve := NewValidationError("spec.field", "invalid")

	errs.AddError(ve)
	require.Len(t, errs.Errors, 1)
	assert.Equal(t, ve, errs.Errors[0])
}

func TestValidationErrors_HasErrors(t *testing.T) {
	errs := NewValidationErrors()
	assert.False(t, errs.HasErrors())

	errs.Add("spec.name", "is required")
	assert.True(t, errs.HasErrors())
}

func TestValidationErrors_ToError(t *testing.T) {
	tests := []struct {
		name      string
		errs      *ValidationErrors
		expectNil bool
	}{
		{
			name:      "no errors returns nil",
			errs:      NewValidationErrors(),
			expectNil: true,
		},
		{
			name: "with errors returns error",
			errs: func() *ValidationErrors {
				e := NewValidationErrors()
				e.Add("spec.name", "is required")
				return e
			}(),
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errs.ToError()
			if tt.expectNil {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

func TestNewValidationErrors(t *testing.T) {
	errs := NewValidationErrors()
	require.NotNil(t, errs)
	assert.NotNil(t, errs.Errors)
	assert.Empty(t, errs.Errors)
}

func TestCommonValidationErrors(t *testing.T) {
	// Test that common error types are defined
	assert.NotNil(t, ErrDuplicateResource)
	assert.NotNil(t, ErrReferenceNotFound)
	assert.NotNil(t, ErrInvalidReference)
	assert.NotNil(t, ErrInvalidConfiguration)
	assert.NotNil(t, ErrMutuallyExclusive)
	assert.NotNil(t, ErrRequiredField)
	assert.NotNil(t, ErrInvalidValue)
}

func TestWrapValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		field    string
		expected string
	}{
		{
			name:     "nil error returns nil",
			err:      nil,
			field:    "spec.field",
			expected: "",
		},
		{
			name:     "wrap ValidationError with field",
			err:      NewValidationError("subfield", "invalid"),
			field:    "spec",
			expected: "spec.subfield: invalid",
		},
		{
			name:     "wrap ValidationError without field",
			err:      NewValidationError("", "invalid"),
			field:    "spec.field",
			expected: "spec.field: invalid",
		},
		{
			name:     "wrap regular error",
			err:      errors.New("something went wrong"),
			field:    "spec.field",
			expected: "spec.field: something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapValidationError(tt.err, tt.field)
			if tt.err == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.expected, result.Error())
			}
		})
	}
}

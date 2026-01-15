// Package validator provides validation logic for CRD webhooks.
package validator

import (
	"errors"
	"fmt"
	"strings"
)

// ValidationError represents a validation error with field path
type ValidationError struct {
	Field   string
	Message string
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
	}
}

// ValidationErrors represents a collection of validation errors
type ValidationErrors struct {
	Errors []*ValidationError
}

// Error implements the error interface
func (e *ValidationErrors) Error() string {
	if len(e.Errors) == 0 {
		return ""
	}
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}

	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, err.Error())
	}
	return fmt.Sprintf("multiple validation errors: [%s]", strings.Join(msgs, "; "))
}

// Add adds a validation error
func (e *ValidationErrors) Add(field, message string) {
	e.Errors = append(e.Errors, NewValidationError(field, message))
}

// AddError adds an existing ValidationError
func (e *ValidationErrors) AddError(err *ValidationError) {
	e.Errors = append(e.Errors, err)
}

// HasErrors returns true if there are any errors
func (e *ValidationErrors) HasErrors() bool {
	return len(e.Errors) > 0
}

// ToError returns nil if no errors, otherwise returns the ValidationErrors
func (e *ValidationErrors) ToError() error {
	if !e.HasErrors() {
		return nil
	}
	return e
}

// NewValidationErrors creates a new ValidationErrors
func NewValidationErrors() *ValidationErrors {
	return &ValidationErrors{
		Errors: make([]*ValidationError, 0),
	}
}

// Common validation error types
var (
	// ErrDuplicateResource indicates a duplicate resource was found
	ErrDuplicateResource = errors.New("duplicate resource found")

	// ErrReferenceNotFound indicates a referenced resource was not found
	ErrReferenceNotFound = errors.New("referenced resource not found")

	// ErrInvalidReference indicates an invalid reference
	ErrInvalidReference = errors.New("invalid reference")

	// ErrInvalidConfiguration indicates an invalid configuration
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrMutuallyExclusive indicates mutually exclusive fields are set
	ErrMutuallyExclusive = errors.New("mutually exclusive fields are set")

	// ErrRequiredField indicates a required field is missing
	ErrRequiredField = errors.New("required field is missing")

	// ErrInvalidValue indicates an invalid value
	ErrInvalidValue = errors.New("invalid value")
)

// WrapValidationError wraps an error with additional context
func WrapValidationError(err error, field string) error {
	if err == nil {
		return nil
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		if ve.Field != "" {
			return NewValidationError(fmt.Sprintf("%s.%s", field, ve.Field), ve.Message)
		}
		return NewValidationError(field, ve.Message)
	}
	return NewValidationError(field, err.Error())
}

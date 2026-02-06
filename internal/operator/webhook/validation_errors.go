// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"fmt"
	"strings"
)

// ValidationError represents a validation error with field path information.
type ValidationError struct {
	// Field is the JSON path to the field that failed validation (e.g., "spec.hosts[0].port").
	Field string

	// Message is a human-readable description of the validation failure.
	Message string

	// Value is the invalid value that was provided (optional).
	Value interface{}

	// Suggestion provides guidance on how to fix the error (optional).
	Suggestion string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("field %q: %s", e.Field, e.Message))
	if e.Value != nil {
		sb.WriteString(fmt.Sprintf(" (got: %v)", e.Value))
	}
	if e.Suggestion != "" {
		sb.WriteString(fmt.Sprintf(". %s", e.Suggestion))
	}
	return sb.String()
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors struct {
	errors []*ValidationError
}

// NewValidationErrors creates a new ValidationErrors collection.
func NewValidationErrors() *ValidationErrors {
	return &ValidationErrors{
		errors: make([]*ValidationError, 0),
	}
}

// Add adds a validation error to the collection.
func (v *ValidationErrors) Add(field, message string) {
	v.errors = append(v.errors, &ValidationError{
		Field:   field,
		Message: message,
	})
}

// AddWithValue adds a validation error with the invalid value.
func (v *ValidationErrors) AddWithValue(field, message string, value interface{}) {
	v.errors = append(v.errors, &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// AddWithSuggestion adds a validation error with a suggestion for fixing it.
func (v *ValidationErrors) AddWithSuggestion(field, message, suggestion string) {
	v.errors = append(v.errors, &ValidationError{
		Field:      field,
		Message:    message,
		Suggestion: suggestion,
	})
}

// AddFull adds a validation error with all fields.
func (v *ValidationErrors) AddFull(field, message string, value interface{}, suggestion string) {
	v.errors = append(v.errors, &ValidationError{
		Field:      field,
		Message:    message,
		Value:      value,
		Suggestion: suggestion,
	})
}

// AddError adds an existing ValidationError to the collection.
func (v *ValidationErrors) AddError(err *ValidationError) {
	v.errors = append(v.errors, err)
}

// HasErrors returns true if there are any validation errors.
func (v *ValidationErrors) HasErrors() bool {
	return len(v.errors) > 0
}

// Count returns the number of validation errors.
func (v *ValidationErrors) Count() int {
	return len(v.errors)
}

// Errors returns all validation errors.
func (v *ValidationErrors) Errors() []*ValidationError {
	return v.errors
}

// Error implements the error interface, returning all errors as a single string.
func (v *ValidationErrors) Error() string {
	if len(v.errors) == 0 {
		return ""
	}

	if len(v.errors) == 1 {
		return v.errors[0].Error()
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("validation failed with %d errors:\n", len(v.errors)))
	for i, err := range v.errors {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, err.Error()))
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

// ToError returns nil if there are no errors, otherwise returns the ValidationErrors as an error.
func (v *ValidationErrors) ToError() error {
	if !v.HasErrors() {
		return nil
	}
	return v
}

// FieldPath helps build field paths for nested structures.
type FieldPath struct {
	parts []string
}

// NewFieldPath creates a new FieldPath with an optional root.
func NewFieldPath(root ...string) *FieldPath {
	return &FieldPath{
		parts: root,
	}
}

// Child returns a new FieldPath with the given child appended.
func (f *FieldPath) Child(name string) *FieldPath {
	newParts := make([]string, len(f.parts), len(f.parts)+1)
	copy(newParts, f.parts)
	newParts = append(newParts, name)
	return &FieldPath{parts: newParts}
}

// Index returns a new FieldPath with an array index appended.
func (f *FieldPath) Index(i int) *FieldPath {
	if len(f.parts) == 0 {
		return &FieldPath{parts: []string{fmt.Sprintf("[%d]", i)}}
	}
	newParts := make([]string, len(f.parts))
	copy(newParts, f.parts)
	// Append index to the last part
	newParts[len(newParts)-1] = fmt.Sprintf("%s[%d]", newParts[len(newParts)-1], i)
	return &FieldPath{parts: newParts}
}

// Key returns a new FieldPath with a map key appended.
func (f *FieldPath) Key(key string) *FieldPath {
	if len(f.parts) == 0 {
		return &FieldPath{parts: []string{fmt.Sprintf("[%q]", key)}}
	}
	newParts := make([]string, len(f.parts))
	copy(newParts, f.parts)
	// Append key to the last part
	newParts[len(newParts)-1] = fmt.Sprintf("%s[%q]", newParts[len(newParts)-1], key)
	return &FieldPath{parts: newParts}
}

// String returns the field path as a dot-separated string.
func (f *FieldPath) String() string {
	return strings.Join(f.parts, ".")
}

// Common validation error messages with suggestions.
var (
	// ErrRequired is the error message for required fields.
	ErrRequired = "is required"

	// ErrMustBePositive is the error message for fields that must be positive.
	ErrMustBePositive = "must be a positive number"

	// ErrMustBeNonNegative is the error message for fields that must be non-negative.
	ErrMustBeNonNegative = "must be non-negative"

	// ErrInvalidFormat is the error message for fields with invalid format.
	ErrInvalidFormat = "has invalid format"

	// ErrOutOfRange is the error message for fields that are out of range.
	ErrOutOfRange = "is out of valid range"

	// ErrInvalidValue is the error message for fields with invalid values.
	ErrInvalidValue = "has invalid value"

	// ErrMutuallyExclusive is the error message for mutually exclusive fields.
	ErrMutuallyExclusive = "is mutually exclusive with other fields"

	// ErrConflict is the error message for conflicting configurations.
	ErrConflict = "conflicts with existing configuration"
)

// NewRequiredError creates a validation error for a required field.
func NewRequiredError(field string) *ValidationError {
	return &ValidationError{
		Field:      field,
		Message:    ErrRequired,
		Suggestion: "Please provide a value for this field",
	}
}

// NewRangeError creates a validation error for a value out of range.
func NewRangeError(field string, value interface{}, minVal, maxVal interface{}) *ValidationError {
	return &ValidationError{
		Field:      field,
		Message:    fmt.Sprintf("must be between %v and %v", minVal, maxVal),
		Value:      value,
		Suggestion: fmt.Sprintf("Provide a value in the range [%v, %v]", minVal, maxVal),
	}
}

// NewEnumError creates a validation error for an invalid enum value.
func NewEnumError(field string, value interface{}, validValues []string) *ValidationError {
	return &ValidationError{
		Field:      field,
		Message:    fmt.Sprintf("must be one of: %s", strings.Join(validValues, ", ")),
		Value:      value,
		Suggestion: fmt.Sprintf("Use one of the valid values: %s", strings.Join(validValues, ", ")),
	}
}

// NewFormatError creates a validation error for an invalid format.
func NewFormatError(field string, value interface{}, expectedFormat string) *ValidationError {
	return &ValidationError{
		Field:      field,
		Message:    fmt.Sprintf("has invalid format, expected: %s", expectedFormat),
		Value:      value,
		Suggestion: fmt.Sprintf("Use the format: %s", expectedFormat),
	}
}

// NewConflictError creates a validation error for conflicting configurations.
func NewConflictError(field string, conflictingField string) *ValidationError {
	return &ValidationError{
		Field:      field,
		Message:    fmt.Sprintf("conflicts with %s", conflictingField),
		Suggestion: fmt.Sprintf("Remove either %s or %s", field, conflictingField),
	}
}

// NewDependencyError creates a validation error for missing dependencies.
func NewDependencyError(field string, dependsOn string) *ValidationError {
	return &ValidationError{
		Field:      field,
		Message:    fmt.Sprintf("requires %s to be set", dependsOn),
		Suggestion: fmt.Sprintf("Set %s when using %s", dependsOn, field),
	}
}

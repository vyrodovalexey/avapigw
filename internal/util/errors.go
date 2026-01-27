// Package util provides utility functions and types for the API Gateway.
//
// # Error Conventions
//
// This project follows a standardized error pattern across all packages:
//
//   - Sentinel errors (errors.New) for well-known, stable conditions
//     that callers check with errors.Is(). Example: ErrNotFound.
//   - Structured error types for context-rich errors that carry
//     additional fields (e.g., ConfigError, BackendError). Each type
//     implements Error(), Unwrap() (if wrapping), and Is().
//   - fmt.Errorf with %w for ad-hoc wrapping that adds context to an
//     existing error without introducing a new type.
//
// All custom error types must implement:
//
//	Error() string           – human-readable message
//	Unwrap() error           – if the type wraps another error
//	Is(target error) bool    – for errors.Is() compatibility
package util

import (
	"errors"
	"fmt"
	"time"
)

// Common sentinel errors.
var (
	ErrNotFound       = errors.New("not found")
	ErrInvalidInput   = errors.New("invalid input")
	ErrTimeout        = errors.New("timeout")
	ErrCircuitOpen    = errors.New("circuit breaker open")
	ErrRateLimited    = errors.New("rate limit exceeded")
	ErrBackendUnavail = errors.New("backend unavailable")
	ErrConfigInvalid  = errors.New("invalid configuration")
)

// ConfigError represents a configuration-related error.
type ConfigError struct {
	Field   string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("config error at %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("config error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *ConfigError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *ConfigError) Is(target error) bool {
	_, ok := target.(*ConfigError)
	return ok || errors.Is(e.Cause, target)
}

// NewConfigError creates a new ConfigError.
func NewConfigError(field, message string) *ConfigError {
	return &ConfigError{Field: field, Message: message}
}

// NewConfigErrorWithCause creates a new ConfigError with a cause.
func NewConfigErrorWithCause(field, message string, cause error) *ConfigError {
	return &ConfigError{Field: field, Message: message, Cause: cause}
}

// ValidationError represents a validation failure.
type ValidationError struct {
	Fields  map[string]string
	Message string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if len(e.Fields) == 0 {
		return fmt.Sprintf("validation error: %s", e.Message)
	}
	return fmt.Sprintf("validation error: %s (fields: %v)", e.Message, e.Fields)
}

// Is checks if the error matches the target.
func (e *ValidationError) Is(target error) bool {
	_, ok := target.(*ValidationError)
	return ok
}

// NewValidationError creates a new ValidationError.
func NewValidationError(message string) *ValidationError {
	return &ValidationError{Message: message, Fields: make(map[string]string)}
}

// NewValidationErrorWithFields creates a new ValidationError with field errors.
func NewValidationErrorWithFields(message string, fields map[string]string) *ValidationError {
	return &ValidationError{Message: message, Fields: fields}
}

// AddField adds a field error.
func (e *ValidationError) AddField(field, message string) {
	if e.Fields == nil {
		e.Fields = make(map[string]string)
	}
	e.Fields[field] = message
}

// RouteNotFoundError represents a route not found error.
type RouteNotFoundError struct {
	Path   string
	Method string
}

// Error implements the error interface.
func (e *RouteNotFoundError) Error() string {
	return fmt.Sprintf("no route found for %s %s", e.Method, e.Path)
}

// Is checks if the error matches the target.
func (e *RouteNotFoundError) Is(target error) bool {
	if target == ErrNotFound {
		return true
	}
	_, ok := target.(*RouteNotFoundError)
	return ok
}

// NewRouteNotFoundError creates a new RouteNotFoundError.
func NewRouteNotFoundError(method, path string) *RouteNotFoundError {
	return &RouteNotFoundError{Path: path, Method: method}
}

// BackendError represents a backend connectivity error.
type BackendError struct {
	Backend string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *BackendError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("backend %s error: %s: %v", e.Backend, e.Message, e.Cause)
	}
	return fmt.Sprintf("backend %s error: %s", e.Backend, e.Message)
}

// Unwrap returns the underlying error.
func (e *BackendError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *BackendError) Is(target error) bool {
	if target == ErrBackendUnavail {
		return true
	}
	_, ok := target.(*BackendError)
	return ok || errors.Is(e.Cause, target)
}

// NewBackendError creates a new BackendError.
func NewBackendError(backend, message string) *BackendError {
	return &BackendError{Backend: backend, Message: message}
}

// NewBackendErrorWithCause creates a new BackendError with a cause.
func NewBackendErrorWithCause(backend, message string, cause error) *BackendError {
	return &BackendError{Backend: backend, Message: message, Cause: cause}
}

// TimeoutError represents a timeout error.
type TimeoutError struct {
	Operation string
	Duration  time.Duration
	Cause     error
}

// Error implements the error interface.
func (e *TimeoutError) Error() string {
	return fmt.Sprintf("timeout after %v during %s", e.Duration, e.Operation)
}

// Unwrap returns the underlying error.
func (e *TimeoutError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *TimeoutError) Is(target error) bool {
	if target == ErrTimeout {
		return true
	}
	_, ok := target.(*TimeoutError)
	return ok || errors.Is(e.Cause, target)
}

// NewTimeoutError creates a new TimeoutError.
func NewTimeoutError(operation string, duration time.Duration) *TimeoutError {
	return &TimeoutError{Operation: operation, Duration: duration}
}

// RateLimitError represents a rate limit exceeded error.
type RateLimitError struct {
	Limit      int
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded (limit: %d, retry after: %v)", e.Limit, e.RetryAfter)
}

// Is checks if the error matches the target.
func (e *RateLimitError) Is(target error) bool {
	if target == ErrRateLimited {
		return true
	}
	_, ok := target.(*RateLimitError)
	return ok
}

// NewRateLimitError creates a new RateLimitError.
func NewRateLimitError(limit int, retryAfter time.Duration) *RateLimitError {
	return &RateLimitError{Limit: limit, RetryAfter: retryAfter}
}

// CircuitOpenError represents a circuit breaker open error.
type CircuitOpenError struct {
	Name  string
	State string
}

// Error implements the error interface.
func (e *CircuitOpenError) Error() string {
	return fmt.Sprintf("circuit breaker %s is %s", e.Name, e.State)
}

// Is checks if the error matches the target.
func (e *CircuitOpenError) Is(target error) bool {
	if target == ErrCircuitOpen {
		return true
	}
	_, ok := target.(*CircuitOpenError)
	return ok
}

// NewCircuitOpenError creates a new CircuitOpenError.
func NewCircuitOpenError(name, state string) *CircuitOpenError {
	return &CircuitOpenError{Name: name, State: state}
}

// WrapError wraps an error with additional context.
func WrapError(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// IsRetryable returns true if the error is retryable.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Timeout errors are retryable
	if errors.Is(err, ErrTimeout) {
		return true
	}

	// Backend unavailable is retryable
	if errors.Is(err, ErrBackendUnavail) {
		return true
	}

	// Check for specific error types
	var timeoutErr *TimeoutError
	if errors.As(err, &timeoutErr) {
		return true
	}

	var backendErr *BackendError
	return errors.As(err, &backendErr)
}

// IsClientError returns true if the error is a client error (4xx).
func IsClientError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrNotFound) {
		return true
	}

	if errors.Is(err, ErrInvalidInput) {
		return true
	}

	if errors.Is(err, ErrRateLimited) {
		return true
	}

	return false
}

// IsServerError returns true if the error is a server error (5xx).
func IsServerError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrBackendUnavail) {
		return true
	}

	if errors.Is(err, ErrCircuitOpen) {
		return true
	}

	if errors.Is(err, ErrTimeout) {
		return true
	}

	return false
}

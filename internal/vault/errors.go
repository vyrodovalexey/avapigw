package vault

import (
	"errors"
	"fmt"
)

// Sentinel errors for Vault operations.
var (
	// ErrVaultDisabled indicates that Vault integration is disabled.
	ErrVaultDisabled = errors.New("vault integration is disabled")

	// ErrVaultSealed indicates that Vault is sealed.
	ErrVaultSealed = errors.New("vault is sealed")

	// ErrVaultUnavailable indicates that Vault is unavailable.
	ErrVaultUnavailable = errors.New("vault is unavailable")

	// ErrAuthenticationFailed indicates that Vault authentication failed.
	ErrAuthenticationFailed = errors.New("vault authentication failed")

	// ErrTokenExpired indicates that the Vault token has expired.
	ErrTokenExpired = errors.New("vault token expired")

	// ErrSecretNotFound indicates that the requested secret was not found.
	ErrSecretNotFound = errors.New("secret not found")

	// ErrPKIIssueFailed indicates that PKI certificate issuance failed.
	ErrPKIIssueFailed = errors.New("PKI certificate issuance failed")

	// ErrInvalidConfig indicates that the Vault configuration is invalid.
	ErrInvalidConfig = errors.New("invalid vault configuration")

	// ErrClientClosed indicates that the Vault client has been closed.
	ErrClientClosed = errors.New("vault client closed")

	// ErrTransitOperationFailed indicates that a Transit operation failed.
	ErrTransitOperationFailed = errors.New("transit operation failed")

	// ErrKVOperationFailed indicates that a KV operation failed.
	ErrKVOperationFailed = errors.New("KV operation failed")
)

// VaultError represents a Vault-related error with additional context.
type VaultError struct {
	Operation string
	Path      string
	Message   string
	Cause     error
}

// Error implements the error interface.
func (e *VaultError) Error() string {
	msg := e.buildMessage()
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

// buildMessage constructs the error message based on available fields.
func (e *VaultError) buildMessage() string {
	switch {
	case e.Operation != "" && e.Path != "":
		return fmt.Sprintf("vault %s at %s: %s", e.Operation, e.Path, e.Message)
	case e.Operation != "":
		return fmt.Sprintf("vault %s: %s", e.Operation, e.Message)
	default:
		return fmt.Sprintf("vault error: %s", e.Message)
	}
}

// Unwrap returns the underlying error.
func (e *VaultError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *VaultError) Is(target error) bool {
	_, ok := target.(*VaultError)
	return ok || errors.Is(e.Cause, target)
}

// NewVaultError creates a new VaultError.
func NewVaultError(operation, path, message string) *VaultError {
	return &VaultError{
		Operation: operation,
		Path:      path,
		Message:   message,
	}
}

// NewVaultErrorWithCause creates a new VaultError with a cause.
func NewVaultErrorWithCause(operation, path, message string, cause error) *VaultError {
	return &VaultError{
		Operation: operation,
		Path:      path,
		Message:   message,
		Cause:     cause,
	}
}

// AuthenticationError represents an authentication-related error.
type AuthenticationError struct {
	Method  string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *AuthenticationError) Error() string {
	msg := fmt.Sprintf("vault authentication failed (%s): %s", e.Method, e.Message)
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *AuthenticationError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *AuthenticationError) Is(target error) bool {
	if errors.Is(target, ErrAuthenticationFailed) {
		return true
	}
	_, ok := target.(*AuthenticationError)
	return ok || errors.Is(e.Cause, target)
}

// NewAuthenticationError creates a new AuthenticationError.
func NewAuthenticationError(method, message string) *AuthenticationError {
	return &AuthenticationError{
		Method:  method,
		Message: message,
	}
}

// NewAuthenticationErrorWithCause creates a new AuthenticationError with a cause.
func NewAuthenticationErrorWithCause(method, message string, cause error) *AuthenticationError {
	return &AuthenticationError{
		Method:  method,
		Message: message,
		Cause:   cause,
	}
}

// ConfigurationError represents a configuration-related error.
type ConfigurationError struct {
	Field   string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *ConfigurationError) Error() string {
	if e.Field != "" {
		if e.Cause != nil {
			return fmt.Sprintf("vault config error at %s: %s: %v", e.Field, e.Message, e.Cause)
		}
		return fmt.Sprintf("vault config error at %s: %s", e.Field, e.Message)
	}
	if e.Cause != nil {
		return fmt.Sprintf("vault config error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("vault config error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *ConfigurationError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *ConfigurationError) Is(target error) bool {
	if errors.Is(target, ErrInvalidConfig) {
		return true
	}
	_, ok := target.(*ConfigurationError)
	return ok || errors.Is(e.Cause, target)
}

// NewConfigurationError creates a new ConfigurationError.
func NewConfigurationError(field, message string) *ConfigurationError {
	return &ConfigurationError{
		Field:   field,
		Message: message,
	}
}

// NewConfigurationErrorWithCause creates a new ConfigurationError with a cause.
func NewConfigurationErrorWithCause(field, message string, cause error) *ConfigurationError {
	return &ConfigurationError{
		Field:   field,
		Message: message,
		Cause:   cause,
	}
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

	// Network errors and unavailability are retryable
	if errors.Is(err, ErrVaultUnavailable) {
		return true
	}

	// Token expiration requires re-authentication, not retry
	if errors.Is(err, ErrTokenExpired) {
		return false
	}

	// Authentication failures are not retryable
	if errors.Is(err, ErrAuthenticationFailed) {
		return false
	}

	// Configuration errors are not retryable
	if errors.Is(err, ErrInvalidConfig) {
		return false
	}

	// Vault sealed is potentially retryable (may be unsealed)
	if errors.Is(err, ErrVaultSealed) {
		return true
	}

	return false
}

package auth

import (
	"errors"
	"fmt"
)

// Sentinel errors for backend authentication operations.
var (
	// ErrProviderClosed indicates that the provider has been closed.
	ErrProviderClosed = errors.New("provider closed")

	// ErrNoCredentials indicates that no credentials are available.
	ErrNoCredentials = errors.New("no credentials available")

	// ErrInvalidCredentials indicates that the credentials are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrTokenExpired indicates that the token has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenRefreshFailed indicates that token refresh failed.
	ErrTokenRefreshFailed = errors.New("token refresh failed")

	// ErrVaultUnavailable indicates that Vault is unavailable.
	ErrVaultUnavailable = errors.New("vault unavailable")

	// ErrOIDCFailed indicates that OIDC token acquisition failed.
	ErrOIDCFailed = errors.New("OIDC token acquisition failed")

	// ErrCertificateExpired indicates that the certificate has expired.
	ErrCertificateExpired = errors.New("certificate expired")

	// ErrCertificateLoadFailed indicates that certificate loading failed.
	ErrCertificateLoadFailed = errors.New("certificate load failed")

	// ErrUnsupportedAuthType indicates an unsupported authentication type.
	ErrUnsupportedAuthType = errors.New("unsupported authentication type")

	// ErrInvalidConfig indicates invalid configuration.
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrContextCanceled indicates that the context was canceled.
	ErrContextCanceled = errors.New("context canceled")
)

// ProviderError represents a backend authentication provider error with context.
type ProviderError struct {
	Provider  string
	Operation string
	Message   string
	Cause     error
}

// Error implements the error interface.
func (e *ProviderError) Error() string {
	msg := e.buildMessage()
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

// buildMessage constructs the error message based on available fields.
func (e *ProviderError) buildMessage() string {
	switch {
	case e.Provider != "" && e.Operation != "":
		return fmt.Sprintf("backend auth %s (%s): %s", e.Operation, e.Provider, e.Message)
	case e.Provider != "":
		return fmt.Sprintf("backend auth (%s): %s", e.Provider, e.Message)
	case e.Operation != "":
		return fmt.Sprintf("backend auth %s: %s", e.Operation, e.Message)
	default:
		return fmt.Sprintf("backend auth: %s", e.Message)
	}
}

// Unwrap returns the underlying error.
func (e *ProviderError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *ProviderError) Is(target error) bool {
	_, ok := target.(*ProviderError)
	return ok || errors.Is(e.Cause, target)
}

// NewProviderError creates a new ProviderError.
func NewProviderError(provider, operation, message string) *ProviderError {
	return &ProviderError{
		Provider:  provider,
		Operation: operation,
		Message:   message,
	}
}

// NewProviderErrorWithCause creates a new ProviderError with a cause.
func NewProviderErrorWithCause(provider, operation, message string, cause error) *ProviderError {
	return &ProviderError{
		Provider:  provider,
		Operation: operation,
		Message:   message,
		Cause:     cause,
	}
}

// ConfigError represents a configuration error.
type ConfigError struct {
	Field   string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	if e.Field != "" {
		if e.Cause != nil {
			return fmt.Sprintf("backend auth config error at %s: %s: %v", e.Field, e.Message, e.Cause)
		}
		return fmt.Sprintf("backend auth config error at %s: %s", e.Field, e.Message)
	}
	if e.Cause != nil {
		return fmt.Sprintf("backend auth config error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("backend auth config error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *ConfigError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *ConfigError) Is(target error) bool {
	if errors.Is(target, ErrInvalidConfig) {
		return true
	}
	_, ok := target.(*ConfigError)
	return ok || errors.Is(e.Cause, target)
}

// NewConfigError creates a new ConfigError.
func NewConfigError(field, message string) *ConfigError {
	return &ConfigError{
		Field:   field,
		Message: message,
	}
}

// NewConfigErrorWithCause creates a new ConfigError with a cause.
func NewConfigErrorWithCause(field, message string, cause error) *ConfigError {
	return &ConfigError{
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

	// OIDC failures may be retryable
	if errors.Is(err, ErrOIDCFailed) {
		return true
	}

	// Token expiration requires refresh, not retry
	if errors.Is(err, ErrTokenExpired) {
		return false
	}

	// Invalid credentials are not retryable
	if errors.Is(err, ErrInvalidCredentials) {
		return false
	}

	// Configuration errors are not retryable
	if errors.Is(err, ErrInvalidConfig) {
		return false
	}

	// Context cancellation is not retryable
	if errors.Is(err, ErrContextCanceled) {
		return false
	}

	return false
}

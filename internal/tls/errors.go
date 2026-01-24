package tls

import (
	"errors"
	"fmt"
)

// Common sentinel errors for TLS operations.
var (
	// ErrCertificateNotFound indicates that a certificate was not found.
	ErrCertificateNotFound = errors.New("certificate not found")

	// ErrCertificateExpired indicates that a certificate has expired.
	ErrCertificateExpired = errors.New("certificate expired")

	// ErrCertificateInvalid indicates that a certificate is invalid.
	ErrCertificateInvalid = errors.New("certificate invalid")

	// ErrPrivateKeyInvalid indicates that a private key is invalid.
	ErrPrivateKeyInvalid = errors.New("private key invalid")

	// ErrCertificateKeyMismatch indicates that the certificate and key do not match.
	ErrCertificateKeyMismatch = errors.New("certificate and key do not match")

	// ErrCAInvalid indicates that a CA certificate is invalid.
	ErrCAInvalid = errors.New("CA certificate invalid")

	// ErrCipherSuiteInvalid indicates that a cipher suite is invalid.
	ErrCipherSuiteInvalid = errors.New("invalid cipher suite")

	// ErrTLSVersionInvalid indicates that a TLS version is invalid.
	ErrTLSVersionInvalid = errors.New("invalid TLS version")

	// ErrTLSModeInvalid indicates that a TLS mode is invalid.
	ErrTLSModeInvalid = errors.New("invalid TLS mode")

	// ErrProviderClosed indicates that the certificate provider has been closed.
	ErrProviderClosed = errors.New("certificate provider closed")

	// ErrClientCertRequired indicates that a client certificate is required but not provided.
	ErrClientCertRequired = errors.New("client certificate required")

	// ErrClientCertNotAllowed indicates that the client certificate is not in the allowed list.
	ErrClientCertNotAllowed = errors.New("client certificate not allowed")

	// ErrConfigInvalid indicates that the TLS configuration is invalid.
	ErrConfigInvalid = errors.New("invalid TLS configuration")
)

// CertificateError represents a certificate-related error.
type CertificateError struct {
	Path    string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *CertificateError) Error() string {
	if e.Path != "" {
		if e.Cause != nil {
			return fmt.Sprintf("certificate error at %s: %s: %v", e.Path, e.Message, e.Cause)
		}
		return fmt.Sprintf("certificate error at %s: %s", e.Path, e.Message)
	}
	if e.Cause != nil {
		return fmt.Sprintf("certificate error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("certificate error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *CertificateError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *CertificateError) Is(target error) bool {
	_, ok := target.(*CertificateError)
	return ok || errors.Is(e.Cause, target)
}

// NewCertificateError creates a new CertificateError.
func NewCertificateError(path, message string) *CertificateError {
	return &CertificateError{Path: path, Message: message}
}

// NewCertificateErrorWithCause creates a new CertificateError with a cause.
func NewCertificateErrorWithCause(path, message string, cause error) *CertificateError {
	return &CertificateError{Path: path, Message: message, Cause: cause}
}

// ConfigurationError represents a TLS configuration error.
type ConfigurationError struct {
	Field   string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *ConfigurationError) Error() string {
	if e.Field != "" {
		if e.Cause != nil {
			return fmt.Sprintf("TLS config error at %s: %s: %v", e.Field, e.Message, e.Cause)
		}
		return fmt.Sprintf("TLS config error at %s: %s", e.Field, e.Message)
	}
	if e.Cause != nil {
		return fmt.Sprintf("TLS config error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("TLS config error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *ConfigurationError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *ConfigurationError) Is(target error) bool {
	if errors.Is(target, ErrConfigInvalid) {
		return true
	}
	_, ok := target.(*ConfigurationError)
	return ok || errors.Is(e.Cause, target)
}

// NewConfigurationError creates a new ConfigurationError.
func NewConfigurationError(field, message string) *ConfigurationError {
	return &ConfigurationError{Field: field, Message: message}
}

// NewConfigurationErrorWithCause creates a new ConfigurationError with a cause.
func NewConfigurationErrorWithCause(field, message string, cause error) *ConfigurationError {
	return &ConfigurationError{Field: field, Message: message, Cause: cause}
}

// ValidationError represents a client certificate validation error.
type ValidationError struct {
	Subject string
	Reason  string
	Cause   error
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Subject != "" {
		if e.Cause != nil {
			return fmt.Sprintf("certificate validation failed for %s: %s: %v", e.Subject, e.Reason, e.Cause)
		}
		return fmt.Sprintf("certificate validation failed for %s: %s", e.Subject, e.Reason)
	}
	if e.Cause != nil {
		return fmt.Sprintf("certificate validation failed: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("certificate validation failed: %s", e.Reason)
}

// Unwrap returns the underlying error.
func (e *ValidationError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *ValidationError) Is(target error) bool {
	_, ok := target.(*ValidationError)
	return ok || errors.Is(e.Cause, target)
}

// NewValidationError creates a new ValidationError.
func NewValidationError(subject, reason string) *ValidationError {
	return &ValidationError{Subject: subject, Reason: reason}
}

// NewValidationErrorWithCause creates a new ValidationError with a cause.
func NewValidationErrorWithCause(subject, reason string, cause error) *ValidationError {
	return &ValidationError{Subject: subject, Reason: reason, Cause: cause}
}

// WrapError wraps an error with additional context.
func WrapError(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

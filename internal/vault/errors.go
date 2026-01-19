// Package vault provides HashiCorp Vault integration for secret management.
package vault

import (
	"errors"
	"fmt"
)

// Common errors for Vault operations.
var (
	// ErrNotAuthenticated indicates the client is not authenticated.
	ErrNotAuthenticated = errors.New("vault: client not authenticated")

	// ErrAuthenticationFailed indicates authentication failed.
	ErrAuthenticationFailed = errors.New("vault: authentication failed")

	// ErrSecretNotFound indicates the secret was not found.
	ErrSecretNotFound = errors.New("vault: secret not found")

	// ErrInvalidPath indicates an invalid secret path.
	ErrInvalidPath = errors.New("vault: invalid secret path")

	// ErrInvalidConfig indicates invalid configuration.
	ErrInvalidConfig = errors.New("vault: invalid configuration")

	// ErrConnectionFailed indicates connection to Vault failed.
	ErrConnectionFailed = errors.New("vault: connection failed")

	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("vault: token expired")

	// ErrPermissionDenied indicates permission was denied.
	ErrPermissionDenied = errors.New("vault: permission denied")

	// ErrCacheMiss indicates a cache miss.
	ErrCacheMiss = errors.New("vault: cache miss")

	// ErrWatcherStopped indicates the watcher was stopped.
	ErrWatcherStopped = errors.New("vault: watcher stopped")

	// ErrCertificateInvalid indicates an invalid certificate.
	ErrCertificateInvalid = errors.New("vault: invalid certificate")

	// ErrRetryExhausted indicates all retry attempts were exhausted.
	ErrRetryExhausted = errors.New("vault: retry attempts exhausted")
)

// VaultError represents a Vault-specific error with additional context.
type VaultError struct {
	Op      string // Operation that failed
	Path    string // Secret path if applicable
	Err     error  // Underlying error
	Code    int    // HTTP status code if applicable
	Message string // Additional message
}

// Error implements the error interface.
func (e *VaultError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("vault %s on path %s: %v", e.Op, e.Path, e.Err)
	}
	return fmt.Sprintf("vault %s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error.
func (e *VaultError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is for VaultError.
func (e *VaultError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewVaultError creates a new VaultError.
func NewVaultError(op, path string, err error) *VaultError {
	return &VaultError{
		Op:   op,
		Path: path,
		Err:  err,
	}
}

// NewVaultErrorWithCode creates a new VaultError with an HTTP status code.
func NewVaultErrorWithCode(op, path string, err error, code int) *VaultError {
	return &VaultError{
		Op:   op,
		Path: path,
		Err:  err,
		Code: code,
	}
}

// IsRetryable returns true if the error is retryable.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	var vaultErr *VaultError
	if errors.As(err, &vaultErr) {
		// Retry on server errors (5xx) and rate limiting (429)
		if vaultErr.Code >= 500 || vaultErr.Code == 429 {
			return true
		}
	}

	// Retry on connection errors
	if errors.Is(err, ErrConnectionFailed) {
		return true
	}

	return false
}

// IsAuthError returns true if the error is an authentication error.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrNotAuthenticated) ||
		errors.Is(err, ErrAuthenticationFailed) ||
		errors.Is(err, ErrTokenExpired) {
		return true
	}

	var vaultErr *VaultError
	if errors.As(err, &vaultErr) {
		// 401 Unauthorized or 403 Forbidden
		if vaultErr.Code == 401 || vaultErr.Code == 403 {
			return true
		}
	}

	return false
}

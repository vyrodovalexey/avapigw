package vault

import (
	"errors"
	"fmt"
	"testing"
)

func TestVaultError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *VaultError
		expected string
	}{
		{
			name: "with operation and path",
			err: &VaultError{
				Operation: "read",
				Path:      "secret/data/test",
				Message:   "access denied",
			},
			expected: "vault read at secret/data/test: access denied",
		},
		{
			name: "with operation only",
			err: &VaultError{
				Operation: "authenticate",
				Message:   "invalid token",
			},
			expected: "vault authenticate: invalid token",
		},
		{
			name: "with message only",
			err: &VaultError{
				Message: "connection failed",
			},
			expected: "vault error: connection failed",
		},
		{
			name: "with cause",
			err: &VaultError{
				Operation: "read",
				Path:      "secret/data/test",
				Message:   "access denied",
				Cause:     errors.New("underlying error"),
			},
			expected: "vault read at secret/data/test: access denied: underlying error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVaultError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &VaultError{
		Operation: "read",
		Message:   "failed",
		Cause:     cause,
	}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}

	// Test with nil cause
	errNoCause := &VaultError{
		Operation: "read",
		Message:   "failed",
	}
	if errNoCause.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause")
	}
}

func TestVaultError_Is(t *testing.T) {
	cause := ErrVaultUnavailable
	err := &VaultError{
		Operation: "read",
		Message:   "failed",
		Cause:     cause,
	}

	// Should match VaultError type
	if !errors.Is(err, &VaultError{}) {
		t.Error("Is() should match VaultError type")
	}

	// Should match underlying cause
	if !errors.Is(err, ErrVaultUnavailable) {
		t.Error("Is() should match underlying cause")
	}

	// Should not match unrelated error
	if errors.Is(err, ErrSecretNotFound) {
		t.Error("Is() should not match unrelated error")
	}
}

func TestAuthenticationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AuthenticationError
		expected string
	}{
		{
			name: "without cause",
			err: &AuthenticationError{
				Method:  "token",
				Message: "invalid token",
			},
			expected: "vault authentication failed (token): invalid token",
		},
		{
			name: "with cause",
			err: &AuthenticationError{
				Method:  "kubernetes",
				Message: "JWT validation failed",
				Cause:   errors.New("token expired"),
			},
			expected: "vault authentication failed (kubernetes): JWT validation failed: token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAuthenticationError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &AuthenticationError{
		Method:  "token",
		Message: "failed",
		Cause:   cause,
	}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestAuthenticationError_Is(t *testing.T) {
	err := &AuthenticationError{
		Method:  "token",
		Message: "invalid token",
	}

	// Should match ErrAuthenticationFailed
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Error("Is() should match ErrAuthenticationFailed")
	}

	// Should match AuthenticationError type
	if !errors.Is(err, &AuthenticationError{}) {
		t.Error("Is() should match AuthenticationError type")
	}

	// Test with cause
	errWithCause := &AuthenticationError{
		Method:  "token",
		Message: "failed",
		Cause:   ErrTokenExpired,
	}
	if !errors.Is(errWithCause, ErrTokenExpired) {
		t.Error("Is() should match underlying cause")
	}
}

func TestConfigurationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ConfigurationError
		expected string
	}{
		{
			name: "with field",
			err: &ConfigurationError{
				Field:   "address",
				Message: "address is required",
			},
			expected: "vault config error at address: address is required",
		},
		{
			name: "without field",
			err: &ConfigurationError{
				Message: "configuration is nil",
			},
			expected: "vault config error: configuration is nil",
		},
		{
			name: "with field and cause",
			err: &ConfigurationError{
				Field:   "tls",
				Message: "failed to load certificate",
				Cause:   errors.New("file not found"),
			},
			expected: "vault config error at tls: failed to load certificate: file not found",
		},
		{
			name: "without field with cause",
			err: &ConfigurationError{
				Message: "validation failed",
				Cause:   errors.New("invalid format"),
			},
			expected: "vault config error: validation failed: invalid format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfigurationError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &ConfigurationError{
		Field:   "address",
		Message: "failed",
		Cause:   cause,
	}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestConfigurationError_Is(t *testing.T) {
	err := &ConfigurationError{
		Field:   "address",
		Message: "address is required",
	}

	// Should match ErrInvalidConfig
	if !errors.Is(err, ErrInvalidConfig) {
		t.Error("Is() should match ErrInvalidConfig")
	}

	// Should match ConfigurationError type
	if !errors.Is(err, &ConfigurationError{}) {
		t.Error("Is() should match ConfigurationError type")
	}

	// Test with cause
	errWithCause := &ConfigurationError{
		Field:   "tls",
		Message: "failed",
		Cause:   ErrVaultUnavailable,
	}
	if !errors.Is(errWithCause, ErrVaultUnavailable) {
		t.Error("Is() should match underlying cause")
	}
}

func TestNewVaultError(t *testing.T) {
	err := NewVaultError("read", "secret/data/test", "access denied")

	if err.Operation != "read" {
		t.Errorf("Operation = %v, want %v", err.Operation, "read")
	}
	if err.Path != "secret/data/test" {
		t.Errorf("Path = %v, want %v", err.Path, "secret/data/test")
	}
	if err.Message != "access denied" {
		t.Errorf("Message = %v, want %v", err.Message, "access denied")
	}
	if err.Cause != nil {
		t.Error("Cause should be nil")
	}
}

func TestNewVaultErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewVaultErrorWithCause("read", "secret/data/test", "access denied", cause)

	if err.Operation != "read" {
		t.Errorf("Operation = %v, want %v", err.Operation, "read")
	}
	if err.Path != "secret/data/test" {
		t.Errorf("Path = %v, want %v", err.Path, "secret/data/test")
	}
	if err.Message != "access denied" {
		t.Errorf("Message = %v, want %v", err.Message, "access denied")
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
}

func TestNewAuthenticationError(t *testing.T) {
	err := NewAuthenticationError("token", "invalid token")

	if err.Method != "token" {
		t.Errorf("Method = %v, want %v", err.Method, "token")
	}
	if err.Message != "invalid token" {
		t.Errorf("Message = %v, want %v", err.Message, "invalid token")
	}
	if err.Cause != nil {
		t.Error("Cause should be nil")
	}
}

func TestNewAuthenticationErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewAuthenticationErrorWithCause("kubernetes", "JWT validation failed", cause)

	if err.Method != "kubernetes" {
		t.Errorf("Method = %v, want %v", err.Method, "kubernetes")
	}
	if err.Message != "JWT validation failed" {
		t.Errorf("Message = %v, want %v", err.Message, "JWT validation failed")
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
}

func TestNewConfigurationError(t *testing.T) {
	err := NewConfigurationError("address", "address is required")

	if err.Field != "address" {
		t.Errorf("Field = %v, want %v", err.Field, "address")
	}
	if err.Message != "address is required" {
		t.Errorf("Message = %v, want %v", err.Message, "address is required")
	}
	if err.Cause != nil {
		t.Error("Cause should be nil")
	}
}

func TestNewConfigurationErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewConfigurationErrorWithCause("tls", "failed to load certificate", cause)

	if err.Field != "tls" {
		t.Errorf("Field = %v, want %v", err.Field, "tls")
	}
	if err.Message != "failed to load certificate" {
		t.Errorf("Message = %v, want %v", err.Message, "failed to load certificate")
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
}

func TestWrapError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		message  string
		expected string
	}{
		{
			name:     "nil error returns nil",
			err:      nil,
			message:  "wrapped",
			expected: "",
		},
		{
			name:     "wraps error with message",
			err:      errors.New("original error"),
			message:  "operation failed",
			expected: "operation failed: original error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapError(tt.err, tt.message)
			if tt.err == nil {
				if result != nil {
					t.Error("WrapError(nil, ...) should return nil")
				}
			} else {
				if result == nil {
					t.Error("WrapError should not return nil for non-nil error")
				}
				if result.Error() != tt.expected {
					t.Errorf("Error() = %v, want %v", result.Error(), tt.expected)
				}
				// Verify unwrapping works
				if !errors.Is(result, tt.err) {
					t.Error("Wrapped error should unwrap to original")
				}
			}
		})
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error is not retryable",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrVaultUnavailable is retryable",
			err:      ErrVaultUnavailable,
			expected: true,
		},
		{
			name:     "ErrVaultSealed is retryable",
			err:      ErrVaultSealed,
			expected: true,
		},
		{
			name:     "ErrTokenExpired is not retryable",
			err:      ErrTokenExpired,
			expected: false,
		},
		{
			name:     "ErrAuthenticationFailed is not retryable",
			err:      ErrAuthenticationFailed,
			expected: false,
		},
		{
			name:     "ErrInvalidConfig is not retryable",
			err:      ErrInvalidConfig,
			expected: false,
		},
		{
			name:     "ErrSecretNotFound is not retryable",
			err:      ErrSecretNotFound,
			expected: false,
		},
		{
			name:     "ErrVaultDisabled is not retryable",
			err:      ErrVaultDisabled,
			expected: false,
		},
		{
			name:     "ErrClientClosed is not retryable",
			err:      ErrClientClosed,
			expected: false,
		},
		{
			name:     "wrapped ErrVaultUnavailable is retryable",
			err:      fmt.Errorf("operation failed: %w", ErrVaultUnavailable),
			expected: true,
		},
		{
			name:     "wrapped ErrAuthenticationFailed is not retryable",
			err:      fmt.Errorf("operation failed: %w", ErrAuthenticationFailed),
			expected: false,
		},
		{
			name:     "ConfigurationError is not retryable",
			err:      NewConfigurationError("address", "required"),
			expected: false,
		},
		{
			name:     "AuthenticationError is not retryable",
			err:      NewAuthenticationError("token", "invalid"),
			expected: false,
		},
		{
			name:     "generic error is not retryable",
			err:      errors.New("some error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			if result != tt.expected {
				t.Errorf("IsRetryable() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	// Verify sentinel errors are distinct
	sentinelErrors := []error{
		ErrVaultDisabled,
		ErrVaultSealed,
		ErrVaultUnavailable,
		ErrAuthenticationFailed,
		ErrTokenExpired,
		ErrSecretNotFound,
		ErrPKIIssueFailed,
		ErrInvalidConfig,
		ErrClientClosed,
		ErrTransitOperationFailed,
		ErrKVOperationFailed,
	}

	for i, err1 := range sentinelErrors {
		for j, err2 := range sentinelErrors {
			if i != j && errors.Is(err1, err2) {
				t.Errorf("Sentinel errors should be distinct: %v and %v", err1, err2)
			}
		}
	}
}

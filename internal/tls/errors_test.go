package tls

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCertificateError(t *testing.T) {
	tests := []struct {
		name     string
		err      *CertificateError
		expected string
	}{
		{
			name: "with path and cause",
			err: &CertificateError{
				Path:    "/path/to/cert.pem",
				Message: "failed to load",
				Cause:   errors.New("file not found"),
			},
			expected: "certificate error at /path/to/cert.pem: failed to load: file not found",
		},
		{
			name: "with path without cause",
			err: &CertificateError{
				Path:    "/path/to/cert.pem",
				Message: "failed to load",
			},
			expected: "certificate error at /path/to/cert.pem: failed to load",
		},
		{
			name: "without path with cause",
			err: &CertificateError{
				Message: "failed to load",
				Cause:   errors.New("parse error"),
			},
			expected: "certificate error: failed to load: parse error",
		},
		{
			name: "without path without cause",
			err: &CertificateError{
				Message: "failed to load",
			},
			expected: "certificate error: failed to load",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestCertificateError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &CertificateError{
		Message: "test",
		Cause:   cause,
	}

	assert.Equal(t, cause, err.Unwrap())
}

func TestCertificateError_Is(t *testing.T) {
	cause := ErrCertificateExpired
	err := &CertificateError{
		Message: "test",
		Cause:   cause,
	}

	// Should match CertificateError type
	assert.True(t, errors.Is(err, &CertificateError{}))

	// Should match underlying cause
	assert.True(t, errors.Is(err, ErrCertificateExpired))

	// Should not match unrelated error
	assert.False(t, errors.Is(err, ErrCipherSuiteInvalid))
}

func TestNewCertificateError(t *testing.T) {
	err := NewCertificateError("/path/to/cert.pem", "test message")

	assert.Equal(t, "/path/to/cert.pem", err.Path)
	assert.Equal(t, "test message", err.Message)
	assert.Nil(t, err.Cause)
}

func TestNewCertificateErrorWithCause(t *testing.T) {
	cause := errors.New("underlying")
	err := NewCertificateErrorWithCause("/path/to/cert.pem", "test message", cause)

	assert.Equal(t, "/path/to/cert.pem", err.Path)
	assert.Equal(t, "test message", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestConfigurationError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ConfigurationError
		expected string
	}{
		{
			name: "with field and cause",
			err: &ConfigurationError{
				Field:   "minVersion",
				Message: "invalid value",
				Cause:   errors.New("parse error"),
			},
			expected: "TLS config error at minVersion: invalid value: parse error",
		},
		{
			name: "with field without cause",
			err: &ConfigurationError{
				Field:   "minVersion",
				Message: "invalid value",
			},
			expected: "TLS config error at minVersion: invalid value",
		},
		{
			name: "without field with cause",
			err: &ConfigurationError{
				Message: "invalid value",
				Cause:   errors.New("parse error"),
			},
			expected: "TLS config error: invalid value: parse error",
		},
		{
			name: "without field without cause",
			err: &ConfigurationError{
				Message: "invalid value",
			},
			expected: "TLS config error: invalid value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestConfigurationError_Is(t *testing.T) {
	err := &ConfigurationError{
		Field:   "test",
		Message: "test",
	}

	// Should match ErrConfigInvalid
	assert.True(t, errors.Is(err, ErrConfigInvalid))

	// Should match ConfigurationError type
	assert.True(t, errors.Is(err, &ConfigurationError{}))
}

func TestNewConfigurationError(t *testing.T) {
	err := NewConfigurationError("field", "message")

	assert.Equal(t, "field", err.Field)
	assert.Equal(t, "message", err.Message)
	assert.Nil(t, err.Cause)
}

func TestNewConfigurationErrorWithCause(t *testing.T) {
	cause := errors.New("underlying")
	err := NewConfigurationErrorWithCause("field", "message", cause)

	assert.Equal(t, "field", err.Field)
	assert.Equal(t, "message", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		expected string
	}{
		{
			name: "with subject and cause",
			err: &ValidationError{
				Subject: "client.example.com",
				Reason:  "expired",
				Cause:   errors.New("certificate expired"),
			},
			expected: "certificate validation failed for client.example.com: expired: certificate expired",
		},
		{
			name: "with subject without cause",
			err: &ValidationError{
				Subject: "client.example.com",
				Reason:  "expired",
			},
			expected: "certificate validation failed for client.example.com: expired",
		},
		{
			name: "without subject with cause",
			err: &ValidationError{
				Reason: "expired",
				Cause:  errors.New("certificate expired"),
			},
			expected: "certificate validation failed: expired: certificate expired",
		},
		{
			name: "without subject without cause",
			err: &ValidationError{
				Reason: "expired",
			},
			expected: "certificate validation failed: expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestValidationError_Is(t *testing.T) {
	cause := ErrCertificateExpired
	err := &ValidationError{
		Subject: "test",
		Reason:  "expired",
		Cause:   cause,
	}

	// Should match ValidationError type
	assert.True(t, errors.Is(err, &ValidationError{}))

	// Should match underlying cause
	assert.True(t, errors.Is(err, ErrCertificateExpired))
}

func TestNewValidationError(t *testing.T) {
	err := NewValidationError("subject", "reason")

	assert.Equal(t, "subject", err.Subject)
	assert.Equal(t, "reason", err.Reason)
	assert.Nil(t, err.Cause)
}

func TestNewValidationErrorWithCause(t *testing.T) {
	cause := errors.New("underlying")
	err := NewValidationErrorWithCause("subject", "reason", cause)

	assert.Equal(t, "subject", err.Subject)
	assert.Equal(t, "reason", err.Reason)
	assert.Equal(t, cause, err.Cause)
}

func TestWrapError(t *testing.T) {
	// Nil error should return nil
	assert.Nil(t, WrapError(nil, "message"))

	// Non-nil error should be wrapped
	cause := errors.New("original")
	wrapped := WrapError(cause, "context")

	assert.Contains(t, wrapped.Error(), "context")
	assert.Contains(t, wrapped.Error(), "original")
	assert.True(t, errors.Is(wrapped, cause))
}

func TestSentinelErrors(t *testing.T) {
	// Verify all sentinel errors are defined
	assert.NotNil(t, ErrCertificateNotFound)
	assert.NotNil(t, ErrCertificateExpired)
	assert.NotNil(t, ErrCertificateInvalid)
	assert.NotNil(t, ErrPrivateKeyInvalid)
	assert.NotNil(t, ErrCertificateKeyMismatch)
	assert.NotNil(t, ErrCAInvalid)
	assert.NotNil(t, ErrCipherSuiteInvalid)
	assert.NotNil(t, ErrTLSVersionInvalid)
	assert.NotNil(t, ErrTLSModeInvalid)
	assert.NotNil(t, ErrProviderClosed)
	assert.NotNil(t, ErrClientCertRequired)
	assert.NotNil(t, ErrClientCertNotAllowed)
	assert.NotNil(t, ErrConfigInvalid)
}

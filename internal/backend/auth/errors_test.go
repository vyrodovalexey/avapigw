package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrProviderClosed", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrProviderClosed)
		assert.Equal(t, "provider closed", ErrProviderClosed.Error())
	})

	t.Run("ErrNoCredentials", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrNoCredentials)
		assert.Equal(t, "no credentials available", ErrNoCredentials.Error())
	})

	t.Run("ErrInvalidCredentials", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrInvalidCredentials)
		assert.Equal(t, "invalid credentials", ErrInvalidCredentials.Error())
	})

	t.Run("ErrTokenExpired", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrTokenExpired)
		assert.Equal(t, "token expired", ErrTokenExpired.Error())
	})

	t.Run("ErrTokenRefreshFailed", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrTokenRefreshFailed)
		assert.Equal(t, "token refresh failed", ErrTokenRefreshFailed.Error())
	})

	t.Run("ErrVaultUnavailable", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrVaultUnavailable)
		assert.Equal(t, "vault unavailable", ErrVaultUnavailable.Error())
	})

	t.Run("ErrOIDCFailed", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrOIDCFailed)
		assert.Equal(t, "OIDC token acquisition failed", ErrOIDCFailed.Error())
	})

	t.Run("ErrCertificateExpired", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrCertificateExpired)
		assert.Equal(t, "certificate expired", ErrCertificateExpired.Error())
	})

	t.Run("ErrCertificateLoadFailed", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrCertificateLoadFailed)
		assert.Equal(t, "certificate load failed", ErrCertificateLoadFailed.Error())
	})

	t.Run("ErrUnsupportedAuthType", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrUnsupportedAuthType)
		assert.Equal(t, "unsupported authentication type", ErrUnsupportedAuthType.Error())
	})

	t.Run("ErrInvalidConfig", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrInvalidConfig)
		assert.Equal(t, "invalid configuration", ErrInvalidConfig.Error())
	})

	t.Run("ErrContextCanceled", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, ErrContextCanceled)
		assert.Equal(t, "context canceled", ErrContextCanceled.Error())
	})
}

func TestProviderError(t *testing.T) {
	t.Parallel()

	t.Run("Error with all fields", func(t *testing.T) {
		t.Parallel()

		err := &ProviderError{
			Provider:  "test-provider",
			Operation: "apply_http",
			Message:   "failed to get token",
		}

		assert.Contains(t, err.Error(), "test-provider")
		assert.Contains(t, err.Error(), "apply_http")
		assert.Contains(t, err.Error(), "failed to get token")
	})

	t.Run("Error with cause", func(t *testing.T) {
		t.Parallel()

		cause := errors.New("underlying error")
		err := &ProviderError{
			Provider:  "test-provider",
			Operation: "apply_http",
			Message:   "failed to get token",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "underlying error")
	})

	t.Run("Error with only provider", func(t *testing.T) {
		t.Parallel()

		err := &ProviderError{
			Provider: "test-provider",
			Message:  "error message",
		}

		assert.Contains(t, err.Error(), "test-provider")
		assert.Contains(t, err.Error(), "error message")
	})

	t.Run("Error with only operation", func(t *testing.T) {
		t.Parallel()

		err := &ProviderError{
			Operation: "apply_http",
			Message:   "error message",
		}

		assert.Contains(t, err.Error(), "apply_http")
		assert.Contains(t, err.Error(), "error message")
	})

	t.Run("Error with only message", func(t *testing.T) {
		t.Parallel()

		err := &ProviderError{
			Message: "error message",
		}

		assert.Contains(t, err.Error(), "error message")
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		t.Parallel()

		cause := errors.New("underlying error")
		err := &ProviderError{
			Message: "error message",
			Cause:   cause,
		}

		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("Is matches ProviderError", func(t *testing.T) {
		t.Parallel()

		err := &ProviderError{
			Message: "error message",
		}

		assert.True(t, err.Is(&ProviderError{}))
	})

	t.Run("Is matches cause", func(t *testing.T) {
		t.Parallel()

		err := &ProviderError{
			Message: "error message",
			Cause:   ErrProviderClosed,
		}

		assert.True(t, errors.Is(err, ErrProviderClosed))
	})
}

func TestNewProviderError(t *testing.T) {
	t.Parallel()

	err := NewProviderError("test-provider", "apply_http", "failed to get token")

	assert.Equal(t, "test-provider", err.Provider)
	assert.Equal(t, "apply_http", err.Operation)
	assert.Equal(t, "failed to get token", err.Message)
	assert.Nil(t, err.Cause)
}

func TestNewProviderErrorWithCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying error")
	err := NewProviderErrorWithCause("test-provider", "apply_http", "failed to get token", cause)

	assert.Equal(t, "test-provider", err.Provider)
	assert.Equal(t, "apply_http", err.Operation)
	assert.Equal(t, "failed to get token", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestConfigError(t *testing.T) {
	t.Parallel()

	t.Run("Error with field", func(t *testing.T) {
		t.Parallel()

		err := &ConfigError{
			Field:   "tokenSource",
			Message: "invalid value",
		}

		assert.Contains(t, err.Error(), "tokenSource")
		assert.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Error with cause", func(t *testing.T) {
		t.Parallel()

		cause := errors.New("underlying error")
		err := &ConfigError{
			Field:   "tokenSource",
			Message: "invalid value",
			Cause:   cause,
		}

		assert.Contains(t, err.Error(), "underlying error")
	})

	t.Run("Error without field", func(t *testing.T) {
		t.Parallel()

		err := &ConfigError{
			Message: "invalid configuration",
		}

		assert.Contains(t, err.Error(), "invalid configuration")
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		t.Parallel()

		cause := errors.New("underlying error")
		err := &ConfigError{
			Message: "error message",
			Cause:   cause,
		}

		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("Is matches ErrInvalidConfig", func(t *testing.T) {
		t.Parallel()

		err := &ConfigError{
			Message: "error message",
		}

		assert.True(t, errors.Is(err, ErrInvalidConfig))
	})

	t.Run("Is matches ConfigError", func(t *testing.T) {
		t.Parallel()

		err := &ConfigError{
			Message: "error message",
		}

		assert.True(t, err.Is(&ConfigError{}))
	})

	t.Run("Is matches cause", func(t *testing.T) {
		t.Parallel()

		err := &ConfigError{
			Message: "error message",
			Cause:   ErrProviderClosed,
		}

		assert.True(t, errors.Is(err, ErrProviderClosed))
	})
}

func TestNewConfigError(t *testing.T) {
	t.Parallel()

	err := NewConfigError("tokenSource", "invalid value")

	assert.Equal(t, "tokenSource", err.Field)
	assert.Equal(t, "invalid value", err.Message)
	assert.Nil(t, err.Cause)
}

func TestNewConfigErrorWithCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying error")
	err := NewConfigErrorWithCause("tokenSource", "invalid value", cause)

	assert.Equal(t, "tokenSource", err.Field)
	assert.Equal(t, "invalid value", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestWrapError(t *testing.T) {
	t.Parallel()

	t.Run("wraps error with message", func(t *testing.T) {
		t.Parallel()

		original := errors.New("original error")
		wrapped := WrapError(original, "additional context")

		assert.Contains(t, wrapped.Error(), "additional context")
		assert.Contains(t, wrapped.Error(), "original error")
		assert.True(t, errors.Is(wrapped, original))
	})

	t.Run("returns nil for nil error", func(t *testing.T) {
		t.Parallel()

		wrapped := WrapError(nil, "additional context")
		assert.Nil(t, wrapped)
	})
}

func TestIsRetryable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrVaultUnavailable is retryable",
			err:      ErrVaultUnavailable,
			expected: true,
		},
		{
			name:     "ErrOIDCFailed is retryable",
			err:      ErrOIDCFailed,
			expected: true,
		},
		{
			name:     "ErrTokenExpired is not retryable",
			err:      ErrTokenExpired,
			expected: false,
		},
		{
			name:     "ErrInvalidCredentials is not retryable",
			err:      ErrInvalidCredentials,
			expected: false,
		},
		{
			name:     "ErrInvalidConfig is not retryable",
			err:      ErrInvalidConfig,
			expected: false,
		},
		{
			name:     "ErrContextCanceled is not retryable",
			err:      ErrContextCanceled,
			expected: false,
		},
		{
			name:     "wrapped ErrVaultUnavailable is retryable",
			err:      WrapError(ErrVaultUnavailable, "context"),
			expected: true,
		},
		{
			name:     "generic error is not retryable",
			err:      errors.New("generic error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsRetryable(tt.err))
		})
	}
}

func TestProviderError_BuildMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         *ProviderError
		contains    []string
		notContains []string
	}{
		{
			name: "with provider and operation",
			err: &ProviderError{
				Provider:  "test-provider",
				Operation: "apply_http",
				Message:   "error message",
			},
			contains: []string{"test-provider", "apply_http", "error message"},
		},
		{
			name: "with only provider",
			err: &ProviderError{
				Provider: "test-provider",
				Message:  "error message",
			},
			contains: []string{"test-provider", "error message"},
		},
		{
			name: "with only operation",
			err: &ProviderError{
				Operation: "apply_http",
				Message:   "error message",
			},
			contains: []string{"apply_http", "error message"},
		},
		{
			name: "with only message",
			err: &ProviderError{
				Message: "error message",
			},
			contains: []string{"error message"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			errStr := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, errStr, s)
			}
		})
	}
}

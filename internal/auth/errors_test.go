package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *AuthError
		expected string
	}{
		{
			name: "without cause",
			err: &AuthError{
				Type:    "jwt",
				Message: "token expired",
			},
			expected: "auth error (jwt): token expired",
		},
		{
			name: "with cause",
			err: &AuthError{
				Type:    "apikey",
				Message: "key not found",
				Cause:   errors.New("database error"),
			},
			expected: "auth error (apikey): key not found: database error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.err.Error()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestAuthError_Unwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying error")
	err := &AuthError{
		Type:    "jwt",
		Message: "validation failed",
		Cause:   cause,
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
}

func TestAuthError_Is(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    *AuthError
		target error
		want   bool
	}{
		{
			name: "matches ErrAuthenticationFailed",
			err: &AuthError{
				Type:    "jwt",
				Message: "failed",
			},
			target: ErrAuthenticationFailed,
			want:   true,
		},
		{
			name: "matches another AuthError",
			err: &AuthError{
				Type:    "jwt",
				Message: "failed",
			},
			target: &AuthError{},
			want:   true,
		},
		{
			name: "matches cause",
			err: &AuthError{
				Type:    "jwt",
				Message: "failed",
				Cause:   ErrTokenExpired,
			},
			target: ErrTokenExpired,
			want:   true,
		},
		{
			name: "does not match unrelated error",
			err: &AuthError{
				Type:    "jwt",
				Message: "failed",
			},
			target: errors.New("unrelated"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.err.Is(tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewAuthError(t *testing.T) {
	t.Parallel()

	err := NewAuthError("jwt", "token invalid")

	assert.Equal(t, "jwt", err.Type)
	assert.Equal(t, "token invalid", err.Message)
	assert.Nil(t, err.Cause)
}

func TestNewAuthErrorWithCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying error")
	err := NewAuthErrorWithCause("apikey", "validation failed", cause)

	assert.Equal(t, "apikey", err.Type)
	assert.Equal(t, "validation failed", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestWrapAuthError(t *testing.T) {
	t.Parallel()

	t.Run("nil error", func(t *testing.T) {
		t.Parallel()

		result := WrapAuthError(nil, "jwt")
		assert.Nil(t, result)
	})

	t.Run("non-nil error", func(t *testing.T) {
		t.Parallel()

		cause := errors.New("original error")
		result := WrapAuthError(cause, "jwt")

		assert.NotNil(t, result)
		authErr, ok := result.(*AuthError)
		assert.True(t, ok)
		assert.Equal(t, "jwt", authErr.Type)
		assert.Equal(t, "original error", authErr.Message)
		assert.Equal(t, cause, authErr.Cause)
	})
}

func TestIsAuthError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "AuthError",
			err:  &AuthError{Type: "jwt", Message: "failed"},
			want: true,
		},
		{
			name: "wrapped AuthError",
			err:  WrapAuthError(errors.New("test"), "jwt"),
			want: true,
		},
		{
			name: "regular error",
			err:  errors.New("regular error"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := IsAuthError(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetAuthErrorType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "AuthError",
			err:  &AuthError{Type: "jwt", Message: "failed"},
			want: "jwt",
		},
		{
			name: "wrapped AuthError",
			err:  WrapAuthError(errors.New("test"), "apikey"),
			want: "apikey",
		},
		{
			name: "regular error",
			err:  errors.New("regular error"),
			want: "",
		},
		{
			name: "nil error",
			err:  nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := GetAuthErrorType(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	// Test that sentinel errors are properly defined
	sentinelErrors := []error{
		ErrNoCredentials,
		ErrInvalidCredentials,
		ErrAuthenticationFailed,
		ErrAuthenticationDisabled,
		ErrUnsupportedAuthType,
		ErrTokenExpired,
		ErrTokenNotYetValid,
		ErrInvalidToken,
		ErrInvalidSignature,
		ErrInvalidIssuer,
		ErrInvalidAudience,
		ErrMissingClaim,
		ErrInvalidClaim,
		ErrUnsupportedAlgorithm,
		ErrKeyNotFound,
		ErrInvalidAPIKey,
		ErrAPIKeyNotFound,
		ErrAPIKeyExpired,
		ErrAPIKeyRevoked,
		ErrCertificateRequired,
		ErrCertificateInvalid,
		ErrCertificateExpired,
		ErrCertificateRevoked,
		ErrCertificateUntrusted,
		ErrOIDCDiscoveryFailed,
		ErrOIDCProviderNotFound,
		ErrTokenRevoked,
	}

	for _, err := range sentinelErrors {
		assert.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

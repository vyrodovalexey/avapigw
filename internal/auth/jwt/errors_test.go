package jwt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *ValidationError
		expected string
	}{
		{
			name: "with cause",
			err: &ValidationError{
				Message: "token expired",
				Cause:   ErrTokenExpired,
			},
			expected: "jwt validation error: token expired: token has expired",
		},
		{
			name: "without cause",
			err: &ValidationError{
				Message: "token expired",
			},
			expected: "jwt validation error: token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestValidationError_Unwrap(t *testing.T) {
	t.Parallel()

	cause := ErrTokenExpired
	err := &ValidationError{
		Message: "token expired",
		Cause:   cause,
	}

	assert.Equal(t, cause, err.Unwrap())
}

func TestValidationError_Is(t *testing.T) {
	t.Parallel()

	err := &ValidationError{
		Message: "token expired",
		Cause:   ErrTokenExpired,
	}

	assert.True(t, errors.Is(err, ErrTokenExpired))
	assert.True(t, errors.Is(err, &ValidationError{}))
	assert.False(t, errors.Is(err, ErrTokenMalformed))
}

func TestNewValidationError(t *testing.T) {
	t.Parallel()

	err := NewValidationError("test message", ErrTokenExpired)

	assert.Equal(t, "test message", err.Message)
	assert.Equal(t, ErrTokenExpired, err.Cause)
	assert.Nil(t, err.Claims)
}

func TestNewValidationErrorWithClaims(t *testing.T) {
	t.Parallel()

	claims := &Claims{Subject: "user123"}
	err := NewValidationErrorWithClaims("test message", ErrTokenExpired, claims)

	assert.Equal(t, "test message", err.Message)
	assert.Equal(t, ErrTokenExpired, err.Cause)
	assert.Equal(t, claims, err.Claims)
}

func TestSigningError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *SigningError
		expected string
	}{
		{
			name: "with cause",
			err: &SigningError{
				Message: "signing failed",
				Cause:   ErrInvalidKey,
			},
			expected: "jwt signing error: signing failed: signing key is invalid",
		},
		{
			name: "without cause",
			err: &SigningError{
				Message: "signing failed",
			},
			expected: "jwt signing error: signing failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestSigningError_Unwrap(t *testing.T) {
	t.Parallel()

	cause := ErrInvalidKey
	err := &SigningError{
		Message: "signing failed",
		Cause:   cause,
	}

	assert.Equal(t, cause, err.Unwrap())
}

func TestNewSigningError(t *testing.T) {
	t.Parallel()

	err := NewSigningError("test message", ErrInvalidKey)

	assert.Equal(t, "test message", err.Message)
	assert.Equal(t, ErrInvalidKey, err.Cause)
}

func TestKeyError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *KeyError
		expected string
	}{
		{
			name: "with keyID and cause",
			err: &KeyError{
				KeyID:   "key123",
				Message: "key not found",
				Cause:   ErrKeyNotFound,
			},
			expected: "jwt key error (kid=key123): key not found: signing key not found",
		},
		{
			name: "with keyID without cause",
			err: &KeyError{
				KeyID:   "key123",
				Message: "key not found",
			},
			expected: "jwt key error (kid=key123): key not found",
		},
		{
			name: "without keyID with cause",
			err: &KeyError{
				Message: "key not found",
				Cause:   ErrKeyNotFound,
			},
			expected: "jwt key error: key not found: signing key not found",
		},
		{
			name: "without keyID without cause",
			err: &KeyError{
				Message: "key not found",
			},
			expected: "jwt key error: key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestKeyError_Unwrap(t *testing.T) {
	t.Parallel()

	cause := ErrKeyNotFound
	err := &KeyError{
		KeyID:   "key123",
		Message: "key not found",
		Cause:   cause,
	}

	assert.Equal(t, cause, err.Unwrap())
}

func TestKeyError_Is(t *testing.T) {
	t.Parallel()

	err := &KeyError{
		KeyID:   "key123",
		Message: "key not found",
		Cause:   ErrKeyNotFound,
	}

	assert.True(t, errors.Is(err, ErrKeyNotFound))
	assert.True(t, errors.Is(err, &KeyError{}))
	assert.False(t, errors.Is(err, ErrTokenExpired))

	// Test with ErrInvalidKey
	err2 := &KeyError{
		KeyID:   "key123",
		Message: "invalid key",
		Cause:   ErrInvalidKey,
	}
	assert.True(t, errors.Is(err2, ErrInvalidKey))
}

func TestNewKeyError(t *testing.T) {
	t.Parallel()

	err := NewKeyError("key123", "test message", ErrKeyNotFound)

	assert.Equal(t, "key123", err.KeyID)
	assert.Equal(t, "test message", err.Message)
	assert.Equal(t, ErrKeyNotFound, err.Cause)
}

func TestIsExpiredError(t *testing.T) {
	t.Parallel()

	assert.True(t, IsExpiredError(ErrTokenExpired))
	assert.True(t, IsExpiredError(NewValidationError("expired", ErrTokenExpired)))
	assert.False(t, IsExpiredError(ErrTokenMalformed))
	assert.False(t, IsExpiredError(nil))
}

func TestIsSignatureError(t *testing.T) {
	t.Parallel()

	assert.True(t, IsSignatureError(ErrTokenInvalidSignature))
	assert.True(t, IsSignatureError(NewValidationError("invalid sig", ErrTokenInvalidSignature)))
	assert.False(t, IsSignatureError(ErrTokenExpired))
	assert.False(t, IsSignatureError(nil))
}

func TestIsValidationError(t *testing.T) {
	t.Parallel()

	validationErr := NewValidationError("test", ErrTokenExpired)
	assert.True(t, IsValidationError(validationErr))

	regularErr := errors.New("regular error")
	assert.False(t, IsValidationError(regularErr))

	assert.False(t, IsValidationError(nil))
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	// Verify all sentinel errors are defined and have expected messages
	sentinelErrors := map[error]string{
		ErrTokenMalformed:        "token is malformed",
		ErrTokenExpired:          "token has expired",
		ErrTokenNotYetValid:      "token is not yet valid",
		ErrTokenInvalidSignature: "token signature is invalid",
		ErrTokenInvalidIssuer:    "token issuer is invalid",
		ErrTokenInvalidAudience:  "token audience is invalid",
		ErrTokenMissingClaim:     "required claim is missing",
		ErrTokenInvalidClaim:     "claim value is invalid",
		ErrUnsupportedAlgorithm:  "signing algorithm is not supported",
		ErrKeyNotFound:           "signing key not found",
		ErrInvalidKey:            "signing key is invalid",
		ErrJWKSFetchFailed:       "failed to fetch JWKS",
		ErrTokenRevoked:          "token has been revoked",
		ErrEmptyToken:            "token is empty",
	}

	for err, expectedMsg := range sentinelErrors {
		t.Run(expectedMsg, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, expectedMsg, err.Error())
		})
	}
}

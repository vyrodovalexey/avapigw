package vault

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *VaultError
		expected string
	}{
		{
			name: "with path",
			err: &VaultError{
				Op:   "read",
				Path: "secret/data/test",
				Err:  errors.New("not found"),
			},
			expected: "vault read on path secret/data/test: not found",
		},
		{
			name: "without path",
			err: &VaultError{
				Op:  "authenticate",
				Err: errors.New("invalid token"),
			},
			expected: "vault authenticate: invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestVaultError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &VaultError{
		Op:  "read",
		Err: underlying,
	}

	assert.Equal(t, underlying, err.Unwrap())
}

func TestVaultError_Is(t *testing.T) {
	err := &VaultError{
		Op:  "read",
		Err: ErrSecretNotFound,
	}

	assert.True(t, errors.Is(err, ErrSecretNotFound))
	assert.False(t, errors.Is(err, ErrAuthenticationFailed))
}

func TestNewVaultError(t *testing.T) {
	err := NewVaultError("read", "secret/path", ErrSecretNotFound)

	assert.Equal(t, "read", err.Op)
	assert.Equal(t, "secret/path", err.Path)
	assert.Equal(t, ErrSecretNotFound, err.Err)
}

func TestNewVaultErrorWithCode(t *testing.T) {
	err := NewVaultErrorWithCode("read", "secret/path", ErrSecretNotFound, 404)

	assert.Equal(t, "read", err.Op)
	assert.Equal(t, "secret/path", err.Path)
	assert.Equal(t, ErrSecretNotFound, err.Err)
	assert.Equal(t, 404, err.Code)
}

func TestIsRetryable(t *testing.T) {
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
			name:     "connection failed",
			err:      ErrConnectionFailed,
			expected: true,
		},
		{
			name: "server error 500",
			err: &VaultError{
				Op:   "read",
				Err:  errors.New("internal server error"),
				Code: 500,
			},
			expected: true,
		},
		{
			name: "server error 503",
			err: &VaultError{
				Op:   "read",
				Err:  errors.New("service unavailable"),
				Code: 503,
			},
			expected: true,
		},
		{
			name: "rate limited 429",
			err: &VaultError{
				Op:   "read",
				Err:  errors.New("rate limited"),
				Code: 429,
			},
			expected: true,
		},
		{
			name: "client error 400",
			err: &VaultError{
				Op:   "read",
				Err:  errors.New("bad request"),
				Code: 400,
			},
			expected: false,
		},
		{
			name: "not found 404",
			err: &VaultError{
				Op:   "read",
				Err:  ErrSecretNotFound,
				Code: 404,
			},
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("some error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAuthError(t *testing.T) {
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
			name:     "not authenticated",
			err:      ErrNotAuthenticated,
			expected: true,
		},
		{
			name:     "authentication failed",
			err:      ErrAuthenticationFailed,
			expected: true,
		},
		{
			name:     "token expired",
			err:      ErrTokenExpired,
			expected: true,
		},
		{
			name: "unauthorized 401",
			err: &VaultError{
				Op:   "read",
				Err:  errors.New("unauthorized"),
				Code: 401,
			},
			expected: true,
		},
		{
			name: "forbidden 403",
			err: &VaultError{
				Op:   "read",
				Err:  errors.New("forbidden"),
				Code: 403,
			},
			expected: true,
		},
		{
			name: "not found 404",
			err: &VaultError{
				Op:   "read",
				Err:  ErrSecretNotFound,
				Code: 404,
			},
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("some error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAuthError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorConstants(t *testing.T) {
	// Verify all error constants are defined
	assert.NotNil(t, ErrNotAuthenticated)
	assert.NotNil(t, ErrAuthenticationFailed)
	assert.NotNil(t, ErrSecretNotFound)
	assert.NotNil(t, ErrInvalidPath)
	assert.NotNil(t, ErrInvalidConfig)
	assert.NotNil(t, ErrConnectionFailed)
	assert.NotNil(t, ErrTokenExpired)
	assert.NotNil(t, ErrPermissionDenied)
	assert.NotNil(t, ErrCacheMiss)
	assert.NotNil(t, ErrWatcherStopped)
	assert.NotNil(t, ErrCertificateInvalid)
	assert.NotNil(t, ErrRetryExhausted)
}

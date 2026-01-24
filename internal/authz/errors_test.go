package authz

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthzError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *AuthzError
		expected string
	}{
		{
			name: "with reason",
			err: &AuthzError{
				Reason: "insufficient permissions",
			},
			expected: "authorization failed: insufficient permissions",
		},
		{
			name: "with underlying error",
			err: &AuthzError{
				Err: ErrAccessDenied,
			},
			expected: "authorization failed: access denied",
		},
		{
			name:     "empty error",
			err:      &AuthzError{},
			expected: "authorization failed",
		},
		{
			name: "reason takes precedence over error",
			err: &AuthzError{
				Err:    ErrAccessDenied,
				Reason: "custom reason",
			},
			expected: "authorization failed: custom reason",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestAuthzError_Unwrap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         *AuthzError
		expectedErr error
	}{
		{
			name: "with underlying error",
			err: &AuthzError{
				Err: ErrAccessDenied,
			},
			expectedErr: ErrAccessDenied,
		},
		{
			name:        "without underlying error",
			err:         &AuthzError{},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expectedErr, tt.err.Unwrap())
		})
	}
}

func TestNewAccessDeniedError(t *testing.T) {
	t.Parallel()

	err := NewAccessDeniedError("user123", "/api/users", "GET", "no permission")

	require.NotNil(t, err)
	assert.Equal(t, "user123", err.Subject)
	assert.Equal(t, "/api/users", err.Resource)
	assert.Equal(t, "GET", err.Action)
	assert.Equal(t, "no permission", err.Reason)
	assert.ErrorIs(t, err, ErrAccessDenied)
}

func TestNewPolicyDeniedError(t *testing.T) {
	t.Parallel()

	err := NewPolicyDeniedError("user123", "/api/users", "DELETE", "admin-only-policy")

	require.NotNil(t, err)
	assert.Equal(t, "user123", err.Subject)
	assert.Equal(t, "/api/users", err.Resource)
	assert.Equal(t, "DELETE", err.Action)
	assert.Equal(t, "admin-only-policy", err.Policy)
	assert.Contains(t, err.Reason, "denied by policy: admin-only-policy")
	assert.ErrorIs(t, err, ErrAccessDenied)
}

func TestIsAccessDenied(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrAccessDenied",
			err:      ErrAccessDenied,
			expected: true,
		},
		{
			name:     "wrapped ErrAccessDenied",
			err:      &AuthzError{Err: ErrAccessDenied},
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("other error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrNoIdentity",
			err:      ErrNoIdentity,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsAccessDenied(tt.err))
		})
	}
}

func TestIsNoIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrNoIdentity",
			err:      ErrNoIdentity,
			expected: true,
		},
		{
			name:     "wrapped ErrNoIdentity",
			err:      &AuthzError{Err: ErrNoIdentity},
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("other error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrAccessDenied",
			err:      ErrAccessDenied,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsNoIdentity(tt.err))
		})
	}
}

func TestIsExternalAuthzError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrExternalAuthzFailed",
			err:      ErrExternalAuthzFailed,
			expected: true,
		},
		{
			name:     "ErrExternalAuthzTimeout",
			err:      ErrExternalAuthzTimeout,
			expected: true,
		},
		{
			name:     "ErrExternalAuthzUnavailable",
			err:      ErrExternalAuthzUnavailable,
			expected: true,
		},
		{
			name:     "wrapped ErrExternalAuthzFailed",
			err:      &AuthzError{Err: ErrExternalAuthzFailed},
			expected: true,
		},
		{
			name:     "wrapped ErrExternalAuthzTimeout",
			err:      &AuthzError{Err: ErrExternalAuthzTimeout},
			expected: true,
		},
		{
			name:     "wrapped ErrExternalAuthzUnavailable",
			err:      &AuthzError{Err: ErrExternalAuthzUnavailable},
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("other error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrAccessDenied",
			err:      ErrAccessDenied,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, IsExternalAuthzError(tt.err))
		})
	}
}

func TestAuthzError_Fields(t *testing.T) {
	t.Parallel()

	err := &AuthzError{
		Err:      ErrAccessDenied,
		Resource: "/api/users/123",
		Action:   "DELETE",
		Subject:  "user@example.com",
		Reason:   "admin role required",
		Policy:   "admin-only",
	}

	assert.Equal(t, ErrAccessDenied, err.Err)
	assert.Equal(t, "/api/users/123", err.Resource)
	assert.Equal(t, "DELETE", err.Action)
	assert.Equal(t, "user@example.com", err.Subject)
	assert.Equal(t, "admin role required", err.Reason)
	assert.Equal(t, "admin-only", err.Policy)
}

func TestErrorsIs(t *testing.T) {
	t.Parallel()

	// Test that errors.Is works correctly with AuthzError
	authzErr := &AuthzError{Err: ErrAccessDenied}

	assert.True(t, errors.Is(authzErr, ErrAccessDenied))
	assert.False(t, errors.Is(authzErr, ErrNoIdentity))
}

func TestCommonErrors(t *testing.T) {
	t.Parallel()

	// Verify all common errors are defined
	assert.NotNil(t, ErrAccessDenied)
	assert.NotNil(t, ErrNoIdentity)
	assert.NotNil(t, ErrInvalidPolicy)
	assert.NotNil(t, ErrPolicyNotFound)
	assert.NotNil(t, ErrExternalAuthzFailed)
	assert.NotNil(t, ErrExternalAuthzTimeout)
	assert.NotNil(t, ErrExternalAuthzUnavailable)
	assert.NotNil(t, ErrCacheError)

	// Verify error messages
	assert.Equal(t, "access denied", ErrAccessDenied.Error())
	assert.Equal(t, "no identity in context", ErrNoIdentity.Error())
	assert.Equal(t, "invalid policy", ErrInvalidPolicy.Error())
	assert.Equal(t, "policy not found", ErrPolicyNotFound.Error())
	assert.Equal(t, "external authorization failed", ErrExternalAuthzFailed.Error())
	assert.Equal(t, "external authorization timeout", ErrExternalAuthzTimeout.Error())
	assert.Equal(t, "external authorization unavailable", ErrExternalAuthzUnavailable.Error())
	assert.Equal(t, "authorization cache error", ErrCacheError.Error())
}

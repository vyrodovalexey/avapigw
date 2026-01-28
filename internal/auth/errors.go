package auth

import (
	"errors"
	"fmt"
)

// Sentinel errors for authentication operations.
var (
	// ErrNoCredentials indicates that no credentials were provided.
	ErrNoCredentials = errors.New("no credentials provided")

	// ErrInvalidCredentials indicates that the provided credentials are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrAuthenticationFailed indicates that authentication failed.
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrAuthenticationDisabled indicates that authentication is disabled.
	ErrAuthenticationDisabled = errors.New("authentication disabled")

	// ErrUnsupportedAuthType indicates an unsupported authentication type.
	ErrUnsupportedAuthType = errors.New("unsupported authentication type")

	// ErrTokenExpired indicates that the token has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenNotYetValid indicates that the token is not yet valid.
	ErrTokenNotYetValid = errors.New("token not yet valid")

	// ErrInvalidToken indicates that the token is invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrInvalidSignature indicates that the token signature is invalid.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidIssuer indicates that the token issuer is invalid.
	ErrInvalidIssuer = errors.New("invalid issuer")

	// ErrInvalidAudience indicates that the token audience is invalid.
	ErrInvalidAudience = errors.New("invalid audience")

	// ErrMissingClaim indicates that a required claim is missing.
	ErrMissingClaim = errors.New("missing required claim")

	// ErrInvalidClaim indicates that a claim value is invalid.
	ErrInvalidClaim = errors.New("invalid claim value")

	// ErrUnsupportedAlgorithm indicates an unsupported signing algorithm.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

	// ErrKeyNotFound indicates that the signing key was not found.
	ErrKeyNotFound = errors.New("signing key not found")

	// ErrInvalidAPIKey indicates that the API key is invalid.
	ErrInvalidAPIKey = errors.New("invalid API key")

	// ErrAPIKeyNotFound indicates that the API key was not found.
	ErrAPIKeyNotFound = errors.New("API key not found")

	// ErrAPIKeyExpired indicates that the API key has expired.
	ErrAPIKeyExpired = errors.New("API key expired")

	// ErrAPIKeyRevoked indicates that the API key has been revoked.
	ErrAPIKeyRevoked = errors.New("API key revoked")

	// ErrCertificateRequired indicates that a client certificate is required.
	ErrCertificateRequired = errors.New("client certificate required")

	// ErrCertificateInvalid indicates that the client certificate is invalid.
	ErrCertificateInvalid = errors.New("client certificate invalid")

	// ErrCertificateExpired indicates that the client certificate has expired.
	ErrCertificateExpired = errors.New("client certificate expired")

	// ErrCertificateRevoked indicates that the client certificate has been revoked.
	ErrCertificateRevoked = errors.New("client certificate revoked")

	// ErrCertificateUntrusted indicates that the client certificate is not trusted.
	ErrCertificateUntrusted = errors.New("client certificate untrusted")

	// ErrOIDCDiscoveryFailed indicates that OIDC discovery failed.
	ErrOIDCDiscoveryFailed = errors.New("OIDC discovery failed")

	// ErrOIDCProviderNotFound indicates that the OIDC provider was not found.
	ErrOIDCProviderNotFound = errors.New("OIDC provider not found")

	// ErrTokenRevoked indicates that the token has been revoked.
	ErrTokenRevoked = errors.New("token revoked")
)

// AuthError represents an authentication error with additional context.
type AuthError struct {
	Type    string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *AuthError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("auth error (%s): %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("auth error (%s): %s", e.Type, e.Message)
}

// Unwrap returns the underlying error.
func (e *AuthError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *AuthError) Is(target error) bool {
	if errors.Is(target, ErrAuthenticationFailed) {
		return true
	}
	_, ok := target.(*AuthError)
	return ok || errors.Is(e.Cause, target)
}

// NewAuthError creates a new AuthError.
func NewAuthError(authType, message string) *AuthError {
	return &AuthError{
		Type:    authType,
		Message: message,
	}
}

// NewAuthErrorWithCause creates a new AuthError with a cause.
func NewAuthErrorWithCause(authType, message string, cause error) *AuthError {
	return &AuthError{
		Type:    authType,
		Message: message,
		Cause:   cause,
	}
}

// WrapAuthError wraps an error with authentication context.
func WrapAuthError(err error, authType string) error {
	if err == nil {
		return nil
	}
	return &AuthError{
		Type:    authType,
		Message: err.Error(),
		Cause:   err,
	}
}

// IsAuthError checks if an error is an authentication error.
func IsAuthError(err error) bool {
	var authErr *AuthError
	return errors.As(err, &authErr)
}

// GetAuthErrorType returns the authentication type from an error.
func GetAuthErrorType(err error) string {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Type
	}
	return ""
}

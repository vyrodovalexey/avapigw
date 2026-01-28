package jwt

import (
	"errors"
	"fmt"
)

// JWT signing algorithm constants.
const (
	AlgRS256   = "RS256"
	AlgRS384   = "RS384"
	AlgRS512   = "RS512"
	AlgPS256   = "PS256"
	AlgPS384   = "PS384"
	AlgPS512   = "PS512"
	AlgES256   = "ES256"
	AlgES384   = "ES384"
	AlgES512   = "ES512"
	AlgHS256   = "HS256"
	AlgHS384   = "HS384"
	AlgHS512   = "HS512"
	AlgEdDSA   = "EdDSA"
	AlgEd25519 = "Ed25519"
)

// Sentinel errors for JWT operations.
var (
	// ErrTokenMalformed indicates that the token is malformed.
	ErrTokenMalformed = errors.New("token is malformed")

	// ErrTokenExpired indicates that the token has expired.
	ErrTokenExpired = errors.New("token has expired")

	// ErrTokenNotYetValid indicates that the token is not yet valid.
	ErrTokenNotYetValid = errors.New("token is not yet valid")

	// ErrTokenInvalidSignature indicates that the token signature is invalid.
	ErrTokenInvalidSignature = errors.New("token signature is invalid")

	// ErrTokenInvalidIssuer indicates that the token issuer is invalid.
	ErrTokenInvalidIssuer = errors.New("token issuer is invalid")

	// ErrTokenInvalidAudience indicates that the token audience is invalid.
	ErrTokenInvalidAudience = errors.New("token audience is invalid")

	// ErrTokenMissingClaim indicates that a required claim is missing.
	ErrTokenMissingClaim = errors.New("required claim is missing")

	// ErrTokenInvalidClaim indicates that a claim value is invalid.
	ErrTokenInvalidClaim = errors.New("claim value is invalid")

	// ErrUnsupportedAlgorithm indicates that the signing algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("signing algorithm is not supported")

	// ErrKeyNotFound indicates that the signing key was not found.
	ErrKeyNotFound = errors.New("signing key not found")

	// ErrInvalidKey indicates that the signing key is invalid.
	ErrInvalidKey = errors.New("signing key is invalid")

	// ErrJWKSFetchFailed indicates that fetching JWKS failed.
	ErrJWKSFetchFailed = errors.New("failed to fetch JWKS")

	// ErrTokenRevoked indicates that the token has been revoked.
	ErrTokenRevoked = errors.New("token has been revoked")

	// ErrEmptyToken indicates that the token is empty.
	ErrEmptyToken = errors.New("token is empty")
)

// ValidationError represents a JWT validation error with details.
type ValidationError struct {
	Message string
	Cause   error
	Claims  *Claims
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("jwt validation error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("jwt validation error: %s", e.Message)
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
func NewValidationError(message string, cause error) *ValidationError {
	return &ValidationError{
		Message: message,
		Cause:   cause,
	}
}

// NewValidationErrorWithClaims creates a new ValidationError with claims.
func NewValidationErrorWithClaims(message string, cause error, claims *Claims) *ValidationError {
	return &ValidationError{
		Message: message,
		Cause:   cause,
		Claims:  claims,
	}
}

// SigningError represents a JWT signing error.
type SigningError struct {
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *SigningError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("jwt signing error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("jwt signing error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *SigningError) Unwrap() error {
	return e.Cause
}

// NewSigningError creates a new SigningError.
func NewSigningError(message string, cause error) *SigningError {
	return &SigningError{
		Message: message,
		Cause:   cause,
	}
}

// KeyError represents a key-related error.
type KeyError struct {
	KeyID   string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *KeyError) Error() string {
	if e.KeyID != "" {
		if e.Cause != nil {
			return fmt.Sprintf("jwt key error (kid=%s): %s: %v", e.KeyID, e.Message, e.Cause)
		}
		return fmt.Sprintf("jwt key error (kid=%s): %s", e.KeyID, e.Message)
	}
	if e.Cause != nil {
		return fmt.Sprintf("jwt key error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("jwt key error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *KeyError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *KeyError) Is(target error) bool {
	if errors.Is(target, ErrKeyNotFound) || errors.Is(target, ErrInvalidKey) {
		return true
	}
	_, ok := target.(*KeyError)
	return ok || errors.Is(e.Cause, target)
}

// NewKeyError creates a new KeyError.
func NewKeyError(keyID, message string, cause error) *KeyError {
	return &KeyError{
		KeyID:   keyID,
		Message: message,
		Cause:   cause,
	}
}

// IsExpiredError checks if an error indicates token expiration.
func IsExpiredError(err error) bool {
	return errors.Is(err, ErrTokenExpired)
}

// IsSignatureError checks if an error indicates a signature problem.
func IsSignatureError(err error) bool {
	return errors.Is(err, ErrTokenInvalidSignature)
}

// IsValidationError checks if an error is a validation error.
func IsValidationError(err error) bool {
	var validationErr *ValidationError
	return errors.As(err, &validationErr)
}

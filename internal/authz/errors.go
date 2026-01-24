package authz

import (
	"errors"
	"fmt"
)

// Common authorization errors.
var (
	// ErrAccessDenied indicates that access was denied.
	ErrAccessDenied = errors.New("access denied")

	// ErrNoIdentity indicates that no identity was found in the context.
	ErrNoIdentity = errors.New("no identity in context")

	// ErrInvalidPolicy indicates that a policy is invalid.
	ErrInvalidPolicy = errors.New("invalid policy")

	// ErrPolicyNotFound indicates that a policy was not found.
	ErrPolicyNotFound = errors.New("policy not found")

	// ErrExternalAuthzFailed indicates that external authorization failed.
	ErrExternalAuthzFailed = errors.New("external authorization failed")

	// ErrExternalAuthzTimeout indicates that external authorization timed out.
	ErrExternalAuthzTimeout = errors.New("external authorization timeout")

	// ErrExternalAuthzUnavailable indicates that external authorization is unavailable.
	ErrExternalAuthzUnavailable = errors.New("external authorization unavailable")

	// ErrCacheError indicates a cache error.
	ErrCacheError = errors.New("authorization cache error")
)

// AuthzError represents an authorization error with additional context.
type AuthzError struct {
	// Err is the underlying error.
	Err error

	// Resource is the resource that was being accessed.
	Resource string

	// Action is the action that was being performed.
	Action string

	// Subject is the subject that was denied.
	Subject string

	// Reason is the reason for the denial.
	Reason string

	// Policy is the policy that denied access.
	Policy string
}

// Error returns the error message.
func (e *AuthzError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("authorization failed: %s", e.Reason)
	}
	if e.Err != nil {
		return fmt.Sprintf("authorization failed: %v", e.Err)
	}
	return "authorization failed"
}

// Unwrap returns the underlying error.
func (e *AuthzError) Unwrap() error {
	return e.Err
}

// NewAccessDeniedError creates a new access denied error.
func NewAccessDeniedError(subject, resource, action, reason string) *AuthzError {
	return &AuthzError{
		Err:      ErrAccessDenied,
		Subject:  subject,
		Resource: resource,
		Action:   action,
		Reason:   reason,
	}
}

// NewPolicyDeniedError creates a new policy denied error.
func NewPolicyDeniedError(subject, resource, action, policy string) *AuthzError {
	return &AuthzError{
		Err:      ErrAccessDenied,
		Subject:  subject,
		Resource: resource,
		Action:   action,
		Policy:   policy,
		Reason:   fmt.Sprintf("denied by policy: %s", policy),
	}
}

// IsAccessDenied checks if an error is an access denied error.
func IsAccessDenied(err error) bool {
	return errors.Is(err, ErrAccessDenied)
}

// IsNoIdentity checks if an error is a no identity error.
func IsNoIdentity(err error) bool {
	return errors.Is(err, ErrNoIdentity)
}

// IsExternalAuthzError checks if an error is an external authorization error.
func IsExternalAuthzError(err error) bool {
	return errors.Is(err, ErrExternalAuthzFailed) ||
		errors.Is(err, ErrExternalAuthzTimeout) ||
		errors.Is(err, ErrExternalAuthzUnavailable)
}

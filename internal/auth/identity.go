package auth

import (
	"context"
	"errors"
	"time"
)

// Identity represents an authenticated identity.
type Identity struct {
	// Subject is the unique identifier for the identity (e.g., user ID).
	Subject string `json:"sub"`

	// Issuer is the issuer of the identity (e.g., OIDC provider).
	Issuer string `json:"iss,omitempty"`

	// Audience is the intended audience for the identity.
	Audience []string `json:"aud,omitempty"`

	// AuthType is the authentication method used.
	AuthType AuthType `json:"auth_type"`

	// AuthTime is when the authentication occurred.
	AuthTime time.Time `json:"auth_time,omitempty"`

	// ExpiresAt is when the identity expires.
	ExpiresAt time.Time `json:"exp,omitempty"`

	// Claims contains additional claims from the authentication.
	Claims map[string]interface{} `json:"claims,omitempty"`

	// Roles contains the roles assigned to the identity.
	Roles []string `json:"roles,omitempty"`

	// Permissions contains the permissions assigned to the identity.
	Permissions []string `json:"permissions,omitempty"`

	// Scopes contains the OAuth scopes granted to the identity.
	Scopes []string `json:"scopes,omitempty"`

	// Groups contains the groups the identity belongs to.
	Groups []string `json:"groups,omitempty"`

	// Email is the email address of the identity.
	Email string `json:"email,omitempty"`

	// EmailVerified indicates if the email has been verified.
	EmailVerified bool `json:"email_verified,omitempty"`

	// Name is the display name of the identity.
	Name string `json:"name,omitempty"`

	// ClientID is the client ID for service accounts or API keys.
	ClientID string `json:"client_id,omitempty"`

	// TenantID is the tenant ID for multi-tenant systems.
	TenantID string `json:"tenant_id,omitempty"`

	// Metadata contains additional metadata about the identity.
	Metadata map[string]string `json:"metadata,omitempty"`

	// CertificateInfo contains certificate information for mTLS.
	CertificateInfo *CertificateInfo `json:"certificate_info,omitempty"`
}

// CertificateInfo contains information extracted from a client certificate.
type CertificateInfo struct {
	// SubjectDN is the subject distinguished name.
	SubjectDN string `json:"subject_dn,omitempty"`

	// IssuerDN is the issuer distinguished name.
	IssuerDN string `json:"issuer_dn,omitempty"`

	// SerialNumber is the certificate serial number.
	SerialNumber string `json:"serial_number,omitempty"`

	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time `json:"not_before,omitempty"`

	// NotAfter is when the certificate expires.
	NotAfter time.Time `json:"not_after,omitempty"`

	// DNSNames contains the DNS SANs.
	DNSNames []string `json:"dns_names,omitempty"`

	// URIs contains the URI SANs.
	URIs []string `json:"uris,omitempty"`

	// EmailAddresses contains the email SANs.
	EmailAddresses []string `json:"email_addresses,omitempty"`

	// SPIFFEID is the SPIFFE ID extracted from URI SANs.
	SPIFFEID string `json:"spiffe_id,omitempty"`

	// Fingerprint is the certificate fingerprint.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// AuthType represents the type of authentication used.
type AuthType string

// Authentication types.
const (
	AuthTypeJWT       AuthType = "jwt"
	AuthTypeAPIKey    AuthType = "apikey"
	AuthTypeMTLS      AuthType = "mtls"
	AuthTypeOIDC      AuthType = "oidc"
	AuthTypeBasic     AuthType = "basic"
	AuthTypeAnonymous AuthType = "anonymous"
)

// IsExpired returns true if the identity has expired.
func (i *Identity) IsExpired() bool {
	if i.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(i.ExpiresAt)
}

// HasRole checks if the identity has a specific role.
func (i *Identity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the identity has any of the specified roles.
func (i *Identity) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if i.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the identity has all of the specified roles.
func (i *Identity) HasAllRoles(roles ...string) bool {
	for _, role := range roles {
		if !i.HasRole(role) {
			return false
		}
	}
	return true
}

// HasPermission checks if the identity has a specific permission.
func (i *Identity) HasPermission(permission string) bool {
	for _, p := range i.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasScope checks if the identity has a specific scope.
func (i *Identity) HasScope(scope string) bool {
	for _, s := range i.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasGroup checks if the identity belongs to a specific group.
func (i *Identity) HasGroup(group string) bool {
	for _, g := range i.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// GetClaim returns a claim value by name.
func (i *Identity) GetClaim(name string) (interface{}, bool) {
	if i.Claims == nil {
		return nil, false
	}
	v, ok := i.Claims[name]
	return v, ok
}

// GetClaimString returns a claim value as a string.
func (i *Identity) GetClaimString(name string) string {
	v, ok := i.GetClaim(name)
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// GetClaimStringSlice returns a claim value as a string slice.
func (i *Identity) GetClaimStringSlice(name string) []string {
	v, ok := i.GetClaim(name)
	if !ok {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// Context key type for identity.
type identityContextKey struct{}

// ContextWithIdentity adds an identity to the context.
func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

// IdentityFromContext extracts the identity from the context.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(*Identity)
	return identity, ok
}

// ErrIdentityNotFound is returned when identity is not found in context.
var ErrIdentityNotFound = errors.New("identity not found in context")

// ErrIdentityNil is returned when identity in context is nil.
var ErrIdentityNil = errors.New("identity in context is nil")

// IdentityFromContextOrError extracts the identity from the context or returns an error.
// This is the preferred method for extracting identity as it allows proper error handling
// without panicking.
//
// Returns ErrIdentityNotFound if the context does not contain an identity.
// Returns ErrIdentityNil if the identity value in the context is nil.
func IdentityFromContextOrError(ctx context.Context) (*Identity, error) {
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return nil, ErrIdentityNotFound
	}
	if identity == nil {
		return nil, ErrIdentityNil
	}
	return identity, nil
}

// MustIdentityFromContext extracts the identity from the context or panics.
//
// Deprecated: Use IdentityFromContextOrError instead for proper error handling.
// This function is retained for backward compatibility but should not be used
// in new code. It will be removed in a future version.
//
// This function is intended for use in code paths where an identity is guaranteed
// to exist (e.g., after authentication middleware). If the identity might not exist,
// use IdentityFromContext or IdentityFromContextOrError instead.
//
// Panics if:
//   - The context does not contain an identity
//   - The identity value in the context is nil
func MustIdentityFromContext(ctx context.Context) *Identity {
	identity, err := IdentityFromContextOrError(ctx)
	if err != nil {
		panic(err.Error())
	}
	return identity
}

// AnonymousIdentity returns an anonymous identity.
func AnonymousIdentity() *Identity {
	return &Identity{
		Subject:  "anonymous",
		AuthType: AuthTypeAnonymous,
		AuthTime: time.Now(),
	}
}

// Package jwt provides JWT token validation and claims handling for the API Gateway.
package jwt

import (
	"encoding/json"
	"strings"
	"time"
)

// Claims represents the claims in a JWT token.
type Claims struct {
	// Standard JWT claims
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  Audience `json:"aud,omitempty"`
	ExpiresAt *Time    `json:"exp,omitempty"`
	NotBefore *Time    `json:"nbf,omitempty"`
	IssuedAt  *Time    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`

	// Standard OIDC claims
	Name          string   `json:"name,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Scope         string   `json:"scope,omitempty"`

	// Custom claims stored as a map
	Custom map[string]interface{} `json:"-"`

	// Raw claims for accessing any claim
	raw map[string]interface{}
}

// Time is a wrapper around time.Time for JSON unmarshaling.
type Time struct {
	time.Time
}

// UnmarshalJSON implements json.Unmarshaler for Time.
func (t *Time) UnmarshalJSON(data []byte) error {
	var timestamp float64
	if err := json.Unmarshal(data, &timestamp); err != nil {
		return err
	}
	t.Time = time.Unix(int64(timestamp), 0)
	return nil
}

// MarshalJSON implements json.Marshaler for Time.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Unix())
}

// Audience represents the audience claim which can be a string or array of strings.
type Audience []string

// UnmarshalJSON implements json.Unmarshaler for Audience.
func (a *Audience) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as a string first
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}

	// Try to unmarshal as an array
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return err
	}
	*a = multiple
	return nil
}

// MarshalJSON implements json.Marshaler for Audience.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Contains checks if the audience contains the given value.
func (a Audience) Contains(value string) bool {
	for _, v := range a {
		if v == value {
			return true
		}
	}
	return false
}

// ParseClaims parses claims from a map.
func ParseClaims(data map[string]interface{}) (*Claims, error) {
	// Marshal to JSON and unmarshal to Claims
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	claims := &Claims{
		Custom: make(map[string]interface{}),
		raw:    data,
	}

	if err := json.Unmarshal(jsonData, claims); err != nil {
		return nil, err
	}

	// Store custom claims (non-standard claims)
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true,
		"nbf": true, "iat": true, "jti": true, "name": true,
		"email": true, "email_verified": true, "groups": true,
		"roles": true, "scope": true,
	}

	for key, value := range data {
		if !standardClaims[key] {
			claims.Custom[key] = value
		}
	}

	return claims, nil
}

// GetClaim returns the value of a claim by name.
// It supports nested claims using dot notation (e.g., "resource_access.client.roles").
func (c *Claims) GetClaim(name string) (interface{}, bool) {
	if c.raw == nil {
		return nil, false
	}

	// Handle nested claims
	parts := strings.Split(name, ".")
	current := interface{}(c.raw)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}

	return current, true
}

// GetStringClaim returns a string claim value.
func (c *Claims) GetStringClaim(name string) (string, bool) {
	value, ok := c.GetClaim(name)
	if !ok {
		return "", false
	}
	str, ok := value.(string)
	return str, ok
}

// GetStringSliceClaim returns a string slice claim value.
func (c *Claims) GetStringSliceClaim(name string) ([]string, bool) {
	value, ok := c.GetClaim(name)
	if !ok {
		return nil, false
	}

	switch v := value.(type) {
	case []string:
		return v, true
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, true
	default:
		return nil, false
	}
}

// HasRole checks if the claims contain the specified role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the claims contain any of the specified roles.
func (c *Claims) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if c.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the claims contain all of the specified roles.
func (c *Claims) HasAllRoles(roles ...string) bool {
	for _, role := range roles {
		if !c.HasRole(role) {
			return false
		}
	}
	return true
}

// HasGroup checks if the claims contain the specified group.
func (c *Claims) HasGroup(group string) bool {
	for _, g := range c.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// HasAnyGroup checks if the claims contain any of the specified groups.
func (c *Claims) HasAnyGroup(groups ...string) bool {
	for _, group := range groups {
		if c.HasGroup(group) {
			return true
		}
	}
	return false
}

// HasAllGroups checks if the claims contain all of the specified groups.
func (c *Claims) HasAllGroups(groups ...string) bool {
	for _, group := range groups {
		if !c.HasGroup(group) {
			return false
		}
	}
	return true
}

// HasScope checks if the claims contain the specified scope.
func (c *Claims) HasScope(scope string) bool {
	scopes := strings.Fields(c.Scope)
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the claims contain any of the specified scopes.
func (c *Claims) HasAnyScope(scopes ...string) bool {
	for _, scope := range scopes {
		if c.HasScope(scope) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the claims contain all of the specified scopes.
func (c *Claims) HasAllScopes(scopes ...string) bool {
	for _, scope := range scopes {
		if !c.HasScope(scope) {
			return false
		}
	}
	return true
}

// GetScopes returns the scopes as a slice.
func (c *Claims) GetScopes() []string {
	if c.Scope == "" {
		return nil
	}
	return strings.Fields(c.Scope)
}

// IsExpired checks if the token is expired.
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(c.ExpiresAt.Time)
}

// IsExpiredWithSkew checks if the token is expired with clock skew tolerance.
func (c *Claims) IsExpiredWithSkew(skew time.Duration) bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().Add(-skew).After(c.ExpiresAt.Time)
}

// IsNotYetValid checks if the token is not yet valid.
func (c *Claims) IsNotYetValid() bool {
	if c.NotBefore == nil {
		return false
	}
	return time.Now().Before(c.NotBefore.Time)
}

// IsNotYetValidWithSkew checks if the token is not yet valid with clock skew tolerance.
func (c *Claims) IsNotYetValidWithSkew(skew time.Duration) bool {
	if c.NotBefore == nil {
		return false
	}
	return time.Now().Add(skew).Before(c.NotBefore.Time)
}

// Valid checks if the claims are valid (not expired and not before).
func (c *Claims) Valid() bool {
	return !c.IsExpired() && !c.IsNotYetValid()
}

// ValidWithSkew checks if the claims are valid with clock skew tolerance.
func (c *Claims) ValidWithSkew(skew time.Duration) bool {
	return !c.IsExpiredWithSkew(skew) && !c.IsNotYetValidWithSkew(skew)
}

// Raw returns the raw claims map.
func (c *Claims) Raw() map[string]interface{} {
	return c.raw
}

// ClaimsContextKey is the context key for storing claims.
type ClaimsContextKey struct{}

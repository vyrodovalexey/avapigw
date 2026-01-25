package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims represents JWT claims.
type Claims struct {
	// Standard claims
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  Audience `json:"aud,omitempty"`
	ExpiresAt *Time    `json:"exp,omitempty"`
	NotBefore *Time    `json:"nbf,omitempty"`
	IssuedAt  *Time    `json:"iat,omitempty"`
	JWTID     string   `json:"jti,omitempty"`

	// Additional claims
	Extra map[string]interface{} `json:"-"`
}

// Time is a wrapper around time.Time for JSON marshaling.
type Time struct {
	time.Time
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Time) UnmarshalJSON(data []byte) error {
	var timestamp float64
	if err := json.Unmarshal(data, &timestamp); err != nil {
		return err
	}
	t.Time = time.Unix(int64(timestamp), 0)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Unix())
}

// Audience represents the JWT audience claim which can be a string or array.
type Audience []string

// UnmarshalJSON implements json.Unmarshaler.
func (a *Audience) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}

	// Try to unmarshal as array
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return err
	}
	*a = Audience(multiple)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Contains checks if the audience contains a specific value.
func (a Audience) Contains(aud string) bool {
	for _, v := range a {
		if v == aud {
			return true
		}
	}
	return false
}

// ContainsAny checks if the audience contains any of the specified values.
func (a Audience) ContainsAny(auds ...string) bool {
	for _, aud := range auds {
		if a.Contains(aud) {
			return true
		}
	}
	return false
}

// Valid validates the claims.
func (c *Claims) Valid() error {
	now := time.Now()

	// Check expiration
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Time) {
		return fmt.Errorf("token expired at %v", c.ExpiresAt.Time)
	}

	// Check not before
	if c.NotBefore != nil && now.Before(c.NotBefore.Time) {
		return fmt.Errorf("token not valid before %v", c.NotBefore.Time)
	}

	return nil
}

// ValidWithSkew validates the claims with clock skew tolerance.
func (c *Claims) ValidWithSkew(skew time.Duration) error {
	now := time.Now()

	// Check expiration with skew
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Time.Add(skew)) {
		return fmt.Errorf("token expired at %v", c.ExpiresAt.Time)
	}

	// Check not before with skew
	if c.NotBefore != nil && now.Before(c.NotBefore.Time.Add(-skew)) {
		return fmt.Errorf("token not valid before %v", c.NotBefore.Time)
	}

	return nil
}

// GetClaim returns a claim value by name.
func (c *Claims) GetClaim(name string) (interface{}, bool) {
	// Check standard claims first
	switch name {
	case "iss":
		return c.Issuer, c.Issuer != ""
	case "sub":
		return c.Subject, c.Subject != ""
	case "aud":
		return []string(c.Audience), len(c.Audience) > 0
	case "exp":
		if c.ExpiresAt != nil {
			return c.ExpiresAt.Unix(), true
		}
		return nil, false
	case "nbf":
		if c.NotBefore != nil {
			return c.NotBefore.Unix(), true
		}
		return nil, false
	case "iat":
		if c.IssuedAt != nil {
			return c.IssuedAt.Unix(), true
		}
		return nil, false
	case "jti":
		return c.JWTID, c.JWTID != ""
	}

	// Check extra claims
	if c.Extra != nil {
		v, ok := c.Extra[name]
		return v, ok
	}

	return nil, false
}

// GetNestedClaim returns a nested claim value using dot notation.
func (c *Claims) GetNestedClaim(path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	if len(parts) == 1 {
		return c.GetClaim(path)
	}

	// Start with the first part
	current, ok := c.GetClaim(parts[0])
	if !ok {
		return nil, false
	}

	// Navigate through the path
	for _, part := range parts[1:] {
		switch v := current.(type) {
		case map[string]interface{}:
			current, ok = v[part]
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
	}

	return current, true
}

// GetStringClaim returns a claim value as a string.
func (c *Claims) GetStringClaim(name string) string {
	v, ok := c.GetClaim(name)
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// GetStringSliceClaim returns a claim value as a string slice.
func (c *Claims) GetStringSliceClaim(name string) []string {
	v, ok := c.GetClaim(name)
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
	case string:
		// Handle space-separated values (common for scopes)
		return strings.Fields(val)
	default:
		return nil
	}
}

// GetNestedStringSliceClaim returns a nested claim value as a string slice.
func (c *Claims) GetNestedStringSliceClaim(path string) []string {
	v, ok := c.GetNestedClaim(path)
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
	case string:
		return strings.Fields(val)
	default:
		return nil
	}
}

// ParseClaims parses claims from a map.
func ParseClaims(data map[string]interface{}) (*Claims, error) {
	claims := &Claims{
		Extra: make(map[string]interface{}),
	}

	for key, value := range data {
		if !parseStandardClaim(claims, key, value) {
			claims.Extra[key] = value
		}
	}

	return claims, nil
}

// parseStandardClaim parses a standard JWT claim and returns true if it was a standard claim.
func parseStandardClaim(claims *Claims, key string, value interface{}) bool {
	switch key {
	case "iss":
		if s, ok := value.(string); ok {
			claims.Issuer = s
		}
		return true
	case "sub":
		if s, ok := value.(string); ok {
			claims.Subject = s
		}
		return true
	case "aud":
		claims.Audience = parseAudience(value)
		return true
	case "exp":
		if t := parseTime(value); t != nil {
			claims.ExpiresAt = t
		}
		return true
	case "nbf":
		if t := parseTime(value); t != nil {
			claims.NotBefore = t
		}
		return true
	case "iat":
		if t := parseTime(value); t != nil {
			claims.IssuedAt = t
		}
		return true
	case "jti":
		if s, ok := value.(string); ok {
			claims.JWTID = s
		}
		return true
	default:
		return false
	}
}

// parseAudience parses the audience claim.
func parseAudience(value interface{}) Audience {
	switch v := value.(type) {
	case string:
		return Audience{v}
	case []string:
		return Audience(v)
	case []interface{}:
		result := make(Audience, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// parseTime parses a time value from various formats.
func parseTime(value interface{}) *Time {
	switch v := value.(type) {
	case float64:
		return &Time{Time: time.Unix(int64(v), 0)}
	case int64:
		return &Time{Time: time.Unix(v, 0)}
	case int:
		return &Time{Time: time.Unix(int64(v), 0)}
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return &Time{Time: time.Unix(i, 0)}
		}
	default:
		return nil
	}
	return nil
}

// ToMap converts claims to a map.
func (c *Claims) ToMap() map[string]interface{} {
	result := make(map[string]interface{})

	if c.Issuer != "" {
		result["iss"] = c.Issuer
	}
	if c.Subject != "" {
		result["sub"] = c.Subject
	}
	if len(c.Audience) > 0 {
		if len(c.Audience) == 1 {
			result["aud"] = c.Audience[0]
		} else {
			result["aud"] = []string(c.Audience)
		}
	}
	if c.ExpiresAt != nil {
		result["exp"] = c.ExpiresAt.Unix()
	}
	if c.NotBefore != nil {
		result["nbf"] = c.NotBefore.Unix()
	}
	if c.IssuedAt != nil {
		result["iat"] = c.IssuedAt.Unix()
	}
	if c.JWTID != "" {
		result["jti"] = c.JWTID
	}

	for k, v := range c.Extra {
		result[k] = v
	}

	return result
}

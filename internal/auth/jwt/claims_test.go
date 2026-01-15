package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTime_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		expected  time.Time
		wantError bool
	}{
		{
			name:     "Valid timestamp",
			input:    "1609459200",
			expected: time.Unix(1609459200, 0),
		},
		{
			name:     "Valid timestamp with decimals",
			input:    "1609459200.5",
			expected: time.Unix(1609459200, 0),
		},
		{
			name:     "Zero timestamp",
			input:    "0",
			expected: time.Unix(0, 0),
		},
		{
			name:      "Invalid timestamp",
			input:     `"not-a-number"`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var tm Time
			err := json.Unmarshal([]byte(tt.input), &tm)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.Unix(), tm.Unix())
			}
		})
	}
}

func TestTime_MarshalJSON(t *testing.T) {
	t.Parallel()

	tm := Time{Time: time.Unix(1609459200, 0)}
	data, err := json.Marshal(tm)

	require.NoError(t, err)
	assert.Equal(t, "1609459200", string(data))
}

func TestAudience_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		expected  Audience
		wantError bool
	}{
		{
			name:     "Single audience as string",
			input:    `"api"`,
			expected: Audience{"api"},
		},
		{
			name:     "Multiple audiences as array",
			input:    `["api", "web", "mobile"]`,
			expected: Audience{"api", "web", "mobile"},
		},
		{
			name:     "Empty array",
			input:    `[]`,
			expected: Audience{},
		},
		{
			name:      "Invalid JSON",
			input:     `{invalid}`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var aud Audience
			err := json.Unmarshal([]byte(tt.input), &aud)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, aud)
			}
		})
	}
}

func TestAudience_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		audience Audience
		expected string
	}{
		{
			name:     "Single audience",
			audience: Audience{"api"},
			expected: `"api"`,
		},
		{
			name:     "Multiple audiences",
			audience: Audience{"api", "web"},
			expected: `["api","web"]`,
		},
		{
			name:     "Empty audience",
			audience: Audience{},
			expected: `[]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.audience)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestAudience_Contains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		audience Audience
		value    string
		expected bool
	}{
		{
			name:     "Contains value",
			audience: Audience{"api", "web", "mobile"},
			value:    "web",
			expected: true,
		},
		{
			name:     "Does not contain value",
			audience: Audience{"api", "web", "mobile"},
			value:    "admin",
			expected: false,
		},
		{
			name:     "Empty audience",
			audience: Audience{},
			value:    "api",
			expected: false,
		},
		{
			name:     "Single audience contains",
			audience: Audience{"api"},
			value:    "api",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.audience.Contains(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      map[string]interface{}
		validate  func(*testing.T, *Claims)
		wantError bool
	}{
		{
			name: "Standard claims",
			data: map[string]interface{}{
				"iss": "https://issuer.example.com",
				"sub": "user123",
				"aud": "api",
				"exp": float64(1609459200),
				"nbf": float64(1609455600),
				"iat": float64(1609455600),
				"jti": "token-id-123",
			},
			validate: func(t *testing.T, c *Claims) {
				assert.Equal(t, "https://issuer.example.com", c.Issuer)
				assert.Equal(t, "user123", c.Subject)
				assert.True(t, c.Audience.Contains("api"))
				assert.NotNil(t, c.ExpiresAt)
				assert.NotNil(t, c.NotBefore)
				assert.NotNil(t, c.IssuedAt)
				assert.Equal(t, "token-id-123", c.ID)
			},
		},
		{
			name: "OIDC claims",
			data: map[string]interface{}{
				"name":           "John Doe",
				"email":          "john@example.com",
				"email_verified": true,
				"groups":         []interface{}{"admin", "users"},
				"roles":          []interface{}{"editor", "viewer"},
				"scope":          "openid profile email",
			},
			validate: func(t *testing.T, c *Claims) {
				assert.Equal(t, "John Doe", c.Name)
				assert.Equal(t, "john@example.com", c.Email)
				assert.True(t, c.EmailVerified)
				assert.Equal(t, []string{"admin", "users"}, c.Groups)
				assert.Equal(t, []string{"editor", "viewer"}, c.Roles)
				assert.Equal(t, "openid profile email", c.Scope)
			},
		},
		{
			name: "Custom claims",
			data: map[string]interface{}{
				"iss":          "issuer",
				"custom_claim": "custom_value",
				"nested": map[string]interface{}{
					"key": "value",
				},
			},
			validate: func(t *testing.T, c *Claims) {
				assert.Equal(t, "custom_value", c.Custom["custom_claim"])
				assert.NotNil(t, c.Custom["nested"])
			},
		},
		{
			name: "Multiple audiences",
			data: map[string]interface{}{
				"aud": []interface{}{"api", "web", "mobile"},
			},
			validate: func(t *testing.T, c *Claims) {
				assert.Len(t, c.Audience, 3)
				assert.True(t, c.Audience.Contains("api"))
				assert.True(t, c.Audience.Contains("web"))
				assert.True(t, c.Audience.Contains("mobile"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims, err := ParseClaims(tt.data)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validate(t, claims)
			}
		})
	}
}

func TestClaims_GetClaim(t *testing.T) {
	t.Parallel()

	data := map[string]interface{}{
		"iss":    "issuer",
		"sub":    "subject",
		"custom": "value",
		"nested": map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": "deep_value",
			},
		},
	}

	claims, err := ParseClaims(data)
	require.NoError(t, err)

	tests := []struct {
		name     string
		claim    string
		expected interface{}
		found    bool
	}{
		{
			name:     "Standard claim",
			claim:    "iss",
			expected: "issuer",
			found:    true,
		},
		{
			name:     "Custom claim",
			claim:    "custom",
			expected: "value",
			found:    true,
		},
		{
			name:     "Nested claim",
			claim:    "nested.level1.level2",
			expected: "deep_value",
			found:    true,
		},
		{
			name:  "Non-existent claim",
			claim: "nonexistent",
			found: false,
		},
		{
			name:  "Non-existent nested claim",
			claim: "nested.nonexistent",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			value, found := claims.GetClaim(tt.claim)
			assert.Equal(t, tt.found, found)
			if tt.found {
				assert.Equal(t, tt.expected, value)
			}
		})
	}
}

func TestClaims_GetClaim_NilRaw(t *testing.T) {
	t.Parallel()

	claims := &Claims{}
	value, found := claims.GetClaim("any")
	assert.False(t, found)
	assert.Nil(t, value)
}

func TestClaims_GetStringClaim(t *testing.T) {
	t.Parallel()

	data := map[string]interface{}{
		"string_claim": "value",
		"int_claim":    123,
	}

	claims, err := ParseClaims(data)
	require.NoError(t, err)

	// String claim
	value, ok := claims.GetStringClaim("string_claim")
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	// Non-string claim
	_, ok = claims.GetStringClaim("int_claim")
	assert.False(t, ok)

	// Non-existent claim
	_, ok = claims.GetStringClaim("nonexistent")
	assert.False(t, ok)
}

func TestClaims_GetStringSliceClaim(t *testing.T) {
	t.Parallel()

	data := map[string]interface{}{
		"string_slice": []interface{}{"a", "b", "c"},
		"mixed_slice":  []interface{}{"a", 1, "c"},
		"string_value": "not-a-slice",
	}

	claims, err := ParseClaims(data)
	require.NoError(t, err)

	// String slice claim
	value, ok := claims.GetStringSliceClaim("string_slice")
	assert.True(t, ok)
	assert.Equal(t, []string{"a", "b", "c"}, value)

	// Mixed slice (only strings extracted)
	value, ok = claims.GetStringSliceClaim("mixed_slice")
	assert.True(t, ok)
	assert.Equal(t, []string{"a", "c"}, value)

	// Non-slice claim
	_, ok = claims.GetStringSliceClaim("string_value")
	assert.False(t, ok)

	// Non-existent claim
	_, ok = claims.GetStringSliceClaim("nonexistent")
	assert.False(t, ok)
}

func TestClaims_HasRole(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Roles: []string{"admin", "editor", "viewer"},
	}

	assert.True(t, claims.HasRole("admin"))
	assert.True(t, claims.HasRole("editor"))
	assert.True(t, claims.HasRole("viewer"))
	assert.False(t, claims.HasRole("superadmin"))
	assert.False(t, claims.HasRole(""))
}

func TestClaims_HasAnyRole(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Roles: []string{"admin", "editor"},
	}

	assert.True(t, claims.HasAnyRole("admin", "superadmin"))
	assert.True(t, claims.HasAnyRole("viewer", "editor"))
	assert.False(t, claims.HasAnyRole("viewer", "superadmin"))
	assert.False(t, claims.HasAnyRole())
}

func TestClaims_HasAllRoles(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Roles: []string{"admin", "editor", "viewer"},
	}

	assert.True(t, claims.HasAllRoles("admin", "editor"))
	assert.True(t, claims.HasAllRoles("admin"))
	assert.True(t, claims.HasAllRoles())
	assert.False(t, claims.HasAllRoles("admin", "superadmin"))
}

func TestClaims_HasGroup(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Groups: []string{"developers", "qa", "devops"},
	}

	assert.True(t, claims.HasGroup("developers"))
	assert.True(t, claims.HasGroup("qa"))
	assert.False(t, claims.HasGroup("management"))
	assert.False(t, claims.HasGroup(""))
}

func TestClaims_HasAnyGroup(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Groups: []string{"developers", "qa"},
	}

	assert.True(t, claims.HasAnyGroup("developers", "management"))
	assert.True(t, claims.HasAnyGroup("devops", "qa"))
	assert.False(t, claims.HasAnyGroup("management", "hr"))
	assert.False(t, claims.HasAnyGroup())
}

func TestClaims_HasAllGroups(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Groups: []string{"developers", "qa", "devops"},
	}

	assert.True(t, claims.HasAllGroups("developers", "qa"))
	assert.True(t, claims.HasAllGroups("developers"))
	assert.True(t, claims.HasAllGroups())
	assert.False(t, claims.HasAllGroups("developers", "management"))
}

func TestClaims_HasScope(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Scope: "openid profile email read:users write:users",
	}

	assert.True(t, claims.HasScope("openid"))
	assert.True(t, claims.HasScope("profile"))
	assert.True(t, claims.HasScope("read:users"))
	assert.True(t, claims.HasScope("write:users"))
	assert.False(t, claims.HasScope("admin"))
	assert.False(t, claims.HasScope(""))
}

func TestClaims_HasAnyScope(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Scope: "openid profile",
	}

	assert.True(t, claims.HasAnyScope("openid", "admin"))
	assert.True(t, claims.HasAnyScope("admin", "profile"))
	assert.False(t, claims.HasAnyScope("admin", "superadmin"))
	assert.False(t, claims.HasAnyScope())
}

func TestClaims_HasAllScopes(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Scope: "openid profile email",
	}

	assert.True(t, claims.HasAllScopes("openid", "profile"))
	assert.True(t, claims.HasAllScopes("openid"))
	assert.True(t, claims.HasAllScopes())
	assert.False(t, claims.HasAllScopes("openid", "admin"))
}

func TestClaims_GetScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		scope    string
		expected []string
	}{
		{
			name:     "Multiple scopes",
			scope:    "openid profile email",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "Single scope",
			scope:    "openid",
			expected: []string{"openid"},
		},
		{
			name:     "Empty scope",
			scope:    "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := &Claims{Scope: tt.scope}
			scopes := claims.GetScopes()
			assert.Equal(t, tt.expected, scopes)
		})
	}
}

func TestClaims_IsExpired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt *Time
		expected  bool
	}{
		{
			name:      "Not expired",
			expiresAt: &Time{Time: time.Now().Add(time.Hour)},
			expected:  false,
		},
		{
			name:      "Expired",
			expiresAt: &Time{Time: time.Now().Add(-time.Hour)},
			expected:  true,
		},
		{
			name:      "No expiry",
			expiresAt: nil,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := &Claims{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, claims.IsExpired())
		})
	}
}

func TestClaims_IsExpiredWithSkew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt *Time
		skew      time.Duration
		expected  bool
	}{
		{
			name:      "Not expired with skew",
			expiresAt: &Time{Time: time.Now().Add(30 * time.Second)},
			skew:      time.Minute,
			expected:  false,
		},
		{
			name:      "Expired even with skew",
			expiresAt: &Time{Time: time.Now().Add(-2 * time.Minute)},
			skew:      time.Minute,
			expected:  true,
		},
		{
			name:      "No expiry",
			expiresAt: nil,
			skew:      time.Minute,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := &Claims{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, claims.IsExpiredWithSkew(tt.skew))
		})
	}
}

func TestClaims_IsNotYetValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		notBefore *Time
		expected  bool
	}{
		{
			name:      "Valid now",
			notBefore: &Time{Time: time.Now().Add(-time.Hour)},
			expected:  false,
		},
		{
			name:      "Not yet valid",
			notBefore: &Time{Time: time.Now().Add(time.Hour)},
			expected:  true,
		},
		{
			name:      "No nbf claim",
			notBefore: nil,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := &Claims{NotBefore: tt.notBefore}
			assert.Equal(t, tt.expected, claims.IsNotYetValid())
		})
	}
}

func TestClaims_IsNotYetValidWithSkew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		notBefore *Time
		skew      time.Duration
		expected  bool
	}{
		{
			name:      "Valid with skew",
			notBefore: &Time{Time: time.Now().Add(30 * time.Second)},
			skew:      time.Minute,
			expected:  false,
		},
		{
			name:      "Not yet valid even with skew",
			notBefore: &Time{Time: time.Now().Add(2 * time.Minute)},
			skew:      time.Minute,
			expected:  true,
		},
		{
			name:      "No nbf claim",
			notBefore: nil,
			skew:      time.Minute,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := &Claims{NotBefore: tt.notBefore}
			assert.Equal(t, tt.expected, claims.IsNotYetValidWithSkew(tt.skew))
		})
	}
}

func TestClaims_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt *Time
		notBefore *Time
		expected  bool
	}{
		{
			name:      "Valid token",
			expiresAt: &Time{Time: time.Now().Add(time.Hour)},
			notBefore: &Time{Time: time.Now().Add(-time.Hour)},
			expected:  true,
		},
		{
			name:      "Expired token",
			expiresAt: &Time{Time: time.Now().Add(-time.Hour)},
			notBefore: &Time{Time: time.Now().Add(-2 * time.Hour)},
			expected:  false,
		},
		{
			name:      "Not yet valid token",
			expiresAt: &Time{Time: time.Now().Add(2 * time.Hour)},
			notBefore: &Time{Time: time.Now().Add(time.Hour)},
			expected:  false,
		},
		{
			name:      "No time claims",
			expiresAt: nil,
			notBefore: nil,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := &Claims{
				ExpiresAt: tt.expiresAt,
				NotBefore: tt.notBefore,
			}
			assert.Equal(t, tt.expected, claims.Valid())
		})
	}
}

func TestClaims_ValidWithSkew(t *testing.T) {
	t.Parallel()

	skew := time.Minute

	tests := []struct {
		name      string
		expiresAt *Time
		notBefore *Time
		expected  bool
	}{
		{
			name:      "Valid with skew",
			expiresAt: &Time{Time: time.Now().Add(30 * time.Second)},
			notBefore: &Time{Time: time.Now().Add(30 * time.Second)},
			expected:  true,
		},
		{
			name:      "Expired even with skew",
			expiresAt: &Time{Time: time.Now().Add(-2 * time.Minute)},
			notBefore: nil,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := &Claims{
				ExpiresAt: tt.expiresAt,
				NotBefore: tt.notBefore,
			}
			assert.Equal(t, tt.expected, claims.ValidWithSkew(skew))
		})
	}
}

func TestClaims_Raw(t *testing.T) {
	t.Parallel()

	data := map[string]interface{}{
		"iss":    "issuer",
		"sub":    "subject",
		"custom": "value",
	}

	claims, err := ParseClaims(data)
	require.NoError(t, err)

	raw := claims.Raw()
	assert.Equal(t, data, raw)
}

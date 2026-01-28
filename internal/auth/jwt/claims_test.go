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
		name     string
		input    string
		expected time.Time
		wantErr  bool
	}{
		{
			name:     "valid timestamp",
			input:    "1609459200",
			expected: time.Unix(1609459200, 0),
			wantErr:  false,
		},
		{
			name:     "valid timestamp with decimals",
			input:    "1609459200.5",
			expected: time.Unix(1609459200, 0),
			wantErr:  false,
		},
		{
			name:     "zero timestamp",
			input:    "0",
			expected: time.Unix(0, 0),
			wantErr:  false,
		},
		{
			name:    "invalid string",
			input:   `"not a number"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var tm Time
			err := json.Unmarshal([]byte(tt.input), &tm)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected.Unix(), tm.Unix())
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
		name     string
		input    string
		expected Audience
		wantErr  bool
	}{
		{
			name:     "single string",
			input:    `"api.example.com"`,
			expected: Audience{"api.example.com"},
			wantErr:  false,
		},
		{
			name:     "array of strings",
			input:    `["api.example.com", "web.example.com"]`,
			expected: Audience{"api.example.com", "web.example.com"},
			wantErr:  false,
		},
		{
			name:     "empty array",
			input:    `[]`,
			expected: Audience{},
			wantErr:  false,
		},
		{
			name:    "invalid type",
			input:   `123`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var aud Audience
			err := json.Unmarshal([]byte(tt.input), &aud)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, aud)
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
			name:     "single value",
			audience: Audience{"api.example.com"},
			expected: `"api.example.com"`,
		},
		{
			name:     "multiple values",
			audience: Audience{"api.example.com", "web.example.com"},
			expected: `["api.example.com","web.example.com"]`,
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

	aud := Audience{"api.example.com", "web.example.com"}

	assert.True(t, aud.Contains("api.example.com"))
	assert.True(t, aud.Contains("web.example.com"))
	assert.False(t, aud.Contains("other.example.com"))
	assert.False(t, aud.Contains(""))
}

func TestAudience_ContainsAny(t *testing.T) {
	t.Parallel()

	aud := Audience{"api.example.com", "web.example.com"}

	assert.True(t, aud.ContainsAny("api.example.com"))
	assert.True(t, aud.ContainsAny("other.example.com", "api.example.com"))
	assert.True(t, aud.ContainsAny("web.example.com", "api.example.com"))
	assert.False(t, aud.ContainsAny("other.example.com"))
	assert.False(t, aud.ContainsAny())
}

func TestClaims_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		claims  *Claims
		wantErr bool
	}{
		{
			name: "valid claims - no expiration",
			claims: &Claims{
				Subject: "user123",
				Issuer:  "test-issuer",
			},
			wantErr: false,
		},
		{
			name: "valid claims - future expiration",
			claims: &Claims{
				Subject:   "user123",
				ExpiresAt: &Time{Time: time.Now().Add(time.Hour)},
			},
			wantErr: false,
		},
		{
			name: "expired token",
			claims: &Claims{
				Subject:   "user123",
				ExpiresAt: &Time{Time: time.Now().Add(-time.Hour)},
			},
			wantErr: true,
		},
		{
			name: "not yet valid",
			claims: &Claims{
				Subject:   "user123",
				NotBefore: &Time{Time: time.Now().Add(time.Hour)},
			},
			wantErr: true,
		},
		{
			name: "valid with not before in past",
			claims: &Claims{
				Subject:   "user123",
				NotBefore: &Time{Time: time.Now().Add(-time.Hour)},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.claims.Valid()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClaims_ValidWithSkew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		claims  *Claims
		skew    time.Duration
		wantErr bool
	}{
		{
			name: "expired but within skew",
			claims: &Claims{
				Subject:   "user123",
				ExpiresAt: &Time{Time: time.Now().Add(-30 * time.Second)},
			},
			skew:    time.Minute,
			wantErr: false,
		},
		{
			name: "expired beyond skew",
			claims: &Claims{
				Subject:   "user123",
				ExpiresAt: &Time{Time: time.Now().Add(-2 * time.Minute)},
			},
			skew:    time.Minute,
			wantErr: true,
		},
		{
			name: "not yet valid but within skew",
			claims: &Claims{
				Subject:   "user123",
				NotBefore: &Time{Time: time.Now().Add(30 * time.Second)},
			},
			skew:    time.Minute,
			wantErr: false,
		},
		{
			name: "not yet valid beyond skew",
			claims: &Claims{
				Subject:   "user123",
				NotBefore: &Time{Time: time.Now().Add(2 * time.Minute)},
			},
			skew:    time.Minute,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.claims.ValidWithSkew(tt.skew)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClaims_GetClaim(t *testing.T) {
	t.Parallel()

	now := time.Now()
	claims := &Claims{
		Issuer:    "test-issuer",
		Subject:   "user123",
		Audience:  Audience{"api.example.com"},
		ExpiresAt: &Time{Time: now},
		NotBefore: &Time{Time: now},
		IssuedAt:  &Time{Time: now},
		JWTID:     "jti-123",
		Extra: map[string]interface{}{
			"custom_claim": "custom_value",
			"nested": map[string]interface{}{
				"key": "value",
			},
		},
	}

	tests := []struct {
		name     string
		claim    string
		expected interface{}
		found    bool
	}{
		{"issuer", "iss", "test-issuer", true},
		{"subject", "sub", "user123", true},
		{"audience", "aud", []string{"api.example.com"}, true},
		{"expiration", "exp", now.Unix(), true},
		{"not before", "nbf", now.Unix(), true},
		{"issued at", "iat", now.Unix(), true},
		{"jwt id", "jti", "jti-123", true},
		{"custom claim", "custom_claim", "custom_value", true},
		{"missing claim", "missing", nil, false},
		{"empty issuer", "iss", "test-issuer", true},
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

func TestClaims_GetNestedClaim(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Subject: "user123",
		Extra: map[string]interface{}{
			"nested": map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": "deep_value",
				},
			},
			"simple": "value",
		},
	}

	tests := []struct {
		name     string
		path     string
		expected interface{}
		found    bool
	}{
		{"simple path", "simple", "value", true},
		{"nested path", "nested.level1.level2", "deep_value", true},
		{"partial path", "nested.level1", map[string]interface{}{"level2": "deep_value"}, true},
		{"missing path", "nested.missing", nil, false},
		{"standard claim", "sub", "user123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			value, found := claims.GetNestedClaim(tt.path)
			assert.Equal(t, tt.found, found)
			if tt.found {
				assert.Equal(t, tt.expected, value)
			}
		})
	}
}

func TestClaims_GetStringClaim(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Subject: "user123",
		Extra: map[string]interface{}{
			"string_claim": "string_value",
			"int_claim":    123,
		},
	}

	assert.Equal(t, "user123", claims.GetStringClaim("sub"))
	assert.Equal(t, "string_value", claims.GetStringClaim("string_claim"))
	assert.Equal(t, "", claims.GetStringClaim("int_claim"))
	assert.Equal(t, "", claims.GetStringClaim("missing"))
}

func TestClaims_GetStringSliceClaim(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Audience: Audience{"aud1", "aud2"},
		Extra: map[string]interface{}{
			"roles":       []string{"admin", "user"},
			"permissions": []interface{}{"read", "write"},
			"scopes":      "read write delete",
			"invalid":     123,
		},
	}

	tests := []struct {
		name     string
		claim    string
		expected []string
	}{
		{"string slice", "roles", []string{"admin", "user"}},
		{"interface slice", "permissions", []string{"read", "write"}},
		{"space-separated string", "scopes", []string{"read", "write", "delete"}},
		{"invalid type", "invalid", nil},
		{"missing claim", "missing", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := claims.GetStringSliceClaim(tt.claim)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClaims_GetNestedStringSliceClaim(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Extra: map[string]interface{}{
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"admin", "user"},
			},
		},
	}

	result := claims.GetNestedStringSliceClaim("realm_access.roles")
	assert.Equal(t, []string{"admin", "user"}, result)

	result = claims.GetNestedStringSliceClaim("missing.path")
	assert.Nil(t, result)
}

func TestParseClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     map[string]interface{}
		expected *Claims
	}{
		{
			name: "full claims",
			data: map[string]interface{}{
				"iss":          "test-issuer",
				"sub":          "user123",
				"aud":          "api.example.com",
				"exp":          float64(1609459200),
				"nbf":          float64(1609455600),
				"iat":          float64(1609455600),
				"jti":          "jti-123",
				"custom_claim": "custom_value",
			},
			expected: &Claims{
				Issuer:    "test-issuer",
				Subject:   "user123",
				Audience:  Audience{"api.example.com"},
				ExpiresAt: &Time{Time: time.Unix(1609459200, 0)},
				NotBefore: &Time{Time: time.Unix(1609455600, 0)},
				IssuedAt:  &Time{Time: time.Unix(1609455600, 0)},
				JWTID:     "jti-123",
				Extra: map[string]interface{}{
					"custom_claim": "custom_value",
				},
			},
		},
		{
			name: "audience as array",
			data: map[string]interface{}{
				"aud": []interface{}{"aud1", "aud2"},
			},
			expected: &Claims{
				Audience: Audience{"aud1", "aud2"},
				Extra:    map[string]interface{}{},
			},
		},
		{
			name: "minimal claims",
			data: map[string]interface{}{
				"sub": "user123",
			},
			expected: &Claims{
				Subject: "user123",
				Extra:   map[string]interface{}{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			claims, err := ParseClaims(tt.data)
			require.NoError(t, err)

			assert.Equal(t, tt.expected.Issuer, claims.Issuer)
			assert.Equal(t, tt.expected.Subject, claims.Subject)
			assert.Equal(t, tt.expected.Audience, claims.Audience)
			assert.Equal(t, tt.expected.JWTID, claims.JWTID)

			if tt.expected.ExpiresAt != nil {
				require.NotNil(t, claims.ExpiresAt)
				assert.Equal(t, tt.expected.ExpiresAt.Unix(), claims.ExpiresAt.Unix())
			}
		})
	}
}

func TestClaims_ToMap(t *testing.T) {
	t.Parallel()

	now := time.Now()
	claims := &Claims{
		Issuer:    "test-issuer",
		Subject:   "user123",
		Audience:  Audience{"api.example.com"},
		ExpiresAt: &Time{Time: now},
		JWTID:     "jti-123",
		Extra: map[string]interface{}{
			"custom": "value",
		},
	}

	result := claims.ToMap()

	assert.Equal(t, "test-issuer", result["iss"])
	assert.Equal(t, "user123", result["sub"])
	assert.Equal(t, "api.example.com", result["aud"])
	assert.Equal(t, now.Unix(), result["exp"])
	assert.Equal(t, "jti-123", result["jti"])
	assert.Equal(t, "value", result["custom"])
}

func TestClaims_ToMap_MultipleAudience(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Audience: Audience{"aud1", "aud2"},
	}

	result := claims.ToMap()
	assert.Equal(t, []string{"aud1", "aud2"}, result["aud"])
}

func TestParseAudience(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected Audience
	}{
		{"string", "single", Audience{"single"}},
		{"string slice", []string{"a", "b"}, Audience{"a", "b"}},
		{"interface slice", []interface{}{"a", "b"}, Audience{"a", "b"}},
		{"invalid type", 123, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := parseAudience(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected int64
		isNil    bool
	}{
		{"float64", float64(1609459200), 1609459200, false},
		{"int64", int64(1609459200), 1609459200, false},
		{"int", int(1609459200), 1609459200, false},
		{"json.Number", json.Number("1609459200"), 1609459200, false},
		{"invalid type", "not a number", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := parseTime(tt.value)
			if tt.isNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.expected, result.Unix())
			}
		})
	}
}

func TestClaims_GetClaim_EmptyValues(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Issuer:  "",
		Subject: "",
	}

	_, found := claims.GetClaim("iss")
	assert.False(t, found)

	_, found = claims.GetClaim("sub")
	assert.False(t, found)
}

func TestClaims_GetClaim_NilExtra(t *testing.T) {
	t.Parallel()

	claims := &Claims{
		Subject: "user123",
		Extra:   nil,
	}

	_, found := claims.GetClaim("custom")
	assert.False(t, found)
}

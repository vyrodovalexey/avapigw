package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentity_IsExpired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "zero time is not expired",
			expiresAt: time.Time{},
			expected:  false,
		},
		{
			name:      "future time is not expired",
			expiresAt: time.Now().Add(time.Hour),
			expected:  false,
		},
		{
			name:      "past time is expired",
			expiresAt: time.Now().Add(-time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			identity := &Identity{
				Subject:   "user123",
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.expected, identity.IsExpired())
		})
	}
}

func TestIdentity_HasRole(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Roles:   []string{"admin", "user", "editor"},
	}

	tests := []struct {
		role     string
		expected bool
	}{
		{"admin", true},
		{"user", true},
		{"editor", true},
		{"superadmin", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, identity.HasRole(tt.role))
		})
	}
}

func TestIdentity_HasAnyRole(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Roles:   []string{"admin", "user"},
	}

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{
			name:     "has one of the roles",
			roles:    []string{"admin", "superadmin"},
			expected: true,
		},
		{
			name:     "has another role",
			roles:    []string{"guest", "user"},
			expected: true,
		},
		{
			name:     "has none of the roles",
			roles:    []string{"guest", "superadmin"},
			expected: false,
		},
		{
			name:     "empty roles",
			roles:    []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, identity.HasAnyRole(tt.roles...))
		})
	}
}

func TestIdentity_HasAllRoles(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Roles:   []string{"admin", "user", "editor"},
	}

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{
			name:     "has all roles",
			roles:    []string{"admin", "user"},
			expected: true,
		},
		{
			name:     "has all three roles",
			roles:    []string{"admin", "user", "editor"},
			expected: true,
		},
		{
			name:     "missing one role",
			roles:    []string{"admin", "superadmin"},
			expected: false,
		},
		{
			name:     "empty roles",
			roles:    []string{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, identity.HasAllRoles(tt.roles...))
		})
	}
}

func TestIdentity_HasPermission(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject:     "user123",
		Permissions: []string{"read:users", "write:users", "delete:posts"},
	}

	tests := []struct {
		permission string
		expected   bool
	}{
		{"read:users", true},
		{"write:users", true},
		{"delete:posts", true},
		{"admin:all", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.permission, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, identity.HasPermission(tt.permission))
		})
	}
}

func TestIdentity_HasScope(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Scopes:  []string{"openid", "profile", "email"},
	}

	tests := []struct {
		scope    string
		expected bool
	}{
		{"openid", true},
		{"profile", true},
		{"email", true},
		{"offline_access", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, identity.HasScope(tt.scope))
		})
	}
}

func TestIdentity_HasGroup(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Groups:  []string{"engineering", "platform", "security"},
	}

	tests := []struct {
		group    string
		expected bool
	}{
		{"engineering", true},
		{"platform", true},
		{"security", true},
		{"finance", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, identity.HasGroup(tt.group))
		})
	}
}

func TestIdentity_GetClaim(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Claims: map[string]interface{}{
			"custom_claim": "value",
			"number":       42,
			"nested": map[string]interface{}{
				"key": "nested_value",
			},
		},
	}

	tests := []struct {
		name     string
		claim    string
		expected interface{}
		found    bool
	}{
		{
			name:     "existing string claim",
			claim:    "custom_claim",
			expected: "value",
			found:    true,
		},
		{
			name:     "existing number claim",
			claim:    "number",
			expected: 42,
			found:    true,
		},
		{
			name:     "existing nested claim",
			claim:    "nested",
			expected: map[string]interface{}{"key": "nested_value"},
			found:    true,
		},
		{
			name:     "non-existing claim",
			claim:    "missing",
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			value, found := identity.GetClaim(tt.claim)
			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.expected, value)
		})
	}
}

func TestIdentity_GetClaim_NilClaims(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Claims:  nil,
	}

	value, found := identity.GetClaim("any")
	assert.False(t, found)
	assert.Nil(t, value)
}

func TestIdentity_GetClaimString(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Claims: map[string]interface{}{
			"string_claim": "value",
			"number_claim": 42,
		},
	}

	tests := []struct {
		name     string
		claim    string
		expected string
	}{
		{
			name:     "existing string claim",
			claim:    "string_claim",
			expected: "value",
		},
		{
			name:     "non-string claim",
			claim:    "number_claim",
			expected: "",
		},
		{
			name:     "non-existing claim",
			claim:    "missing",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, identity.GetClaimString(tt.claim))
		})
	}
}

func TestIdentity_GetClaimStringSlice(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
		Claims: map[string]interface{}{
			"string_slice":    []string{"a", "b", "c"},
			"interface_slice": []interface{}{"x", "y", "z"},
			"mixed_slice":     []interface{}{"a", 1, "b"},
			"string_claim":    "not_a_slice",
		},
	}

	tests := []struct {
		name     string
		claim    string
		expected []string
	}{
		{
			name:     "string slice",
			claim:    "string_slice",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "interface slice with strings",
			claim:    "interface_slice",
			expected: []string{"x", "y", "z"},
		},
		{
			name:     "mixed slice filters non-strings",
			claim:    "mixed_slice",
			expected: []string{"a", "b"},
		},
		{
			name:     "non-slice claim",
			claim:    "string_claim",
			expected: nil,
		},
		{
			name:     "non-existing claim",
			claim:    "missing",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, identity.GetClaimStringSlice(tt.claim))
		})
	}
}

func TestContextWithIdentity(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject:  "user123",
		AuthType: AuthTypeJWT,
	}

	ctx := context.Background()
	ctx = ContextWithIdentity(ctx, identity)

	retrieved, ok := IdentityFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, identity, retrieved)
	assert.Equal(t, "user123", retrieved.Subject)
	assert.Equal(t, AuthTypeJWT, retrieved.AuthType)
}

func TestIdentityFromContext_NotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	identity, ok := IdentityFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, identity)
}

func TestMustIdentityFromContext(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
	}

	ctx := ContextWithIdentity(context.Background(), identity)
	retrieved := MustIdentityFromContext(ctx)
	assert.Equal(t, identity, retrieved)
}

func TestMustIdentityFromContext_Panics(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	assert.Panics(t, func() {
		MustIdentityFromContext(ctx)
	})
}

func TestIdentityFromContextOrError(t *testing.T) {
	t.Parallel()

	t.Run("returns identity when present", func(t *testing.T) {
		t.Parallel()

		identity := &Identity{
			Subject:  "user123",
			AuthType: AuthTypeJWT,
		}

		ctx := ContextWithIdentity(context.Background(), identity)
		retrieved, err := IdentityFromContextOrError(ctx)

		require.NoError(t, err)
		assert.Equal(t, identity, retrieved)
		assert.Equal(t, "user123", retrieved.Subject)
	})

	t.Run("returns ErrIdentityNotFound when not present", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		identity, err := IdentityFromContextOrError(ctx)

		assert.Nil(t, identity)
		assert.ErrorIs(t, err, ErrIdentityNotFound)
	})

	t.Run("returns ErrIdentityNil when identity is nil", func(t *testing.T) {
		t.Parallel()

		// Create context with nil identity
		ctx := context.WithValue(context.Background(), identityContextKey{}, (*Identity)(nil))
		identity, err := IdentityFromContextOrError(ctx)

		assert.Nil(t, identity)
		assert.ErrorIs(t, err, ErrIdentityNil)
	})
}

func TestIdentityErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrIdentityNotFound message", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "identity not found in context", ErrIdentityNotFound.Error())
	})

	t.Run("ErrIdentityNil message", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "identity in context is nil", ErrIdentityNil.Error())
	})
}

func TestAnonymousIdentity(t *testing.T) {
	t.Parallel()

	identity := AnonymousIdentity()

	assert.Equal(t, "anonymous", identity.Subject)
	assert.Equal(t, AuthTypeAnonymous, identity.AuthType)
	assert.False(t, identity.AuthTime.IsZero())
}

func TestAuthTypeConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, AuthType("jwt"), AuthTypeJWT)
	assert.Equal(t, AuthType("apikey"), AuthTypeAPIKey)
	assert.Equal(t, AuthType("mtls"), AuthTypeMTLS)
	assert.Equal(t, AuthType("oidc"), AuthTypeOIDC)
	assert.Equal(t, AuthType("basic"), AuthTypeBasic)
	assert.Equal(t, AuthType("anonymous"), AuthTypeAnonymous)
}

func TestIdentity_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	identity := &Identity{
		Subject:       "user123",
		Issuer:        "https://issuer.example.com",
		Audience:      []string{"api", "web"},
		AuthType:      AuthTypeJWT,
		AuthTime:      now,
		ExpiresAt:     now.Add(time.Hour),
		Claims:        map[string]interface{}{"custom": "value"},
		Roles:         []string{"admin"},
		Permissions:   []string{"read:all"},
		Scopes:        []string{"openid"},
		Groups:        []string{"engineering"},
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
		ClientID:      "client123",
		TenantID:      "tenant456",
		Metadata:      map[string]string{"key": "value"},
	}

	assert.Equal(t, "user123", identity.Subject)
	assert.Equal(t, "https://issuer.example.com", identity.Issuer)
	assert.Equal(t, []string{"api", "web"}, identity.Audience)
	assert.Equal(t, AuthTypeJWT, identity.AuthType)
	assert.Equal(t, now, identity.AuthTime)
	assert.Equal(t, now.Add(time.Hour), identity.ExpiresAt)
	assert.Equal(t, map[string]interface{}{"custom": "value"}, identity.Claims)
	assert.Equal(t, []string{"admin"}, identity.Roles)
	assert.Equal(t, []string{"read:all"}, identity.Permissions)
	assert.Equal(t, []string{"openid"}, identity.Scopes)
	assert.Equal(t, []string{"engineering"}, identity.Groups)
	assert.Equal(t, "user@example.com", identity.Email)
	assert.True(t, identity.EmailVerified)
	assert.Equal(t, "Test User", identity.Name)
	assert.Equal(t, "client123", identity.ClientID)
	assert.Equal(t, "tenant456", identity.TenantID)
	assert.Equal(t, map[string]string{"key": "value"}, identity.Metadata)
}

func TestCertificateInfo_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	certInfo := &CertificateInfo{
		SubjectDN:      "CN=client,O=Example",
		IssuerDN:       "CN=CA,O=Example",
		SerialNumber:   "123456",
		NotBefore:      now,
		NotAfter:       now.Add(365 * 24 * time.Hour),
		DNSNames:       []string{"client.example.com"},
		URIs:           []string{"spiffe://example.com/client"},
		EmailAddresses: []string{"client@example.com"},
		SPIFFEID:       "spiffe://example.com/client",
		Fingerprint:    "sha256:abc123",
	}

	assert.Equal(t, "CN=client,O=Example", certInfo.SubjectDN)
	assert.Equal(t, "CN=CA,O=Example", certInfo.IssuerDN)
	assert.Equal(t, "123456", certInfo.SerialNumber)
	assert.Equal(t, now, certInfo.NotBefore)
	assert.Equal(t, now.Add(365*24*time.Hour), certInfo.NotAfter)
	assert.Equal(t, []string{"client.example.com"}, certInfo.DNSNames)
	assert.Equal(t, []string{"spiffe://example.com/client"}, certInfo.URIs)
	assert.Equal(t, []string{"client@example.com"}, certInfo.EmailAddresses)
	assert.Equal(t, "spiffe://example.com/client", certInfo.SPIFFEID)
	assert.Equal(t, "sha256:abc123", certInfo.Fingerprint)
}

func TestIdentity_WithCertificateInfo(t *testing.T) {
	t.Parallel()

	certInfo := &CertificateInfo{
		SubjectDN: "CN=client,O=Example",
		SPIFFEID:  "spiffe://example.com/client",
	}

	identity := &Identity{
		Subject:         "client",
		AuthType:        AuthTypeMTLS,
		CertificateInfo: certInfo,
	}

	assert.NotNil(t, identity.CertificateInfo)
	assert.Equal(t, "CN=client,O=Example", identity.CertificateInfo.SubjectDN)
	assert.Equal(t, "spiffe://example.com/client", identity.CertificateInfo.SPIFFEID)
}

func TestIdentity_EmptySlices(t *testing.T) {
	t.Parallel()

	identity := &Identity{
		Subject: "user123",
	}

	// Test with nil slices
	assert.False(t, identity.HasRole("admin"))
	assert.False(t, identity.HasPermission("read:all"))
	assert.False(t, identity.HasScope("openid"))
	assert.False(t, identity.HasGroup("engineering"))
	assert.False(t, identity.HasAnyRole("admin", "user"))
	assert.True(t, identity.HasAllRoles()) // Empty check returns true
}

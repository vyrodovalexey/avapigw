package oidc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================
// Mock JWT Validator for testing ValidateToken
// ============================================================

type mockJWTValidator struct {
	claims *jwt.Claims
	err    error
}

func (m *mockJWTValidator) Validate(_ context.Context, _ string) (*jwt.Claims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

func (m *mockJWTValidator) ValidateWithOptions(_ context.Context, _ string, _ jwt.ValidationOptions) (*jwt.Claims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

// ============================================================
// provider.go coverage: ValidateToken, Close with nil discoveryClient,
// NewProvider without discovery client (error path)
// ============================================================

func TestProvider_ValidateToken_Success(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	now := time.Now()
	mockValidator := &mockJWTValidator{
		claims: &jwt.Claims{
			Subject:   "user123",
			Issuer:    "https://issuer.example.com",
			Audience:  jwt.Audience{"client-id"},
			ExpiresAt: &jwt.Time{Time: now.Add(time.Hour)},
			IssuedAt:  &jwt.Time{Time: now},
			Extra: map[string]interface{}{
				"roles":          []interface{}{"admin"},
				"email":          "user@example.com",
				"name":           "Test User",
				"scope":          "openid profile",
				"email_verified": true,
			},
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
		ClaimMapping: &ClaimMapping{
			Roles: "roles",
			Email: "email",
			Name:  "name",
		},
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	// Inject mock JWT validator
	p := prov.(*provider)
	p.jwtValidator = mockValidator

	tokenInfo, err := prov.ValidateToken(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, "user123", tokenInfo.Subject)
	assert.Equal(t, "https://issuer.example.com", tokenInfo.Issuer)
	assert.Equal(t, []string{"admin"}, tokenInfo.Roles)
	assert.Equal(t, "user@example.com", tokenInfo.Email)
	assert.Equal(t, "Test User", tokenInfo.Name)
	assert.Equal(t, []string{"openid", "profile"}, tokenInfo.Scopes)
	assert.True(t, tokenInfo.EmailVerified)
}

func TestProvider_ValidateToken_DiscoveryError(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		err: fmt.Errorf("discovery failed"),
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	_, err = prov.ValidateToken(context.Background(), "test-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get discovery document")
}

func TestProvider_ValidateToken_ValidationError(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	mockValidator := &mockJWTValidator{
		err: errors.New("token expired"),
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	// Inject mock JWT validator
	p := prov.(*provider)
	p.jwtValidator = mockValidator

	_, err = prov.ValidateToken(context.Background(), "expired-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token validation failed")
}

func TestProvider_ValidateToken_WithoutExpiresAt(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	mockValidator := &mockJWTValidator{
		claims: &jwt.Claims{
			Subject:  "user123",
			Issuer:   "https://issuer.example.com",
			Audience: jwt.Audience{"client-id"},
			// No ExpiresAt or IssuedAt
			Extra: map[string]interface{}{},
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	p := prov.(*provider)
	p.jwtValidator = mockValidator

	tokenInfo, err := prov.ValidateToken(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, "user123", tokenInfo.Subject)
	assert.True(t, tokenInfo.ExpiresAt.IsZero())
	assert.True(t, tokenInfo.IssuedAt.IsZero())
}

func TestProvider_ValidateToken_WithPermissionsAndGroups(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	mockValidator := &mockJWTValidator{
		claims: &jwt.Claims{
			Subject:  "user123",
			Issuer:   "https://issuer.example.com",
			Audience: jwt.Audience{"client-id"},
			Extra: map[string]interface{}{
				"permissions": []interface{}{"read", "write"},
				"groups":      []interface{}{"group1", "group2"},
			},
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
		ClaimMapping: &ClaimMapping{
			Permissions: "permissions",
			Groups:      "groups",
		},
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	p := prov.(*provider)
	p.jwtValidator = mockValidator

	tokenInfo, err := prov.ValidateToken(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, []string{"read", "write"}, tokenInfo.Permissions)
	assert.Equal(t, []string{"group1", "group2"}, tokenInfo.Groups)
}

func TestProvider_ValidateToken_EmailVerifiedNotBool(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	mockValidator := &mockJWTValidator{
		claims: &jwt.Claims{
			Subject:  "user123",
			Issuer:   "https://issuer.example.com",
			Audience: jwt.Audience{"client-id"},
			Extra: map[string]interface{}{
				"email_verified": "not-a-bool",
			},
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	p := prov.(*provider)
	p.jwtValidator = mockValidator

	tokenInfo, err := prov.ValidateToken(context.Background(), "test-token")
	require.NoError(t, err)
	assert.False(t, tokenInfo.EmailVerified) // Should remain false since value is not bool
}

func TestProvider_Close_NilDiscoveryClient(t *testing.T) {
	t.Parallel()

	// Create provider with discovery client, then set it to nil
	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	// Set discoveryClient to nil to test the nil path
	p := prov.(*provider)
	p.discoveryClient = nil

	err = prov.Close()
	assert.NoError(t, err)
}

func TestProvider_GetUserInfo_DiscoveryError(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		err: fmt.Errorf("discovery failed"),
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	_, err = prov.GetUserInfo(context.Background(), "access-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get discovery document")
}

func TestProvider_IntrospectToken_DiscoveryError(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		err: fmt.Errorf("discovery failed"),
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
		Introspection: &IntrospectionConfig{
			Enabled: true,
		},
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	_, err = prov.IntrospectToken(context.Background(), "token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get discovery document")
}

func TestProvider_IntrospectToken_WithCustomURL(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
		Introspection: &IntrospectionConfig{
			Enabled: true,
			URL:     "https://issuer.example.com/custom-introspect",
		},
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	// Will fail with "not yet implemented" but exercises the custom URL path
	_, err = prov.IntrospectToken(context.Background(), "token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestNewProvider_WithNilGlobalConfig(t *testing.T) {
	t.Parallel()

	// When no discovery client is provided and globalConfig is nil,
	// NewDiscoveryClient will fail because config is nil
	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	_, err := NewProvider(config, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create discovery client")
}

func TestNewProvider_WithGlobalConfig(t *testing.T) {
	t.Parallel()

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	globalConfig := &Config{
		Enabled: true,
		Providers: []ProviderConfig{
			{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
		},
	}

	prov, err := NewProvider(config, globalConfig, WithProviderLogger(observability.NopLogger()))
	require.NoError(t, err)
	assert.NotNil(t, prov)
	assert.Equal(t, "test", prov.Name())

	err = prov.Close()
	assert.NoError(t, err)
}

// ============================================================
// discovery.go coverage: fetchDiscovery error paths
// ============================================================

func TestDiscoveryClient_GetDiscovery_CacheHit(t *testing.T) {
	t.Parallel()

	globalConfig := &Config{
		Enabled: true,
		Providers: []ProviderConfig{
			{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
		},
		DiscoveryCacheTTL: time.Hour,
	}

	dc, err := NewDiscoveryClient(globalConfig, WithDiscoveryLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Manually populate cache
	client := dc.(*discoveryClient)
	client.mu.Lock()
	client.cache["test"] = &discoveryEntry{
		document: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
		expiresAt: time.Now().Add(time.Hour),
	}
	client.mu.Unlock()

	doc, err := dc.GetDiscovery(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com", doc.Issuer)
}

func TestDiscoveryClient_GetDiscovery_ProviderNotFound_Coverage(t *testing.T) {
	t.Parallel()

	globalConfig := &Config{
		Enabled:   true,
		Providers: []ProviderConfig{},
	}

	dc, err := NewDiscoveryClient(globalConfig)
	require.NoError(t, err)

	_, err = dc.GetDiscovery(context.Background(), "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider nonexistent not found")
}

func TestDiscoveryClient_Refresh_Coverage(t *testing.T) {
	t.Parallel()

	globalConfig := &Config{
		Enabled:   true,
		Providers: []ProviderConfig{},
	}

	dc, err := NewDiscoveryClient(globalConfig)
	require.NoError(t, err)

	err = dc.Refresh(context.Background(), "nonexistent")
	assert.Error(t, err)
}

func TestDiscoveryClient_Close_Coverage(t *testing.T) {
	t.Parallel()

	globalConfig := &Config{
		Enabled: true,
	}

	dc, err := NewDiscoveryClient(globalConfig)
	require.NoError(t, err)

	err = dc.Close()
	assert.NoError(t, err)
}

func TestNewDiscoveryClient_NilConfig(t *testing.T) {
	t.Parallel()

	_, err := NewDiscoveryClient(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestNewDiscoveryClient_WithOptions(t *testing.T) {
	t.Parallel()

	globalConfig := &Config{
		Enabled: true,
	}

	metrics := NewMetrics("test")
	dc, err := NewDiscoveryClient(globalConfig,
		WithDiscoveryLogger(observability.NopLogger()),
		WithDiscoveryMetrics(metrics),
	)
	require.NoError(t, err)
	assert.NotNil(t, dc)
}

// ============================================================
// config.go coverage: GetEffectiveClaimMapping for different types
// ============================================================

func TestProviderConfig_GetEffectiveClaimMapping_Keycloak(t *testing.T) {
	t.Parallel()

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
		Type:     "keycloak",
	}

	mapping := config.GetEffectiveClaimMapping()
	assert.Equal(t, "sub", mapping.Subject)
	assert.Equal(t, "realm_access.roles", mapping.Roles)
	assert.Equal(t, "email", mapping.Email)
	assert.Equal(t, "name", mapping.Name)
	assert.Equal(t, "groups", mapping.Groups)
}

func TestProviderConfig_GetEffectiveClaimMapping_Auth0(t *testing.T) {
	t.Parallel()

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
		Type:     "auth0",
	}

	mapping := config.GetEffectiveClaimMapping()
	assert.Equal(t, "sub", mapping.Subject)
	assert.Equal(t, "https://auth0.com/roles", mapping.Roles)
	assert.Equal(t, "permissions", mapping.Permissions)
	assert.Equal(t, "email", mapping.Email)
	assert.Equal(t, "name", mapping.Name)
}

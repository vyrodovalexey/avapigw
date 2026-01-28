package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockDiscoveryClient is a mock implementation of DiscoveryClient for testing.
type mockDiscoveryClient struct {
	discovery *DiscoveryDocument
	err       error
}

func (m *mockDiscoveryClient) GetDiscovery(ctx context.Context, providerName string) (*DiscoveryDocument, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.discovery, nil
}

func (m *mockDiscoveryClient) Refresh(ctx context.Context, providerName string) error {
	return m.err
}

func (m *mockDiscoveryClient) Close() error {
	return nil
}

func TestNewProvider(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	tests := []struct {
		name         string
		config       *ProviderConfig
		globalConfig *Config
		opts         []ProviderOption
		wantErr      bool
		errMsg       string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is required",
		},
		{
			name: "valid config with discovery client",
			config: &ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
			globalConfig: &Config{
				Enabled: true,
				Providers: []ProviderConfig{
					{
						Name:     "test",
						Issuer:   "https://issuer.example.com",
						ClientID: "client-id",
					},
				},
			},
			opts: []ProviderOption{
				WithDiscoveryClient(mockDC),
			},
			wantErr: false,
		},
		{
			name: "with logger option",
			config: &ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
			globalConfig: &Config{
				Enabled: true,
				Providers: []ProviderConfig{
					{
						Name:     "test",
						Issuer:   "https://issuer.example.com",
						ClientID: "client-id",
					},
				},
			},
			opts: []ProviderOption{
				WithDiscoveryClient(mockDC),
				WithProviderLogger(observability.NopLogger()),
			},
			wantErr: false,
		},
		{
			name: "with metrics option",
			config: &ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
			globalConfig: &Config{
				Enabled: true,
				Providers: []ProviderConfig{
					{
						Name:     "test",
						Issuer:   "https://issuer.example.com",
						ClientID: "client-id",
					},
				},
			},
			opts: []ProviderOption{
				WithDiscoveryClient(mockDC),
				WithProviderMetrics(NewMetrics("test")),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewProvider(tt.config, tt.globalConfig, tt.opts...)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestProvider_Name(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
		},
	}

	config := &ProviderConfig{
		Name:     "test-provider",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	provider, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	assert.Equal(t, "test-provider", provider.Name())
}

func TestProvider_Close(t *testing.T) {
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
	}

	provider, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	err = provider.Close()
	assert.NoError(t, err)
}

func TestProvider_GetUserInfo_NotImplemented(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:           "https://issuer.example.com",
			JWKSUri:          "https://issuer.example.com/.well-known/jwks.json",
			UserinfoEndpoint: "https://issuer.example.com/userinfo",
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	provider, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	_, err = provider.GetUserInfo(context.Background(), "access-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestProvider_GetUserInfo_NoEndpoint(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
			// No UserinfoEndpoint
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	provider, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	_, err = provider.GetUserInfo(context.Background(), "access-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "userinfo endpoint not available")
}

func TestProvider_IntrospectToken_NotEnabled(t *testing.T) {
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
		// No Introspection config
	}

	provider, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	_, err = provider.IntrospectToken(context.Background(), "token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token introspection is not enabled")
}

func TestProvider_IntrospectToken_NoEndpoint(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:  "https://issuer.example.com",
			JWKSUri: "https://issuer.example.com/.well-known/jwks.json",
			// No IntrospectionEndpoint
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
		Introspection: &IntrospectionConfig{
			Enabled: true,
			// No URL
		},
	}

	provider, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	_, err = provider.IntrospectToken(context.Background(), "token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "introspection endpoint not available")
}

func TestProvider_IntrospectToken_NotImplemented(t *testing.T) {
	t.Parallel()

	mockDC := &mockDiscoveryClient{
		discovery: &DiscoveryDocument{
			Issuer:                "https://issuer.example.com",
			JWKSUri:               "https://issuer.example.com/.well-known/jwks.json",
			IntrospectionEndpoint: "https://issuer.example.com/introspect",
		},
	}

	config := &ProviderConfig{
		Name:     "test",
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
		Introspection: &IntrospectionConfig{
			Enabled: true,
		},
	}

	provider, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	_, err = provider.IntrospectToken(context.Background(), "token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestTokenInfo_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	info := &TokenInfo{
		Subject:       "user123",
		Issuer:        "https://issuer.example.com",
		Audience:      []string{"client-id"},
		ExpiresAt:     now.Add(time.Hour),
		IssuedAt:      now,
		Scopes:        []string{"openid", "profile"},
		Roles:         []string{"admin", "user"},
		Permissions:   []string{"read", "write"},
		Groups:        []string{"group1", "group2"},
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Claims:        map[string]interface{}{"custom": "value"},
		TokenType:     "access_token",
	}

	assert.Equal(t, "user123", info.Subject)
	assert.Equal(t, "https://issuer.example.com", info.Issuer)
	assert.Equal(t, []string{"client-id"}, info.Audience)
	assert.Equal(t, []string{"openid", "profile"}, info.Scopes)
	assert.Equal(t, []string{"admin", "user"}, info.Roles)
	assert.Equal(t, []string{"read", "write"}, info.Permissions)
	assert.Equal(t, []string{"group1", "group2"}, info.Groups)
	assert.Equal(t, "user@example.com", info.Email)
	assert.True(t, info.EmailVerified)
	assert.Equal(t, "Test User", info.Name)
	assert.Equal(t, "access_token", info.TokenType)
}

func TestUserInfo_Fields(t *testing.T) {
	t.Parallel()

	info := &UserInfo{
		Subject:       "user123",
		Name:          "Test User",
		GivenName:     "Test",
		FamilyName:    "User",
		Email:         "user@example.com",
		EmailVerified: true,
		Picture:       "https://example.com/picture.jpg",
		Locale:        "en-US",
		Claims:        map[string]interface{}{"custom": "value"},
	}

	assert.Equal(t, "user123", info.Subject)
	assert.Equal(t, "Test User", info.Name)
	assert.Equal(t, "Test", info.GivenName)
	assert.Equal(t, "User", info.FamilyName)
	assert.Equal(t, "user@example.com", info.Email)
	assert.True(t, info.EmailVerified)
	assert.Equal(t, "https://example.com/picture.jpg", info.Picture)
	assert.Equal(t, "en-US", info.Locale)
}

func TestIntrospectionResult_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	result := &IntrospectionResult{
		Active:    true,
		Scope:     "openid profile",
		ClientID:  "client-id",
		Username:  "user123",
		TokenType: "access_token",
		ExpiresAt: &now,
		IssuedAt:  &now,
		Subject:   "user123",
		Audience:  []string{"client-id"},
		Issuer:    "https://issuer.example.com",
	}

	assert.True(t, result.Active)
	assert.Equal(t, "openid profile", result.Scope)
	assert.Equal(t, "client-id", result.ClientID)
	assert.Equal(t, "user123", result.Username)
	assert.Equal(t, "access_token", result.TokenType)
	assert.Equal(t, "user123", result.Subject)
	assert.Equal(t, []string{"client-id"}, result.Audience)
	assert.Equal(t, "https://issuer.example.com", result.Issuer)
}

func TestExtractTokenInfo(t *testing.T) {
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
		ClaimMapping: &ClaimMapping{
			Roles:       "roles",
			Permissions: "permissions",
			Groups:      "groups",
			Email:       "email",
			Name:        "name",
		},
	}

	prov, err := NewProvider(config, nil, WithDiscoveryClient(mockDC))
	require.NoError(t, err)

	// Access the internal provider to test extractTokenInfo
	p := prov.(*provider)

	now := time.Now()
	claims := &jwt.Claims{
		Subject:  "user123",
		Issuer:   "https://issuer.example.com",
		Audience: jwt.Audience{"client-id"},
	}
	claims.ExpiresAt = &jwt.Time{Time: now.Add(time.Hour)}
	claims.IssuedAt = &jwt.Time{Time: now}
	claims.Extra = map[string]interface{}{
		"roles":          []interface{}{"admin", "user"},
		"permissions":    []interface{}{"read", "write"},
		"groups":         []interface{}{"group1"},
		"email":          "user@example.com",
		"name":           "Test User",
		"scope":          "openid profile",
		"email_verified": true,
	}

	info := p.extractTokenInfo(claims)

	assert.Equal(t, "user123", info.Subject)
	assert.Equal(t, "https://issuer.example.com", info.Issuer)
	assert.Equal(t, []string{"client-id"}, info.Audience)
	assert.Equal(t, []string{"admin", "user"}, info.Roles)
	assert.Equal(t, []string{"read", "write"}, info.Permissions)
	assert.Equal(t, []string{"group1"}, info.Groups)
	assert.Equal(t, "user@example.com", info.Email)
	assert.Equal(t, "Test User", info.Name)
	assert.Equal(t, []string{"openid", "profile"}, info.Scopes)
	assert.True(t, info.EmailVerified)
}

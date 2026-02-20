package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestConvertFromGatewayConfig_NilInput(t *testing.T) {
	t.Parallel()

	result, err := ConvertFromGatewayConfig(nil)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestConvertFromGatewayConfig_Disabled(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled: false,
	}

	result, err := ConvertFromGatewayConfig(cfg)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestConvertFromGatewayConfig_EnabledNoMethods(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled: true,
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Nil(t, result.JWT)
	assert.Nil(t, result.APIKey)
	assert.Nil(t, result.MTLS)
	assert.Nil(t, result.OIDC)
}

func TestConvertFromGatewayConfig_JWTOnly(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Issuer:    "https://issuer.example.com",
			Audience:  []string{"api"},
			JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
			Algorithm: "RS256",
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	require.NotNil(t, result.JWT)
	assert.True(t, result.JWT.Enabled)
	assert.Equal(t, "https://issuer.example.com", result.JWT.Issuer)
	assert.Equal(t, []string{"api"}, result.JWT.Audience)
	assert.Equal(t, "https://issuer.example.com/.well-known/jwks.json", result.JWT.JWKSUrl)
	assert.Equal(t, []string{"RS256"}, result.JWT.Algorithms)
	assert.Nil(t, result.APIKey)
	assert.Nil(t, result.MTLS)
	assert.Nil(t, result.OIDC)
}

func TestConvertFromGatewayConfig_JWTDisabled(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled: false,
			Issuer:  "https://issuer.example.com",
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Nil(t, result.JWT)
}

func TestConvertFromGatewayConfig_APIKeyOnly(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled: true,
		APIKey: &config.APIKeyAuthConfig{
			Enabled:       true,
			Header:        "X-API-Key",
			Query:         "api_key",
			HashAlgorithm: "sha256",
			VaultPath:     "secret/api-keys",
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.APIKey)
	assert.True(t, result.APIKey.Enabled)
	assert.Equal(t, "sha256", result.APIKey.HashAlgorithm)
	require.Len(t, result.APIKey.Extraction, 2)
	assert.Equal(t, "header", result.APIKey.Extraction[0].Type)
	assert.Equal(t, "X-API-Key", result.APIKey.Extraction[0].Name)
	assert.Equal(t, "query", result.APIKey.Extraction[1].Type)
	assert.Equal(t, "api_key", result.APIKey.Extraction[1].Name)
	require.NotNil(t, result.APIKey.Vault)
	assert.True(t, result.APIKey.Vault.Enabled)
	assert.Equal(t, "secret/api-keys", result.APIKey.Vault.Path)
}

func TestConvertFromGatewayConfig_MTLSOnly(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled: true,
		MTLS: &config.MTLSAuthConfig{
			Enabled:         true,
			CAFile:          "/etc/certs/ca.pem",
			ExtractIdentity: "CN",
			AllowedCNs:      []string{"client1.example.com"},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.MTLS)
	assert.True(t, result.MTLS.Enabled)
	assert.Equal(t, "/etc/certs/ca.pem", result.MTLS.CAFile)
	require.NotNil(t, result.MTLS.ExtractIdentity)
	assert.Equal(t, "CN", result.MTLS.ExtractIdentity.SubjectField)
	assert.True(t, result.MTLS.RequireClientCert)
}

func TestConvertFromGatewayConfig_OIDCOnly(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled: true,
		OIDC: &config.OIDCAuthConfig{
			Enabled: true,
			Providers: []config.OIDCProviderConfig{
				{
					Name:         "keycloak",
					IssuerURL:    "https://keycloak.example.com/realms/test",
					ClientID:     "my-client",
					ClientSecret: "my-secret",
					Scopes:       []string{"openid", "profile"},
				},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.OIDC)
	assert.True(t, result.OIDC.Enabled)
	require.Len(t, result.OIDC.Providers, 1)
	assert.Equal(t, "keycloak", result.OIDC.Providers[0].Name)
	assert.Equal(t, "https://keycloak.example.com/realms/test", result.OIDC.Providers[0].Issuer)
	assert.Equal(t, "my-client", result.OIDC.Providers[0].ClientID)
	assert.Equal(t, "my-secret", result.OIDC.Providers[0].ClientSecret)
	assert.Equal(t, []string{"openid", "profile"}, result.OIDC.Providers[0].Scopes)
}

func TestConvertFromGatewayConfig_AllMethods(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled: true,
			Issuer:  "https://issuer.example.com",
		},
		APIKey: &config.APIKeyAuthConfig{
			Enabled: true,
			Header:  "X-API-Key",
		},
		MTLS: &config.MTLSAuthConfig{
			Enabled: true,
			CAFile:  "/etc/certs/ca.pem",
		},
		OIDC: &config.OIDCAuthConfig{
			Enabled: true,
			Providers: []config.OIDCProviderConfig{
				{
					Name:      "provider1",
					IssuerURL: "https://oidc.example.com",
					ClientID:  "client1",
				},
			},
		},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.JWT)
	assert.NotNil(t, result.APIKey)
	assert.NotNil(t, result.MTLS)
	assert.NotNil(t, result.OIDC)
}

func TestConvertFromGatewayConfig_SkipPaths(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled:   true,
		SkipPaths: []string{"/health", "/metrics", "/api/public/*"},
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []string{"/health", "/metrics", "/api/public/*"}, result.SkipPaths)
}

func TestConvertFromGatewayConfig_AllowAnonymous(t *testing.T) {
	t.Parallel()

	cfg := &config.AuthenticationConfig{
		Enabled:        true,
		AllowAnonymous: true,
	}

	result, err := ConvertFromGatewayConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.AllowAnonymous)
}

func TestConvertJWTConfig_WithSecret(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled:   true,
		Secret:    "my-hmac-secret",
		Algorithm: "HS384",
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, []string{"HS384"}, result.Algorithms)
	require.Len(t, result.StaticKeys, 1)
	assert.Equal(t, jwt.StaticKey{
		KeyID:     "default",
		Algorithm: "HS384",
		Key:       "my-hmac-secret",
	}, result.StaticKeys[0])
}

func TestConvertJWTConfig_WithSecretDefaultAlgorithm(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled: true,
		Secret:  "my-hmac-secret",
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	require.Len(t, result.StaticKeys, 1)
	assert.Equal(t, "HS256", result.StaticKeys[0].Algorithm)
	assert.Equal(t, "default", result.StaticKeys[0].KeyID)
}

func TestConvertJWTConfig_WithPublicKey(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled:   true,
		PublicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----",
		Algorithm: "RS512",
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	require.Len(t, result.StaticKeys, 1)
	assert.Equal(t, "default-public", result.StaticKeys[0].KeyID)
	assert.Equal(t, "RS512", result.StaticKeys[0].Algorithm)
	assert.Equal(t, "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----", result.StaticKeys[0].Key)
}

func TestConvertJWTConfig_WithPublicKeyDefaultAlgorithm(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled:   true,
		PublicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----",
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	require.Len(t, result.StaticKeys, 1)
	assert.Equal(t, "RS256", result.StaticKeys[0].Algorithm)
}

func TestConvertJWTConfig_WithSecretAndPublicKey(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled:   true,
		Secret:    "hmac-secret",
		PublicKey: "rsa-public-key",
		Algorithm: "RS256",
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	require.Len(t, result.StaticKeys, 2)
	assert.Equal(t, "default", result.StaticKeys[0].KeyID)
	assert.Equal(t, "hmac-secret", result.StaticKeys[0].Key)
	assert.Equal(t, "default-public", result.StaticKeys[1].KeyID)
	assert.Equal(t, "rsa-public-key", result.StaticKeys[1].Key)
}

func TestConvertJWTConfig_WithClaimMapping(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled: true,
		ClaimMapping: &config.ClaimMappingConfig{
			Roles:       "realm_access.roles",
			Permissions: "permissions",
			Groups:      "groups",
			Scopes:      "scope",
			Email:       "email",
			Name:        "preferred_username",
		},
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	require.NotNil(t, result.ClaimMapping)
	assert.Equal(t, "realm_access.roles", result.ClaimMapping.Roles)
	assert.Equal(t, "permissions", result.ClaimMapping.Permissions)
	assert.Equal(t, "groups", result.ClaimMapping.Groups)
	assert.Equal(t, "scope", result.ClaimMapping.Scopes)
	assert.Equal(t, "email", result.ClaimMapping.Email)
	assert.Equal(t, "preferred_username", result.ClaimMapping.Name)
}

func TestConvertJWTConfig_NoClaimMapping(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled: true,
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	assert.Nil(t, result.ClaimMapping)
}

func TestConvertJWTConfig_NoAlgorithm(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled: true,
		Issuer:  "https://issuer.example.com",
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	assert.Empty(t, result.Algorithms)
}

func TestConvertAPIKeyConfig_HeaderOnly(t *testing.T) {
	t.Parallel()

	src := &config.APIKeyAuthConfig{
		Enabled: true,
		Header:  "X-API-Key",
	}

	result := convertAPIKeyConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	require.Len(t, result.Extraction, 1)
	assert.Equal(t, apikey.ExtractionSource{Type: "header", Name: "X-API-Key"}, result.Extraction[0])
	assert.Nil(t, result.Vault)
}

func TestConvertAPIKeyConfig_QueryOnly(t *testing.T) {
	t.Parallel()

	src := &config.APIKeyAuthConfig{
		Enabled: true,
		Query:   "api_key",
	}

	result := convertAPIKeyConfig(src)
	require.NotNil(t, result)
	require.Len(t, result.Extraction, 1)
	assert.Equal(t, apikey.ExtractionSource{Type: "query", Name: "api_key"}, result.Extraction[0])
}

func TestConvertAPIKeyConfig_NoExtractionSources(t *testing.T) {
	t.Parallel()

	src := &config.APIKeyAuthConfig{
		Enabled: true,
	}

	result := convertAPIKeyConfig(src)
	require.NotNil(t, result)
	assert.Empty(t, result.Extraction)
}

func TestConvertAPIKeyConfig_WithVaultPath(t *testing.T) {
	t.Parallel()

	src := &config.APIKeyAuthConfig{
		Enabled:   true,
		VaultPath: "secret/data/api-keys",
	}

	result := convertAPIKeyConfig(src)
	require.NotNil(t, result)
	require.NotNil(t, result.Vault)
	assert.True(t, result.Vault.Enabled)
	assert.Equal(t, "secret/data/api-keys", result.Vault.Path)
}

func TestConvertAPIKeyConfig_NoVaultPath(t *testing.T) {
	t.Parallel()

	src := &config.APIKeyAuthConfig{
		Enabled: true,
	}

	result := convertAPIKeyConfig(src)
	require.NotNil(t, result)
	assert.Nil(t, result.Vault)
}

func TestConvertMTLSConfig_Basic(t *testing.T) {
	t.Parallel()

	src := &config.MTLSAuthConfig{
		Enabled: true,
		CAFile:  "/etc/certs/ca.pem",
	}

	result := convertMTLSConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, "/etc/certs/ca.pem", result.CAFile)
	assert.Nil(t, result.ExtractIdentity)
	assert.False(t, result.RequireClientCert)
}

func TestConvertMTLSConfig_WithExtractIdentity(t *testing.T) {
	t.Parallel()

	src := &config.MTLSAuthConfig{
		Enabled:         true,
		ExtractIdentity: "CN",
	}

	result := convertMTLSConfig(src)
	require.NotNil(t, result)
	require.NotNil(t, result.ExtractIdentity)
	assert.Equal(t, "CN", result.ExtractIdentity.SubjectField)
}

func TestConvertMTLSConfig_WithAllowedCNs(t *testing.T) {
	t.Parallel()

	src := &config.MTLSAuthConfig{
		Enabled:    true,
		AllowedCNs: []string{"client1.example.com", "client2.example.com"},
	}

	result := convertMTLSConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.RequireClientCert)
}

func TestConvertMTLSConfig_WithAllowedOUs(t *testing.T) {
	t.Parallel()

	src := &config.MTLSAuthConfig{
		Enabled:    true,
		AllowedOUs: []string{"engineering"},
	}

	result := convertMTLSConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.RequireClientCert)
}

func TestConvertMTLSConfig_NoConstraints(t *testing.T) {
	t.Parallel()

	src := &config.MTLSAuthConfig{
		Enabled: true,
	}

	result := convertMTLSConfig(src)
	require.NotNil(t, result)
	assert.False(t, result.RequireClientCert)
}

func TestConvertOIDCConfig_SingleProvider(t *testing.T) {
	t.Parallel()

	src := &config.OIDCAuthConfig{
		Enabled: true,
		Providers: []config.OIDCProviderConfig{
			{
				Name:         "google",
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "google-client-id",
				ClientSecret: "google-client-secret",
				Scopes:       []string{"openid", "email"},
			},
		},
	}

	result := convertOIDCConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	require.Len(t, result.Providers, 1)
	assert.Equal(t, oidc.ProviderConfig{
		Name:         "google",
		Issuer:       "https://accounts.google.com",
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		Scopes:       []string{"openid", "email"},
	}, result.Providers[0])
}

func TestConvertOIDCConfig_MultipleProviders(t *testing.T) {
	t.Parallel()

	src := &config.OIDCAuthConfig{
		Enabled: true,
		Providers: []config.OIDCProviderConfig{
			{
				Name:      "google",
				IssuerURL: "https://accounts.google.com",
				ClientID:  "google-client-id",
			},
			{
				Name:      "keycloak",
				IssuerURL: "https://keycloak.example.com/realms/test",
				ClientID:  "keycloak-client-id",
				Scopes:    []string{"openid", "profile", "email"},
			},
		},
	}

	result := convertOIDCConfig(src)
	require.NotNil(t, result)
	require.Len(t, result.Providers, 2)
	assert.Equal(t, "google", result.Providers[0].Name)
	assert.Equal(t, "keycloak", result.Providers[1].Name)
}

func TestConvertOIDCConfig_NoProviders(t *testing.T) {
	t.Parallel()

	src := &config.OIDCAuthConfig{
		Enabled: true,
	}

	result := convertOIDCConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Empty(t, result.Providers)
}

func TestConvertFromGatewayConfig_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cfg           *config.AuthenticationConfig
		expectNil     bool
		expectEnabled bool
		expectJWT     bool
		expectAPIKey  bool
		expectMTLS    bool
		expectOIDC    bool
		expectAnon    bool
		expectSkipLen int
	}{
		{
			name:      "nil config",
			cfg:       nil,
			expectNil: true,
		},
		{
			name:      "disabled config",
			cfg:       &config.AuthenticationConfig{Enabled: false},
			expectNil: true,
		},
		{
			name: "enabled with JWT",
			cfg: &config.AuthenticationConfig{
				Enabled: true,
				JWT:     &config.JWTAuthConfig{Enabled: true, Issuer: "test"},
			},
			expectEnabled: true,
			expectJWT:     true,
		},
		{
			name: "enabled with APIKey",
			cfg: &config.AuthenticationConfig{
				Enabled: true,
				APIKey:  &config.APIKeyAuthConfig{Enabled: true, Header: "X-Key"},
			},
			expectEnabled: true,
			expectAPIKey:  true,
		},
		{
			name: "enabled with MTLS",
			cfg: &config.AuthenticationConfig{
				Enabled: true,
				MTLS:    &config.MTLSAuthConfig{Enabled: true, CAFile: "/ca.pem"},
			},
			expectEnabled: true,
			expectMTLS:    true,
		},
		{
			name: "enabled with OIDC",
			cfg: &config.AuthenticationConfig{
				Enabled: true,
				OIDC: &config.OIDCAuthConfig{
					Enabled: true,
					Providers: []config.OIDCProviderConfig{
						{Name: "p1", IssuerURL: "https://oidc.test", ClientID: "c1"},
					},
				},
			},
			expectEnabled: true,
			expectOIDC:    true,
		},
		{
			name: "allow anonymous with skip paths",
			cfg: &config.AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
				SkipPaths:      []string{"/health", "/ready"},
			},
			expectEnabled: true,
			expectAnon:    true,
			expectSkipLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ConvertFromGatewayConfig(tt.cfg)
			assert.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.expectEnabled, result.Enabled)
			assert.Equal(t, tt.expectJWT, result.JWT != nil)
			assert.Equal(t, tt.expectAPIKey, result.APIKey != nil)
			assert.Equal(t, tt.expectMTLS, result.MTLS != nil)
			assert.Equal(t, tt.expectOIDC, result.OIDC != nil)
			assert.Equal(t, tt.expectAnon, result.AllowAnonymous)
			assert.Len(t, result.SkipPaths, tt.expectSkipLen)
		})
	}
}

func TestConvertJWTConfig_FullConfig(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{
		Enabled:   true,
		Issuer:    "https://issuer.example.com",
		Audience:  []string{"api", "web"},
		JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
		Secret:    "hmac-secret",
		PublicKey: "rsa-public-key",
		Algorithm: "RS256",
		ClaimMapping: &config.ClaimMappingConfig{
			Roles:       "roles",
			Permissions: "perms",
			Groups:      "groups",
			Scopes:      "scope",
			Email:       "email",
			Name:        "name",
		},
	}

	result := convertJWTConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, "https://issuer.example.com", result.Issuer)
	assert.Equal(t, []string{"api", "web"}, result.Audience)
	assert.Equal(t, "https://issuer.example.com/.well-known/jwks.json", result.JWKSUrl)
	assert.Equal(t, []string{"RS256"}, result.Algorithms)
	require.Len(t, result.StaticKeys, 2)
	require.NotNil(t, result.ClaimMapping)
	assert.Equal(t, &jwt.ClaimMapping{
		Roles:       "roles",
		Permissions: "perms",
		Groups:      "groups",
		Scopes:      "scope",
		Email:       "email",
		Name:        "name",
	}, result.ClaimMapping)
}

func TestConvertAPIKeyConfig_FullConfig(t *testing.T) {
	t.Parallel()

	src := &config.APIKeyAuthConfig{
		Enabled:       true,
		Header:        "Authorization",
		Query:         "token",
		HashAlgorithm: "sha512",
		VaultPath:     "secret/keys",
	}

	result := convertAPIKeyConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, "sha512", result.HashAlgorithm)
	require.Len(t, result.Extraction, 2)
	assert.Equal(t, "header", result.Extraction[0].Type)
	assert.Equal(t, "Authorization", result.Extraction[0].Name)
	assert.Equal(t, "query", result.Extraction[1].Type)
	assert.Equal(t, "token", result.Extraction[1].Name)
	require.NotNil(t, result.Vault)
	assert.True(t, result.Vault.Enabled)
	assert.Equal(t, "secret/keys", result.Vault.Path)
}

func TestConvertMTLSConfig_FullConfig(t *testing.T) {
	t.Parallel()

	src := &config.MTLSAuthConfig{
		Enabled:         true,
		CAFile:          "/etc/ssl/ca.pem",
		ExtractIdentity: "OU",
		AllowedCNs:      []string{"cn1"},
		AllowedOUs:      []string{"ou1"},
	}

	result := convertMTLSConfig(src)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, "/etc/ssl/ca.pem", result.CAFile)
	require.NotNil(t, result.ExtractIdentity)
	assert.Equal(t, "OU", result.ExtractIdentity.SubjectField)
	assert.True(t, result.RequireClientCert)
}

func TestConvertMTLSConfig_EmptyExtractIdentity(t *testing.T) {
	t.Parallel()

	src := &config.MTLSAuthConfig{
		Enabled:         true,
		ExtractIdentity: "",
	}

	result := convertMTLSConfig(src)
	require.NotNil(t, result)
	assert.Nil(t, result.ExtractIdentity)
}

func TestConvertOIDCConfig_ProviderFieldMapping(t *testing.T) {
	t.Parallel()

	src := &config.OIDCAuthConfig{
		Enabled: true,
		Providers: []config.OIDCProviderConfig{
			{
				Name:         "test-provider",
				IssuerURL:    "https://oidc.test.com",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				Scopes:       []string{"openid", "profile", "email"},
			},
		},
	}

	result := convertOIDCConfig(src)
	require.NotNil(t, result)
	require.Len(t, result.Providers, 1)
	p := result.Providers[0]
	assert.Equal(t, "test-provider", p.Name)
	assert.Equal(t, "https://oidc.test.com", p.Issuer)
	assert.Equal(t, "test-client", p.ClientID)
	assert.Equal(t, "test-secret", p.ClientSecret)
	assert.Equal(t, []string{"openid", "profile", "email"}, p.Scopes)
}

// Verify the types returned match expected interfaces.
func TestConvertJWTConfig_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	src := &config.JWTAuthConfig{Enabled: true}
	result := convertJWTConfig(src)
	assert.IsType(t, &jwt.Config{}, result)
}

func TestConvertAPIKeyConfig_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	src := &config.APIKeyAuthConfig{Enabled: true}
	result := convertAPIKeyConfig(src)
	assert.IsType(t, &apikey.Config{}, result)
}

func TestConvertMTLSConfig_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	src := &config.MTLSAuthConfig{Enabled: true}
	result := convertMTLSConfig(src)
	assert.IsType(t, &mtls.Config{}, result)
}

func TestConvertOIDCConfig_ReturnsCorrectType(t *testing.T) {
	t.Parallel()

	src := &config.OIDCAuthConfig{Enabled: true}
	result := convertOIDCConfig(src)
	assert.IsType(t, &oidc.Config{}, result)
}

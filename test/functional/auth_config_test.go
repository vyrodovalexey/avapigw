//go:build functional
// +build functional

package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
)

func TestFunctional_AuthConfig_Validation(t *testing.T) {
	t.Parallel()

	t.Run("valid config with JWT enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			JWT: &jwt.Config{
				Enabled:    true,
				Algorithms: []string{"RS256"},
				JWKSUrl:    "https://example.com/.well-known/jwks.json",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid config with API Key enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			APIKey: &apikey.Config{
				Enabled:       true,
				HashAlgorithm: "sha256",
				Store: &apikey.StoreConfig{
					Type: "memory",
					Keys: []apikey.StaticKey{
						{ID: "key1", Key: "test-key", Enabled: true},
					},
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid config with mTLS enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			MTLS: &mtls.Config{
				Enabled:           true,
				RequireClientCert: true,
				CACert:            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid config with OIDC enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			OIDC: &oidc.Config{
				Enabled: true,
				Providers: []oidc.ProviderConfig{
					{
						Name:     "test",
						Issuer:   "https://issuer.example.com",
						ClientID: "client-id",
					},
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid config - enabled but no auth method", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one authentication method")
	})

	t.Run("disabled config is always valid", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: false,
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("nil config is valid", func(t *testing.T) {
		t.Parallel()

		var cfg *auth.Config
		err := cfg.Validate()
		require.NoError(t, err)
	})
}

func TestFunctional_AuthConfig_JWTValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid JWT config with JWKS URL", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256", "ES256"},
			JWKSUrl:    "https://example.com/.well-known/jwks.json",
			ClockSkew:  5 * time.Minute,
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid JWT config with static keys", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{
					KeyID:     "key1",
					Algorithm: "HS256",
					Key:       "c2VjcmV0LWtleS1mb3ItdGVzdGluZw==",
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid JWT config - no key source", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key source")
	})

	t.Run("invalid JWT config - invalid algorithm", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"INVALID"},
			JWKSUrl:    "https://example.com/.well-known/jwks.json",
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid algorithm")
	})

	t.Run("invalid JWT config - negative clock skew", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"RS256"},
			JWKSUrl:    "https://example.com/.well-known/jwks.json",
			ClockSkew:  -1 * time.Minute,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clockSkew")
	})

	t.Run("invalid static key - missing key ID", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled: true,
			StaticKeys: []jwt.StaticKey{
				{
					Algorithm: "HS256",
					Key:       "secret",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keyId")
	})

	t.Run("invalid static key - missing algorithm", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled: true,
			StaticKeys: []jwt.StaticKey{
				{
					KeyID: "key1",
					Key:   "secret",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm")
	})

	t.Run("invalid static key - missing key", func(t *testing.T) {
		t.Parallel()

		cfg := &jwt.Config{
			Enabled: true,
			StaticKeys: []jwt.StaticKey{
				{
					KeyID:     "key1",
					Algorithm: "HS256",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key")
	})
}

func TestFunctional_AuthConfig_APIKeyValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid API Key config", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Extraction: []apikey.ExtractionSource{
				{Type: "header", Name: "X-API-Key"},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid API Key config with memory store", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Store: &apikey.StoreConfig{
				Type: "memory",
				Keys: []apikey.StaticKey{
					{ID: "key1", Key: "test-key", Enabled: true},
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid API Key config with Vault store", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid API Key config - invalid hash algorithm", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "invalid",
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hash algorithm")
	})

	t.Run("invalid API Key config - invalid extraction type", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled: true,
			Extraction: []apikey.ExtractionSource{
				{Type: "invalid", Name: "X-API-Key"},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "extraction type")
	})

	t.Run("invalid API Key config - missing extraction name", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled: true,
			Extraction: []apikey.ExtractionSource{
				{Type: "header", Name: ""},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("invalid API Key config - file store without path", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled: true,
			Store: &apikey.StoreConfig{
				Type: "file",
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "filePath")
	})

	t.Run("invalid API Key config - Vault without mount", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled: true,
			Vault: &apikey.VaultConfig{
				Enabled: true,
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kvMount")
	})
}

func TestFunctional_AuthConfig_MTLSValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid mTLS config with CA file", func(t *testing.T) {
		t.Parallel()

		cfg := &mtls.Config{
			Enabled:           true,
			RequireClientCert: true,
			CAFile:            "/path/to/ca.crt",
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid mTLS config with CA cert", func(t *testing.T) {
		t.Parallel()

		cfg := &mtls.Config{
			Enabled:           true,
			RequireClientCert: true,
			CACert:            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid mTLS config with Vault", func(t *testing.T) {
		t.Parallel()

		cfg := &mtls.Config{
			Enabled:           true,
			RequireClientCert: true,
			Vault: &mtls.VaultConfig{
				Enabled:  true,
				PKIMount: "pki",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid mTLS config - no CA source", func(t *testing.T) {
		t.Parallel()

		cfg := &mtls.Config{
			Enabled:           true,
			RequireClientCert: true,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CA source")
	})

	t.Run("invalid mTLS config - Vault without mount", func(t *testing.T) {
		t.Parallel()

		cfg := &mtls.Config{
			Enabled: true,
			Vault: &mtls.VaultConfig{
				Enabled: true,
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pkiMount")
	})

	t.Run("invalid mTLS config - invalid subject field", func(t *testing.T) {
		t.Parallel()

		cfg := &mtls.Config{
			Enabled: true,
			CACert:  "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			ExtractIdentity: &mtls.IdentityExtractionConfig{
				SubjectField: "INVALID",
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subject field")
	})

	t.Run("invalid mTLS config - revocation without method", func(t *testing.T) {
		t.Parallel()

		cfg := &mtls.Config{
			Enabled: true,
			CACert:  "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			Revocation: &mtls.RevocationConfig{
				Enabled: true,
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "revocation method")
	})
}

func TestFunctional_AuthConfig_OIDCValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid OIDC config", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled: true,
			Providers: []oidc.ProviderConfig{
				{
					Name:     "test",
					Issuer:   "https://issuer.example.com",
					ClientID: "client-id",
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid OIDC config with multiple providers", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled: true,
			Providers: []oidc.ProviderConfig{
				{
					Name:     "provider1",
					Issuer:   "https://issuer1.example.com",
					ClientID: "client-id-1",
				},
				{
					Name:     "provider2",
					Issuer:   "https://issuer2.example.com",
					ClientID: "client-id-2",
				},
			},
			DefaultProvider: "provider1",
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid OIDC config with Keycloak", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled: true,
			Providers: []oidc.ProviderConfig{
				{
					Name:     "keycloak",
					Issuer:   "https://keycloak.example.com/realms/test",
					ClientID: "client-id",
					Type:     "keycloak",
					Keycloak: &oidc.KeycloakConfig{
						Realm:         "test",
						UseRealmRoles: true,
					},
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid OIDC config - no providers", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled:   true,
			Providers: []oidc.ProviderConfig{},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "provider")
	})

	t.Run("invalid OIDC config - missing provider name", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled: true,
			Providers: []oidc.ProviderConfig{
				{
					Issuer:   "https://issuer.example.com",
					ClientID: "client-id",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("invalid OIDC config - missing issuer", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled: true,
			Providers: []oidc.ProviderConfig{
				{
					Name:     "test",
					ClientID: "client-id",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer")
	})

	t.Run("invalid OIDC config - missing client ID", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled: true,
			Providers: []oidc.ProviderConfig{
				{
					Name:   "test",
					Issuer: "https://issuer.example.com",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clientId")
	})

	t.Run("invalid OIDC config - invalid provider type", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled: true,
			Providers: []oidc.ProviderConfig{
				{
					Name:     "test",
					Issuer:   "https://issuer.example.com",
					ClientID: "client-id",
					Type:     "invalid",
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "provider type")
	})

	t.Run("invalid OIDC config - default provider not found", func(t *testing.T) {
		t.Parallel()

		cfg := &oidc.Config{
			Enabled: true,
			Providers: []oidc.ProviderConfig{
				{
					Name:     "test",
					Issuer:   "https://issuer.example.com",
					ClientID: "client-id",
				},
			},
			DefaultProvider: "nonexistent",
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "default provider")
	})
}

func TestFunctional_AuthConfig_ExtractionValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid extraction config", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			JWT: &jwt.Config{
				Enabled: true,
				JWKSUrl: "https://example.com/.well-known/jwks.json",
			},
			Extraction: &auth.ExtractionConfig{
				JWT: []auth.ExtractionSource{
					{Type: auth.ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
					{Type: auth.ExtractionTypeCookie, Name: "jwt_token"},
				},
				APIKey: []auth.ExtractionSource{
					{Type: auth.ExtractionTypeHeader, Name: "X-API-Key"},
					{Type: auth.ExtractionTypeQuery, Name: "api_key"},
				},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid extraction config - invalid type", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			JWT: &jwt.Config{
				Enabled: true,
				JWKSUrl: "https://example.com/.well-known/jwks.json",
			},
			Extraction: &auth.ExtractionConfig{
				JWT: []auth.ExtractionSource{
					{Type: "invalid", Name: "Authorization"},
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "extraction type")
	})

	t.Run("invalid extraction config - missing name", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			JWT: &jwt.Config{
				Enabled: true,
				JWKSUrl: "https://example.com/.well-known/jwks.json",
			},
			Extraction: &auth.ExtractionConfig{
				JWT: []auth.ExtractionSource{
					{Type: auth.ExtractionTypeHeader, Name: ""},
				},
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})
}

func TestFunctional_AuthConfig_CacheValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid cache config", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			JWT: &jwt.Config{
				Enabled: true,
				JWKSUrl: "https://example.com/.well-known/jwks.json",
			},
			Cache: &auth.AuthCacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: 10000,
				Type:    "memory",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid cache config - negative TTL", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			JWT: &jwt.Config{
				Enabled: true,
				JWKSUrl: "https://example.com/.well-known/jwks.json",
			},
			Cache: &auth.AuthCacheConfig{
				Enabled: true,
				TTL:     -1 * time.Minute,
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ttl")
	})

	t.Run("invalid cache config - negative max size", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			JWT: &jwt.Config{
				Enabled: true,
				JWKSUrl: "https://example.com/.well-known/jwks.json",
			},
			Cache: &auth.AuthCacheConfig{
				Enabled: true,
				MaxSize: -1,
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maxSize")
	})

	t.Run("invalid cache config - invalid type", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			Enabled: true,
			JWT: &jwt.Config{
				Enabled: true,
				JWKSUrl: "https://example.com/.well-known/jwks.json",
			},
			Cache: &auth.AuthCacheConfig{
				Enabled: true,
				Type:    "invalid",
			},
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cache type")
	})
}

func TestFunctional_AuthConfig_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := auth.DefaultConfig()
	require.NotNil(t, cfg)

	assert.False(t, cfg.Enabled)
	assert.NotNil(t, cfg.Extraction)
	assert.NotNil(t, cfg.Cache)
	assert.True(t, cfg.Cache.Enabled)
	assert.Equal(t, "memory", cfg.Cache.Type)
}

func TestFunctional_AuthConfig_HelperMethods(t *testing.T) {
	t.Parallel()

	t.Run("IsJWTEnabled", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			JWT: &jwt.Config{Enabled: true},
		}
		assert.True(t, cfg.IsJWTEnabled())

		cfg.JWT.Enabled = false
		assert.False(t, cfg.IsJWTEnabled())

		cfg.JWT = nil
		assert.False(t, cfg.IsJWTEnabled())
	})

	t.Run("IsAPIKeyEnabled", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			APIKey: &apikey.Config{Enabled: true},
		}
		assert.True(t, cfg.IsAPIKeyEnabled())

		cfg.APIKey.Enabled = false
		assert.False(t, cfg.IsAPIKeyEnabled())

		cfg.APIKey = nil
		assert.False(t, cfg.IsAPIKeyEnabled())
	})

	t.Run("IsMTLSEnabled", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			MTLS: &mtls.Config{Enabled: true},
		}
		assert.True(t, cfg.IsMTLSEnabled())

		cfg.MTLS.Enabled = false
		assert.False(t, cfg.IsMTLSEnabled())

		cfg.MTLS = nil
		assert.False(t, cfg.IsMTLSEnabled())
	})

	t.Run("IsOIDCEnabled", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			OIDC: &oidc.Config{Enabled: true},
		}
		assert.True(t, cfg.IsOIDCEnabled())

		cfg.OIDC.Enabled = false
		assert.False(t, cfg.IsOIDCEnabled())

		cfg.OIDC = nil
		assert.False(t, cfg.IsOIDCEnabled())
	})

	t.Run("ShouldSkipPath", func(t *testing.T) {
		t.Parallel()

		cfg := &auth.Config{
			SkipPaths: []string{
				"/health",
				"/metrics",
				"/api/public/*",
			},
		}

		assert.True(t, cfg.ShouldSkipPath("/health"))
		assert.True(t, cfg.ShouldSkipPath("/metrics"))
		assert.True(t, cfg.ShouldSkipPath("/api/public/test"))
		assert.True(t, cfg.ShouldSkipPath("/api/public/nested/path"))
		assert.False(t, cfg.ShouldSkipPath("/api/private"))
		assert.False(t, cfg.ShouldSkipPath("/healthcheck"))
	})
}

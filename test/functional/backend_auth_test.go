//go:build functional
// +build functional

package functional

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestFunctional_BackendAuth_JWTConfig(t *testing.T) {
	t.Parallel()

	t.Run("backend with JWT authentication static token", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:      true,
				TokenSource:  "static",
				StaticToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
				HeaderName:   "Authorization",
				HeaderPrefix: "Bearer",
			},
		}

		err := authConfig.Validate()
		assert.NoError(t, err)
		assert.Equal(t, "jwt", authConfig.Type)
		assert.True(t, authConfig.JWT.Enabled)
		assert.Equal(t, "static", authConfig.JWT.TokenSource)
		assert.NotEmpty(t, authConfig.JWT.StaticToken)
	})

	t.Run("backend JWT auth with OIDC token source", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &config.BackendOIDCConfig{
					IssuerURL:     "http://127.0.0.1:8090/realms/test",
					ClientID:      "backend-service",
					ClientSecret:  "secret",
					Scopes:        []string{"openid"},
					TokenCacheTTL: config.Duration(5 * time.Minute),
				},
			},
		}

		err := authConfig.Validate()
		assert.NoError(t, err)
		assert.Equal(t, "oidc", authConfig.JWT.TokenSource)
		assert.NotNil(t, authConfig.JWT.OIDC)
	})

	t.Run("backend JWT auth with Vault token source", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "vault",
				VaultPath:   "secret/jwt-token",
			},
		}

		err := authConfig.Validate()
		assert.NoError(t, err)
		assert.Equal(t, "vault", authConfig.JWT.TokenSource)
		assert.NotEmpty(t, authConfig.JWT.VaultPath)
	})

	t.Run("backend JWT auth validation errors", func(t *testing.T) {
		t.Parallel()

		// Invalid token source
		authConfig := &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "invalid",
			},
		}
		err := authConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token source")

		// Static source without token
		authConfig = &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "",
			},
		}
		err = authConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "staticToken is required")

		// Vault source without path
		authConfig = &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "vault",
				VaultPath:   "",
			},
		}
		err = authConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "vaultPath is required")

		// OIDC source without config
		authConfig = &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC:        nil,
			},
		}
		err = authConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "oidc config is required")
	})
}

func TestFunctional_BackendAuth_BasicConfig(t *testing.T) {
	t.Parallel()

	t.Run("backend with Basic authentication static credentials", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "backend-user",
				Password: "backend-pass",
			},
		}

		err := authConfig.Validate()
		assert.NoError(t, err)
		assert.Equal(t, "basic", authConfig.Type)
		assert.True(t, authConfig.Basic.Enabled)
		assert.Equal(t, "backend-user", authConfig.Basic.Username)
		assert.Equal(t, "backend-pass", authConfig.Basic.Password)
	})

	t.Run("backend Basic auth with Vault credentials", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:     true,
				VaultPath:   "secret/backend-creds",
				UsernameKey: "user",
				PasswordKey: "pass",
			},
		}

		err := authConfig.Validate()
		assert.NoError(t, err)
		assert.NotEmpty(t, authConfig.Basic.VaultPath)
	})

	t.Run("backend Basic auth validation errors", func(t *testing.T) {
		t.Parallel()

		// Missing credentials
		authConfig := &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled: true,
			},
		}
		err := authConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either username/password or vaultPath is required")

		// Partial credentials
		authConfig = &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				// Missing password
			},
		}
		err = authConfig.Validate()
		assert.Error(t, err)
	})

	t.Run("backend Basic auth header generation", func(t *testing.T) {
		t.Parallel()

		username := "backend-user"
		password := "backend-pass"

		// Generate Basic auth header value
		credentials := username + ":" + password
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		headerValue := "Basic " + encoded

		assert.Contains(t, headerValue, "Basic ")
		assert.NotEmpty(t, encoded)

		// Decode and verify
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		require.NoError(t, err)
		assert.Equal(t, credentials, string(decoded))
	})
}

func TestFunctional_BackendAuth_MTLSConfig(t *testing.T) {
	t.Parallel()

	t.Run("backend with mTLS authentication file-based", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "mtls",
			MTLS: &config.BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: "/path/to/client.crt",
				KeyFile:  "/path/to/client.key",
				CAFile:   "/path/to/ca.crt",
			},
		}

		err := authConfig.Validate()
		assert.NoError(t, err)
		assert.Equal(t, "mtls", authConfig.Type)
		assert.True(t, authConfig.MTLS.Enabled)
		assert.NotEmpty(t, authConfig.MTLS.CertFile)
		assert.NotEmpty(t, authConfig.MTLS.KeyFile)
	})

	t.Run("backend mTLS auth with Vault PKI", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "mtls",
			MTLS: &config.BackendMTLSAuthConfig{
				Enabled: true,
				Vault: &config.VaultBackendTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "backend-role",
					CommonName: "backend-client.local",
					TTL:        "1h",
				},
			},
		}

		err := authConfig.Validate()
		assert.NoError(t, err)
		assert.NotNil(t, authConfig.MTLS.Vault)
		assert.True(t, authConfig.MTLS.Vault.Enabled)
	})

	t.Run("backend mTLS auth validation errors", func(t *testing.T) {
		t.Parallel()

		// Missing cert and vault
		authConfig := &config.BackendAuthConfig{
			Type: "mtls",
			MTLS: &config.BackendMTLSAuthConfig{
				Enabled: true,
			},
		}
		err := authConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either certFile/keyFile or vault config is required")

		// Partial file config
		authConfig = &config.BackendAuthConfig{
			Type: "mtls",
			MTLS: &config.BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				// Missing key file
			},
		}
		err = authConfig.Validate()
		assert.Error(t, err)

		// Invalid vault config
		authConfig = &config.BackendAuthConfig{
			Type: "mtls",
			MTLS: &config.BackendMTLSAuthConfig{
				Enabled: true,
				Vault: &config.VaultBackendTLSConfig{
					Enabled: true,
					// Missing required fields
				},
			},
		}
		err = authConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pkiMount is required")
	})
}

func TestFunctional_BackendAuth_HeaderVerification(t *testing.T) {
	t.Parallel()

	t.Run("JWT auth header name and prefix", func(t *testing.T) {
		t.Parallel()

		// Default header name and prefix
		jwtConfig := &config.BackendJWTAuthConfig{
			Enabled:     true,
			TokenSource: "static",
			StaticToken: "test-token",
		}

		assert.Equal(t, "Authorization", jwtConfig.GetEffectiveHeaderName())
		assert.Equal(t, "Bearer", jwtConfig.GetEffectiveHeaderPrefix())

		// Custom header name and prefix
		jwtConfig = &config.BackendJWTAuthConfig{
			Enabled:      true,
			TokenSource:  "static",
			StaticToken:  "test-token",
			HeaderName:   "X-Backend-Auth",
			HeaderPrefix: "Token",
		}

		assert.Equal(t, "X-Backend-Auth", jwtConfig.GetEffectiveHeaderName())
		assert.Equal(t, "Token", jwtConfig.GetEffectiveHeaderPrefix())
	})

	t.Run("Basic auth Vault key names", func(t *testing.T) {
		t.Parallel()

		// Default key names
		basicConfig := &config.BackendBasicAuthConfig{
			Enabled:   true,
			VaultPath: "secret/creds",
		}

		assert.Equal(t, "username", basicConfig.GetEffectiveUsernameKey())
		assert.Equal(t, "password", basicConfig.GetEffectivePasswordKey())

		// Custom key names
		basicConfig = &config.BackendBasicAuthConfig{
			Enabled:     true,
			VaultPath:   "secret/creds",
			UsernameKey: "user",
			PasswordKey: "pass",
		}

		assert.Equal(t, "user", basicConfig.GetEffectiveUsernameKey())
		assert.Equal(t, "pass", basicConfig.GetEffectivePasswordKey())
	})
}

func TestFunctional_BackendAuth_CustomHeaderName(t *testing.T) {
	t.Parallel()

	t.Run("backend authentication with custom header name", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:      true,
				TokenSource:  "static",
				StaticToken:  "custom-token-value",
				HeaderName:   "X-Backend-Auth",
				HeaderPrefix: "Token",
			},
		}

		err := authConfig.Validate()
		assert.NoError(t, err)

		// Verify custom header configuration
		assert.Equal(t, "X-Backend-Auth", authConfig.JWT.HeaderName)
		assert.Equal(t, "Token", authConfig.JWT.HeaderPrefix)

		// Build expected header value
		expectedHeader := authConfig.JWT.HeaderPrefix + " " + authConfig.JWT.StaticToken
		assert.Equal(t, "Token custom-token-value", expectedHeader)
	})
}

func TestFunctional_BackendAuth_TypeValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid auth types", func(t *testing.T) {
		t.Parallel()

		validTypes := []string{"jwt", "basic", "mtls", ""}

		for _, authType := range validTypes {
			authConfig := &config.BackendAuthConfig{
				Type: authType,
			}
			err := authConfig.Validate()
			assert.NoError(t, err, "Type '%s' should be valid", authType)
		}
	})

	t.Run("invalid auth type", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.BackendAuthConfig{
			Type: "invalid",
		}
		err := authConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend auth type")
	})
}

func TestFunctional_BackendAuth_OIDCConfig(t *testing.T) {
	t.Parallel()

	t.Run("OIDC config validation", func(t *testing.T) {
		t.Parallel()

		// Valid config with client secret
		oidcConfig := &config.BackendOIDCConfig{
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		}
		err := oidcConfig.Validate()
		assert.NoError(t, err)

		// Valid config with vault path
		oidcConfig = &config.BackendOIDCConfig{
			IssuerURL:             "https://issuer.example.com",
			ClientID:              "client-id",
			ClientSecretVaultPath: "secret/oidc-secret",
		}
		err = oidcConfig.Validate()
		assert.NoError(t, err)

		// Missing issuer URL
		oidcConfig = &config.BackendOIDCConfig{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		}
		err = oidcConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuerUrl is required")

		// Missing client ID
		oidcConfig = &config.BackendOIDCConfig{
			IssuerURL:    "https://issuer.example.com",
			ClientSecret: "client-secret",
		}
		err = oidcConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "clientId is required")

		// Missing both client secret and vault path
		oidcConfig = &config.BackendOIDCConfig{
			IssuerURL: "https://issuer.example.com",
			ClientID:  "client-id",
		}
		err = oidcConfig.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either clientSecret or clientSecretVaultPath is required")
	})

	t.Run("OIDC token cache TTL", func(t *testing.T) {
		t.Parallel()

		oidcConfig := &config.BackendOIDCConfig{
			IssuerURL:     "https://issuer.example.com",
			ClientID:      "client-id",
			ClientSecret:  "client-secret",
			TokenCacheTTL: config.Duration(5 * time.Minute),
		}

		assert.Equal(t, 5*time.Minute, oidcConfig.TokenCacheTTL.Duration())
	})
}

func TestFunctional_BackendAuth_BackendConfig(t *testing.T) {
	t.Parallel()

	t.Run("backend with authentication config", func(t *testing.T) {
		t.Parallel()

		backend := config.Backend{
			Name: "authenticated-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
			Authentication: &config.BackendAuthConfig{
				Type: "jwt",
				JWT: &config.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "static",
					StaticToken: "test-token",
				},
			},
		}

		require.NotNil(t, backend.Authentication)
		assert.Equal(t, "jwt", backend.Authentication.Type)
		assert.NotNil(t, backend.Authentication.JWT)
		assert.True(t, backend.Authentication.JWT.Enabled)
	})

	t.Run("backend with both circuit breaker and authentication", func(t *testing.T) {
		t.Parallel()

		backend := config.Backend{
			Name: "full-config-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   config.Duration(30 * time.Second),
			},
			Authentication: &config.BackendAuthConfig{
				Type: "basic",
				Basic: &config.BackendBasicAuthConfig{
					Enabled:  true,
					Username: "user",
					Password: "pass",
				},
			},
		}

		require.NotNil(t, backend.CircuitBreaker)
		require.NotNil(t, backend.Authentication)
		assert.True(t, backend.CircuitBreaker.Enabled)
		assert.Equal(t, "basic", backend.Authentication.Type)
	})
}

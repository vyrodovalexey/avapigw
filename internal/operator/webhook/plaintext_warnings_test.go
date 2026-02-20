// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// warnPlaintextAuthSecrets Tests
// ============================================================================

func TestWarnPlaintextAuthSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		auth             *avapigwv1alpha1.AuthenticationConfig
		expectedWarnings int
		wantSubstrings   []string
	}{
		{
			name: "nil JWT and OIDC - no warnings",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
			},
			expectedWarnings: 0,
		},
		{
			name: "JWT disabled - no warnings",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: false,
					Secret:  "my-secret",
				},
			},
			expectedWarnings: 0,
		},
		{
			name: "JWT enabled with plaintext secret",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					Secret:  "my-hmac-secret",
				},
			},
			expectedWarnings: 1,
			wantSubstrings:   []string{"authentication.jwt.secret"},
		},
		{
			name: "JWT enabled without secret - no warnings",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					JWKSURL: "https://example.com/.well-known/jwks.json",
				},
			},
			expectedWarnings: 0,
		},
		{
			name: "OIDC disabled - no warnings",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				OIDC: &avapigwv1alpha1.OIDCAuthConfig{
					Enabled: false,
					Providers: []avapigwv1alpha1.OIDCProviderConfig{
						{
							Name:         "test",
							ClientSecret: "plaintext-secret",
						},
					},
				},
			},
			expectedWarnings: 0,
		},
		{
			name: "OIDC enabled with plaintext client secret",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				OIDC: &avapigwv1alpha1.OIDCAuthConfig{
					Enabled: true,
					Providers: []avapigwv1alpha1.OIDCProviderConfig{
						{
							Name:         "keycloak",
							IssuerURL:    "https://keycloak.example.com",
							ClientID:     "my-client",
							ClientSecret: "plaintext-secret",
						},
					},
				},
			},
			expectedWarnings: 1,
			wantSubstrings:   []string{"authentication.oidc.providers[0].clientSecret"},
		},
		{
			name: "OIDC enabled with clientSecretRef - no warnings",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				OIDC: &avapigwv1alpha1.OIDCAuthConfig{
					Enabled: true,
					Providers: []avapigwv1alpha1.OIDCProviderConfig{
						{
							Name:         "keycloak",
							IssuerURL:    "https://keycloak.example.com",
							ClientID:     "my-client",
							ClientSecret: "plaintext-secret",
							ClientSecretRef: &avapigwv1alpha1.SecretKeySelector{
								Name: "my-secret",
								Key:  "client-secret",
							},
						},
					},
				},
			},
			expectedWarnings: 0,
		},
		{
			name: "both JWT secret and OIDC plaintext secret",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					Secret:  "my-hmac-secret",
				},
				OIDC: &avapigwv1alpha1.OIDCAuthConfig{
					Enabled: true,
					Providers: []avapigwv1alpha1.OIDCProviderConfig{
						{
							Name:         "provider1",
							IssuerURL:    "https://provider1.example.com",
							ClientID:     "client1",
							ClientSecret: "secret1",
						},
						{
							Name:         "provider2",
							IssuerURL:    "https://provider2.example.com",
							ClientID:     "client2",
							ClientSecret: "secret2",
						},
					},
				},
			},
			expectedWarnings: 3, // 1 JWT + 2 OIDC providers
			wantSubstrings: []string{
				"authentication.jwt.secret",
				"authentication.oidc.providers[0].clientSecret",
				"authentication.oidc.providers[1].clientSecret",
			},
		},
		{
			name: "OIDC with mixed providers - some with ref some without",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				OIDC: &avapigwv1alpha1.OIDCAuthConfig{
					Enabled: true,
					Providers: []avapigwv1alpha1.OIDCProviderConfig{
						{
							Name:         "provider-with-ref",
							IssuerURL:    "https://provider1.example.com",
							ClientID:     "client1",
							ClientSecret: "secret1",
							ClientSecretRef: &avapigwv1alpha1.SecretKeySelector{
								Name: "secret-ref",
								Key:  "key",
							},
						},
						{
							Name:         "provider-without-ref",
							IssuerURL:    "https://provider2.example.com",
							ClientID:     "client2",
							ClientSecret: "secret2",
						},
					},
				},
			},
			expectedWarnings: 1, // Only the provider without ref
			wantSubstrings:   []string{"authentication.oidc.providers[1].clientSecret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			warnings := warnPlaintextAuthSecrets(tt.auth)
			assert.Len(t, warnings, tt.expectedWarnings)

			for i, substr := range tt.wantSubstrings {
				if i < len(warnings) {
					assert.Contains(t, warnings[i], substr)
				}
			}
		})
	}
}

// ============================================================================
// warnPlaintextSentinelSecrets Tests
// ============================================================================

func TestWarnPlaintextSentinelSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		sentinel         *avapigwv1alpha1.RedisSentinelSpec
		expectedWarnings int
		wantSubstrings   []string
	}{
		{
			name: "no passwords - no warnings",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
			},
			expectedWarnings: 0,
		},
		{
			name: "password with vault path - no warnings",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:        "mymaster",
				SentinelAddrs:     []string{"sentinel-0:26379"},
				Password:          "my-password",
				PasswordVaultPath: "secret/redis/password",
			},
			expectedWarnings: 0,
		},
		{
			name: "sentinel password with vault path - no warnings",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:                "mymaster",
				SentinelAddrs:             []string{"sentinel-0:26379"},
				SentinelPassword:          "sentinel-pass",
				SentinelPasswordVaultPath: "secret/redis/sentinel-password",
			},
			expectedWarnings: 0,
		},
		{
			name: "plaintext password without vault path",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
				Password:      "my-password",
			},
			expectedWarnings: 1,
			wantSubstrings:   []string{"sentinel.password"},
		},
		{
			name: "plaintext sentinel password without vault path",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:       "mymaster",
				SentinelAddrs:    []string{"sentinel-0:26379"},
				SentinelPassword: "sentinel-pass",
			},
			expectedWarnings: 1,
			wantSubstrings:   []string{"sentinel.sentinelPassword"},
		},
		{
			name: "both plaintext passwords without vault paths",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:       "mymaster",
				SentinelAddrs:    []string{"sentinel-0:26379"},
				Password:         "my-password",
				SentinelPassword: "sentinel-pass",
			},
			expectedWarnings: 2,
			wantSubstrings: []string{
				"sentinel.password",
				"sentinel.sentinelPassword",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			warnings := warnPlaintextSentinelSecrets(tt.sentinel)
			assert.Len(t, warnings, tt.expectedWarnings)

			for i, substr := range tt.wantSubstrings {
				if i < len(warnings) {
					assert.Contains(t, warnings[i], substr)
				}
			}
		})
	}
}

// ============================================================================
// warnPlaintextBackendAuthSecrets Tests
// ============================================================================

func TestWarnPlaintextBackendAuthSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		auth             *avapigwv1alpha1.BackendAuthConfig
		expectedWarnings int
		wantSubstrings   []string
	}{
		{
			name: "no plaintext secrets",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "vault",
					VaultPath:   "secret/jwt",
				},
			},
			expectedWarnings: 0,
		},
		{
			name: "basic auth with plaintext password",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled:  true,
					Username: "user",
					Password: "pass",
				},
			},
			expectedWarnings: 1,
			wantSubstrings:   []string{"authentication.basic.password"},
		},
		{
			name: "basic auth with vault path - no warnings",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled:   true,
					Username:  "user",
					Password:  "pass",
					VaultPath: "secret/basic",
				},
			},
			expectedWarnings: 0,
		},
		{
			name: "JWT OIDC with plaintext client secret",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "oidc",
					OIDC: &avapigwv1alpha1.BackendOIDCConfig{
						IssuerURL:    "https://issuer.example.com",
						ClientID:     "client-id",
						ClientSecret: "plaintext-secret",
					},
				},
			},
			expectedWarnings: 1,
			wantSubstrings:   []string{"authentication.jwt.oidc.clientSecret"},
		},
		{
			name: "JWT OIDC with clientSecretRef - no warnings",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "oidc",
					OIDC: &avapigwv1alpha1.BackendOIDCConfig{
						IssuerURL:    "https://issuer.example.com",
						ClientID:     "client-id",
						ClientSecret: "plaintext-secret",
						ClientSecretRef: &avapigwv1alpha1.SecretKeySelector{
							Name: "secret-ref",
							Key:  "key",
						},
					},
				},
			},
			expectedWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			warnings := warnPlaintextBackendAuthSecrets(tt.auth)
			assert.Len(t, warnings, tt.expectedWarnings)

			for i, substr := range tt.wantSubstrings {
				if i < len(warnings) {
					assert.Contains(t, warnings[i], substr)
				}
			}
		})
	}
}

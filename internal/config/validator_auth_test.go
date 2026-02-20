package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// Authentication Validation Tests
// ============================================================

func TestValidator_ValidateAuthentication(t *testing.T) {
	t.Parallel()

	baseConfig := func(auth *AuthenticationConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners:      []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Authentication: auth,
			},
		}
	}

	tests := []struct {
		name         string
		auth         *AuthenticationConfig
		wantErr      bool
		errContains  string
		wantWarnings int
		warnContains string
	}{
		{
			name:    "nil authentication - no validation",
			auth:    nil,
			wantErr: false,
		},
		{
			name:    "disabled authentication - no validation",
			auth:    &AuthenticationConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "enabled with no methods and no anonymous - warning",
			auth: &AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: false,
			},
			wantErr:      false,
			wantWarnings: 1,
			warnContains: "no authentication method is configured",
		},
		{
			name: "enabled with allow anonymous - no warning",
			auth: &AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
			},
			wantErr:      false,
			wantWarnings: 0,
		},
		{
			name: "valid JWT config",
			auth: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled: true,
					JWKSURL: "https://example.com/.well-known/jwks.json",
				},
			},
			wantErr: false,
		},
		{
			name: "valid JWT with secret",
			auth: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled: true,
					Secret:  "my-secret-key",
				},
			},
			wantErr: false,
		},
		{
			name: "valid JWT with public key",
			auth: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled:   true,
					PublicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid JWT - no key source",
			auth: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled: true,
				},
			},
			wantErr:     true,
			errContains: "JWT requires at least one of jwksUrl, secret, or publicKey",
		},
		{
			name: "valid API key with header",
			auth: &AuthenticationConfig{
				Enabled: true,
				APIKey: &APIKeyAuthConfig{
					Enabled: true,
					Header:  "X-API-Key",
				},
			},
			wantErr: false,
		},
		{
			name: "valid API key with query",
			auth: &AuthenticationConfig{
				Enabled: true,
				APIKey: &APIKeyAuthConfig{
					Enabled: true,
					Query:   "api_key",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid API key - no header or query",
			auth: &AuthenticationConfig{
				Enabled: true,
				APIKey: &APIKeyAuthConfig{
					Enabled: true,
				},
			},
			wantErr:     true,
			errContains: "API key requires at least one of header or query parameter name",
		},
		{
			name: "valid mTLS config",
			auth: &AuthenticationConfig{
				Enabled: true,
				MTLS: &MTLSAuthConfig{
					Enabled: true,
					CAFile:  "/path/to/ca.pem",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid mTLS - missing CA file",
			auth: &AuthenticationConfig{
				Enabled: true,
				MTLS: &MTLSAuthConfig{
					Enabled: true,
				},
			},
			wantErr:     true,
			errContains: "caFile is required for mTLS authentication",
		},
		{
			name: "valid OIDC config",
			auth: &AuthenticationConfig{
				Enabled: true,
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{
							Name:      "google",
							IssuerURL: "https://accounts.google.com",
							ClientID:  "my-client-id",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid OIDC - empty providers",
			auth: &AuthenticationConfig{
				Enabled: true,
				OIDC: &OIDCAuthConfig{
					Enabled:   true,
					Providers: []OIDCProviderConfig{},
				},
			},
			wantErr:     true,
			errContains: "at least one OIDC provider is required",
		},
		{
			name: "invalid OIDC - missing issuer URL",
			auth: &AuthenticationConfig{
				Enabled: true,
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{
							Name:     "google",
							ClientID: "my-client-id",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "issuerUrl is required",
		},
		{
			name: "invalid OIDC - missing client ID",
			auth: &AuthenticationConfig{
				Enabled: true,
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{
							Name:      "google",
							IssuerURL: "https://accounts.google.com",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "clientId is required",
		},
		{
			name: "invalid OIDC - missing provider name",
			auth: &AuthenticationConfig{
				Enabled: true,
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{
							IssuerURL: "https://accounts.google.com",
							ClientID:  "my-client-id",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "provider name is required",
		},
		{
			name: "invalid OIDC - duplicate provider names",
			auth: &AuthenticationConfig{
				Enabled: true,
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{
							Name:      "google",
							IssuerURL: "https://accounts.google.com",
							ClientID:  "client-1",
						},
						{
							Name:      "google",
							IssuerURL: "https://accounts.google.com",
							ClientID:  "client-2",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "duplicate OIDC provider name",
		},
		{
			name: "multiple auth methods configured",
			auth: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled: true,
					JWKSURL: "https://example.com/.well-known/jwks.json",
				},
				APIKey: &APIKeyAuthConfig{
					Enabled: true,
					Header:  "X-API-Key",
				},
			},
			wantErr: false,
		},
		{
			name: "disabled JWT method not validated",
			auth: &AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
				JWT: &JWTAuthConfig{
					Enabled: false,
					// Missing key source, but should not be validated since disabled
				},
			},
			wantErr: false,
		},
		{
			name: "disabled API key method not validated",
			auth: &AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
				APIKey: &APIKeyAuthConfig{
					Enabled: false,
					// Missing header/query, but should not be validated since disabled
				},
			},
			wantErr: false,
		},
		{
			name: "disabled mTLS method not validated",
			auth: &AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
				MTLS: &MTLSAuthConfig{
					Enabled: false,
					// Missing CA file, but should not be validated since disabled
				},
			},
			wantErr: false,
		},
		{
			name: "disabled OIDC method not validated",
			auth: &AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
				OIDC: &OIDCAuthConfig{
					Enabled: false,
					// Empty providers, but should not be validated since disabled
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			warnings, err := ValidateConfigWithWarnings(baseConfig(tt.auth))

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}

			if tt.wantWarnings > 0 {
				require.Len(t, warnings, tt.wantWarnings)
				if tt.warnContains != "" {
					assert.Contains(t, warnings[0].Message, tt.warnContains)
				}
			}
		})
	}
}

// ============================================================
// Authorization Validation Tests
// ============================================================

func TestValidator_ValidateAuthorization(t *testing.T) {
	t.Parallel()

	baseConfig := func(authz *AuthorizationConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners:     []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Authorization: authz,
			},
		}
	}

	tests := []struct {
		name         string
		authz        *AuthorizationConfig
		wantErr      bool
		errContains  string
		wantWarnings int
		warnContains string
	}{
		{
			name:    "nil authorization - no validation",
			authz:   nil,
			wantErr: false,
		},
		{
			name:    "disabled authorization - no validation",
			authz:   &AuthorizationConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "valid default policy allow",
			authz: &AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "allow",
			},
			wantErr: false,
		},
		{
			name: "valid default policy deny",
			authz: &AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
			},
			wantErr: false,
		},
		{
			name: "invalid default policy",
			authz: &AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "invalid",
			},
			wantErr:     true,
			errContains: "invalid default policy",
		},
		{
			name: "empty default policy - valid",
			authz: &AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "",
			},
			wantErr: false,
		},
		{
			name: "valid RBAC config",
			authz: &AuthorizationConfig{
				Enabled: true,
				RBAC: &RBACConfig{
					Enabled: true,
					Policies: []RBACPolicyConfig{
						{
							Name:   "admin-policy",
							Roles:  []string{"admin"},
							Effect: "allow",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "RBAC enabled with no policies - warning",
			authz: &AuthorizationConfig{
				Enabled: true,
				RBAC: &RBACConfig{
					Enabled:  true,
					Policies: []RBACPolicyConfig{},
				},
			},
			wantErr:      false,
			wantWarnings: 1,
			warnContains: "RBAC is enabled but no policies are defined",
		},
		{
			name: "RBAC policy missing name",
			authz: &AuthorizationConfig{
				Enabled: true,
				RBAC: &RBACConfig{
					Enabled: true,
					Policies: []RBACPolicyConfig{
						{
							Roles:  []string{"admin"},
							Effect: "allow",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "policy name is required",
		},
		{
			name: "RBAC policy duplicate name",
			authz: &AuthorizationConfig{
				Enabled: true,
				RBAC: &RBACConfig{
					Enabled: true,
					Policies: []RBACPolicyConfig{
						{
							Name:   "policy1",
							Roles:  []string{"admin"},
							Effect: "allow",
						},
						{
							Name:   "policy1",
							Roles:  []string{"user"},
							Effect: "deny",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "duplicate RBAC policy name",
		},
		{
			name: "RBAC policy missing roles",
			authz: &AuthorizationConfig{
				Enabled: true,
				RBAC: &RBACConfig{
					Enabled: true,
					Policies: []RBACPolicyConfig{
						{
							Name:   "policy1",
							Roles:  []string{},
							Effect: "allow",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "at least one role is required",
		},
		{
			name: "RBAC policy invalid effect",
			authz: &AuthorizationConfig{
				Enabled: true,
				RBAC: &RBACConfig{
					Enabled: true,
					Policies: []RBACPolicyConfig{
						{
							Name:   "policy1",
							Roles:  []string{"admin"},
							Effect: "invalid",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "invalid effect",
		},
		{
			name: "RBAC policy empty effect - valid",
			authz: &AuthorizationConfig{
				Enabled: true,
				RBAC: &RBACConfig{
					Enabled: true,
					Policies: []RBACPolicyConfig{
						{
							Name:  "policy1",
							Roles: []string{"admin"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ABAC config",
			authz: &AuthorizationConfig{
				Enabled: true,
				ABAC: &ABACConfig{
					Enabled: true,
					Policies: []ABACPolicyConfig{
						{
							Name:       "time-policy",
							Expression: "request.time.getHours() >= 9 && request.time.getHours() <= 17",
							Effect:     "allow",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ABAC enabled with no policies - warning",
			authz: &AuthorizationConfig{
				Enabled: true,
				ABAC: &ABACConfig{
					Enabled:  true,
					Policies: []ABACPolicyConfig{},
				},
			},
			wantErr:      false,
			wantWarnings: 1,
			warnContains: "ABAC is enabled but no policies are defined",
		},
		{
			name: "ABAC policy missing name",
			authz: &AuthorizationConfig{
				Enabled: true,
				ABAC: &ABACConfig{
					Enabled: true,
					Policies: []ABACPolicyConfig{
						{
							Expression: "true",
							Effect:     "allow",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "policy name is required",
		},
		{
			name: "ABAC policy duplicate name",
			authz: &AuthorizationConfig{
				Enabled: true,
				ABAC: &ABACConfig{
					Enabled: true,
					Policies: []ABACPolicyConfig{
						{
							Name:       "policy1",
							Expression: "true",
							Effect:     "allow",
						},
						{
							Name:       "policy1",
							Expression: "false",
							Effect:     "deny",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "duplicate ABAC policy name",
		},
		{
			name: "ABAC policy missing expression",
			authz: &AuthorizationConfig{
				Enabled: true,
				ABAC: &ABACConfig{
					Enabled: true,
					Policies: []ABACPolicyConfig{
						{
							Name:   "policy1",
							Effect: "allow",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "expression is required",
		},
		{
			name: "ABAC policy invalid effect",
			authz: &AuthorizationConfig{
				Enabled: true,
				ABAC: &ABACConfig{
					Enabled: true,
					Policies: []ABACPolicyConfig{
						{
							Name:       "policy1",
							Expression: "true",
							Effect:     "audit",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "invalid effect",
		},
		{
			name: "valid external authz with OPA",
			authz: &AuthorizationConfig{
				Enabled: true,
				External: &ExternalAuthzConfig{
					Enabled: true,
					OPA: &OPAAuthzConfig{
						URL:    "http://opa:8181/v1/data/authz",
						Policy: "authz/allow",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "external authz OPA missing URL",
			authz: &AuthorizationConfig{
				Enabled: true,
				External: &ExternalAuthzConfig{
					Enabled: true,
					OPA: &OPAAuthzConfig{
						Policy: "authz/allow",
					},
				},
			},
			wantErr:     true,
			errContains: "OPA URL is required",
		},
		{
			name: "external authz negative timeout",
			authz: &AuthorizationConfig{
				Enabled: true,
				External: &ExternalAuthzConfig{
					Enabled: true,
					Timeout: Duration(-1 * time.Second),
				},
			},
			wantErr:     true,
			errContains: "timeout cannot be negative",
		},
		{
			name: "external authz valid timeout",
			authz: &AuthorizationConfig{
				Enabled: true,
				External: &ExternalAuthzConfig{
					Enabled: true,
					Timeout: Duration(5 * time.Second),
				},
			},
			wantErr: false,
		},
		{
			name: "external authz no OPA - valid",
			authz: &AuthorizationConfig{
				Enabled: true,
				External: &ExternalAuthzConfig{
					Enabled: true,
				},
			},
			wantErr: false,
		},
		{
			name: "valid authz cache config",
			authz: &AuthorizationConfig{
				Enabled: true,
				Cache: &AuthzCacheConfig{
					Enabled: true,
					TTL:     Duration(5 * time.Minute),
					MaxSize: 1000,
					Type:    "memory",
				},
			},
			wantErr: false,
		},
		{
			name: "valid authz cache redis type",
			authz: &AuthorizationConfig{
				Enabled: true,
				Cache: &AuthzCacheConfig{
					Enabled: true,
					TTL:     Duration(5 * time.Minute),
					MaxSize: 1000,
					Type:    "redis",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid authz cache type",
			authz: &AuthorizationConfig{
				Enabled: true,
				Cache: &AuthzCacheConfig{
					Enabled: true,
					Type:    "invalid",
				},
			},
			wantErr:     true,
			errContains: "invalid cache type",
		},
		{
			name: "authz cache negative TTL",
			authz: &AuthorizationConfig{
				Enabled: true,
				Cache: &AuthzCacheConfig{
					Enabled: true,
					TTL:     Duration(-1 * time.Second),
				},
			},
			wantErr:     true,
			errContains: "TTL cannot be negative",
		},
		{
			name: "authz cache negative maxSize",
			authz: &AuthorizationConfig{
				Enabled: true,
				Cache: &AuthzCacheConfig{
					Enabled: true,
					MaxSize: -1,
				},
			},
			wantErr:     true,
			errContains: "maxSize cannot be negative",
		},
		{
			name: "authz cache empty type - valid",
			authz: &AuthorizationConfig{
				Enabled: true,
				Cache: &AuthzCacheConfig{
					Enabled: true,
					Type:    "",
				},
			},
			wantErr: false,
		},
		{
			name: "disabled RBAC not validated",
			authz: &AuthorizationConfig{
				Enabled: true,
				RBAC: &RBACConfig{
					Enabled: false,
					// Empty policies, but should not be validated since disabled
				},
			},
			wantErr: false,
		},
		{
			name: "disabled ABAC not validated",
			authz: &AuthorizationConfig{
				Enabled: true,
				ABAC: &ABACConfig{
					Enabled: false,
				},
			},
			wantErr: false,
		},
		{
			name: "disabled external not validated",
			authz: &AuthorizationConfig{
				Enabled: true,
				External: &ExternalAuthzConfig{
					Enabled: false,
				},
			},
			wantErr: false,
		},
		{
			name: "disabled cache not validated",
			authz: &AuthorizationConfig{
				Enabled: true,
				Cache: &AuthzCacheConfig{
					Enabled: false,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			warnings, err := ValidateConfigWithWarnings(baseConfig(tt.authz))

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}

			if tt.wantWarnings > 0 {
				require.Len(t, warnings, tt.wantWarnings)
				if tt.warnContains != "" {
					assert.Contains(t, warnings[0].Message, tt.warnContains)
				}
			}
		})
	}
}

// ============================================================
// Direct unit tests for individual validation functions
// ============================================================

func TestValidator_ValidateAuthMethodsConfigured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		auth         *AuthenticationConfig
		wantWarnings int
	}{
		{
			name: "no methods and no anonymous - warning",
			auth: &AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: false,
			},
			wantWarnings: 1,
		},
		{
			name: "JWT enabled - no warning",
			auth: &AuthenticationConfig{
				Enabled: true,
				JWT:     &JWTAuthConfig{Enabled: true, JWKSURL: "https://example.com/jwks"},
			},
			wantWarnings: 0,
		},
		{
			name: "API key enabled - no warning",
			auth: &AuthenticationConfig{
				Enabled: true,
				APIKey:  &APIKeyAuthConfig{Enabled: true, Header: "X-API-Key"},
			},
			wantWarnings: 0,
		},
		{
			name: "mTLS enabled - no warning",
			auth: &AuthenticationConfig{
				Enabled: true,
				MTLS:    &MTLSAuthConfig{Enabled: true, CAFile: "/ca.pem"},
			},
			wantWarnings: 0,
		},
		{
			name: "OIDC enabled - no warning",
			auth: &AuthenticationConfig{
				Enabled: true,
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{Name: "p1", IssuerURL: "https://issuer.com", ClientID: "cid"},
					},
				},
			},
			wantWarnings: 0,
		},
		{
			name: "allow anonymous - no warning",
			auth: &AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
			},
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateAuthMethodsConfigured(tt.auth, "spec.authentication")

			assert.Len(t, v.Warnings(), tt.wantWarnings)
		})
	}
}

func TestValidator_ValidateAuthMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		auth    *AuthenticationConfig
		wantErr bool
	}{
		{
			name: "valid JWT method",
			auth: &AuthenticationConfig{
				JWT: &JWTAuthConfig{Enabled: true, JWKSURL: "https://example.com/jwks"},
			},
			wantErr: false,
		},
		{
			name: "invalid JWT method",
			auth: &AuthenticationConfig{
				JWT: &JWTAuthConfig{Enabled: true},
			},
			wantErr: true,
		},
		{
			name: "valid API key method",
			auth: &AuthenticationConfig{
				APIKey: &APIKeyAuthConfig{Enabled: true, Header: "X-API-Key"},
			},
			wantErr: false,
		},
		{
			name: "invalid API key method",
			auth: &AuthenticationConfig{
				APIKey: &APIKeyAuthConfig{Enabled: true},
			},
			wantErr: true,
		},
		{
			name: "valid mTLS method",
			auth: &AuthenticationConfig{
				MTLS: &MTLSAuthConfig{Enabled: true, CAFile: "/ca.pem"},
			},
			wantErr: false,
		},
		{
			name: "invalid mTLS method",
			auth: &AuthenticationConfig{
				MTLS: &MTLSAuthConfig{Enabled: true},
			},
			wantErr: true,
		},
		{
			name: "valid OIDC method",
			auth: &AuthenticationConfig{
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{Name: "p1", IssuerURL: "https://issuer.com", ClientID: "cid"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid OIDC method",
			auth: &AuthenticationConfig{
				OIDC: &OIDCAuthConfig{
					Enabled:   true,
					Providers: []OIDCProviderConfig{},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateAuthMethods(tt.auth, "spec.authentication")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
			} else {
				assert.False(t, v.errors.HasErrors())
			}
		})
	}
}

func TestValidator_ValidateJWTAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		jwt     *JWTAuthConfig
		wantErr bool
	}{
		{
			name:    "valid with JWKS URL",
			jwt:     &JWTAuthConfig{Enabled: true, JWKSURL: "https://example.com/jwks"},
			wantErr: false,
		},
		{
			name:    "valid with secret",
			jwt:     &JWTAuthConfig{Enabled: true, Secret: "secret"},
			wantErr: false,
		},
		{
			name:    "valid with public key",
			jwt:     &JWTAuthConfig{Enabled: true, PublicKey: "key"},
			wantErr: false,
		},
		{
			name:    "valid with multiple key sources",
			jwt:     &JWTAuthConfig{Enabled: true, JWKSURL: "https://example.com/jwks", Secret: "secret"},
			wantErr: false,
		},
		{
			name:    "invalid - no key source",
			jwt:     &JWTAuthConfig{Enabled: true},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateJWTAuth(tt.jwt, "spec.authentication.jwt")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
			} else {
				assert.False(t, v.errors.HasErrors())
			}
		})
	}
}

func TestValidator_ValidateAPIKeyAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		apiKey  *APIKeyAuthConfig
		wantErr bool
	}{
		{
			name:    "valid with header",
			apiKey:  &APIKeyAuthConfig{Enabled: true, Header: "X-API-Key"},
			wantErr: false,
		},
		{
			name:    "valid with query",
			apiKey:  &APIKeyAuthConfig{Enabled: true, Query: "api_key"},
			wantErr: false,
		},
		{
			name:    "valid with both",
			apiKey:  &APIKeyAuthConfig{Enabled: true, Header: "X-API-Key", Query: "api_key"},
			wantErr: false,
		},
		{
			name:    "invalid - missing both",
			apiKey:  &APIKeyAuthConfig{Enabled: true},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateAPIKeyAuth(tt.apiKey, "spec.authentication.apiKey")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
			} else {
				assert.False(t, v.errors.HasErrors())
			}
		})
	}
}

func TestValidator_ValidateMTLSAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mtls    *MTLSAuthConfig
		wantErr bool
	}{
		{
			name:    "valid with CA file",
			mtls:    &MTLSAuthConfig{Enabled: true, CAFile: "/path/to/ca.pem"},
			wantErr: false,
		},
		{
			name:    "invalid - missing CA file",
			mtls:    &MTLSAuthConfig{Enabled: true},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateMTLSAuth(tt.mtls, "spec.authentication.mtls")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
			} else {
				assert.False(t, v.errors.HasErrors())
			}
		})
	}
}

func TestValidator_ValidateOIDCAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oidc    *OIDCAuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid single provider",
			oidc: &OIDCAuthConfig{
				Enabled: true,
				Providers: []OIDCProviderConfig{
					{Name: "google", IssuerURL: "https://accounts.google.com", ClientID: "cid"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid multiple providers",
			oidc: &OIDCAuthConfig{
				Enabled: true,
				Providers: []OIDCProviderConfig{
					{Name: "google", IssuerURL: "https://accounts.google.com", ClientID: "cid1"},
					{Name: "github", IssuerURL: "https://github.com", ClientID: "cid2"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty providers",
			oidc: &OIDCAuthConfig{
				Enabled:   true,
				Providers: []OIDCProviderConfig{},
			},
			wantErr: true,
			errMsg:  "at least one OIDC provider is required",
		},
		{
			name: "missing issuer URL",
			oidc: &OIDCAuthConfig{
				Enabled: true,
				Providers: []OIDCProviderConfig{
					{Name: "google", ClientID: "cid"},
				},
			},
			wantErr: true,
			errMsg:  "issuerUrl is required",
		},
		{
			name: "missing client ID",
			oidc: &OIDCAuthConfig{
				Enabled: true,
				Providers: []OIDCProviderConfig{
					{Name: "google", IssuerURL: "https://accounts.google.com"},
				},
			},
			wantErr: true,
			errMsg:  "clientId is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateOIDCAuth(tt.oidc, "spec.authentication.oidc")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
				if tt.errMsg != "" {
					assert.Contains(t, v.errors.Error(), tt.errMsg)
				}
			} else {
				assert.False(t, v.errors.HasErrors())
			}
		})
	}
}

func TestValidator_ValidatePolicyEffect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		effect  string
		wantErr bool
	}{
		{name: "allow", effect: "allow", wantErr: false},
		{name: "deny", effect: "deny", wantErr: false},
		{name: "invalid - audit", effect: "audit", wantErr: true},
		{name: "invalid - empty", effect: "", wantErr: true},
		{name: "invalid - random", effect: "random", wantErr: true},
		{name: "invalid - ALLOW uppercase", effect: "ALLOW", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validatePolicyEffect(tt.effect, "test.path")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
				assert.Contains(t, v.errors.Error(), "invalid effect")
			} else {
				assert.False(t, v.errors.HasErrors())
			}
		})
	}
}

func TestValidator_ValidateRBACConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rbac         *RBACConfig
		wantErr      bool
		errContains  string
		wantWarnings int
	}{
		{
			name: "valid policies",
			rbac: &RBACConfig{
				Enabled: true,
				Policies: []RBACPolicyConfig{
					{Name: "p1", Roles: []string{"admin"}, Effect: "allow"},
					{Name: "p2", Roles: []string{"user"}, Effect: "deny"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty policies - warning",
			rbac: &RBACConfig{
				Enabled:  true,
				Policies: []RBACPolicyConfig{},
			},
			wantErr:      false,
			wantWarnings: 1,
		},
		{
			name: "missing roles",
			rbac: &RBACConfig{
				Enabled: true,
				Policies: []RBACPolicyConfig{
					{Name: "p1", Roles: []string{}, Effect: "allow"},
				},
			},
			wantErr:     true,
			errContains: "at least one role is required",
		},
		{
			name: "invalid effect",
			rbac: &RBACConfig{
				Enabled: true,
				Policies: []RBACPolicyConfig{
					{Name: "p1", Roles: []string{"admin"}, Effect: "invalid"},
				},
			},
			wantErr:     true,
			errContains: "invalid effect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateRBACConfig(tt.rbac, "spec.authorization.rbac")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
				if tt.errContains != "" {
					assert.Contains(t, v.errors.Error(), tt.errContains)
				}
			} else {
				assert.False(t, v.errors.HasErrors())
			}

			if tt.wantWarnings > 0 {
				assert.Len(t, v.Warnings(), tt.wantWarnings)
			}
		})
	}
}

func TestValidator_ValidateABACConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		abac         *ABACConfig
		wantErr      bool
		errContains  string
		wantWarnings int
	}{
		{
			name: "valid policies",
			abac: &ABACConfig{
				Enabled: true,
				Policies: []ABACPolicyConfig{
					{Name: "p1", Expression: "true", Effect: "allow"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty policies - warning",
			abac: &ABACConfig{
				Enabled:  true,
				Policies: []ABACPolicyConfig{},
			},
			wantErr:      false,
			wantWarnings: 1,
		},
		{
			name: "missing expression",
			abac: &ABACConfig{
				Enabled: true,
				Policies: []ABACPolicyConfig{
					{Name: "p1", Effect: "allow"},
				},
			},
			wantErr:     true,
			errContains: "expression is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateABACConfig(tt.abac, "spec.authorization.abac")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
				if tt.errContains != "" {
					assert.Contains(t, v.errors.Error(), tt.errContains)
				}
			} else {
				assert.False(t, v.errors.HasErrors())
			}

			if tt.wantWarnings > 0 {
				assert.Len(t, v.Warnings(), tt.wantWarnings)
			}
		})
	}
}

func TestValidator_ValidateExternalAuthzConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ext         *ExternalAuthzConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid OPA config",
			ext: &ExternalAuthzConfig{
				Enabled: true,
				OPA:     &OPAAuthzConfig{URL: "http://opa:8181/v1/data/authz"},
			},
			wantErr: false,
		},
		{
			name: "OPA missing URL",
			ext: &ExternalAuthzConfig{
				Enabled: true,
				OPA:     &OPAAuthzConfig{Policy: "authz/allow"},
			},
			wantErr:     true,
			errContains: "OPA URL is required",
		},
		{
			name: "no OPA - valid",
			ext: &ExternalAuthzConfig{
				Enabled: true,
			},
			wantErr: false,
		},
		{
			name: "negative timeout",
			ext: &ExternalAuthzConfig{
				Enabled: true,
				Timeout: Duration(-1 * time.Second),
			},
			wantErr:     true,
			errContains: "timeout cannot be negative",
		},
		{
			name: "valid timeout",
			ext: &ExternalAuthzConfig{
				Enabled: true,
				Timeout: Duration(5 * time.Second),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateExternalAuthzConfig(tt.ext, "spec.authorization.external")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
				if tt.errContains != "" {
					assert.Contains(t, v.errors.Error(), tt.errContains)
				}
			} else {
				assert.False(t, v.errors.HasErrors())
			}
		})
	}
}

func TestValidator_ValidateAuthzCacheConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cache       *AuthzCacheConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid memory cache",
			cache: &AuthzCacheConfig{
				Enabled: true,
				TTL:     Duration(5 * time.Minute),
				MaxSize: 1000,
				Type:    "memory",
			},
			wantErr: false,
		},
		{
			name: "valid redis cache",
			cache: &AuthzCacheConfig{
				Enabled: true,
				TTL:     Duration(5 * time.Minute),
				MaxSize: 1000,
				Type:    "redis",
			},
			wantErr: false,
		},
		{
			name: "invalid type",
			cache: &AuthzCacheConfig{
				Enabled: true,
				Type:    "memcached",
			},
			wantErr:     true,
			errContains: "invalid cache type",
		},
		{
			name: "negative TTL",
			cache: &AuthzCacheConfig{
				Enabled: true,
				TTL:     Duration(-1 * time.Second),
			},
			wantErr:     true,
			errContains: "TTL cannot be negative",
		},
		{
			name: "negative maxSize",
			cache: &AuthzCacheConfig{
				Enabled: true,
				MaxSize: -1,
			},
			wantErr:     true,
			errContains: "maxSize cannot be negative",
		},
		{
			name: "empty type - valid",
			cache: &AuthzCacheConfig{
				Enabled: true,
				Type:    "",
			},
			wantErr: false,
		},
		{
			name: "zero TTL - valid",
			cache: &AuthzCacheConfig{
				Enabled: true,
				TTL:     Duration(0),
			},
			wantErr: false,
		},
		{
			name: "zero maxSize - valid",
			cache: &AuthzCacheConfig{
				Enabled: true,
				MaxSize: 0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			v.validateAuthzCacheConfig(tt.cache, "spec.authorization.cache")

			if tt.wantErr {
				assert.True(t, v.errors.HasErrors())
				if tt.errContains != "" {
					assert.Contains(t, v.errors.Error(), tt.errContains)
				}
			} else {
				assert.False(t, v.errors.HasErrors())
			}
		})
	}
}

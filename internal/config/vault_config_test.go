package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// Fixtures
// ============================================================================

// fullVaultConfig returns a VaultConfig with every field populated.
func fullVaultConfig() *VaultConfig {
	return &VaultConfig{
		Enabled:    true,
		Address:    "https://vault.example.com:8200",
		Namespace:  "team-a",
		AuthMethod: VaultAuthMethodAppRole,
		Token:      "inline-token",
		TokenFile:  "/etc/vault/token",
		Kubernetes: &VaultKubernetesAuthConfig{
			Role:      "gateway",
			MountPath: "k8s",
			TokenPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		AppRole: &VaultAppRoleAuthConfig{
			RoleID:       "role-id",
			SecretID:     "secret-id",
			SecretIDFile: "/etc/vault/secret-id",
			MountPath:    "approle-alt",
		},
		TLS: &VaultClientTLSConfig{
			CACert:     "/etc/ssl/ca.pem",
			CAPath:     "/etc/ssl/cas",
			ClientCert: "/etc/ssl/client.pem",
			ClientKey:  "/etc/ssl/client-key.pem",
			ServerName: "vault.internal",
			SkipVerify: true,
		},
		Cache: &VaultClientCacheConfig{
			Enabled: true,
			TTL:     Duration(5 * time.Minute),
			MaxSize: 500,
		},
		Retry: &VaultClientRetryConfig{
			MaxRetries:  4,
			BackoffBase: Duration(100 * time.Millisecond),
			BackoffMax:  Duration(2 * time.Second),
		},
		Auth: &VaultAuthRetryConfig{
			MaxRetries:     5,
			InitialBackoff: Duration(2 * time.Second),
			MaxBackoff:     Duration(20 * time.Second),
			Timeout:        Duration(time.Minute),
		},
	}
}

// vaultBaseConfig returns a minimal valid gateway configuration carrying the
// given vault section.
func vaultBaseConfig(vault *VaultConfig) *GatewayConfig {
	return &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "vault-test"},
		Spec: GatewaySpec{
			Listeners: []Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP", Bind: "0.0.0.0"},
			},
			Vault: vault,
		},
	}
}

// enabledTokenVault returns a minimal enabled token-auth section.
func enabledTokenVault() *VaultConfig {
	return &VaultConfig{
		Enabled:   true,
		Address:   "https://vault.example.com:8200",
		TokenFile: "/etc/vault/token",
	}
}

// ============================================================================
// YAML / JSON round-trips
// ============================================================================

func TestVaultConfig_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	yamlDoc := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  vault:
    enabled: true
    address: https://vault.example.com:8200
    namespace: team-a
    authMethod: approle
    tokenFile: /etc/vault/token
    kubernetes:
      role: gateway
      mountPath: k8s
      tokenPath: /custom/token
    appRole:
      roleId: role-id
      secretIdFile: /etc/vault/secret-id
      mountPath: approle-alt
    tls:
      caCert: /etc/ssl/ca.pem
      caPath: /etc/ssl/cas
      clientCert: /etc/ssl/client.pem
      clientKey: /etc/ssl/client-key.pem
      serverName: vault.internal
      skipVerify: true
    cache:
      enabled: true
      ttl: "5m"
      maxSize: 500
    retry:
      maxRetries: 4
      backoffBase: "100ms"
      backoffMax: "2s"
    auth:
      maxRetries: 5
      initialBackoff: "2s"
      maxBackoff: "20s"
      timeout: "1m"
`

	var cfg GatewayConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlDoc), &cfg))

	v := cfg.Spec.Vault
	require.NotNil(t, v)
	assert.True(t, v.Enabled)
	assert.Equal(t, "https://vault.example.com:8200", v.Address)
	assert.Equal(t, "team-a", v.Namespace)
	assert.Equal(t, VaultAuthMethodAppRole, v.AuthMethod)
	assert.Empty(t, v.Token)
	assert.Equal(t, "/etc/vault/token", v.TokenFile)

	require.NotNil(t, v.Kubernetes)
	assert.Equal(t, "gateway", v.Kubernetes.Role)
	assert.Equal(t, "k8s", v.Kubernetes.MountPath)
	assert.Equal(t, "/custom/token", v.Kubernetes.TokenPath)

	require.NotNil(t, v.AppRole)
	assert.Equal(t, "role-id", v.AppRole.RoleID)
	assert.Empty(t, v.AppRole.SecretID)
	assert.Equal(t, "/etc/vault/secret-id", v.AppRole.SecretIDFile)
	assert.Equal(t, "approle-alt", v.AppRole.MountPath)

	require.NotNil(t, v.TLS)
	assert.Equal(t, "/etc/ssl/ca.pem", v.TLS.CACert)
	assert.Equal(t, "/etc/ssl/cas", v.TLS.CAPath)
	assert.Equal(t, "/etc/ssl/client.pem", v.TLS.ClientCert)
	assert.Equal(t, "/etc/ssl/client-key.pem", v.TLS.ClientKey)
	assert.Equal(t, "vault.internal", v.TLS.ServerName)
	assert.True(t, v.TLS.SkipVerify)

	require.NotNil(t, v.Cache)
	assert.True(t, v.Cache.Enabled)
	assert.Equal(t, 5*time.Minute, v.Cache.TTL.Duration())
	assert.Equal(t, 500, v.Cache.MaxSize)

	require.NotNil(t, v.Retry)
	assert.Equal(t, 4, v.Retry.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, v.Retry.BackoffBase.Duration())
	assert.Equal(t, 2*time.Second, v.Retry.BackoffMax.Duration())

	require.NotNil(t, v.Auth)
	assert.Equal(t, 5, v.Auth.MaxRetries)
	assert.Equal(t, 2*time.Second, v.Auth.InitialBackoff.Duration())
	assert.Equal(t, 20*time.Second, v.Auth.MaxBackoff.Duration())
	assert.Equal(t, time.Minute, v.Auth.Timeout.Duration())

	// Marshal back and re-parse: the section must survive a full round-trip.
	out, err := yaml.Marshal(&cfg)
	require.NoError(t, err)

	var reparsed GatewayConfig
	require.NoError(t, yaml.Unmarshal(out, &reparsed))
	assert.Equal(t, cfg.Spec.Vault, reparsed.Spec.Vault)
}

func TestVaultConfig_YAMLAbsentSectionIsNil(t *testing.T) {
	t.Parallel()

	yamlDoc := `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: test
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
`

	var cfg GatewayConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlDoc), &cfg))
	assert.Nil(t, cfg.Spec.Vault, "absent spec.vault must stay nil (legacy env-only behavior)")
}

func TestVaultConfig_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := fullVaultConfig()

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded VaultConfig
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, original, &decoded)
}

func TestVaultConfig_YAMLInvalidDurationRejected(t *testing.T) {
	t.Parallel()

	yamlDoc := `
enabled: true
cache:
  ttl: "not-a-duration"
`
	var v VaultConfig
	err := yaml.Unmarshal([]byte(yamlDoc), &v)
	require.Error(t, err)
}

// ============================================================================
// Clone
// ============================================================================

func TestVaultConfig_Clone_Nil(t *testing.T) {
	t.Parallel()

	var v *VaultConfig
	assert.Nil(t, v.Clone())
}

func TestVaultConfig_Clone_DeepCopiesEveryBlock(t *testing.T) {
	t.Parallel()

	original := fullVaultConfig()
	clone := original.Clone()

	require.Equal(t, original, clone)

	// Distinct pointers for every sub-block.
	assert.NotSame(t, original, clone)
	assert.NotSame(t, original.Kubernetes, clone.Kubernetes)
	assert.NotSame(t, original.AppRole, clone.AppRole)
	assert.NotSame(t, original.TLS, clone.TLS)
	assert.NotSame(t, original.Cache, clone.Cache)
	assert.NotSame(t, original.Retry, clone.Retry)
	assert.NotSame(t, original.Auth, clone.Auth)

	// Mutations of the clone must not leak into the original.
	clone.Address = "https://other:8200"
	clone.Kubernetes.Role = "mutated"
	clone.AppRole.SecretID = "mutated"
	clone.TLS.SkipVerify = false
	clone.Cache.MaxSize = 1
	clone.Retry.MaxRetries = 99
	clone.Auth.Timeout = Duration(time.Second)

	assert.Equal(t, "https://vault.example.com:8200", original.Address)
	assert.Equal(t, "gateway", original.Kubernetes.Role)
	assert.Equal(t, "secret-id", original.AppRole.SecretID)
	assert.True(t, original.TLS.SkipVerify)
	assert.Equal(t, 500, original.Cache.MaxSize)
	assert.Equal(t, 4, original.Retry.MaxRetries)
	assert.Equal(t, time.Minute, original.Auth.Timeout.Duration())
}

func TestVaultConfig_Clone_NilBlocksStayNil(t *testing.T) {
	t.Parallel()

	original := &VaultConfig{Enabled: true, Address: "https://v:8200"}
	clone := original.Clone()

	require.NotNil(t, clone)
	assert.Nil(t, clone.Kubernetes)
	assert.Nil(t, clone.AppRole)
	assert.Nil(t, clone.TLS)
	assert.Nil(t, clone.Cache)
	assert.Nil(t, clone.Retry)
	assert.Nil(t, clone.Auth)
}

// ============================================================================
// EffectiveAuthMethod
// ============================================================================

func TestVaultConfig_EffectiveAuthMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *VaultConfig
		expected string
	}{
		{name: "nil receiver defaults to token", cfg: nil, expected: VaultAuthMethodToken},
		{name: "empty defaults to token", cfg: &VaultConfig{}, expected: VaultAuthMethodToken},
		{name: "token", cfg: &VaultConfig{AuthMethod: VaultAuthMethodToken}, expected: VaultAuthMethodToken},
		{
			name:     "kubernetes",
			cfg:      &VaultConfig{AuthMethod: VaultAuthMethodKubernetes},
			expected: VaultAuthMethodKubernetes,
		},
		{name: "approle", cfg: &VaultConfig{AuthMethod: VaultAuthMethodAppRole}, expected: VaultAuthMethodAppRole},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.EffectiveAuthMethod())
		})
	}
}

// ============================================================================
// RequiresVaultTLS
// ============================================================================

func TestGatewaySpec_RequiresVaultTLS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		spec     GatewaySpec
		expected bool
	}{
		{
			name:     "empty spec",
			spec:     GatewaySpec{},
			expected: false,
		},
		{
			name: "listener without vault TLS",
			spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", TLS: &ListenerTLSConfig{}}},
			},
			expected: false,
		},
		{
			name: "listener with disabled vault TLS",
			spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "https", TLS: &ListenerTLSConfig{Vault: &VaultTLSConfig{Enabled: false}}},
				},
			},
			expected: false,
		},
		{
			name: "listener with enabled vault TLS",
			spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "https", TLS: &ListenerTLSConfig{Vault: &VaultTLSConfig{Enabled: true}}},
				},
			},
			expected: true,
		},
		{
			name: "grpc listener with enabled vault TLS",
			spec: GatewaySpec{
				Listeners: []Listener{
					{
						Name: "grpc",
						GRPC: &GRPCListenerConfig{
							TLS: &TLSConfig{Vault: &VaultGRPCTLSConfig{Enabled: true}},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "route with enabled vault TLS",
			spec: GatewaySpec{
				Routes: []Route{
					{Name: "r1", TLS: &RouteTLSConfig{Vault: &VaultTLSConfig{Enabled: true}}},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.spec.RequiresVaultTLS())
		})
	}
}

// ============================================================================
// Validation — errors
// ============================================================================

func TestValidateVaultConfig_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		vault   *VaultConfig
		wantErr string // substring expected in the error; empty = valid
	}{
		{
			name:  "nil section skipped",
			vault: nil,
		},
		{
			name:  "disabled section skips semantic checks",
			vault: &VaultConfig{Enabled: false},
		},
		{
			name: "disabled section still type-checks durations",
			vault: &VaultConfig{
				Enabled: false,
				Cache:   &VaultClientCacheConfig{TTL: Duration(-time.Second)},
			},
			wantErr: "spec.vault.cache.ttl",
		},
		{
			name:    "enabled without address",
			vault:   &VaultConfig{Enabled: true, Token: "t"},
			wantErr: "spec.vault.address",
		},
		{
			name:  "token auth via inline token valid",
			vault: &VaultConfig{Enabled: true, Address: "https://v:8200", Token: "t"},
		},
		{
			name:  "token auth via tokenFile valid",
			vault: enabledTokenVault(),
		},
		{
			name: "token and tokenFile mutually exclusive",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				Token: "t", TokenFile: "/etc/vault/token",
			},
			wantErr: "mutually exclusive",
		},
		{
			name:    "token auth with neither token nor tokenFile",
			vault:   &VaultConfig{Enabled: true, Address: "https://v:8200"},
			wantErr: "one of token or tokenFile is required",
		},
		{
			name: "invalid auth method",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", AuthMethod: "ldap",
			},
			wantErr: "invalid auth method",
		},
		{
			name: "kubernetes without block",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				AuthMethod: VaultAuthMethodKubernetes,
			},
			wantErr: "spec.vault.kubernetes",
		},
		{
			name: "kubernetes without role",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				AuthMethod: VaultAuthMethodKubernetes,
				Kubernetes: &VaultKubernetesAuthConfig{},
			},
			wantErr: "spec.vault.kubernetes.role",
		},
		{
			name: "kubernetes valid",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				AuthMethod: VaultAuthMethodKubernetes,
				Kubernetes: &VaultKubernetesAuthConfig{Role: "gateway"},
			},
		},
		{
			name: "approle without block",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				AuthMethod: VaultAuthMethodAppRole,
			},
			wantErr: "spec.vault.appRole",
		},
		{
			name: "approle without roleId",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				AuthMethod: VaultAuthMethodAppRole,
				AppRole:    &VaultAppRoleAuthConfig{SecretID: "s"},
			},
			wantErr: "spec.vault.appRole.roleId",
		},
		{
			name: "approle secretId and secretIdFile mutually exclusive",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				AuthMethod: VaultAuthMethodAppRole,
				AppRole: &VaultAppRoleAuthConfig{
					RoleID: "r", SecretID: "s", SecretIDFile: "/etc/vault/sid",
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "approle with neither secretId nor secretIdFile",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				AuthMethod: VaultAuthMethodAppRole,
				AppRole:    &VaultAppRoleAuthConfig{RoleID: "r"},
			},
			wantErr: "one of secretId or secretIdFile is required",
		},
		{
			name: "approle via secretIdFile valid",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200",
				AuthMethod: VaultAuthMethodAppRole,
				AppRole:    &VaultAppRoleAuthConfig{RoleID: "r", SecretIDFile: "/etc/vault/sid"},
			},
		},
		{
			name: "tls clientCert without clientKey",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				TLS: &VaultClientTLSConfig{ClientCert: "/c.pem"},
			},
			wantErr: "spec.vault.tls.clientKey",
		},
		{
			name: "tls clientKey without clientCert",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				TLS: &VaultClientTLSConfig{ClientKey: "/k.pem"},
			},
			wantErr: "spec.vault.tls.clientCert",
		},
		{
			name: "tls pair valid",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				TLS: &VaultClientTLSConfig{ClientCert: "/c.pem", ClientKey: "/k.pem"},
			},
		},
		{
			name: "negative cache maxSize",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Cache: &VaultClientCacheConfig{MaxSize: -1},
			},
			wantErr: "spec.vault.cache.maxSize",
		},
		{
			name: "negative retry maxRetries",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Retry: &VaultClientRetryConfig{MaxRetries: -1},
			},
			wantErr: "spec.vault.retry.maxRetries",
		},
		{
			name: "negative retry backoffBase",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Retry: &VaultClientRetryConfig{BackoffBase: Duration(-time.Second)},
			},
			wantErr: "spec.vault.retry.backoffBase",
		},
		{
			name: "negative retry backoffMax",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Retry: &VaultClientRetryConfig{BackoffMax: Duration(-time.Second)},
			},
			wantErr: "spec.vault.retry.backoffMax",
		},
		{
			name: "retry backoffBase greater than backoffMax",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Retry: &VaultClientRetryConfig{
					BackoffBase: Duration(5 * time.Second),
					BackoffMax:  Duration(time.Second),
				},
			},
			wantErr: "backoffBase cannot be greater than backoffMax",
		},
		{
			name: "negative auth maxRetries",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Auth: &VaultAuthRetryConfig{MaxRetries: -1},
			},
			wantErr: "spec.vault.auth.maxRetries",
		},
		{
			name: "negative auth initialBackoff",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Auth: &VaultAuthRetryConfig{InitialBackoff: Duration(-time.Second)},
			},
			wantErr: "spec.vault.auth.initialBackoff",
		},
		{
			name: "negative auth maxBackoff",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Auth: &VaultAuthRetryConfig{MaxBackoff: Duration(-time.Second)},
			},
			wantErr: "spec.vault.auth.maxBackoff",
		},
		{
			name: "negative auth timeout",
			vault: &VaultConfig{
				Enabled: true, Address: "https://v:8200", Token: "t",
				Auth: &VaultAuthRetryConfig{Timeout: Duration(-time.Second)},
			},
			wantErr: "spec.vault.auth.timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateConfig(vaultBaseConfig(tt.vault))
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// ============================================================================
// Validation — warnings
// ============================================================================

// findWarning returns the first warning whose Path equals path.
func findWarning(warnings ValidationWarnings, path string) *ValidationWarning {
	for i := range warnings {
		if warnings[i].Path == path {
			return &warnings[i]
		}
	}
	return nil
}

func TestValidateVaultConfig_InlineTokenWarning(t *testing.T) {
	t.Parallel()

	cfg := vaultBaseConfig(&VaultConfig{
		Enabled: true, Address: "https://v:8200", Token: "inline",
	})

	warnings, err := ValidateConfigWithWarnings(cfg)
	require.NoError(t, err)

	w := findWarning(warnings, "spec.vault.token")
	require.NotNil(t, w, "expected inline token warning at spec.vault.token")
	assert.Contains(t, w.Message, "discouraged")
}

func TestValidateVaultConfig_InlineSecretIDWarning(t *testing.T) {
	t.Parallel()

	cfg := vaultBaseConfig(&VaultConfig{
		Enabled: true, Address: "https://v:8200",
		AuthMethod: VaultAuthMethodAppRole,
		AppRole:    &VaultAppRoleAuthConfig{RoleID: "r", SecretID: "inline"},
	})

	warnings, err := ValidateConfigWithWarnings(cfg)
	require.NoError(t, err)

	w := findWarning(warnings, "spec.vault.appRole.secretId")
	require.NotNil(t, w, "expected inline secretId warning at spec.vault.appRole.secretId")
	assert.Contains(t, w.Message, "discouraged")
}

func TestValidateVaultConfig_UnusedBlockWarnings(t *testing.T) {
	t.Parallel()

	t.Run("appRole block ignored under kubernetes method", func(t *testing.T) {
		t.Parallel()
		cfg := vaultBaseConfig(&VaultConfig{
			Enabled: true, Address: "https://v:8200",
			AuthMethod: VaultAuthMethodKubernetes,
			Kubernetes: &VaultKubernetesAuthConfig{Role: "gw"},
			AppRole:    &VaultAppRoleAuthConfig{RoleID: "r", SecretID: "s"},
		})

		warnings, err := ValidateConfigWithWarnings(cfg)
		require.NoError(t, err)

		w := findWarning(warnings, "spec.vault.appRole")
		require.NotNil(t, w)
		assert.Contains(t, w.Message, "authMethod=kubernetes")
	})

	t.Run("kubernetes block ignored under token method", func(t *testing.T) {
		t.Parallel()
		cfg := vaultBaseConfig(&VaultConfig{
			Enabled: true, Address: "https://v:8200", Token: "t",
			Kubernetes: &VaultKubernetesAuthConfig{Role: "gw"},
		})

		warnings, err := ValidateConfigWithWarnings(cfg)
		require.NoError(t, err)

		w := findWarning(warnings, "spec.vault.kubernetes")
		require.NotNil(t, w)
		assert.Contains(t, w.Message, "authMethod=token")
	})

	t.Run("no warnings for matching block", func(t *testing.T) {
		t.Parallel()
		cfg := vaultBaseConfig(&VaultConfig{
			Enabled: true, Address: "https://v:8200",
			AuthMethod: VaultAuthMethodKubernetes,
			Kubernetes: &VaultKubernetesAuthConfig{Role: "gw"},
		})

		warnings, err := ValidateConfigWithWarnings(cfg)
		require.NoError(t, err)
		assert.Nil(t, findWarning(warnings, "spec.vault.kubernetes"))
		assert.Nil(t, findWarning(warnings, "spec.vault.appRole"))
	})
}

// ============================================================================
// Validation — PKI issuance cross-check
// ============================================================================

func TestValidateVaultConfig_DisabledWithPKIRequirement(t *testing.T) {
	t.Parallel()

	cfg := vaultBaseConfig(&VaultConfig{Enabled: false})
	cfg.Spec.Listeners[0].TLS = &ListenerTLSConfig{
		Vault: &VaultTLSConfig{Enabled: true, PKIMount: "pki", Role: "gw", CommonName: "example.com"},
	}

	err := ValidateConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.vault.enabled")
	assert.Contains(t, err.Error(), "tls.vault")
}

func TestValidateVaultConfig_EnabledWithPKIRequirement(t *testing.T) {
	t.Parallel()

	cfg := vaultBaseConfig(enabledTokenVault())
	cfg.Spec.Listeners[0].TLS = &ListenerTLSConfig{
		Vault: &VaultTLSConfig{Enabled: true, PKIMount: "pki", Role: "gw", CommonName: "example.com"},
	}

	assert.NoError(t, ValidateConfig(cfg))
}

func TestValidateVaultConfig_AbsentSectionWithPKIRequirement(t *testing.T) {
	t.Parallel()

	// Absent spec.vault + PKI usage must NOT be a validation error: the
	// legacy env-only path (VAULT_ADDR) or the runtime init failure handles
	// it, preserving backward compatibility.
	cfg := vaultBaseConfig(nil)
	cfg.Spec.Listeners[0].TLS = &ListenerTLSConfig{
		Vault: &VaultTLSConfig{Enabled: true, PKIMount: "pki", Role: "gw", CommonName: "example.com"},
	}

	assert.NoError(t, ValidateConfig(cfg))
}

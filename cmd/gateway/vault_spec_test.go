// Package main: spec.vault wiring tests — config→vault.Config mapping,
// tokenFile/secretIdFile resolution, needsVault gating, file-config-driven
// client initialization against a mock Vault server, backward compatibility
// of the legacy env-only path, and the reload detect-and-warn behavior.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// writeSecretFile writes secret material into a temp file and returns its path.
func writeSecretFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// ============================================================================
// convertVaultClientConfig
// ============================================================================

func TestConvertVaultClientConfig_NilPreservesLegacyPKIOnlyPath(t *testing.T) {
	t.Parallel()

	got, err := convertVaultClientConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, &vault.Config{Enabled: true, AuthMethod: vault.AuthMethodToken}, got)
}

func TestConvertVaultClientConfig_FullTokenMapping(t *testing.T) {
	t.Parallel()

	vcfg := &config.VaultConfig{
		Enabled:   true,
		Address:   "https://vault:8200",
		Namespace: "ns",
		Token:     "inline-token",
		TLS: &config.VaultClientTLSConfig{
			CACert:     "/ca.pem",
			CAPath:     "/cas",
			ClientCert: "/client.pem",
			ClientKey:  "/key.pem",
			ServerName: "vault.internal",
			SkipVerify: true,
		},
		Cache: &config.VaultClientCacheConfig{
			Enabled: true,
			TTL:     config.Duration(5 * time.Minute),
			MaxSize: 200,
		},
		Retry: &config.VaultClientRetryConfig{
			MaxRetries:  7,
			BackoffBase: config.Duration(50 * time.Millisecond),
			BackoffMax:  config.Duration(3 * time.Second),
		},
	}

	got, err := convertVaultClientConfig(vcfg)
	require.NoError(t, err)

	assert.True(t, got.Enabled)
	assert.Equal(t, "https://vault:8200", got.Address)
	assert.Equal(t, "ns", got.Namespace)
	assert.Equal(t, vault.AuthMethodToken, got.AuthMethod, "empty authMethod must default to token")
	assert.Equal(t, "inline-token", got.Token)

	require.NotNil(t, got.TLS)
	assert.Equal(t, "/ca.pem", got.TLS.CACert)
	assert.Equal(t, "/cas", got.TLS.CAPath)
	assert.Equal(t, "/client.pem", got.TLS.ClientCert)
	assert.Equal(t, "/key.pem", got.TLS.ClientKey)
	assert.Equal(t, "vault.internal", got.TLS.ServerName)
	assert.True(t, got.TLS.SkipVerify)

	require.NotNil(t, got.Cache)
	assert.True(t, got.Cache.Enabled)
	assert.Equal(t, 5*time.Minute, got.Cache.TTL)
	assert.Equal(t, 200, got.Cache.MaxSize)

	require.NotNil(t, got.Retry)
	assert.Equal(t, 7, got.Retry.MaxRetries)
	assert.Equal(t, 50*time.Millisecond, got.Retry.BackoffBase)
	assert.Equal(t, 3*time.Second, got.Retry.BackoffMax)

	assert.Nil(t, got.Kubernetes)
	assert.Nil(t, got.AppRole)
}

func TestConvertVaultClientConfig_KubernetesDefaultsNormalized(t *testing.T) {
	t.Parallel()

	vcfg := &config.VaultConfig{
		Enabled: true, Address: "https://vault:8200",
		AuthMethod: config.VaultAuthMethodKubernetes,
		Kubernetes: &config.VaultKubernetesAuthConfig{Role: "gateway"},
	}

	got, err := convertVaultClientConfig(vcfg)
	require.NoError(t, err)

	require.NotNil(t, got.Kubernetes)
	assert.Equal(t, "gateway", got.Kubernetes.Role)
	assert.Equal(t, "kubernetes", got.Kubernetes.MountPath, "legacy default mount path")
	assert.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount/token", got.Kubernetes.TokenPath,
		"legacy default ServiceAccount token path")
	assert.Nil(t, got.AppRole)
}

func TestConvertVaultClientConfig_AppRoleDefaultsNormalized(t *testing.T) {
	t.Parallel()

	vcfg := &config.VaultConfig{
		Enabled: true, Address: "https://vault:8200",
		AuthMethod: config.VaultAuthMethodAppRole,
		AppRole:    &config.VaultAppRoleAuthConfig{RoleID: "rid", SecretID: "sid"},
	}

	got, err := convertVaultClientConfig(vcfg)
	require.NoError(t, err)

	require.NotNil(t, got.AppRole)
	assert.Equal(t, "rid", got.AppRole.RoleID)
	assert.Equal(t, "sid", got.AppRole.SecretID)
	assert.Equal(t, "approle", got.AppRole.MountPath, "legacy default mount path")
	assert.Nil(t, got.Kubernetes)
}

// TestConvertVaultClientConfig_MissingAuthBlocksSynthesized covers the
// defensive nil-block fallbacks: a method selection without its sub-block
// (possible on the operator boot path, which skips validation) still maps to
// a well-formed vault.Config whose own validation reports the missing role.
func TestConvertVaultClientConfig_MissingAuthBlocksSynthesized(t *testing.T) {
	t.Parallel()

	t.Run("kubernetes without block", func(t *testing.T) {
		t.Parallel()
		got, err := convertVaultClientConfig(&config.VaultConfig{
			Enabled: true, Address: "https://vault:8200",
			AuthMethod: config.VaultAuthMethodKubernetes,
		})
		require.NoError(t, err)
		require.NotNil(t, got.Kubernetes)
		assert.Empty(t, got.Kubernetes.Role)
		assert.Equal(t, "kubernetes", got.Kubernetes.MountPath)
	})

	t.Run("approle without block", func(t *testing.T) {
		t.Parallel()
		got, err := convertVaultClientConfig(&config.VaultConfig{
			Enabled: true, Address: "https://vault:8200",
			AuthMethod: config.VaultAuthMethodAppRole,
		})
		require.NoError(t, err)
		require.NotNil(t, got.AppRole)
		assert.Empty(t, got.AppRole.RoleID)
		assert.Equal(t, "approle", got.AppRole.MountPath)
	})
}

func TestConvertVaultClientConfig_TokenFile(t *testing.T) {
	t.Parallel()

	t.Run("happy path strips trailing newline and whitespace", func(t *testing.T) {
		t.Parallel()
		path := writeSecretFile(t, "token", "  s.file-token\n")

		got, err := convertVaultClientConfig(&config.VaultConfig{
			Enabled: true, Address: "https://vault:8200", TokenFile: path,
		})
		require.NoError(t, err)
		assert.Equal(t, "s.file-token", got.Token)
	})

	t.Run("missing file is a clear error", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(t.TempDir(), "no-such-token")

		_, err := convertVaultClientConfig(&config.VaultConfig{
			Enabled: true, Address: "https://vault:8200", TokenFile: missing,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "vault token file")
		assert.Contains(t, err.Error(), missing)
	})

	t.Run("inline token wins when both are present", func(t *testing.T) {
		t.Parallel()
		// Validation rejects this combination for file-based mode; the
		// mapping must still be deterministic for callers that skip
		// validation (operator boot path): the inline value wins and the
		// (possibly missing) file is not read.
		missing := filepath.Join(t.TempDir(), "unread-token")

		got, err := convertVaultClientConfig(&config.VaultConfig{
			Enabled: true, Address: "https://vault:8200",
			Token: "inline", TokenFile: missing,
		})
		require.NoError(t, err)
		assert.Equal(t, "inline", got.Token)
	})
}

func TestConvertVaultClientConfig_SecretIDFile(t *testing.T) {
	t.Parallel()

	t.Run("happy path strips trailing newline", func(t *testing.T) {
		t.Parallel()
		path := writeSecretFile(t, "secret-id", "sid-value\n")

		got, err := convertVaultClientConfig(&config.VaultConfig{
			Enabled: true, Address: "https://vault:8200",
			AuthMethod: config.VaultAuthMethodAppRole,
			AppRole:    &config.VaultAppRoleAuthConfig{RoleID: "rid", SecretIDFile: path},
		})
		require.NoError(t, err)
		require.NotNil(t, got.AppRole)
		assert.Equal(t, "sid-value", got.AppRole.SecretID)
	})

	t.Run("missing file is a clear error", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(t.TempDir(), "no-such-secret")

		_, err := convertVaultClientConfig(&config.VaultConfig{
			Enabled: true, Address: "https://vault:8200",
			AuthMethod: config.VaultAuthMethodAppRole,
			AppRole:    &config.VaultAppRoleAuthConfig{RoleID: "rid", SecretIDFile: missing},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secretId file")
		assert.Contains(t, err.Error(), missing)
	})
}

// ============================================================================
// vaultAuthRetrySettings
// ============================================================================

func TestVaultAuthRetrySettings(t *testing.T) {
	t.Parallel()

	t.Run("defaults for nil config and nil auth block", func(t *testing.T) {
		t.Parallel()

		for _, vcfg := range []*config.VaultConfig{nil, {Enabled: true}} {
			retryCfg, timeout := vaultAuthRetrySettings(vcfg)
			assert.Equal(t, defaultVaultAuthMaxRetries, retryCfg.MaxRetries)
			assert.Equal(t, defaultVaultAuthInitialBackoff, retryCfg.InitialBackoff)
			assert.Equal(t, defaultVaultAuthMaxBackoff, retryCfg.MaxBackoff)
			assert.InDelta(t, retry.DefaultJitterFactor, retryCfg.JitterFactor, 0.0001)
			assert.Equal(t, defaultVaultAuthTimeout, timeout)
		}
	})

	t.Run("config overrides", func(t *testing.T) {
		t.Parallel()

		retryCfg, timeout := vaultAuthRetrySettings(&config.VaultConfig{
			Auth: &config.VaultAuthRetryConfig{
				MaxRetries:     9,
				InitialBackoff: config.Duration(2 * time.Second),
				MaxBackoff:     config.Duration(40 * time.Second),
				Timeout:        config.Duration(90 * time.Second),
			},
		})
		assert.Equal(t, 9, retryCfg.MaxRetries)
		assert.Equal(t, 2*time.Second, retryCfg.InitialBackoff)
		assert.Equal(t, 40*time.Second, retryCfg.MaxBackoff)
		assert.Equal(t, 90*time.Second, timeout)
	})

	t.Run("zero values keep defaults", func(t *testing.T) {
		t.Parallel()

		retryCfg, timeout := vaultAuthRetrySettings(&config.VaultConfig{
			Auth: &config.VaultAuthRetryConfig{},
		})
		assert.Equal(t, defaultVaultAuthMaxRetries, retryCfg.MaxRetries)
		assert.Equal(t, defaultVaultAuthInitialBackoff, retryCfg.InitialBackoff)
		assert.Equal(t, defaultVaultAuthMaxBackoff, retryCfg.MaxBackoff)
		assert.Equal(t, defaultVaultAuthTimeout, timeout)
	})
}

// ============================================================================
// needsVault truth table
// ============================================================================

func TestNeedsVault_TruthTable(t *testing.T) {
	pkiConfig := func() *config.GatewayConfig {
		cfg := validGatewayConfig("pki")
		cfg.Spec.Listeners[0].TLS = &config.ListenerTLSConfig{
			Vault: &config.VaultTLSConfig{Enabled: true},
		}
		return cfg
	}

	tests := []struct {
		name     string
		cfg      func() *config.GatewayConfig
		envAddr  string
		expected bool
	}{
		{
			name:     "nothing configured",
			cfg:      func() *config.GatewayConfig { return validGatewayConfig("plain") },
			expected: false,
		},
		{
			name:     "PKI only",
			cfg:      pkiConfig,
			expected: true,
		},
		{
			name:     "env only",
			cfg:      func() *config.GatewayConfig { return validGatewayConfig("env-only") },
			envAddr:  "https://env:8200",
			expected: true,
		},
		{
			name: "file only (spec.vault enabled)",
			cfg: func() *config.GatewayConfig {
				cfg := validGatewayConfig("file-only")
				cfg.Spec.Vault = &config.VaultConfig{Enabled: true, Address: "https://file:8200"}
				return cfg
			},
			expected: true,
		},
		{
			name: "disabled section without env",
			cfg: func() *config.GatewayConfig {
				cfg := validGatewayConfig("disabled")
				cfg.Spec.Vault = &config.VaultConfig{Enabled: false, Address: "https://file:8200"}
				return cfg
			},
			expected: false,
		},
		{
			name: "disabled section with env addr (env wins)",
			cfg: func() *config.GatewayConfig {
				cfg := validGatewayConfig("disabled-env")
				cfg.Spec.Vault = &config.VaultConfig{Enabled: false, Address: "https://file:8200"}
				return cfg
			},
			envAddr:  "https://env:8200",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVaultEnv(t)
			if tt.envAddr != "" {
				t.Setenv(envVaultAddr, tt.envAddr)
			}
			assert.Equal(t, tt.expected, needsVault(tt.cfg()))
		})
	}
}

// ============================================================================
// initVaultClient driven by FILE configuration (no VAULT_* env)
// ============================================================================

// newMockVaultServer returns an httptest server that accepts token lookups
// and generic secret reads (mirrors the coverage_iter4 mock pattern).
func newMockVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			_, _ = w.Write([]byte(`{"data": {"id": "test-token", "ttl": 3600, "renewable": true}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data": {}}`))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestInitVaultClient_FromFileConfig_InlineToken drives initVaultClient
// purely from a file-style configuration section with all VAULT_* variables
// cleared. Not parallel — mutates the environment.
func TestInitVaultClient_FromFileConfig_InlineToken(t *testing.T) {
	clearVaultEnv(t)
	server := newMockVaultServer(t)

	vcfg := &config.VaultConfig{
		Enabled: true,
		Address: server.URL,
		Token:   "test-token",
	}

	client := initVaultClient(vcfg, observability.NopLogger())
	require.NotNil(t, client)
	assert.True(t, client.IsEnabled())
	_ = client.Close()
}

// TestInitVaultClient_FromFileConfig_TokenFile proves the tokenFile reference
// is resolved at init. Not parallel — mutates the environment.
func TestInitVaultClient_FromFileConfig_TokenFile(t *testing.T) {
	clearVaultEnv(t)
	server := newMockVaultServer(t)
	tokenPath := writeSecretFile(t, "token", "test-token\n")

	vcfg := &config.VaultConfig{
		Enabled:   true,
		Address:   server.URL,
		TokenFile: tokenPath,
		Auth: &config.VaultAuthRetryConfig{
			MaxRetries: 1,
			Timeout:    config.Duration(5 * time.Second),
		},
	}

	client := initVaultClient(vcfg, observability.NopLogger())
	require.NotNil(t, client)
	assert.True(t, client.IsEnabled())
	_ = client.Close()
}

// TestInitVaultClient_TokenFileMissing_Fatal proves a broken file reference
// fails startup with a clear fatal error. Not parallel — modifies exitFunc.
func TestInitVaultClient_TokenFileMissing_Fatal(t *testing.T) {
	clearVaultEnv(t)

	origExit := exitFunc
	defer func() { exitFunc = origExit }()
	var exitCode int32
	exitFunc = func(code int) { atomic.StoreInt32(&exitCode, int32(code)) }

	vcfg := &config.VaultConfig{
		Enabled:   true,
		Address:   "https://vault:8200",
		TokenFile: filepath.Join(t.TempDir(), "missing-token"),
	}

	client := initVaultClient(vcfg, observability.NopLogger())

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	assert.Nil(t, client)
}

// ============================================================================
// Backward compatibility: absent spec.vault + legacy env vars only
// ============================================================================

// TestVaultBackwardCompat_EnvOnlyTokenPath asserts the overlay+mapping
// pipeline reproduces the exact vault.Config the legacy env-only
// initVaultClient built. Not parallel — mutates the environment.
func TestVaultBackwardCompat_EnvOnlyTokenPath(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://legacy:8200")
	t.Setenv(envVaultToken, "legacy-token")
	t.Setenv(envVaultNamespace, "legacy-ns")
	t.Setenv(envVaultSkipVerify, "true")

	effective := applyVaultEnv(nil, observability.NopLogger())
	got, err := convertVaultClientConfig(effective)
	require.NoError(t, err)

	want := &vault.Config{
		Enabled:    true,
		Address:    "https://legacy:8200",
		AuthMethod: vault.AuthMethodToken,
		Token:      "legacy-token",
		Namespace:  "legacy-ns",
		TLS:        &vault.VaultTLSConfig{SkipVerify: true},
	}
	assert.Equal(t, want, got, "env-only path must be byte-for-byte identical to the legacy construction")
}

// TestVaultBackwardCompat_EnvOnlyKubernetesPath covers the kubernetes-method
// legacy construction including its filled-in defaults. Not parallel.
func TestVaultBackwardCompat_EnvOnlyKubernetesPath(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://legacy:8200")
	t.Setenv(envVaultAuthMethod, "kubernetes")
	t.Setenv(envVaultK8sRole, "legacy-role")

	effective := applyVaultEnv(nil, observability.NopLogger())
	got, err := convertVaultClientConfig(effective)
	require.NoError(t, err)

	want := &vault.Config{
		Enabled:    true,
		Address:    "https://legacy:8200",
		AuthMethod: vault.AuthMethodKubernetes,
		Kubernetes: &vault.KubernetesAuthConfig{
			Role:      "legacy-role",
			MountPath: "kubernetes",
			TokenPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
	assert.Equal(t, want, got)
}

// TestVaultBackwardCompat_EnvOnlyAppRolePath covers the approle-method
// legacy construction including its filled-in defaults, completing the
// 3/3 auth-method legacy-parity claim (token/kubernetes/approle).
// Not parallel — mutates the environment.
func TestVaultBackwardCompat_EnvOnlyAppRolePath(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://legacy:8200")
	t.Setenv(envVaultAuthMethod, "approle")
	t.Setenv(envVaultAppRoleRoleID, "legacy-role-id")
	t.Setenv(envVaultAppRoleSecretID, "legacy-secret-id")

	effective := applyVaultEnv(nil, observability.NopLogger())
	got, err := convertVaultClientConfig(effective)
	require.NoError(t, err)

	want := &vault.Config{
		Enabled:    true,
		Address:    "https://legacy:8200",
		AuthMethod: vault.AuthMethodAppRole,
		AppRole: &vault.AppRoleAuthConfig{
			RoleID:    "legacy-role-id",
			SecretID:  "legacy-secret-id",
			MountPath: "approle",
		},
	}
	assert.Equal(t, want, got,
		"env-only approle path must be byte-for-byte identical to the legacy construction")
}

// ============================================================================
// loadAndValidateConfig + loadOperatorInitialConfig wiring (overlay-before-validate)
// ============================================================================

// vaultWiringConfigYAML is a gateway config whose vault section carries no
// address — valid only when VAULT_ADDR provides it (Helm env-mixed pattern).
const vaultWiringConfigYAML = `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: vault-wiring
spec:
  listeners:
    - name: http
      port: 18098
      protocol: HTTP
  vault:
    enabled: true
    tokenFile: /etc/vault/token
`

// TestLoadAndValidateConfig_VaultOverlayBeforeValidate proves the R6
// ordering: the env overlay runs before validation, so an env-supplied
// address passes and its absence fails. Not parallel — env + exitFunc.
func TestLoadAndValidateConfig_VaultOverlayBeforeValidate(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "gateway.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(vaultWiringConfigYAML), 0o600))

	t.Run("env address satisfies validation", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv(envVaultAddr, "https://env:8200")

		cfg := loadAndValidateConfig(configPath, observability.NopLogger())
		require.NotNil(t, cfg)
		require.NotNil(t, cfg.Spec.Vault)
		assert.Equal(t, "https://env:8200", cfg.Spec.Vault.Address,
			"the stored config must be the effective (post-overlay) one")
		assert.True(t, cfg.Spec.Vault.Enabled)
	})

	t.Run("missing address fails validation", func(t *testing.T) {
		clearVaultEnv(t)

		origExit := exitFunc
		defer func() { exitFunc = origExit }()
		var exitCode int32
		exitFunc = func(code int) { atomic.StoreInt32(&exitCode, int32(code)) }

		cfg := loadAndValidateConfig(configPath, observability.NopLogger())
		assert.Nil(t, cfg)
		assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
	})
}

// TestLoadOperatorInitialConfig_VaultOverlayApplied proves operator-mode boot
// config also carries the effective vault section. Not parallel — env.
func TestLoadOperatorInitialConfig_VaultOverlayApplied(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "gateway.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(vaultWiringConfigYAML), 0o600))

	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://operator-env:8200")
	t.Setenv(envVaultToken, "env-token")

	cfg := loadOperatorInitialConfig(cliFlags{configPath: configPath}, observability.NopLogger())

	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Spec.Vault)
	assert.Equal(t, "https://operator-env:8200", cfg.Spec.Vault.Address)
	assert.Equal(t, "env-token", cfg.Spec.Vault.Token)
	assert.Empty(t, cfg.Spec.Vault.TokenFile, "env token must clear the file reference")
}

// TestLoadOperatorInitialConfig_MinimalFallbackWithEnv proves the minimal
// fallback path (config file unreadable) also synthesizes the section from
// the environment — legacy operator env-only behavior. Not parallel — env.
func TestLoadOperatorInitialConfig_MinimalFallbackWithEnv(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://operator-env:8200")

	cfg := loadOperatorInitialConfig(cliFlags{
		configPath:  "/nonexistent/config.yaml",
		gatewayName: "fallback-gw",
	}, observability.NopLogger())

	require.NotNil(t, cfg)
	assert.Equal(t, "fallback-gw", cfg.Metadata.Name)
	require.NotNil(t, cfg.Spec.Vault)
	assert.True(t, cfg.Spec.Vault.Enabled)
	assert.Equal(t, "https://operator-env:8200", cfg.Spec.Vault.Address)
}

// ============================================================================
// reload: spec.vault change → warn + skip metric, client untouched
// ============================================================================

// newVaultReloadApp builds a minimal application suitable for
// reloadComponents with a pinned vault client.
func newVaultReloadApp(t *testing.T, cfg *config.GatewayConfig) *application {
	t.Helper()

	gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	return &application{
		gateway:         gw,
		backendRegistry: backend.NewRegistry(observability.NopLogger()),
		router:          router.New(),
		config:          cfg,
		vaultClient:     &mockVaultClientForApp{enabled: true},
	}
}

// TestReloadComponents_VaultChanged_WarnsAndSkips asserts the detect-and-warn
// contract: warning logged, "vault"/"skipped" counter incremented, running
// client pointer unchanged. Not parallel — clears VAULT_* env.
func TestReloadComponents_VaultChanged_WarnsAndSkips(t *testing.T) {
	clearVaultEnv(t)

	cfg := validGatewayConfig("vault-reload")
	cfg.Spec.Vault = &config.VaultConfig{Enabled: true, Address: "https://old:8200", Token: "t"}
	app := newVaultReloadApp(t, cfg)
	originalClient := app.vaultClient

	rm := ensureReloadMetrics(app)
	skipped := rm.configReloadComponentTotal.WithLabelValues(reloadComponentVault, reloadResultSkipped)
	require.InDelta(t, 0.0, testutil.ToFloat64(skipped), 0.0001)

	newCfg := validGatewayConfig("vault-reload")
	newCfg.Spec.Vault = &config.VaultConfig{Enabled: true, Address: "https://new:8200", Token: "t"}

	rec := &warnRecorder{}
	reloadComponents(context.Background(), app, newCfg, rec)

	// Warn logged.
	var found bool
	for _, w := range rec.warnings() {
		if w.msg == "spec.vault changed; vault client settings apply at startup — restart required" {
			found = true
		}
	}
	assert.True(t, found, "the spec.vault change warning must be logged")

	// Skip metric incremented exactly once.
	assert.InDelta(t, 1.0, testutil.ToFloat64(skipped), 0.0001)

	// Running client pointer unchanged, config swapped.
	assert.Same(t, originalClient, app.vaultClient, "the vault client must never be recreated on reload")
	assert.Equal(t, newCfg, app.config)
}

// TestReloadComponents_VaultUnchanged_NoWarnNoSkip is the negative case.
// Not parallel — clears VAULT_* env.
func TestReloadComponents_VaultUnchanged_NoWarnNoSkip(t *testing.T) {
	clearVaultEnv(t)

	cfg := validGatewayConfig("vault-same")
	cfg.Spec.Vault = &config.VaultConfig{Enabled: true, Address: "https://same:8200", Token: "t"}
	app := newVaultReloadApp(t, cfg)

	rm := ensureReloadMetrics(app)
	skipped := rm.configReloadComponentTotal.WithLabelValues(reloadComponentVault, reloadResultSkipped)

	newCfg := validGatewayConfig("vault-same")
	newCfg.Spec.Vault = &config.VaultConfig{Enabled: true, Address: "https://same:8200", Token: "t"}

	rec := &warnRecorder{}
	reloadComponents(context.Background(), app, newCfg, rec)

	for _, w := range rec.warnings() {
		assert.NotContains(t, w.msg, "spec.vault changed")
	}
	assert.InDelta(t, 0.0, testutil.ToFloat64(skipped), 0.0001)
}

// TestReloadComponents_VaultEnvOnly_NoSpuriousWarn proves effective-vs-
// effective comparison: a raw file config without a vault section plus a
// process-stable VAULT_ADDR must NOT trigger the change warning on every
// reload (the boot config already carries the synthesized section).
// Not parallel — env.
func TestReloadComponents_VaultEnvOnly_NoSpuriousWarn(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://env:8200")

	bootCfg := validGatewayConfig("vault-env-only")
	bootCfg.Spec.Vault = applyVaultEnv(bootCfg.Spec.Vault, observability.NopLogger())
	require.NotNil(t, bootCfg.Spec.Vault, "boot overlay must synthesize the section")

	app := newVaultReloadApp(t, bootCfg)
	rm := ensureReloadMetrics(app)
	skipped := rm.configReloadComponentTotal.WithLabelValues(reloadComponentVault, reloadResultSkipped)

	// Watcher hands over the RAW file config (no vault section).
	newCfg := validGatewayConfig("vault-env-only")

	rec := &warnRecorder{}
	reloadComponents(context.Background(), app, newCfg, rec)

	for _, w := range rec.warnings() {
		assert.NotContains(t, w.msg, "spec.vault changed",
			"env-only deployments must not see spurious vault-change warnings")
	}
	assert.InDelta(t, 0.0, testutil.ToFloat64(skipped), 0.0001)
	require.NotNil(t, app.config.Spec.Vault, "stored config must remain effective after reload")
	assert.Equal(t, "https://env:8200", app.config.Spec.Vault.Address)
}

func TestVaultConfigChanged_NilCombos(t *testing.T) {
	t.Parallel()

	cfg := validGatewayConfig("a")

	assert.False(t, vaultConfigChanged(nil, nil))
	assert.True(t, vaultConfigChanged(cfg, nil))
	assert.True(t, vaultConfigChanged(nil, cfg))
	assert.False(t, vaultConfigChanged(cfg, cfg))
}

func TestReloadMetrics_Init_IncludesVaultSkipped(t *testing.T) {
	t.Parallel()

	m := observability.NewMetrics("test_vault_init")
	rm := newReloadMetrics(m)

	require.NotPanics(t, func() {
		counter := rm.configReloadComponentTotal.WithLabelValues(reloadComponentVault, reloadResultSkipped)
		assert.InDelta(t, 0.0, testutil.ToFloat64(counter), 0.0001,
			"the vault/skipped pair must be pre-created at zero")
	})
}

// ============================================================================
// startConfigWatcher: env-mixed vault config keeps hot reload alive (M-1 fix)
// ============================================================================

// TestStartConfigWatcher_VaultEnvMixed_HotReloadProceeds is the end-to-end
// M-1 regression test: a Helm-style deployment whose vault address lives
// ONLY in VAULT_ADDR (file: enabled+tokenFile, no address) must (1) start
// the config watcher, (2) hot-reload on file edits (previously EVERY edit
// failed raw-file validation and ALL hot reload was silently dead), and
// (3) still warn+skip the vault section per the no-hot-reload policy.
// Not parallel — mutates the environment and the file system.
func TestStartConfigWatcher_VaultEnvMixed_HotReloadProceeds(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://env:8200")

	configPath := filepath.Join(t.TempDir(), "gateway.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(vaultWiringConfigYAML), 0o600))

	// Boot exactly as production does: the boot config carries the overlay.
	bootCfg := loadAndValidateConfig(configPath, observability.NopLogger())
	require.NotNil(t, bootCfg)

	app := newVaultReloadApp(t, bootCfg)
	originalClient := app.vaultClient
	rm := ensureReloadMetrics(app)
	successTotal := rm.configReloadTotal.WithLabelValues("success")
	skipped := rm.configReloadComponentTotal.WithLabelValues(reloadComponentVault, reloadResultSkipped)

	rec := &warnRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := startConfigWatcher(ctx, app, configPath, rec)
	require.NotNil(t, watcher)
	defer func() { _ = watcher.Stop() }()

	// (1) The watcher validates the EFFECTIVE config (pre-validate
	// transform), so it starts even though the raw file has no address.
	assert.InDelta(t, 1.0, testutil.ToFloat64(rm.configWatcherStatus), 0.0001,
		"the watcher must start on an env-mixed vault config")

	// (2) Edit the file (rotate the tokenFile path). Any edit previously
	// died in raw validation with hot reload silently disabled.
	time.Sleep(200 * time.Millisecond)
	edited := strings.Replace(vaultWiringConfigYAML,
		"/etc/vault/token", "/etc/vault/token-rotated", 1)
	require.NoError(t, os.WriteFile(configPath, []byte(edited), 0o600))

	require.Eventually(t, func() bool {
		return testutil.ToFloat64(successTotal) >= 1.0
	}, 5*time.Second, 20*time.Millisecond,
		"hot reload must proceed for env-mixed vault deployments (M-1 regression)")

	// (3) The vault change itself is still warn+skipped, never applied.
	assert.InDelta(t, 1.0, testutil.ToFloat64(skipped), 0.0001,
		"the vault section change must be counted as skipped")

	// Stop the watcher before inspecting shared state: Stop() joins the
	// watch goroutine, making the reads below race-free.
	require.NoError(t, watcher.Stop())

	var found bool
	for _, w := range rec.warnings() {
		if strings.Contains(w.msg, "spec.vault changed") {
			found = true
		}
	}
	assert.True(t, found, "the vault no-hot-reload warning must be logged")
	assert.Same(t, originalClient, app.vaultClient,
		"the running vault client must never be recreated on reload")

	require.NotNil(t, app.config.Spec.Vault)
	assert.Equal(t, "https://env:8200", app.config.Spec.Vault.Address,
		"reload must see the effective (overlaid) config, consistent with boot")
	assert.Equal(t, "/etc/vault/token-rotated", app.config.Spec.Vault.TokenFile,
		"the edited file content must have been applied")
}

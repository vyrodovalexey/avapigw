//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
//
// This file exercises the SUITE-level path for the gateway-wide spec.vault
// section (internal/config.VaultConfig): a gateway configuration FILE declares
// the Vault client connection (address, authMethod, tokenFile) and the gateway
// builds a working Vault client from it — against LIVE Vault — resolving a real
// KV secret. It complements the exhaustive unit coverage of the field mapping
// (cmd/gateway/vault_spec_test.go) and the ENV overlay
// (cmd/gateway/env_vault_test.go) by proving the full config-file → vault
// client → secret-resolution journey end to end.
//
// The simplest existing vault-backed fixture is reused: the basic-auth backend
// credentials stored by test/docker-compose/scripts/setup-vault.sh at
// secret/backend-auth/basic (username=backend-user, password=backend-pass).
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	internalvault "github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// specVaultBackendAuthPath is the KV path (relative to the mount) of the
// basic-auth backend credentials provisioned by the compose Vault setup.
const specVaultBackendAuthPath = "backend-auth/basic"

// writeSpecVaultConfigFile writes a gateway configuration FILE with a
// spec.vault section and returns its path. The token material lives in a
// SEPARATE tokenFile (never inline), mirroring the Kubernetes Secret-mounted
// deployment pattern the feature is designed for.
func writeSpecVaultConfigFile(t *testing.T, address, tokenFilePath string) string {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway-spec-vault.yaml")

	// A minimal but VALID gateway config carrying the spec.vault client
	// connection. The listener/route are only present so the document is a
	// well-formed Gateway resource; this test drives the vault seam directly.
	content := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: spec-vault-it
spec:
  listeners:
    - name: http
      port: 18470
      protocol: HTTP
      bind: 127.0.0.1
  vault:
    enabled: true
    address: ` + address + `
    authMethod: token
    tokenFile: ` + tokenFilePath + `
  routes:
    - name: health
      match:
        - uri:
            exact: /health
          methods: ["GET"]
      directResponse:
        status: 200
        body: '{"status":"healthy"}'
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	return cfgPath
}

// writeVaultTokenFile writes the Vault token to a temp file (no trailing
// newline handling needed — the production reader trims it, and this test
// exercises that trimming by appending a newline).
func writeVaultTokenFile(t *testing.T, token string) string {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "vault-token")
	// Trailing newline is intentional: `vault login` and Secret mounts leave
	// one, and the production reader (readVaultSecretFile) trims it. The suite
	// mapping helper mirrors that trimming.
	require.NoError(t, os.WriteFile(tokenPath, []byte(token+"\n"), 0o600))
	return tokenPath
}

// buildVaultClientFromConfigFile loads the config FILE, applies the production
// spec.vault ENV overlay, maps the effective section to an internal/vault
// client configuration (resolving tokenFile), and constructs + authenticates
// the client — the same sequence cmd/gateway performs at boot.
func buildVaultClientFromConfigFile(
	t *testing.T,
	ctx context.Context,
	cfgPath string,
) internalvault.Client {
	t.Helper()

	cfg, err := config.LoadConfig(cfgPath)
	require.NoError(t, err, "config file must load")
	require.NotNil(t, cfg.Spec.Vault, "spec.vault section must be parsed from the file")

	effective := helpers.ApplySpecVaultEnvOverlay(cfg.Spec.Vault)
	require.NotNil(t, effective, "effective spec.vault must not be nil")

	vaultCfg, err := helpers.SpecVaultConfigToVaultClientConfig(effective)
	require.NoError(t, err, "spec.vault must map to a vault client config (tokenFile resolved)")
	require.Equal(t, internalvault.AuthMethodToken, vaultCfg.AuthMethod)
	require.NotEmpty(t, vaultCfg.Token, "token must have been resolved from tokenFile")

	client, err := internalvault.New(vaultCfg, observability.NopLogger())
	require.NoError(t, err, "vault client must be constructed from the config-file connection")
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, client.Authenticate(ctx), "vault client must authenticate against live Vault")
	return client
}

// TestIntegration_SpecVault_ConfigFile_TokenFile_ResolvesSecret proves the
// primary journey: a gateway config FILE with spec.vault{enabled, address,
// authMethod: token, tokenFile}, and NO VAULT_* environment in the process,
// yields a working Vault client that resolves a real KV secret.
func TestIntegration_SpecVault_ConfigFile_TokenFile_ResolvesSecret(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	// Ensure NO VAULT_* env leaks into this process for the pure-file case:
	// the file must be self-sufficient.
	unsetVaultEnvForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()
	tokenFile := writeVaultTokenFile(t, vaultCfg.Token)
	cfgPath := writeSpecVaultConfigFile(t, vaultCfg.Address, tokenFile)

	client := buildVaultClientFromConfigFile(t, ctx, cfgPath)

	// The feature under test: the file-configured client resolves a real
	// secret from live Vault.
	data, err := client.KV().Read(ctx, vaultCfg.KVMount, specVaultBackendAuthPath)
	require.NoError(t, err, "file-configured vault client must read the backend-auth secret")
	require.NotNil(t, data)

	assert.Equal(t, "backend-user", data["username"],
		"secret resolved through the spec.vault file-configured client")
	assert.Equal(t, "backend-pass", data["password"])
}

// TestIntegration_SpecVault_EnvAddressWins proves per-field ENV > file
// precedence: the config FILE carries a WRONG address, but a correct VAULT_ADDR
// in the environment wins, so the gateway boots and Vault works.
func TestIntegration_SpecVault_EnvAddressWins(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()
	tokenFile := writeVaultTokenFile(t, vaultCfg.Token)

	// Deliberately WRONG address in the file — a black-holed port that would
	// hang/refuse if the file value were used.
	const wrongAddr = "http://127.0.0.1:1"
	cfgPath := writeSpecVaultConfigFile(t, wrongAddr, tokenFile)

	// Correct address supplied ONLY via the environment (Helm env-mixed
	// pattern). t.Setenv restores the previous value after the test.
	t.Setenv("VAULT_ADDR", vaultCfg.Address)

	client := buildVaultClientFromConfigFile(t, ctx, cfgPath)

	data, err := client.KV().Read(ctx, vaultCfg.KVMount, specVaultBackendAuthPath)
	require.NoError(t, err,
		"env VAULT_ADDR must win over the wrong file address (per-field precedence)")
	require.NotNil(t, data)
	assert.Equal(t, "backend-user", data["username"])
}

// TestIntegration_SpecVault_EnvTokenClearsTokenFile proves the token override:
// the file references a tokenFile, but VAULT_TOKEN in the environment wins and
// clears the file reference (per-field precedence), and the resulting client
// still works against live Vault.
func TestIntegration_SpecVault_EnvTokenClearsTokenFile(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	// The tokenFile contains a BOGUS token; the correct token comes from the
	// environment and must win, clearing the file reference.
	bogusTokenFile := writeVaultTokenFile(t, "bogus-token-must-be-overridden")
	cfgPath := writeSpecVaultConfigFile(t, vaultCfg.Address, bogusTokenFile)

	t.Setenv("VAULT_TOKEN", vaultCfg.Token)

	cfg, err := config.LoadConfig(cfgPath)
	require.NoError(t, err)
	effective := helpers.ApplySpecVaultEnvOverlay(cfg.Spec.Vault)
	require.NotNil(t, effective)
	assert.Empty(t, effective.TokenFile,
		"env token override must clear tokenFile to keep the exactly-one invariant")
	assert.Equal(t, vaultCfg.Token, effective.Token, "env token must win")

	vc, err := helpers.SpecVaultConfigToVaultClientConfig(effective)
	require.NoError(t, err)
	client, err := internalvault.New(vc, observability.NopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Authenticate(ctx))

	data, err := client.KV().Read(ctx, vaultCfg.KVMount, specVaultBackendAuthPath)
	require.NoError(t, err, "env-token-configured client must read the secret")
	assert.Equal(t, "backend-pass", data["password"])
}

// TestIntegration_SpecVault_Validation_FileSeam exercises the validation seam
// on configurations LOADED FROM FILE: an inline token surfaces a WARNING (not
// an error), and an approle config missing roleId is REJECTED at load-time
// validation. This is the suite seam for the validator behavior; the
// field-by-field validation matrix is unit covered in
// internal/config/vault_config_test.go.
func TestIntegration_SpecVault_Validation_FileSeam(t *testing.T) {
	// No live Vault needed: validation is a pure config-time check, but this
	// runs in the integration suite because it validates the FILE-loaded
	// spec.vault seam alongside the live tests above.
	t.Run("inline token in file surfaces a warning", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "inline-token.yaml")
		content := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: spec-vault-inline-token
spec:
  listeners:
    - name: http
      port: 18471
      protocol: HTTP
      bind: 127.0.0.1
  vault:
    enabled: true
    address: https://vault.example.com:8200
    authMethod: token
    token: inline-secret-token
  routes:
    - name: health
      match:
        - uri:
            exact: /health
          methods: ["GET"]
      directResponse:
        status: 200
        body: 'ok'
`
		require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))

		cfg, err := config.LoadConfig(cfgPath)
		require.NoError(t, err)

		warnings, verr := config.ValidateConfigWithWarnings(cfg)
		require.NoError(t, verr, "inline token is discouraged but NOT an error")

		var found bool
		for _, w := range warnings {
			if w.Path == "spec.vault.token" {
				found = true
				assert.Contains(t, w.Message, "discouraged")
			}
		}
		assert.True(t, found, "inline token in the config file must surface a warning")
	})

	t.Run("approle without roleId is rejected at load-time validation", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "approle-no-roleid.yaml")
		content := `apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: spec-vault-approle-invalid
spec:
  listeners:
    - name: http
      port: 18472
      protocol: HTTP
      bind: 127.0.0.1
  vault:
    enabled: true
    address: https://vault.example.com:8200
    authMethod: approle
    appRole:
      secretId: some-secret
  routes:
    - name: health
      match:
        - uri:
            exact: /health
          methods: ["GET"]
      directResponse:
        status: 200
        body: 'ok'
`
		require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))

		cfg, err := config.LoadConfig(cfgPath)
		require.NoError(t, err)

		verr := config.ValidateConfig(cfg)
		require.Error(t, verr, "approle without roleId must be rejected")
		assert.Contains(t, verr.Error(), "roleId")
	})
}

// unsetVaultEnvForTest clears all VAULT_* variables for the duration of the
// test so the pure-file case cannot accidentally rely on an inherited value.
// t.Setenv restores each variable after the test.
func unsetVaultEnvForTest(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_AUTH_METHOD", "VAULT_NAMESPACE",
		"VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY",
		"VAULT_SKIP_VERIFY",
	} {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))
	}
}

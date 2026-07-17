// Package main: spec.vault environment overlay tests. They prove the
// per-field precedence contract (ENV > config file > defaults) for every
// modeled VAULT_* variable, the legacy env-only synthesis path, and the
// warn-on-invalid convention for boolean parsing (A-2).
package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// allVaultEnvVars lists every modeled VAULT_* environment variable.
var allVaultEnvVars = []string{
	envVaultAddr, envVaultAuthMethod, envVaultToken, envVaultNamespace,
	envVaultCACert, envVaultCAPath, envVaultClientCert, envVaultClientKey,
	envVaultSkipVerify, envVaultK8sRole, envVaultK8sMountPath,
	envVaultK8sTokenPath, envVaultAppRoleRoleID, envVaultAppRoleSecretID,
	envVaultAppRoleMountPath,
}

// clearVaultEnv unsets every modeled VAULT_* variable for the test duration
// so ambient developer/CI environments cannot leak into assertions.
// t.Setenv also marks the test as non-parallel, which the env overlay tests
// require anyway.
func clearVaultEnv(t *testing.T) {
	t.Helper()
	for _, key := range allVaultEnvVars {
		t.Setenv(key, "")
	}
}

// ============================================================================
// applyVaultEnv: nil-section paths
// ============================================================================

func TestApplyVaultEnv_NilSectionNoEnv_ReturnsNil(t *testing.T) {
	clearVaultEnv(t)

	assert.Nil(t, applyVaultEnv(nil, observability.NopLogger()),
		"absent section without VAULT_ADDR must keep vault off")
}

func TestApplyVaultEnv_NilSectionWithAddr_SynthesizesLegacyConfig(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://env:8200")
	t.Setenv(envVaultToken, "env-token")
	t.Setenv(envVaultNamespace, "env-ns")
	t.Setenv(envVaultCACert, "/env/ca.pem")
	t.Setenv(envVaultSkipVerify, "true")

	effective := applyVaultEnv(nil, observability.NopLogger())

	require.NotNil(t, effective)
	assert.True(t, effective.Enabled, "VAULT_ADDR must force Enabled (legacy trigger)")
	assert.Equal(t, "https://env:8200", effective.Address)
	assert.Equal(t, "env-token", effective.Token)
	assert.Empty(t, effective.TokenFile)
	assert.Equal(t, "env-ns", effective.Namespace)
	require.NotNil(t, effective.TLS)
	assert.Equal(t, "/env/ca.pem", effective.TLS.CACert)
	assert.True(t, effective.TLS.SkipVerify)
	assert.Nil(t, effective.Kubernetes, "token method must not synthesize a kubernetes block")
	assert.Nil(t, effective.AppRole, "token method must not synthesize an appRole block")
}

func TestApplyVaultEnv_NilSectionKubernetesMethod_SynthesizesBlock(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://env:8200")
	t.Setenv(envVaultAuthMethod, config.VaultAuthMethodKubernetes)
	t.Setenv(envVaultK8sRole, "env-role")
	t.Setenv(envVaultK8sMountPath, "k8s-alt")
	t.Setenv(envVaultK8sTokenPath, "/env/token")

	effective := applyVaultEnv(nil, observability.NopLogger())

	require.NotNil(t, effective)
	assert.Equal(t, config.VaultAuthMethodKubernetes, effective.AuthMethod)
	require.NotNil(t, effective.Kubernetes)
	assert.Equal(t, "env-role", effective.Kubernetes.Role)
	assert.Equal(t, "k8s-alt", effective.Kubernetes.MountPath)
	assert.Equal(t, "/env/token", effective.Kubernetes.TokenPath)
}

// ============================================================================
// applyVaultEnv: per-field precedence matrix
// ============================================================================

// vaultStringFieldCase describes one string field of the precedence matrix.
type vaultStringFieldCase struct {
	name     string
	envVar   string
	envValue string
	// baseEnv holds extra environment needed for the field to be applied
	// (e.g. the auth method selection for method-scoped variables).
	baseEnv map[string]string
	// baseFile returns the file section WITHOUT the field under test set.
	baseFile func() *config.VaultConfig
	// fileSet sets the field under test on the file section.
	fileSet func(v *config.VaultConfig)
	// fileValue is the expected value in the file-only scenario.
	fileValue string
	// defValue is the expected value in the neither scenario.
	defValue string
	// get extracts the field from the effective config (nil-block safe).
	get func(v *config.VaultConfig) string
}

// enabledVaultFileBase returns a file section with address+token so method
// resolution and validation-independent overlay behavior stay stable.
func enabledVaultFileBase() *config.VaultConfig {
	return &config.VaultConfig{Enabled: true, Address: "https://file:8200", Token: "file-token"}
}

// vaultPrecedenceMatrix returns one case per modeled string field.
//
//nolint:funlen // exhaustive per-field table, one entry per VAULT_* variable
func vaultPrecedenceMatrix() []vaultStringFieldCase {
	tlsGet := func(get func(*config.VaultClientTLSConfig) string) func(*config.VaultConfig) string {
		return func(v *config.VaultConfig) string {
			if v.TLS == nil {
				return ""
			}
			return get(v.TLS)
		}
	}
	k8sBase := func() *config.VaultConfig {
		base := enabledVaultFileBase()
		base.Token = ""
		base.AuthMethod = config.VaultAuthMethodKubernetes
		base.Kubernetes = &config.VaultKubernetesAuthConfig{Role: "base-role"}
		return base
	}
	appRoleBase := func() *config.VaultConfig {
		base := enabledVaultFileBase()
		base.Token = ""
		base.AuthMethod = config.VaultAuthMethodAppRole
		base.AppRole = &config.VaultAppRoleAuthConfig{RoleID: "base-role-id", SecretID: "base-secret"}
		return base
	}

	return []vaultStringFieldCase{
		{
			name: "address", envVar: envVaultAddr, envValue: "https://env:8200",
			baseFile: func() *config.VaultConfig {
				return &config.VaultConfig{Enabled: true, Token: "file-token"}
			},
			fileSet:   func(v *config.VaultConfig) { v.Address = "https://file:8200" },
			fileValue: "https://file:8200",
			get:       func(v *config.VaultConfig) string { return v.Address },
		},
		{
			name: "authMethod", envVar: envVaultAuthMethod, envValue: config.VaultAuthMethodAppRole,
			baseFile:  enabledVaultFileBase,
			fileSet:   func(v *config.VaultConfig) { v.AuthMethod = config.VaultAuthMethodKubernetes },
			fileValue: config.VaultAuthMethodKubernetes,
			get:       func(v *config.VaultConfig) string { return v.AuthMethod },
		},
		{
			name: "token", envVar: envVaultToken, envValue: "env-token",
			baseFile: func() *config.VaultConfig {
				return &config.VaultConfig{Enabled: true, Address: "https://file:8200"}
			},
			fileSet:   func(v *config.VaultConfig) { v.Token = "file-token" },
			fileValue: "file-token",
			get:       func(v *config.VaultConfig) string { return v.Token },
		},
		{
			name: "namespace", envVar: envVaultNamespace, envValue: "env-ns",
			baseFile:  enabledVaultFileBase,
			fileSet:   func(v *config.VaultConfig) { v.Namespace = "file-ns" },
			fileValue: "file-ns",
			get:       func(v *config.VaultConfig) string { return v.Namespace },
		},
		{
			name: "tls.caCert", envVar: envVaultCACert, envValue: "/env/ca.pem",
			baseFile: enabledVaultFileBase,
			fileSet: func(v *config.VaultConfig) {
				v.TLS = &config.VaultClientTLSConfig{CACert: "/file/ca.pem"}
			},
			fileValue: "/file/ca.pem",
			get:       tlsGet(func(t *config.VaultClientTLSConfig) string { return t.CACert }),
		},
		{
			name: "tls.caPath", envVar: envVaultCAPath, envValue: "/env/cas",
			baseFile: enabledVaultFileBase,
			fileSet: func(v *config.VaultConfig) {
				v.TLS = &config.VaultClientTLSConfig{CAPath: "/file/cas"}
			},
			fileValue: "/file/cas",
			get:       tlsGet(func(t *config.VaultClientTLSConfig) string { return t.CAPath }),
		},
		{
			name: "tls.clientCert", envVar: envVaultClientCert, envValue: "/env/client.pem",
			baseFile: enabledVaultFileBase,
			fileSet: func(v *config.VaultConfig) {
				v.TLS = &config.VaultClientTLSConfig{ClientCert: "/file/client.pem"}
			},
			fileValue: "/file/client.pem",
			get:       tlsGet(func(t *config.VaultClientTLSConfig) string { return t.ClientCert }),
		},
		{
			name: "tls.clientKey", envVar: envVaultClientKey, envValue: "/env/key.pem",
			baseFile: enabledVaultFileBase,
			fileSet: func(v *config.VaultConfig) {
				v.TLS = &config.VaultClientTLSConfig{ClientKey: "/file/key.pem"}
			},
			fileValue: "/file/key.pem",
			get:       tlsGet(func(t *config.VaultClientTLSConfig) string { return t.ClientKey }),
		},
		{
			name: "kubernetes.role", envVar: envVaultK8sRole, envValue: "env-role",
			baseFile:  k8sBase,
			fileSet:   func(v *config.VaultConfig) { v.Kubernetes.Role = "file-role" },
			fileValue: "file-role",
			defValue:  "base-role",
			get: func(v *config.VaultConfig) string {
				if v.Kubernetes == nil {
					return ""
				}
				return v.Kubernetes.Role
			},
		},
		{
			name: "kubernetes.mountPath", envVar: envVaultK8sMountPath, envValue: "env-mount",
			baseFile:  k8sBase,
			fileSet:   func(v *config.VaultConfig) { v.Kubernetes.MountPath = "file-mount" },
			fileValue: "file-mount",
			get: func(v *config.VaultConfig) string {
				if v.Kubernetes == nil {
					return ""
				}
				return v.Kubernetes.MountPath
			},
		},
		{
			name: "kubernetes.tokenPath", envVar: envVaultK8sTokenPath, envValue: "/env/sa-token",
			baseFile:  k8sBase,
			fileSet:   func(v *config.VaultConfig) { v.Kubernetes.TokenPath = "/file/sa-token" },
			fileValue: "/file/sa-token",
			get: func(v *config.VaultConfig) string {
				if v.Kubernetes == nil {
					return ""
				}
				return v.Kubernetes.TokenPath
			},
		},
		{
			name: "appRole.roleId", envVar: envVaultAppRoleRoleID, envValue: "env-role-id",
			baseFile:  appRoleBase,
			fileSet:   func(v *config.VaultConfig) { v.AppRole.RoleID = "file-role-id" },
			fileValue: "file-role-id",
			defValue:  "base-role-id",
			get: func(v *config.VaultConfig) string {
				if v.AppRole == nil {
					return ""
				}
				return v.AppRole.RoleID
			},
		},
		{
			name: "appRole.secretId", envVar: envVaultAppRoleSecretID, envValue: "env-secret",
			baseFile:  appRoleBase,
			fileSet:   func(v *config.VaultConfig) { v.AppRole.SecretID = "file-secret" },
			fileValue: "file-secret",
			defValue:  "base-secret",
			get: func(v *config.VaultConfig) string {
				if v.AppRole == nil {
					return ""
				}
				return v.AppRole.SecretID
			},
		},
		{
			name: "appRole.mountPath", envVar: envVaultAppRoleMountPath, envValue: "env-approle",
			baseFile:  appRoleBase,
			fileSet:   func(v *config.VaultConfig) { v.AppRole.MountPath = "file-approle" },
			fileValue: "file-approle",
			get: func(v *config.VaultConfig) string {
				if v.AppRole == nil {
					return ""
				}
				return v.AppRole.MountPath
			},
		},
	}
}

// TestApplyVaultEnv_PrecedenceMatrix drives every modeled string field
// through the four precedence scenarios: neither (defaults), file-only,
// env-only, and both (env must win).
func TestApplyVaultEnv_PrecedenceMatrix(t *testing.T) {
	logger := observability.NopLogger()

	for _, tc := range vaultPrecedenceMatrix() {
		t.Run(tc.name+"/neither", func(t *testing.T) {
			clearVaultEnv(t)
			applyBaseEnv(t, tc.baseEnv)

			effective := applyVaultEnv(tc.baseFile(), logger)

			require.NotNil(t, effective)
			assert.Equal(t, tc.defValue, tc.get(effective))
		})

		t.Run(tc.name+"/file-only", func(t *testing.T) {
			clearVaultEnv(t)
			applyBaseEnv(t, tc.baseEnv)
			fileCfg := tc.baseFile()
			tc.fileSet(fileCfg)

			effective := applyVaultEnv(fileCfg, logger)

			require.NotNil(t, effective)
			assert.Equal(t, tc.fileValue, tc.get(effective))
		})

		t.Run(tc.name+"/env-only", func(t *testing.T) {
			clearVaultEnv(t)
			applyBaseEnv(t, tc.baseEnv)
			t.Setenv(tc.envVar, tc.envValue)

			effective := applyVaultEnv(tc.baseFile(), logger)

			require.NotNil(t, effective)
			assert.Equal(t, tc.envValue, tc.get(effective))
		})

		t.Run(tc.name+"/both-env-wins", func(t *testing.T) {
			clearVaultEnv(t)
			applyBaseEnv(t, tc.baseEnv)
			t.Setenv(tc.envVar, tc.envValue)
			fileCfg := tc.baseFile()
			tc.fileSet(fileCfg)

			effective := applyVaultEnv(fileCfg, logger)

			require.NotNil(t, effective)
			assert.Equal(t, tc.envValue, tc.get(effective))
		})
	}
}

// applyBaseEnv sets scenario-scoped extra environment variables.
func applyBaseEnv(t *testing.T, baseEnv map[string]string) {
	t.Helper()
	for k, v := range baseEnv {
		t.Setenv(k, v)
	}
}

// ============================================================================
// applyVaultEnv: skipVerify boolean semantics (A-2)
// ============================================================================

func TestApplyVaultEnv_SkipVerify(t *testing.T) {
	t.Run("yes accepted as true (A-2 fix)", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv(envVaultAddr, "https://env:8200")
		t.Setenv(envVaultSkipVerify, "yes")

		effective := applyVaultEnv(nil, observability.NopLogger())

		require.NotNil(t, effective)
		require.NotNil(t, effective.TLS, "true skipVerify must create the TLS block")
		assert.True(t, effective.TLS.SkipVerify)
	})

	t.Run("invalid value warns and keeps file value", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv(envVaultSkipVerify, "maybe")

		rec := &warnRecorder{}
		fileCfg := enabledVaultFileBase()
		fileCfg.TLS = &config.VaultClientTLSConfig{SkipVerify: true}

		effective := applyVaultEnv(fileCfg, rec)

		require.NotNil(t, effective)
		require.NotNil(t, effective.TLS)
		assert.True(t, effective.TLS.SkipVerify, "invalid boolean must keep the previous value")

		warns := rec.warnings()
		require.Len(t, warns, 1)
		assert.Equal(t, warnInvalidEnvValue, warns[0].msg)
		gotVar, ok := fieldString(warns[0].fields, "variable")
		require.True(t, ok)
		assert.Equal(t, envVaultSkipVerify, gotVar)
	})

	t.Run("invalid value without TLS block does not create one", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv(envVaultSkipVerify, "maybe")

		rec := &warnRecorder{}
		effective := applyVaultEnv(enabledVaultFileBase(), rec)

		require.NotNil(t, effective)
		assert.Nil(t, effective.TLS)
		assert.Len(t, rec.warnings(), 1, "invalid value must be reported exactly once")
	})

	t.Run("false does not create TLS block", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv(envVaultSkipVerify, "false")

		effective := applyVaultEnv(enabledVaultFileBase(), observability.NopLogger())

		require.NotNil(t, effective)
		assert.Nil(t, effective.TLS, "false skipVerify alone must not create a TLS block (legacy parity)")
	})

	t.Run("file-only value kept when env is unset", func(t *testing.T) {
		// Completes the 15-variable × 4-scenario precedence symmetry: the
		// file-only scenario for the boolean VAULT_SKIP_VERIFY field.
		clearVaultEnv(t)

		fileCfg := enabledVaultFileBase()
		fileCfg.TLS = &config.VaultClientTLSConfig{SkipVerify: true}

		effective := applyVaultEnv(fileCfg, observability.NopLogger())

		require.NotNil(t, effective)
		require.NotNil(t, effective.TLS)
		assert.True(t, effective.TLS.SkipVerify,
			"the file value must be preserved when no env override is set")
	})

	t.Run("env false overrides file true", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv(envVaultSkipVerify, "false")

		fileCfg := enabledVaultFileBase()
		fileCfg.TLS = &config.VaultClientTLSConfig{SkipVerify: true}

		effective := applyVaultEnv(fileCfg, observability.NopLogger())

		require.NotNil(t, effective)
		require.NotNil(t, effective.TLS)
		assert.False(t, effective.TLS.SkipVerify, "env false must win over file true (per-field ENV priority)")
	})
}

// ============================================================================
// applyVaultEnv: cross-field semantics
// ============================================================================

func TestApplyVaultEnv_AddrForcesEnabled_WarnsOnDisabledFile(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://env:8200")

	rec := &warnRecorder{}
	fileCfg := &config.VaultConfig{Enabled: false, Address: "https://file:8200", Token: "t"}

	effective := applyVaultEnv(fileCfg, rec)

	require.NotNil(t, effective)
	assert.True(t, effective.Enabled, "VAULT_ADDR must force Enabled=true (env wins)")
	assert.Equal(t, "https://env:8200", effective.Address)

	warns := rec.warnings()
	require.Len(t, warns, 1, "the enabled:false vs VAULT_ADDR conflict must be surfaced")
	assert.Contains(t, warns[0].msg, "VAULT_ADDR")
}

func TestApplyVaultEnv_TokenEnvClearsTokenFile(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultToken, "env-token")

	fileCfg := &config.VaultConfig{
		Enabled: true, Address: "https://file:8200", TokenFile: "/etc/vault/token",
	}

	effective := applyVaultEnv(fileCfg, observability.NopLogger())

	require.NotNil(t, effective)
	assert.Equal(t, "env-token", effective.Token)
	assert.Empty(t, effective.TokenFile,
		"env token must clear the file reference so exactly-one validation stays coherent")
}

func TestApplyVaultEnv_SecretIDEnvClearsSecretIDFile(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAppRoleSecretID, "env-secret")

	fileCfg := &config.VaultConfig{
		Enabled: true, Address: "https://file:8200",
		AuthMethod: config.VaultAuthMethodAppRole,
		AppRole:    &config.VaultAppRoleAuthConfig{RoleID: "r", SecretIDFile: "/etc/vault/sid"},
	}

	effective := applyVaultEnv(fileCfg, observability.NopLogger())

	require.NotNil(t, effective)
	require.NotNil(t, effective.AppRole)
	assert.Equal(t, "env-secret", effective.AppRole.SecretID)
	assert.Empty(t, effective.AppRole.SecretIDFile)
}

func TestApplyVaultEnv_MethodOverrideLazyInitsBlock(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAuthMethod, config.VaultAuthMethodKubernetes)
	t.Setenv(envVaultK8sRole, "env-role")

	fileCfg := enabledVaultFileBase() // token method in the file, no k8s block

	effective := applyVaultEnv(fileCfg, observability.NopLogger())

	require.NotNil(t, effective)
	assert.Equal(t, config.VaultAuthMethodKubernetes, effective.AuthMethod)
	require.NotNil(t, effective.Kubernetes, "method override must lazily create the sub-block")
	assert.Equal(t, "env-role", effective.Kubernetes.Role)
}

func TestApplyVaultEnv_NonSelectedMethodVarsIgnored(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultK8sRole, "stray-role")
	t.Setenv(envVaultAppRoleRoleID, "stray-role-id")

	fileCfg := enabledVaultFileBase() // token method

	effective := applyVaultEnv(fileCfg, observability.NopLogger())

	require.NotNil(t, effective)
	assert.Nil(t, effective.Kubernetes, "kubernetes vars must be ignored under token method (legacy parity)")
	assert.Nil(t, effective.AppRole, "approle vars must be ignored under token method (legacy parity)")
}

func TestApplyVaultEnv_DoesNotMutateInput(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv(envVaultAddr, "https://env:8200")
	t.Setenv(envVaultToken, "env-token")
	t.Setenv(envVaultCACert, "/env/ca.pem")

	fileCfg := &config.VaultConfig{
		Enabled: true, Address: "https://file:8200", TokenFile: "/etc/vault/token",
		TLS: &config.VaultClientTLSConfig{CACert: "/file/ca.pem"},
	}
	snapshot := fileCfg.Clone()

	effective := applyVaultEnv(fileCfg, observability.NopLogger())

	require.NotNil(t, effective)
	assert.NotSame(t, fileCfg, effective)
	assert.Equal(t, snapshot, fileCfg, "the input section must never be mutated by the overlay")
}

func TestApplyVaultEnv_SectionWithoutEnvIsEquivalentCopy(t *testing.T) {
	clearVaultEnv(t)

	fileCfg := &config.VaultConfig{
		Enabled: true, Address: "https://file:8200", Token: "file-token",
		Cache: &config.VaultClientCacheConfig{Enabled: true, MaxSize: 10},
	}

	effective := applyVaultEnv(fileCfg, observability.NopLogger())

	require.NotNil(t, effective)
	assert.Equal(t, fileCfg, effective, "no env set: the effective config equals the file config")
	assert.NotSame(t, fileCfg, effective, "but it must be an independent copy")
}

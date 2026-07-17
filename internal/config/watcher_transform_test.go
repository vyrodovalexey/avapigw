// Watcher pre-validate transform hook tests. They pin the M-1 contract:
// with a hook, the watcher validates and delivers the EFFECTIVE (transformed)
// configuration, so files that rely on environment-supplied values (Helm
// env-mixed Vault deployments) keep hot reload alive; without a hook, the
// legacy raw-file validation behavior is byte-identical.
package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envMixedVaultConfigYAML enables spec.vault with a tokenFile but WITHOUT an
// address — the Helm env-mixed pattern where VAULT_ADDR supplies the address.
// Raw-file validation rejects it ("address is required when vault is
// enabled"); only the transformed (overlaid) config passes.
const envMixedVaultConfigYAML = `
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: env-mixed-gateway
spec:
  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  vault:
    enabled: true
    tokenFile: /etc/vault/token
`

// overlayAddress is the address the test transform injects, standing in for
// the VAULT_ADDR environment overlay applied by cmd/gateway.
const overlayAddress = "https://env-overlay:8200"

// addressFillingTransform mirrors the cmd/gateway wiring shape: it REPLACES
// the vault section on the received copy with a clone carrying the
// environment-supplied address, never deep-mutating the input section.
func addressFillingTransform(cfg *GatewayConfig) *GatewayConfig {
	v := cfg.Spec.Vault.Clone()
	if v == nil {
		v = &VaultConfig{Enabled: true}
	}
	v.Address = overlayAddress
	cfg.Spec.Vault = v
	return cfg
}

// writeConfigFile writes content to a temp config file and returns its path.
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// TestWatcher_PreValidateTransform_EnvMixedVault_HotReloadWorks is the M-1
// regression test: a config valid only together with the environment overlay
// must (1) start the watcher, (2) survive file edits with the reload
// callback receiving the TRANSFORMED config, and (3) never hit the error
// callback.
func TestWatcher_PreValidateTransform_EnvMixedVault_HotReloadWorks(t *testing.T) {
	// Not parallel due to file system operations and timing.

	configPath := writeConfigFile(t, envMixedVaultConfigYAML)

	var mu sync.Mutex
	var receivedConfig *GatewayConfig
	callbackCalled := make(chan struct{}, 1)
	callback := func(cfg *GatewayConfig) {
		mu.Lock()
		receivedConfig = cfg
		mu.Unlock()
		select {
		case callbackCalled <- struct{}{}:
		default:
		}
	}

	var errorCount atomic.Int32
	errorCallback := func(error) { errorCount.Add(1) }

	watcher, err := NewWatcher(configPath, callback,
		WithDebounceDelay(50*time.Millisecond),
		WithErrorCallback(errorCallback),
		WithPreValidateTransform(addressFillingTransform),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// (1) Start validates the TRANSFORMED config: it must succeed even
	// though the raw file has no vault address.
	require.NoError(t, watcher.Start(ctx),
		"the watcher must start on an env-mixed config when the transform fills the address")

	initial := watcher.GetLastConfig()
	require.NotNil(t, initial)
	require.NotNil(t, initial.Spec.Vault)
	assert.Equal(t, overlayAddress, initial.Spec.Vault.Address,
		"the stored initial config must be the effective (transformed) one")

	// (2) Edit the file — before the fix, ANY change to such a file failed
	// raw validation and hot reload was silently dead.
	time.Sleep(100 * time.Millisecond)
	edited := strings.Replace(envMixedVaultConfigYAML, "env-mixed-gateway", "env-mixed-updated", 1)
	require.NoError(t, os.WriteFile(configPath, []byte(edited), 0o600))

	select {
	case <-callbackCalled:
		mu.Lock()
		require.NotNil(t, receivedConfig)
		assert.Equal(t, "env-mixed-updated", receivedConfig.Metadata.Name,
			"the callback must see the edited file content")
		require.NotNil(t, receivedConfig.Spec.Vault)
		assert.Equal(t, overlayAddress, receivedConfig.Spec.Vault.Address,
			"the callback must receive the TRANSFORMED (effective) config")
		assert.Equal(t, "/etc/vault/token", receivedConfig.Spec.Vault.TokenFile,
			"file-supplied fields must survive the transform")
		mu.Unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("hot reload did not fire for the env-mixed config — M-1 regression")
	}

	// (3) Validation passed on every load: no error callback.
	assert.Equal(t, int32(0), errorCount.Load(),
		"the error callback must never fire when the transformed config is valid")

	require.NoError(t, watcher.Stop())
}

// TestWatcher_NoTransform_EnvMixedVault_RawValidationBehaviorPinned pins the
// hook-less behavior (unchanged by the fix): the watcher validates the RAW
// file config, so an env-mixed vault section fails at Start and, when it
// appears through a file edit, kills the reload with the error callback.
func TestWatcher_NoTransform_EnvMixedVault_RawValidationBehaviorPinned(t *testing.T) {
	// Not parallel due to file system operations and timing.

	t.Run("start fails on raw validation", func(t *testing.T) {
		configPath := writeConfigFile(t, envMixedVaultConfigYAML)

		watcher, err := NewWatcher(configPath, func(*GatewayConfig) {})
		require.NoError(t, err)

		err = watcher.Start(context.Background())
		require.Error(t, err, "without a hook the raw config must fail validation")
		assert.Contains(t, err.Error(), "address is required")
	})

	t.Run("file edit rejected, reload callback never runs", func(t *testing.T) {
		configPath := writeConfigFile(t, validConfigYAML)

		var callbackCount atomic.Int32
		errorReceived := make(chan error, 1)

		watcher, err := NewWatcher(configPath,
			func(*GatewayConfig) { callbackCount.Add(1) },
			WithDebounceDelay(50*time.Millisecond),
			WithErrorCallback(func(err error) {
				select {
				case errorReceived <- err:
				default:
				}
			}),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, watcher.Start(ctx))

		time.Sleep(100 * time.Millisecond)
		require.NoError(t, os.WriteFile(configPath, []byte(envMixedVaultConfigYAML), 0o600))

		select {
		case err := <-errorReceived:
			assert.Contains(t, err.Error(), "address is required",
				"the raw-validation error must surface via the error callback")
		case <-time.After(2 * time.Second):
			t.Fatal("error callback was not called for the raw-invalid config")
		}
		assert.Equal(t, int32(0), callbackCount.Load(),
			"the reload callback must not run when raw validation fails")

		require.NoError(t, watcher.Stop())
	})
}

// TestWatcher_EffectiveConfig_HookReceivesCopy_RawNotMutated proves the copy
// semantics: the hook receives a defensive shallow copy, so in-place
// scalar mutation and pointer-section replacement never leak into the raw
// parsed configuration.
func TestWatcher_EffectiveConfig_HookReceivesCopy_RawNotMutated(t *testing.T) {
	t.Parallel()

	rawVault := &VaultConfig{Enabled: true, TokenFile: "/etc/vault/token"}
	raw := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "raw"},
		Spec:       GatewaySpec{Vault: rawVault},
	}

	var received *GatewayConfig
	w := &Watcher{
		preValidateTransform: func(cfg *GatewayConfig) *GatewayConfig {
			received = cfg
			cfg.Metadata.Name = "transformed"
			return addressFillingTransform(cfg)
		},
	}

	effective := w.effectiveConfig(raw)

	require.NotNil(t, received)
	assert.NotSame(t, raw, received, "the hook must receive a copy, never the raw config")
	assert.Same(t, received, effective, "the hook result is the effective config")

	// Raw untouched: scalar field, section pointer, and section contents.
	assert.Equal(t, "raw", raw.Metadata.Name)
	assert.Same(t, rawVault, raw.Spec.Vault)
	assert.Equal(t, &VaultConfig{Enabled: true, TokenFile: "/etc/vault/token"}, raw.Spec.Vault,
		"the raw vault section must not be mutated by the transform")

	// Effective carries the transformation.
	assert.Equal(t, "transformed", effective.Metadata.Name)
	require.NotNil(t, effective.Spec.Vault)
	assert.Equal(t, overlayAddress, effective.Spec.Vault.Address)
	assert.NotSame(t, rawVault, effective.Spec.Vault,
		"the effective vault section must be an independent clone")
}

// TestWatcher_EffectiveConfig_NoHook_ReturnsRawIdentity guarantees the
// watcher is byte-identical without a hook: the raw pointer passes through.
func TestWatcher_EffectiveConfig_NoHook_ReturnsRawIdentity(t *testing.T) {
	t.Parallel()

	w := &Watcher{}
	raw := &GatewayConfig{Metadata: Metadata{Name: "raw"}}

	assert.Same(t, raw, w.effectiveConfig(raw),
		"without a hook the raw config must pass through unchanged (identity)")
}

// TestWatcher_EffectiveConfig_NilHookResult_FallsBackToCopy covers the
// defensive branch: a hook returning nil falls back to the (possibly
// in-place transformed) copy instead of propagating nil downstream.
func TestWatcher_EffectiveConfig_NilHookResult_FallsBackToCopy(t *testing.T) {
	t.Parallel()

	w := &Watcher{
		preValidateTransform: func(cfg *GatewayConfig) *GatewayConfig {
			cfg.Metadata.Name = "mutated-in-place"
			return nil
		},
	}
	raw := &GatewayConfig{Metadata: Metadata{Name: "raw"}}

	effective := w.effectiveConfig(raw)

	require.NotNil(t, effective, "a nil hook result must never propagate")
	assert.NotSame(t, raw, effective)
	assert.Equal(t, "mutated-in-place", effective.Metadata.Name,
		"the fallback copy carries in-place transformations")
	assert.Equal(t, "raw", raw.Metadata.Name, "the raw config stays untouched")
}

// TestWatcher_ForceReload_AppliesTransform proves ForceReload also validates
// and delivers the transformed config (all three load sites share the hook).
func TestWatcher_ForceReload_AppliesTransform(t *testing.T) {
	// Not parallel due to file system operations.

	configPath := writeConfigFile(t, envMixedVaultConfigYAML)

	var mu sync.Mutex
	var receivedConfig *GatewayConfig
	callback := func(cfg *GatewayConfig) {
		mu.Lock()
		receivedConfig = cfg
		mu.Unlock()
	}

	watcher, err := NewWatcher(configPath, callback,
		WithPreValidateTransform(addressFillingTransform),
	)
	require.NoError(t, err)

	require.NoError(t, watcher.ForceReload(),
		"ForceReload must validate the transformed config")

	mu.Lock()
	require.NotNil(t, receivedConfig)
	require.NotNil(t, receivedConfig.Spec.Vault)
	assert.Equal(t, overlayAddress, receivedConfig.Spec.Vault.Address)
	mu.Unlock()

	last := watcher.GetLastConfig()
	require.NotNil(t, last)
	require.NotNil(t, last.Spec.Vault)
	assert.Equal(t, overlayAddress, last.Spec.Vault.Address,
		"the stored config must be the effective one")
}

// TestWithPreValidateTransform covers the functional option itself.
func TestWithPreValidateTransform(t *testing.T) {
	t.Parallel()

	w := &Watcher{}
	opt := WithPreValidateTransform(addressFillingTransform)
	opt(w)

	require.NotNil(t, w.preValidateTransform)
	got := w.preValidateTransform(&GatewayConfig{})
	require.NotNil(t, got)
	require.NotNil(t, got.Spec.Vault)
	assert.Equal(t, overlayAddress, got.Spec.Vault.Address)
}

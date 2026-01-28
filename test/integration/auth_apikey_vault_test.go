//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
Vault API Key Integration Test Setup Instructions:

1. Start Vault in dev mode:
   docker run -d --name vault-test \
     -p 8200:8200 \
     -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
     -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
     vault:latest

2. Configure KV secrets engine:
   export VAULT_ADDR=http://127.0.0.1:8200
   export VAULT_TOKEN=myroot
   vault secrets enable -path=secret kv-v2

3. Run tests:
   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=myroot go test -tags=integration ./test/integration/...
*/

func TestIntegration_APIKey_VaultStore(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Store test API keys in Vault
	testKeys := []struct {
		id     string
		key    string
		scopes []string
		roles  []string
	}{
		{
			id:     "key-1",
			key:    "test-api-key-12345",
			scopes: []string{"read", "write"},
			roles:  []string{"user"},
		},
		{
			id:     "key-2",
			key:    "admin-api-key-67890",
			scopes: []string{"read", "write", "admin"},
			roles:  []string{"admin"},
		},
		{
			id:     "key-3",
			key:    "readonly-api-key-abcde",
			scopes: []string{"read"},
			roles:  []string{"reader"},
		},
	}

	// Store keys in Vault
	for _, tk := range testKeys {
		keyHash := hashAPIKey(tk.key)
		keyPath := "apikeys/" + keyHash

		keyData := map[string]interface{}{
			"id":      tk.id,
			"hash":    keyHash,
			"scopes":  tk.scopes,
			"roles":   tk.roles,
			"enabled": true,
		}

		err := setup.WriteSecret(keyPath, keyData)
		require.NoError(t, err, "Failed to write key %s to Vault", tk.id)

		// Also store by ID for lookup
		byIDPath := "apikeys/by-id/" + tk.id
		err = setup.WriteSecret(byIDPath, keyData)
		require.NoError(t, err, "Failed to write key by ID %s to Vault", tk.id)
	}

	t.Cleanup(func() {
		for _, tk := range testKeys {
			keyHash := hashAPIKey(tk.key)
			_ = setup.DeleteSecret("apikeys/" + keyHash)
			_ = setup.DeleteSecret("apikeys/by-id/" + tk.id)
		}
	})

	t.Run("create Vault store", func(t *testing.T) {
		apikeyConfig := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: setup.KVMount,
				Path:    "apikeys",
			},
			Cache: &apikey.CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: 1000,
			},
		}

		store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
		require.NoError(t, err)
		require.NotNil(t, store)
		defer store.Close()
	})

	t.Run("get key by value", func(t *testing.T) {
		apikeyConfig := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: setup.KVMount,
				Path:    "apikeys",
			},
		}

		store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
		require.NoError(t, err)
		defer store.Close()

		key, err := store.Get(ctx, "test-api-key-12345")
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, "key-1", key.ID)
		assert.Contains(t, key.Scopes, "read")
		assert.Contains(t, key.Scopes, "write")
		assert.Contains(t, key.Roles, "user")
		assert.True(t, key.Enabled)
	})

	t.Run("get key by ID", func(t *testing.T) {
		apikeyConfig := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: setup.KVMount,
				Path:    "apikeys",
			},
		}

		store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
		require.NoError(t, err)
		defer store.Close()

		key, err := store.GetByID(ctx, "key-2")
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, "key-2", key.ID)
		assert.Contains(t, key.Scopes, "admin")
		assert.Contains(t, key.Roles, "admin")
	})

	t.Run("key not found", func(t *testing.T) {
		apikeyConfig := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: setup.KVMount,
				Path:    "apikeys",
			},
		}

		store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
		require.NoError(t, err)
		defer store.Close()

		_, err = store.Get(ctx, "nonexistent-key")
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrAPIKeyNotFound)
	})

	t.Run("cache hit", func(t *testing.T) {
		apikeyConfig := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: setup.KVMount,
				Path:    "apikeys",
			},
			Cache: &apikey.CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: 1000,
			},
		}

		store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
		require.NoError(t, err)
		defer store.Close()

		// First call - cache miss
		start := time.Now()
		key1, err := store.Get(ctx, "test-api-key-12345")
		require.NoError(t, err)
		firstDuration := time.Since(start)

		// Second call - cache hit
		start = time.Now()
		key2, err := store.Get(ctx, "test-api-key-12345")
		require.NoError(t, err)
		secondDuration := time.Since(start)

		assert.Equal(t, key1.ID, key2.ID)
		t.Logf("First call: %v, Second call (cached): %v", firstDuration, secondDuration)
	})
}

func TestIntegration_APIKey_VaultValidator(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Store test API key
	testKey := "integration-test-key-xyz"
	keyHash := hashAPIKey(testKey)
	keyPath := "apikeys/" + keyHash

	keyData := map[string]interface{}{
		"id":      "integration-key",
		"hash":    keyHash,
		"scopes":  []string{"read", "write"},
		"roles":   []string{"user", "tester"},
		"enabled": true,
	}

	err = setup.WriteSecret(keyPath, keyData)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = setup.DeleteSecret(keyPath)
	})

	t.Run("validate API key with Vault store", func(t *testing.T) {
		apikeyConfig := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Extraction: []apikey.ExtractionSource{
				{
					Type: "header",
					Name: "X-API-Key",
				},
			},
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: setup.KVMount,
				Path:    "apikeys",
			},
		}

		store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
		require.NoError(t, err)
		defer store.Close()

		validator, err := apikey.NewValidator(apikeyConfig, apikey.WithStore(store), apikey.WithValidatorLogger(logger))
		require.NoError(t, err)

		identity, err := validator.Validate(ctx, testKey)
		require.NoError(t, err)
		require.NotNil(t, identity)

		assert.Equal(t, "integration-key", identity.ID)
		assert.Contains(t, identity.Roles, "user")
		assert.Contains(t, identity.Roles, "tester")
		assert.Contains(t, identity.Scopes, "read")
		assert.Contains(t, identity.Scopes, "write")
	})

	t.Run("reject invalid API key", func(t *testing.T) {
		apikeyConfig := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: setup.KVMount,
				Path:    "apikeys",
			},
		}

		store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
		require.NoError(t, err)
		defer store.Close()

		validator, err := apikey.NewValidator(apikeyConfig, apikey.WithStore(store), apikey.WithValidatorLogger(logger))
		require.NoError(t, err)

		_, err = validator.Validate(ctx, "invalid-key")
		require.Error(t, err)
	})
}

func TestIntegration_APIKey_VaultDisabledKey(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Store disabled API key
	disabledKey := "disabled-test-key"
	keyHash := hashAPIKey(disabledKey)
	keyPath := "apikeys/" + keyHash

	keyData := map[string]interface{}{
		"id":      "disabled-key",
		"hash":    keyHash,
		"scopes":  []string{"read"},
		"roles":   []string{"user"},
		"enabled": false, // Key is disabled
	}

	err = setup.WriteSecret(keyPath, keyData)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = setup.DeleteSecret(keyPath)
	})

	t.Run("reject disabled API key", func(t *testing.T) {
		apikeyConfig := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: setup.KVMount,
				Path:    "apikeys",
			},
		}

		store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
		require.NoError(t, err)
		defer store.Close()

		validator, err := apikey.NewValidator(apikeyConfig, apikey.WithStore(store), apikey.WithValidatorLogger(logger))
		require.NoError(t, err)

		_, err = validator.Validate(ctx, disabledKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disabled")
	})
}

func TestIntegration_APIKey_VaultMultipleKeys(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Store multiple API keys with different permissions
	keys := map[string]struct {
		id     string
		scopes []string
		roles  []string
	}{
		"service-a-key": {
			id:     "service-a",
			scopes: []string{"service-a:read", "service-a:write"},
			roles:  []string{"service"},
		},
		"service-b-key": {
			id:     "service-b",
			scopes: []string{"service-b:read"},
			roles:  []string{"service", "readonly"},
		},
		"admin-service-key": {
			id:     "admin-service",
			scopes: []string{"*"},
			roles:  []string{"admin", "service"},
		},
	}

	for key, info := range keys {
		keyHash := hashAPIKey(key)
		keyPath := "apikeys/" + keyHash

		keyData := map[string]interface{}{
			"id":      info.id,
			"hash":    keyHash,
			"scopes":  info.scopes,
			"roles":   info.roles,
			"enabled": true,
		}

		err := setup.WriteSecret(keyPath, keyData)
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		for key := range keys {
			keyHash := hashAPIKey(key)
			_ = setup.DeleteSecret("apikeys/" + keyHash)
		}
	})

	apikeyConfig := &apikey.Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
		Vault: &apikey.VaultConfig{
			Enabled: true,
			KVMount: setup.KVMount,
			Path:    "apikeys",
		},
	}

	store, err := apikey.NewVaultStore(client, apikeyConfig, logger)
	require.NoError(t, err)
	defer store.Close()

	validator, err := apikey.NewValidator(apikeyConfig, apikey.WithStore(store), apikey.WithValidatorLogger(logger))
	require.NoError(t, err)

	for key, expected := range keys {
		t.Run("validate "+expected.id, func(t *testing.T) {
			identity, err := validator.Validate(ctx, key)
			require.NoError(t, err)
			require.NotNil(t, identity)

			assert.Equal(t, expected.id, identity.ID)
			for _, scope := range expected.scopes {
				assert.Contains(t, identity.Scopes, scope)
			}
			for _, role := range expected.roles {
				assert.Contains(t, identity.Roles, role)
			}
		})
	}
}

// hashAPIKey hashes an API key using SHA-256.
func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

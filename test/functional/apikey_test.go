//go:build functional
// +build functional

package functional

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestFunctional_APIKey_Validator_BasicValidation(t *testing.T) {
	t.Parallel()

	testKeys := []apikey.StaticKey{
		{
			ID:      "key-1",
			Key:     "test-api-key-12345",
			Name:    "Test Key 1",
			Scopes:  []string{"read", "write"},
			Roles:   []string{"user"},
			Enabled: true,
		},
		{
			ID:      "key-2",
			Key:     "another-api-key-67890",
			Name:    "Test Key 2",
			Scopes:  []string{"read"},
			Roles:   []string{"reader"},
			Enabled: true,
		},
		{
			ID:      "key-disabled",
			Key:     "disabled-key",
			Name:    "Disabled Key",
			Enabled: false,
		},
	}

	cfg := &apikey.Config{
		Enabled:       true,
		HashAlgorithm: "plaintext", // For testing
		Store: &apikey.StoreConfig{
			Type: "memory",
			Keys: testKeys,
		},
	}

	validator, err := apikey.NewValidator(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("validate valid key", func(t *testing.T) {
		t.Parallel()

		keyInfo, err := validator.Validate(ctx, "test-api-key-12345")
		require.NoError(t, err)
		require.NotNil(t, keyInfo)

		assert.Equal(t, "key-1", keyInfo.ID)
		assert.Equal(t, "Test Key 1", keyInfo.Name)
		assert.Contains(t, keyInfo.Scopes, "read")
		assert.Contains(t, keyInfo.Scopes, "write")
		assert.Contains(t, keyInfo.Roles, "user")
	})

	t.Run("validate another valid key", func(t *testing.T) {
		t.Parallel()

		keyInfo, err := validator.Validate(ctx, "another-api-key-67890")
		require.NoError(t, err)
		require.NotNil(t, keyInfo)

		assert.Equal(t, "key-2", keyInfo.ID)
		assert.Contains(t, keyInfo.Scopes, "read")
		assert.NotContains(t, keyInfo.Scopes, "write")
	})

	t.Run("reject invalid key", func(t *testing.T) {
		t.Parallel()

		_, err := validator.Validate(ctx, "invalid-key")
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrAPIKeyNotFound)
	})

	t.Run("reject empty key", func(t *testing.T) {
		t.Parallel()

		_, err := validator.Validate(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrEmptyAPIKey)
	})

	t.Run("reject disabled key", func(t *testing.T) {
		t.Parallel()

		_, err := validator.Validate(ctx, "disabled-key")
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrAPIKeyDisabled)
	})
}

func TestFunctional_APIKey_Validator_SHA256Hashing(t *testing.T) {
	t.Parallel()

	// Pre-compute hash for "test-api-key"
	keyHash := helpers.HashAPIKey("test-api-key")

	// When using SHA256 hashing, the store lookup is by raw key value,
	// but validation compares the hash of the provided key against the stored hash.
	// So we need to store the key with its raw value for lookup, and the hash for validation.
	testKeys := []apikey.StaticKey{
		{
			ID:      "hashed-key",
			Key:     "test-api-key", // Raw key for store lookup
			Hash:    keyHash,        // Hash for validation
			Name:    "Hashed Key",
			Scopes:  []string{"read"},
			Enabled: true,
		},
	}

	cfg := &apikey.Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
		Store: &apikey.StoreConfig{
			Type: "memory",
			Keys: testKeys,
		},
	}

	validator, err := apikey.NewValidator(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("validate key with SHA256 hash", func(t *testing.T) {
		t.Parallel()

		keyInfo, err := validator.Validate(ctx, "test-api-key")
		require.NoError(t, err)
		require.NotNil(t, keyInfo)

		assert.Equal(t, "hashed-key", keyInfo.ID)
	})

	t.Run("reject wrong key", func(t *testing.T) {
		t.Parallel()

		_, err := validator.Validate(ctx, "wrong-key")
		require.Error(t, err)
	})
}

func TestFunctional_APIKey_Validator_Expiration(t *testing.T) {
	t.Parallel()

	pastTime := time.Now().Add(-1 * time.Hour)
	futureTime := time.Now().Add(1 * time.Hour)

	testKeys := []apikey.StaticKey{
		{
			ID:        "expired-key",
			Key:       "expired-api-key",
			ExpiresAt: &pastTime,
			Enabled:   true,
		},
		{
			ID:        "valid-key",
			Key:       "valid-api-key",
			ExpiresAt: &futureTime,
			Enabled:   true,
		},
		{
			ID:      "no-expiry-key",
			Key:     "no-expiry-api-key",
			Enabled: true,
		},
	}

	cfg := &apikey.Config{
		Enabled:       true,
		HashAlgorithm: "plaintext",
		Store: &apikey.StoreConfig{
			Type: "memory",
			Keys: testKeys,
		},
	}

	validator, err := apikey.NewValidator(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("reject expired key", func(t *testing.T) {
		t.Parallel()

		_, err := validator.Validate(ctx, "expired-api-key")
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrAPIKeyExpired)
	})

	t.Run("accept valid key with future expiry", func(t *testing.T) {
		t.Parallel()

		keyInfo, err := validator.Validate(ctx, "valid-api-key")
		require.NoError(t, err)
		require.NotNil(t, keyInfo)
		assert.Equal(t, "valid-key", keyInfo.ID)
	})

	t.Run("accept key without expiry", func(t *testing.T) {
		t.Parallel()

		keyInfo, err := validator.Validate(ctx, "no-expiry-api-key")
		require.NoError(t, err)
		require.NotNil(t, keyInfo)
		assert.Equal(t, "no-expiry-key", keyInfo.ID)
	})
}

func TestFunctional_APIKey_KeyInfo_IsExpired(t *testing.T) {
	t.Parallel()

	t.Run("expired key", func(t *testing.T) {
		t.Parallel()

		pastTime := time.Now().Add(-1 * time.Hour)
		keyInfo := &apikey.KeyInfo{
			ID:        "test",
			ExpiresAt: &pastTime,
		}
		assert.True(t, keyInfo.IsExpired())
	})

	t.Run("valid key", func(t *testing.T) {
		t.Parallel()

		futureTime := time.Now().Add(1 * time.Hour)
		keyInfo := &apikey.KeyInfo{
			ID:        "test",
			ExpiresAt: &futureTime,
		}
		assert.False(t, keyInfo.IsExpired())
	})

	t.Run("key without expiry", func(t *testing.T) {
		t.Parallel()

		keyInfo := &apikey.KeyInfo{
			ID: "test",
		}
		assert.False(t, keyInfo.IsExpired())
	})
}

func TestFunctional_APIKey_HashKey(t *testing.T) {
	t.Parallel()

	t.Run("SHA256 hash", func(t *testing.T) {
		t.Parallel()

		hash, err := apikey.HashKey("test-key", "sha256")
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.Len(t, hash, 64) // SHA256 produces 64 hex characters

		// Same input should produce same hash
		hash2, err := apikey.HashKey("test-key", "sha256")
		require.NoError(t, err)
		assert.Equal(t, hash, hash2)

		// Different input should produce different hash
		hash3, err := apikey.HashKey("different-key", "sha256")
		require.NoError(t, err)
		assert.NotEqual(t, hash, hash3)
	})

	t.Run("SHA512 hash", func(t *testing.T) {
		t.Parallel()

		hash, err := apikey.HashKey("test-key", "sha512")
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.Len(t, hash, 128) // SHA512 produces 128 hex characters
	})

	t.Run("bcrypt hash", func(t *testing.T) {
		t.Parallel()

		hash, err := apikey.HashKey("test-key", "bcrypt")
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.True(t, len(hash) > 50) // bcrypt hashes are typically 60 characters
	})

	t.Run("plaintext", func(t *testing.T) {
		t.Parallel()

		hash, err := apikey.HashKey("test-key", "plaintext")
		require.NoError(t, err)
		assert.Equal(t, "test-key", hash)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		t.Parallel()

		_, err := apikey.HashKey("test-key", "unsupported")
		require.Error(t, err)
	})
}

func TestFunctional_APIKey_Config_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := apikey.DefaultConfig()
	require.NotNil(t, cfg)

	assert.False(t, cfg.Enabled)
	assert.Equal(t, "sha256", cfg.HashAlgorithm)
	assert.NotNil(t, cfg.Extraction)
	assert.Len(t, cfg.Extraction, 1)
	assert.Equal(t, "header", cfg.Extraction[0].Type)
	assert.Equal(t, "X-API-Key", cfg.Extraction[0].Name)
	assert.NotNil(t, cfg.Cache)
	assert.True(t, cfg.Cache.Enabled)
}

func TestFunctional_APIKey_Config_GetEffectiveHashAlgorithm(t *testing.T) {
	t.Parallel()

	t.Run("explicit algorithm", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			HashAlgorithm: "sha512",
		}
		assert.Equal(t, "sha512", cfg.GetEffectiveHashAlgorithm())
	})

	t.Run("default algorithm", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{}
		assert.Equal(t, "sha256", cfg.GetEffectiveHashAlgorithm())
	})
}

func TestFunctional_APIKey_Validator_Creation(t *testing.T) {
	t.Parallel()

	t.Run("create with memory store", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Store: &apikey.StoreConfig{
				Type: "memory",
				Keys: []apikey.StaticKey{
					{ID: "key1", Key: "test", Enabled: true},
				},
			},
		}

		validator, err := apikey.NewValidator(cfg)
		require.NoError(t, err)
		require.NotNil(t, validator)
	})

	t.Run("fail with nil config", func(t *testing.T) {
		t.Parallel()

		_, err := apikey.NewValidator(nil)
		require.Error(t, err)
	})
}

func TestFunctional_APIKey_Validator_Metadata(t *testing.T) {
	t.Parallel()

	testKeys := []apikey.StaticKey{
		{
			ID:      "key-with-metadata",
			Key:     "metadata-key",
			Name:    "Key with Metadata",
			Scopes:  []string{"read"},
			Roles:   []string{"user"},
			Enabled: true,
			Metadata: map[string]string{
				"environment": "production",
				"team":        "platform",
				"version":     "v1",
			},
		},
	}

	cfg := &apikey.Config{
		Enabled:       true,
		HashAlgorithm: "plaintext",
		Store: &apikey.StoreConfig{
			Type: "memory",
			Keys: testKeys,
		},
	}

	validator, err := apikey.NewValidator(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("retrieve key with metadata", func(t *testing.T) {
		t.Parallel()

		keyInfo, err := validator.Validate(ctx, "metadata-key")
		require.NoError(t, err)
		require.NotNil(t, keyInfo)

		assert.Equal(t, "production", keyInfo.Metadata["environment"])
		assert.Equal(t, "platform", keyInfo.Metadata["team"])
		assert.Equal(t, "v1", keyInfo.Metadata["version"])
	})
}

func TestFunctional_APIKey_Validator_MultipleKeys(t *testing.T) {
	t.Parallel()

	// Create many keys
	var testKeys []apikey.StaticKey
	for i := 0; i < 100; i++ {
		testKeys = append(testKeys, apikey.StaticKey{
			ID:      helpers.HashAPIKey(string(rune('a' + i%26))),
			Key:     helpers.HashAPIKey(string(rune('a' + i%26))),
			Name:    "Key " + string(rune('a'+i%26)),
			Enabled: true,
		})
	}

	cfg := &apikey.Config{
		Enabled:       true,
		HashAlgorithm: "plaintext",
		Store: &apikey.StoreConfig{
			Type: "memory",
			Keys: testKeys,
		},
	}

	validator, err := apikey.NewValidator(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("validate keys from large set", func(t *testing.T) {
		t.Parallel()

		// Validate first key
		keyInfo, err := validator.Validate(ctx, testKeys[0].Key)
		require.NoError(t, err)
		require.NotNil(t, keyInfo)

		// Validate last key
		keyInfo, err = validator.Validate(ctx, testKeys[len(testKeys)-1].Key)
		require.NoError(t, err)
		require.NotNil(t, keyInfo)
	})
}

func TestFunctional_APIKey_StaticKey_Validation(t *testing.T) {
	t.Parallel()

	t.Run("valid static key", func(t *testing.T) {
		t.Parallel()

		key := helpers.CreateTestAPIKey("key-1", "test-key", []string{"read"}, []string{"user"})
		assert.Equal(t, "key-1", key.ID)
		assert.Equal(t, "test-key", key.Key)
		assert.Contains(t, key.Scopes, "read")
		assert.Contains(t, key.Roles, "user")
		assert.True(t, key.Enabled)
	})
}

func TestFunctional_APIKey_ExtractionSources(t *testing.T) {
	t.Parallel()

	t.Run("header extraction", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled: true,
			Extraction: []apikey.ExtractionSource{
				{Type: "header", Name: "X-API-Key"},
				{Type: "header", Name: "Authorization", Prefix: "ApiKey "},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("query extraction", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled: true,
			Extraction: []apikey.ExtractionSource{
				{Type: "query", Name: "api_key"},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("metadata extraction for gRPC", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled: true,
			Extraction: []apikey.ExtractionSource{
				{Type: "metadata", Name: "x-api-key"},
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})
}

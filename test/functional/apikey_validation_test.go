//go:build functional
// +build functional

// API key configuration-tightening functional tests.
//
// They cover the load-time validation introduced for static key entries
// (an entry must carry either a raw key or a hash compatible with the
// effective hash algorithm), the bcrypt-with-Vault rejection, hash-only
// authentication through the public Validator API, and the store_error
// metric reason emitted when the backing store fails (as opposed to a
// genuine not-found miss).
package functional

import (
	"context"
	"fmt"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
)

// mustHash hashes a key with the given algorithm, failing the test on error.
func mustHash(t *testing.T, key, algorithm string) string {
	t.Helper()
	hash, err := apikey.HashKey(key, algorithm)
	require.NoError(t, err)
	return hash
}

// memoryConfig builds an enabled memory-store config with the given
// algorithm and static keys.
func memoryConfig(algorithm string, keys ...apikey.StaticKey) *apikey.Config {
	return &apikey.Config{
		Enabled:       true,
		HashAlgorithm: algorithm,
		Store: &apikey.StoreConfig{
			Type: "memory",
			Keys: keys,
		},
	}
}

// TestFunctional_APIKey_ConfigValidation_StaticKeys verifies the tightened
// load-time validation: entries that could never authenticate are rejected.
func TestFunctional_APIKey_ConfigValidation_StaticKeys(t *testing.T) {
	t.Parallel()

	sha256Hash := mustHash(t, "some-api-key", "sha256")
	sha512Hash := mustHash(t, "some-api-key", "sha512")
	bcryptHash := mustHash(t, "some-api-key", "bcrypt")

	tests := []struct {
		name      string
		algorithm string
		key       apikey.StaticKey
		wantErr   string // empty means valid
	}{
		{
			name:      "raw key only is valid",
			algorithm: "sha256",
			key:       apikey.StaticKey{ID: "k", Key: "raw-value", Enabled: true},
		},
		{
			name:      "sha256 hash-only entry is valid",
			algorithm: "sha256",
			key:       apikey.StaticKey{ID: "k", Hash: sha256Hash, Enabled: true},
		},
		{
			name:      "sha512 hash-only entry is valid",
			algorithm: "sha512",
			key:       apikey.StaticKey{ID: "k", Hash: sha512Hash, Enabled: true},
		},
		{
			name:      "bcrypt hash-only entry is valid",
			algorithm: "bcrypt",
			key:       apikey.StaticKey{ID: "k", Hash: bcryptHash, Enabled: true},
		},
		{
			name:      "uppercase sha256 hash is valid",
			algorithm: "sha256",
			key:       apikey.StaticKey{ID: "k", Hash: strings.ToUpper(sha256Hash), Enabled: true},
		},
		{
			name:      "entry with neither key nor hash is rejected",
			algorithm: "sha256",
			key:       apikey.StaticKey{ID: "empty", Enabled: true},
			wantErr:   "either key or hash must be set",
		},
		{
			name:      "fake hash is rejected under sha256",
			algorithm: "sha256",
			key:       apikey.StaticKey{ID: "fake", Hash: "hash1", Enabled: true},
			wantErr:   "not compatible with hash algorithm",
		},
		{
			name:      "sha512-length hash is rejected under sha256",
			algorithm: "sha256",
			key:       apikey.StaticKey{ID: "mismatch", Hash: sha512Hash, Enabled: true},
			wantErr:   "not compatible with hash algorithm",
		},
		{
			name:      "sha256-length hash is rejected under sha512",
			algorithm: "sha512",
			key:       apikey.StaticKey{ID: "mismatch", Hash: sha256Hash, Enabled: true},
			wantErr:   "not compatible with hash algorithm",
		},
		{
			name:      "non-bcrypt hash is rejected under bcrypt",
			algorithm: "bcrypt",
			key:       apikey.StaticKey{ID: "mismatch", Hash: sha256Hash, Enabled: true},
			wantErr:   "not compatible with hash algorithm",
		},
		{
			name:      "hash-only entry is rejected under plaintext",
			algorithm: "plaintext",
			key:       apikey.StaticKey{ID: "plain", Hash: sha256Hash, Enabled: true},
			wantErr:   "not compatible with hash algorithm",
		},
		{
			name:      "non-hex value of digest length is rejected",
			algorithm: "sha256",
			key:       apikey.StaticKey{ID: "nothex", Hash: strings.Repeat("z", 64), Enabled: true},
			wantErr:   "not compatible with hash algorithm",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := memoryConfig(tc.algorithm, tc.key).Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	t.Run("disabled config skips static key validation", func(t *testing.T) {
		t.Parallel()

		cfg := memoryConfig("sha256", apikey.StaticKey{ID: "broken", Hash: "hash1"})
		cfg.Enabled = false
		assert.NoError(t, cfg.Validate(),
			"validation only applies to enabled API key configs")
	})
}

// TestFunctional_APIKey_ConfigValidation_VaultBcrypt verifies that
// bcrypt-hashed keys are rejected at load time for Vault-backed storage
// (bcrypt hashes are salted and can never address a Vault path).
func TestFunctional_APIKey_ConfigValidation_VaultBcrypt(t *testing.T) {
	t.Parallel()

	t.Run("bcrypt with store.type=vault is rejected", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "bcrypt",
			Store:         &apikey.StoreConfig{Type: "vault"},
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bcrypt")
		assert.Contains(t, err.Error(), "vault")
	})

	t.Run("bcrypt with enabled vault section is rejected", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "bcrypt",
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bcrypt")
	})

	t.Run("sha256 with vault store is accepted", func(t *testing.T) {
		t.Parallel()

		cfg := &apikey.Config{
			Enabled:       true,
			HashAlgorithm: "sha256",
			Store:         &apikey.StoreConfig{Type: "vault"},
			Vault: &apikey.VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("bcrypt with memory store is accepted", func(t *testing.T) {
		t.Parallel()

		hash := mustHash(t, "bcrypt-key", "bcrypt")
		cfg := memoryConfig("bcrypt", apikey.StaticKey{ID: "b", Hash: hash, Enabled: true})
		assert.NoError(t, cfg.Validate())
	})
}

// TestFunctional_APIKey_Validator_HashOnlyKeys verifies that static entries
// carrying only a pre-computed hash (no raw key material in config)
// authenticate presented raw keys through the public Validator API.
func TestFunctional_APIKey_Validator_HashOnlyKeys(t *testing.T) {
	t.Parallel()

	const rawKey = "hash-only-secret-key"

	algorithms := []string{"sha256", "sha512", "bcrypt"}
	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()

			cfg := memoryConfig(algorithm, apikey.StaticKey{
				ID:      "hash-only-" + algorithm,
				Hash:    mustHash(t, rawKey, algorithm),
				Name:    "Hash Only " + algorithm,
				Scopes:  []string{"read"},
				Enabled: true,
			})
			require.NoError(t, cfg.Validate())

			validator, err := apikey.NewValidator(cfg)
			require.NoError(t, err)

			ctx := context.Background()

			keyInfo, err := validator.Validate(ctx, rawKey)
			require.NoError(t, err, "hash-only entry must authenticate the raw key")
			assert.Equal(t, "hash-only-"+algorithm, keyInfo.ID)
			assert.Contains(t, keyInfo.Scopes, "read")

			_, err = validator.Validate(ctx, "wrong-key")
			require.Error(t, err, "wrong key must not authenticate")
			assert.ErrorIs(t, err, apikey.ErrAPIKeyNotFound)
		})
	}

	t.Run("uppercase hex hash normalizes for lookup and comparison", func(t *testing.T) {
		t.Parallel()

		cfg := memoryConfig("sha256", apikey.StaticKey{
			ID:      "upper",
			Hash:    strings.ToUpper(mustHash(t, rawKey, "sha256")),
			Enabled: true,
		})
		require.NoError(t, cfg.Validate())

		validator, err := apikey.NewValidator(cfg)
		require.NoError(t, err)

		keyInfo, err := validator.Validate(context.Background(), rawKey)
		require.NoError(t, err)
		assert.Equal(t, "upper", keyInfo.ID)
	})
}

// failingStore is a Store stub whose lookups always fail with the given
// error, simulating an infrastructure outage (for example sealed Vault).
type failingStore struct {
	err error
}

func (s *failingStore) Get(context.Context, string) (*apikey.StaticKey, error) {
	return nil, s.err
}

func (s *failingStore) GetByID(context.Context, string) (*apikey.StaticKey, error) {
	return nil, s.err
}

func (s *failingStore) List(context.Context) ([]*apikey.StaticKey, error) {
	return nil, s.err
}

func (s *failingStore) Close() error { return nil }

// counterValue extracts a labeled counter value from a gathered metric
// family, returning 0 when the label combination is absent.
func counterValue(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			got := make(map[string]string, len(metric.GetLabel()))
			for _, pair := range metric.GetLabel() {
				got[pair.GetName()] = pair.GetValue()
			}
			matched := true
			for k, v := range labels {
				if got[k] != v {
					matched = false
					break
				}
			}
			if matched {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// TestFunctional_APIKey_Validator_StoreErrorMetric verifies that store
// outages surface as reason="store_error" while genuine misses keep
// reason="not_found", so operators can tell outages from misses.
func TestFunctional_APIKey_Validator_StoreErrorMetric(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("store outage records store_error and propagates the error", func(t *testing.T) {
		t.Parallel()

		metrics := apikey.NewMetrics("fnstoreerr")
		storeErr := fmt.Errorf("%w: vault sealed", apikey.ErrStoreUnavailable)

		validator, err := apikey.NewValidator(
			memoryConfig("sha256"),
			apikey.WithStore(&failingStore{err: storeErr}),
			apikey.WithValidatorMetrics(metrics),
		)
		require.NoError(t, err)

		_, err = validator.Validate(ctx, "any-key")
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrStoreUnavailable,
			"store outages must propagate, not masquerade as not-found")
		assert.NotErrorIs(t, err, apikey.ErrAPIKeyNotFound)

		families, gatherErr := metrics.Registry().Gather()
		require.NoError(t, gatherErr)

		assert.Equal(t, float64(1), counterValue(t, families,
			"fnstoreerr_apikey_validation_total",
			map[string]string{"status": "error", "reason": "store_error"}),
			"store failure must be recorded with reason=store_error")
		assert.Equal(t, float64(0), counterValue(t, families,
			"fnstoreerr_apikey_validation_total",
			map[string]string{"status": "error", "reason": "not_found"}),
			"store failure must not be recorded as a miss")
	})

	t.Run("genuine miss records not_found", func(t *testing.T) {
		t.Parallel()

		metrics := apikey.NewMetrics("fnnotfound")

		validator, err := apikey.NewValidator(
			memoryConfig("sha256", apikey.StaticKey{ID: "k", Key: "known-key", Enabled: true}),
			apikey.WithValidatorMetrics(metrics),
		)
		require.NoError(t, err)

		_, err = validator.Validate(ctx, "unknown-key")
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrAPIKeyNotFound)

		families, gatherErr := metrics.Registry().Gather()
		require.NoError(t, gatherErr)

		assert.Equal(t, float64(1), counterValue(t, families,
			"fnnotfound_apikey_validation_total",
			map[string]string{"status": "error", "reason": "not_found"}))
		assert.Equal(t, float64(0), counterValue(t, families,
			"fnnotfound_apikey_validation_total",
			map[string]string{"status": "error", "reason": "store_error"}))
	})
}

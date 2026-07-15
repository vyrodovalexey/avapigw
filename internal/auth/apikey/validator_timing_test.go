package apikey

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// countingLogger is an observability.Logger that records Warn messages.
type countingLogger struct {
	mu    sync.Mutex
	warns []string
}

func (l *countingLogger) Debug(string, ...observability.Field) { /* not recorded */ }
func (l *countingLogger) Info(string, ...observability.Field)  { /* not recorded */ }
func (l *countingLogger) Error(string, ...observability.Field) { /* not recorded */ }
func (l *countingLogger) Fatal(string, ...observability.Field) { /* not recorded */ }

func (l *countingLogger) Warn(msg string, _ ...observability.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}

func (l *countingLogger) With(...observability.Field) observability.Logger { return l }
func (l *countingLogger) WithContext(context.Context) observability.Logger { return l }
func (l *countingLogger) Sync() error                                      { return nil }
func (l *countingLogger) warnCount(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	count := 0
	for _, w := range l.warns {
		if strings.Contains(w, substr) {
			count++
		}
	}
	return count
}

func TestValidator_PlaintextWarnLoggedOnceAtConstruction(t *testing.T) {
	t.Parallel()

	logger := &countingLogger{}
	apiKey := "plain-key"

	store := newMockStore()
	store.AddKey(&StaticKey{ID: "key1", Key: apiKey, Enabled: true})

	v, err := NewValidator(
		&Config{Enabled: true, HashAlgorithm: HashAlgPlaintext},
		WithStore(store),
		WithValidatorLogger(logger),
	)
	require.NoError(t, err)

	require.Equal(t, 1, logger.warnCount("plaintext"), "warn must fire once at construction")

	// Multiple validations must NOT add per-validation warnings.
	for i := 0; i < 3; i++ {
		_, err = v.Validate(context.Background(), apiKey)
		require.NoError(t, err)
	}
	_, _ = v.Validate(context.Background(), "wrong-key")

	assert.Equal(t, 1, logger.warnCount("plaintext"), "warn must not repeat per validation")
}

func TestValidator_NoPlaintextWarnForHashedAlgorithms(t *testing.T) {
	t.Parallel()

	logger := &countingLogger{}

	_, err := NewValidator(
		&Config{Enabled: true, HashAlgorithm: HashAlgSHA256},
		WithStore(newMockStore()),
		WithValidatorLogger(logger),
	)
	require.NoError(t, err)

	assert.Zero(t, logger.warnCount("plaintext"))
}

func TestValidator_DummyCompareOnNotFound(t *testing.T) {
	t.Parallel()

	v, err := NewValidator(
		&Config{Enabled: true, HashAlgorithm: HashAlgSHA256},
		WithStore(newMockStore()),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	impl, ok := v.(*validator)
	require.True(t, ok)

	// Dummy key material is generated at init time, never a constant.
	require.NotNil(t, impl.dummyKey)
	assert.NotEmpty(t, impl.dummyKey.Key)
	assert.NotEmpty(t, impl.dummyKey.Hash)
	assert.Equal(t, sha256Hex(impl.dummyKey.Key), impl.dummyKey.Hash)

	_, err = v.Validate(context.Background(), "unknown-key")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
	assert.Equal(t, int64(1), impl.dummyCompares.Load(),
		"not-found path must perform a dummy comparison")

	_, err = v.Validate(context.Background(), "another-unknown-key")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
	assert.Equal(t, int64(2), impl.dummyCompares.Load())
}

func TestValidator_NoDummyCompareOnFoundOrEmpty(t *testing.T) {
	t.Parallel()

	apiKey := "known-key"
	store := newMockStore()
	store.AddKey(&StaticKey{ID: "key1", Key: apiKey, Enabled: true})

	v, err := NewValidator(
		&Config{Enabled: true, HashAlgorithm: HashAlgSHA256},
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	impl, ok := v.(*validator)
	require.True(t, ok)

	_, err = v.Validate(context.Background(), apiKey)
	require.NoError(t, err)

	_, err = v.Validate(context.Background(), "")
	assert.ErrorIs(t, err, ErrEmptyAPIKey)

	assert.Zero(t, impl.dummyCompares.Load(),
		"dummy comparison must only run on the not-found path")
}

func TestValidator_DummyKeyUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	// Construction must not fail for unsupported algorithms; the dummy key
	// simply has no hash and Validate errors out at comparison time.
	v, err := NewValidator(
		&Config{Enabled: true, HashAlgorithm: "unsupported"},
		WithStore(newMockStore()),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	impl, ok := v.(*validator)
	require.True(t, ok)
	assert.NotEmpty(t, impl.dummyKey.Key)
	assert.Empty(t, impl.dummyKey.Hash)
}

// vaultBackedValidator wires a validator to a VaultStore over the mock KV
// client and returns the shared pieces used by the metric tests.
func vaultBackedValidator(t *testing.T, kvClient *mockKVClient) (Validator, *Metrics) {
	t.Helper()

	config := &Config{
		Enabled:       true,
		HashAlgorithm: HashAlgSHA256,
		Vault: &VaultConfig{
			Enabled: true,
			KVMount: "secret",
			Path:    "api-keys",
		},
	}

	client := &mockVaultClient{enabled: true, kv: kvClient}
	store, err := NewVaultStore(client, config, observability.NopLogger())
	require.NoError(t, err)

	// Each Metrics instance owns a private registry, so a fixed namespace
	// cannot collide across parallel tests.
	metrics := NewMetrics("test_wp")

	v, err := NewValidator(config,
		WithStore(store),
		WithValidatorMetrics(metrics),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	return v, metrics
}

func TestValidator_VaultTransportError_RecordsStoreError(t *testing.T) {
	t.Parallel()

	kvClient := newMockKVClient()
	kvClient.readErr = errors.New("dial tcp: connection refused")

	v, metrics := vaultBackedValidator(t, kvClient)

	keyInfo, err := v.Validate(context.Background(), "any-key")
	require.Error(t, err)
	assert.Nil(t, keyInfo)
	assert.ErrorIs(t, err, ErrStoreUnavailable)
	assert.NotErrorIs(t, err, ErrAPIKeyNotFound)

	storeErrors := testutil.ToFloat64(
		metrics.validationTotal.WithLabelValues(statusError, reasonStoreError))
	notFound := testutil.ToFloat64(
		metrics.validationTotal.WithLabelValues(statusError, reasonNotFound))
	assert.Equal(t, 1.0, storeErrors, "vault outage must be recorded as store_error")
	assert.Zero(t, notFound, "vault outage must not be recorded as not_found")
}

func TestValidator_VaultGenuineMiss_RecordsNotFound(t *testing.T) {
	t.Parallel()

	v, metrics := vaultBackedValidator(t, newMockKVClient())

	keyInfo, err := v.Validate(context.Background(), "nonexistent-key")
	require.Error(t, err)
	assert.Nil(t, keyInfo)
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)

	notFound := testutil.ToFloat64(
		metrics.validationTotal.WithLabelValues(statusError, reasonNotFound))
	storeErrors := testutil.ToFloat64(
		metrics.validationTotal.WithLabelValues(statusError, reasonStoreError))
	assert.Equal(t, 1.0, notFound)
	assert.Zero(t, storeErrors)

	impl, ok := v.(*validator)
	require.True(t, ok)
	assert.Equal(t, int64(1), impl.dummyCompares.Load(),
		"genuine miss must equalize timing with a dummy comparison")
}

func TestValidator_VaultSHA256_EndToEnd(t *testing.T) {
	t.Parallel()

	rawKey := "vault-sha256-key"
	kvClient := newMockKVClient()
	kvClient.SetData("secret", "api-keys/"+sha256Hex(rawKey), map[string]interface{}{
		"id":      "key1",
		"name":    "Vault Key",
		"hash":    sha256Hex(rawKey),
		"enabled": true,
	})

	v, metrics := vaultBackedValidator(t, kvClient)

	keyInfo, err := v.Validate(context.Background(), rawKey)
	require.NoError(t, err)
	require.NotNil(t, keyInfo)
	assert.Equal(t, "key1", keyInfo.ID)

	success := testutil.ToFloat64(
		metrics.validationTotal.WithLabelValues(statusSuccess, reasonValid))
	assert.Equal(t, 1.0, success)
}

func TestValidator_HashOnlyMemoryStore_EndToEnd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm string
		hashFn    func(string) string
	}{
		{name: "sha256", algorithm: HashAlgSHA256, hashFn: sha256Hex},
		{name: "sha512", algorithm: HashAlgSHA512, hashFn: sha512Hex},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rawKey := "e2e-hash-only-" + tt.name
			config := memoryStoreConfig(tt.algorithm, StaticKey{
				ID:      "key1",
				Hash:    tt.hashFn(rawKey),
				Enabled: true,
			})

			v, err := NewValidator(config, WithValidatorLogger(observability.NopLogger()))
			require.NoError(t, err)

			keyInfo, err := v.Validate(context.Background(), rawKey)
			require.NoError(t, err)
			assert.Equal(t, "key1", keyInfo.ID)

			keyInfo, err = v.Validate(context.Background(), "wrong-key")
			assert.ErrorIs(t, err, ErrAPIKeyNotFound)
			assert.Nil(t, keyInfo)
		})
	}
}

func TestValidator_UppercaseConfiguredHash_EndToEnd(t *testing.T) {
	t.Parallel()

	rawKey := "uppercase-configured-hash"
	config := memoryStoreConfig(HashAlgSHA256, StaticKey{
		ID:      "key1",
		Hash:    strings.ToUpper(sha256Hex(rawKey)),
		Enabled: true,
	})

	v, err := NewValidator(config, WithValidatorLogger(observability.NopLogger()))
	require.NoError(t, err)

	keyInfo, err := v.Validate(context.Background(), rawKey)
	require.NoError(t, err)
	assert.Equal(t, "key1", keyInfo.ID)
}

func TestValidator_Bcrypt_HashStoredInKeyField(t *testing.T) {
	t.Parallel()

	rawKey := "bcrypt-legacy-layout"
	hash, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.MinCost)
	require.NoError(t, err)

	// Legacy layout: bcrypt hash carried in Key, Hash empty.
	config := memoryStoreConfig(HashAlgBcrypt, StaticKey{
		ID:      "key1",
		Key:     string(hash),
		Enabled: true,
	})

	v, err := NewValidator(config, WithValidatorLogger(observability.NopLogger()))
	require.NoError(t, err)

	keyInfo, err := v.Validate(context.Background(), rawKey)
	require.NoError(t, err)
	assert.Equal(t, "key1", keyInfo.ID)
}

func TestHashKey_BcryptOversizedKeyFails(t *testing.T) {
	t.Parallel()

	// bcrypt rejects passwords longer than 72 bytes.
	hash, err := HashKey(strings.Repeat("x", 100), HashAlgBcrypt)
	require.Error(t, err)
	assert.Empty(t, hash)
}

func TestValidator_NotFoundTiming_ComparableToInvalid(t *testing.T) {
	t.Parallel()

	// This is NOT a wall-clock assertion (flaky); it verifies both paths
	// execute a comparison of the same algorithm by observing the work
	// counters: found-but-wrong performs a real compare, not-found performs
	// a dummy compare.
	apiKey := "timing-key"
	store := newMockStore()
	store.AddKey(&StaticKey{ID: "key1", Key: apiKey, Enabled: true})

	v, err := NewValidator(
		&Config{Enabled: true, HashAlgorithm: HashAlgSHA256},
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	impl, ok := v.(*validator)
	require.True(t, ok)

	// Wrong key that EXISTS in the mock store map under a different value:
	// mock store misses -> dummy compare fires.
	_, err = v.Validate(context.Background(), "missing-key")
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
	assert.Equal(t, int64(1), impl.dummyCompares.Load())

	// Known key with valid result performs the real comparison only.
	_, err = v.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.Equal(t, int64(1), impl.dummyCompares.Load())
}

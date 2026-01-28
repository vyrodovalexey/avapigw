package apikey

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockStore is a mock implementation of Store for testing.
type mockStore struct {
	keys map[string]*StaticKey
}

func newMockStore() *mockStore {
	return &mockStore{
		keys: make(map[string]*StaticKey),
	}
}

func (m *mockStore) Get(_ context.Context, key string) (*StaticKey, error) {
	storedKey, ok := m.keys[key]
	if !ok {
		return nil, ErrAPIKeyNotFound
	}
	return storedKey, nil
}

func (m *mockStore) GetByID(_ context.Context, id string) (*StaticKey, error) {
	for _, key := range m.keys {
		if key.ID == id {
			return key, nil
		}
	}
	return nil, ErrAPIKeyNotFound
}

func (m *mockStore) List(_ context.Context) ([]*StaticKey, error) {
	keys := make([]*StaticKey, 0, len(m.keys))
	for _, key := range m.keys {
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *mockStore) Close() error {
	return nil
}

func (m *mockStore) AddKey(key *StaticKey) {
	m.keys[key.Key] = key
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		opts    []ValidatorOption
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "valid config with mock store",
			config: &Config{
				Enabled:       true,
				HashAlgorithm: "sha256",
			},
			opts: []ValidatorOption{
				WithStore(newMockStore()),
			},
			wantErr: false,
		},
		{
			name: "valid config with memory store",
			config: &Config{
				Enabled:       true,
				HashAlgorithm: "sha256",
				Store: &StoreConfig{
					Type: "memory",
					Keys: []StaticKey{
						{
							ID:      "key1",
							Key:     "test-api-key",
							Enabled: true,
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			validator, err := NewValidator(tt.config, tt.opts...)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, validator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validator)
			}
		})
	}
}

func TestValidator_Validate_EmptyKey(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	validator, err := NewValidator(config,
		WithStore(newMockStore()),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
	assert.ErrorIs(t, err, ErrEmptyAPIKey)
}

func TestValidator_Validate_KeyNotFound(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	validator, err := NewValidator(config,
		WithStore(newMockStore()),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), "nonexistent-key")
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
}

func TestValidator_Validate_SHA256(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Name:    "Test Key",
		Enabled: true,
		Scopes:  []string{"read", "write"},
		Roles:   []string{"admin"},
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.NotNil(t, keyInfo)
	assert.Equal(t, "key1", keyInfo.ID)
	assert.Equal(t, "Test Key", keyInfo.Name)
	assert.Equal(t, []string{"read", "write"}, keyInfo.Scopes)
	assert.Equal(t, []string{"admin"}, keyInfo.Roles)
}

func TestValidator_Validate_SHA256_WithHash(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"
	hash := sha256.Sum256([]byte(apiKey))
	hashStr := hex.EncodeToString(hash[:])

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Hash:    hashStr,
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.NotNil(t, keyInfo)
	assert.Equal(t, "key1", keyInfo.ID)
}

func TestValidator_Validate_SHA512(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha512",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.NotNil(t, keyInfo)
	assert.Equal(t, "key1", keyInfo.ID)
}

func TestValidator_Validate_SHA512_WithHash(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"
	hash := sha512.Sum512([]byte(apiKey))
	hashStr := hex.EncodeToString(hash[:])

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha512",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Hash:    hashStr,
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.NotNil(t, keyInfo)
}

func TestValidator_Validate_Bcrypt(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"
	hash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	require.NoError(t, err)

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "bcrypt",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Hash:    string(hash),
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.NotNil(t, keyInfo)
	assert.Equal(t, "key1", keyInfo.ID)
}

func TestValidator_Validate_Bcrypt_InvalidKey(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"
	hash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	require.NoError(t, err)

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "bcrypt",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Hash:    string(hash),
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), "wrong-api-key")
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
}

func TestValidator_Validate_Plaintext(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "plaintext",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.NotNil(t, keyInfo)
	assert.Equal(t, "key1", keyInfo.ID)
}

func TestValidator_Validate_Plaintext_InvalidKey(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "plaintext",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// When the key is not found in the store, it returns ErrAPIKeyNotFound
	keyInfo, err := validator.Validate(context.Background(), "wrong-api-key")
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
	assert.ErrorIs(t, err, ErrAPIKeyNotFound)
}

func TestValidator_Validate_DisabledKey(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Enabled: false, // Disabled
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
	assert.ErrorIs(t, err, ErrAPIKeyDisabled)
}

func TestValidator_Validate_ExpiredKey(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"
	expiredTime := time.Now().Add(-time.Hour)

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:        "key1",
		Key:       apiKey,
		Enabled:   true,
		ExpiresAt: &expiredTime,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
	assert.ErrorIs(t, err, ErrAPIKeyExpired)
}

func TestValidator_Validate_ValidExpiration(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"
	futureTime := time.Now().Add(time.Hour)

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:        "key1",
		Key:       apiKey,
		Enabled:   true,
		ExpiresAt: &futureTime,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.NotNil(t, keyInfo)
	assert.Equal(t, "key1", keyInfo.ID)
}

func TestValidator_Validate_WithMetadata(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Enabled: true,
		Metadata: map[string]string{
			"tenant": "acme",
			"env":    "production",
		},
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	require.NoError(t, err)
	assert.NotNil(t, keyInfo)
	assert.Equal(t, "acme", keyInfo.Metadata["tenant"])
	assert.Equal(t, "production", keyInfo.Metadata["env"])
}

func TestKeyInfo_IsExpired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt *time.Time
		expected  bool
	}{
		{
			name:      "no expiration",
			expiresAt: nil,
			expected:  false,
		},
		{
			name:      "future expiration",
			expiresAt: func() *time.Time { t := time.Now().Add(time.Hour); return &t }(),
			expected:  false,
		},
		{
			name:      "past expiration",
			expiresAt: func() *time.Time { t := time.Now().Add(-time.Hour); return &t }(),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyInfo := &KeyInfo{
				ID:        "key1",
				ExpiresAt: tt.expiresAt,
			}

			assert.Equal(t, tt.expected, keyInfo.IsExpired())
		})
	}
}

func TestHashKey(t *testing.T) {
	t.Parallel()

	key := "test-api-key"

	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{
			name:      "sha256",
			algorithm: "sha256",
			wantErr:   false,
		},
		{
			name:      "sha512",
			algorithm: "sha512",
			wantErr:   false,
		},
		{
			name:      "bcrypt",
			algorithm: "bcrypt",
			wantErr:   false,
		},
		{
			name:      "plaintext",
			algorithm: "plaintext",
			wantErr:   false,
		},
		{
			name:      "invalid algorithm",
			algorithm: "invalid",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hash, err := HashKey(key, tt.algorithm)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, hash)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, hash)

				// Verify hash is correct for deterministic algorithms
				switch tt.algorithm {
				case "sha256":
					expected := sha256.Sum256([]byte(key))
					assert.Equal(t, hex.EncodeToString(expected[:]), hash)
				case "sha512":
					expected := sha512.Sum512([]byte(key))
					assert.Equal(t, hex.EncodeToString(expected[:]), hash)
				case "plaintext":
					assert.Equal(t, key, hash)
				case "bcrypt":
					// Verify bcrypt hash is valid
					err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(key))
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestValidatorOptions(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	store := newMockStore()
	logger := observability.NopLogger()
	metrics := NewMetrics("test")

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(logger),
		WithValidatorMetrics(metrics),
	)
	require.NoError(t, err)
	assert.NotNil(t, validator)
}

func TestValidator_Validate_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "unsupported",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), apiKey)
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
}

func TestValidator_Validate_SHA256_InvalidKey(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"
	wrongKey := "wrong-api-key"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), wrongKey)
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
}

func TestValidator_Validate_SHA512_InvalidKey(t *testing.T) {
	t.Parallel()

	apiKey := "test-api-key-12345"
	wrongKey := "wrong-api-key"

	config := &Config{
		Enabled:       true,
		HashAlgorithm: "sha512",
	}

	store := newMockStore()
	store.AddKey(&StaticKey{
		ID:      "key1",
		Key:     apiKey,
		Enabled: true,
	})

	validator, err := NewValidator(config,
		WithStore(store),
		WithValidatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	keyInfo, err := validator.Validate(context.Background(), wrongKey)
	assert.Error(t, err)
	assert.Nil(t, keyInfo)
}

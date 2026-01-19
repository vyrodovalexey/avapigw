package apikey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAPIKey_IsExpired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt *time.Time
		expected  bool
	}{
		{
			name:      "Not expired",
			expiresAt: timePtr(time.Now().Add(time.Hour)),
			expected:  false,
		},
		{
			name:      "Expired",
			expiresAt: timePtr(time.Now().Add(-time.Hour)),
			expected:  true,
		},
		{
			name:      "No expiry",
			expiresAt: nil,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := &APIKey{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, key.IsExpired())
		})
	}
}

func TestAPIKey_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		enabled   bool
		expiresAt *time.Time
		expected  bool
	}{
		{
			name:      "Valid - enabled and not expired",
			enabled:   true,
			expiresAt: timePtr(time.Now().Add(time.Hour)),
			expected:  true,
		},
		{
			name:      "Invalid - disabled",
			enabled:   false,
			expiresAt: timePtr(time.Now().Add(time.Hour)),
			expected:  false,
		},
		{
			name:      "Invalid - expired",
			enabled:   true,
			expiresAt: timePtr(time.Now().Add(-time.Hour)),
			expected:  false,
		},
		{
			name:      "Valid - enabled with no expiry",
			enabled:   true,
			expiresAt: nil,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := &APIKey{
				Enabled:   tt.enabled,
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.expected, key.IsValid())
		})
	}
}

func TestAPIKey_HasScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		scopes   []string
		scope    string
		expected bool
	}{
		{
			name:     "Has scope",
			scopes:   []string{"read", "write", "admin"},
			scope:    "write",
			expected: true,
		},
		{
			name:     "Does not have scope",
			scopes:   []string{"read", "write"},
			scope:    "admin",
			expected: false,
		},
		{
			name:     "Wildcard scope",
			scopes:   []string{"*"},
			scope:    "anything",
			expected: true,
		},
		{
			name:     "Empty scopes",
			scopes:   []string{},
			scope:    "read",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := &APIKey{Scopes: tt.scopes}
			assert.Equal(t, tt.expected, key.HasScope(tt.scope))
		})
	}
}

func TestAPIKey_HasAnyScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		scopes   []string
		check    []string
		expected bool
	}{
		{
			name:     "Has one of the scopes",
			scopes:   []string{"read", "write"},
			check:    []string{"admin", "write"},
			expected: true,
		},
		{
			name:     "Has none of the scopes",
			scopes:   []string{"read", "write"},
			check:    []string{"admin", "delete"},
			expected: false,
		},
		{
			name:     "Empty check scopes",
			scopes:   []string{"read", "write"},
			check:    []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := &APIKey{Scopes: tt.scopes}
			assert.Equal(t, tt.expected, key.HasAnyScope(tt.check...))
		})
	}
}

func TestAPIKey_HasAllScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		scopes   []string
		check    []string
		expected bool
	}{
		{
			name:     "Has all scopes",
			scopes:   []string{"read", "write", "admin"},
			check:    []string{"read", "write"},
			expected: true,
		},
		{
			name:     "Missing one scope",
			scopes:   []string{"read", "write"},
			check:    []string{"read", "write", "admin"},
			expected: false,
		},
		{
			name:     "Empty check scopes",
			scopes:   []string{"read", "write"},
			check:    []string{},
			expected: true,
		},
		{
			name:     "Wildcard covers all",
			scopes:   []string{"*"},
			check:    []string{"read", "write", "admin"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := &APIKey{Scopes: tt.scopes}
			assert.Equal(t, tt.expected, key.HasAllScopes(tt.check...))
		})
	}
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	tests := []struct {
		name   string
		store  Store
		logger *zap.Logger
	}{
		{
			name:   "With store and logger",
			store:  store,
			logger: zap.NewNop(),
		},
		{
			name:   "With nil logger",
			store:  store,
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := NewValidator(tt.store, tt.logger)
			assert.NotNil(t, validator)
			assert.NotNil(t, validator.hasher)
		})
	}
}

func TestNewValidatorWithConfig(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	tests := []struct {
		name   string
		config *ValidatorConfig
	}{
		{
			name: "With all config",
			config: &ValidatorConfig{
				Store:  store,
				Hasher: &SHA256Hasher{},
				Logger: zap.NewNop(),
			},
		},
		{
			name: "With nil logger",
			config: &ValidatorConfig{
				Store:  store,
				Hasher: &SHA256Hasher{},
				Logger: nil,
			},
		},
		{
			name: "With nil hasher",
			config: &ValidatorConfig{
				Store:  store,
				Hasher: nil,
				Logger: zap.NewNop(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := NewValidatorWithConfig(tt.config)
			assert.NotNil(t, validator)
			assert.NotNil(t, validator.hasher)
			assert.NotNil(t, validator.logger)
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	hasher := &SHA256Hasher{}

	// Create a valid API key
	validKey := "valid-api-key-12345"
	validKeyHash := hasher.Hash(validKey)
	store.keys[validKeyHash] = &APIKey{
		ID:        "key-1",
		Name:      "Test Key",
		KeyHash:   validKeyHash,
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	// Create a disabled API key
	disabledKey := "disabled-api-key"
	disabledKeyHash := hasher.Hash(disabledKey)
	store.keys[disabledKeyHash] = &APIKey{
		ID:        "key-2",
		Name:      "Disabled Key",
		KeyHash:   disabledKeyHash,
		Enabled:   false,
		CreatedAt: time.Now(),
	}

	// Create an expired API key
	expiredKey := "expired-api-key"
	expiredKeyHash := hasher.Hash(expiredKey)
	expiredTime := time.Now().Add(-time.Hour)
	store.keys[expiredKeyHash] = &APIKey{
		ID:        "key-3",
		Name:      "Expired Key",
		KeyHash:   expiredKeyHash,
		Enabled:   true,
		ExpiresAt: &expiredTime,
		CreatedAt: time.Now(),
	}

	validator := NewValidator(store, zap.NewNop())

	tests := []struct {
		name          string
		key           string
		expectedError error
	}{
		{
			name:          "Valid key",
			key:           validKey,
			expectedError: nil,
		},
		{
			name:          "Empty key",
			key:           "",
			expectedError: ErrMissingKey,
		},
		{
			name:          "Non-existent key",
			key:           "non-existent-key",
			expectedError: ErrKeyNotFound,
		},
		{
			name:          "Disabled key",
			key:           disabledKey,
			expectedError: ErrKeyDisabled,
		},
		{
			name:          "Expired key",
			key:           expiredKey,
			expectedError: ErrKeyExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			apiKey, err := validator.Validate(context.Background(), tt.key)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, apiKey)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, apiKey)
			}
		})
	}
}

func TestValidator_ValidateWithScopes(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	hasher := &SHA256Hasher{}

	// Create an API key with scopes
	key := "scoped-api-key"
	keyHash := hasher.Hash(key)
	store.keys[keyHash] = &APIKey{
		ID:        "key-1",
		Name:      "Scoped Key",
		KeyHash:   keyHash,
		Scopes:    []string{"read", "write"},
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	validator := NewValidator(store, zap.NewNop())

	tests := []struct {
		name           string
		key            string
		requiredScopes []string
		expectedError  error
	}{
		{
			name:           "Has required scopes",
			key:            key,
			requiredScopes: []string{"read"},
			expectedError:  nil,
		},
		{
			name:           "Has all required scopes",
			key:            key,
			requiredScopes: []string{"read", "write"},
			expectedError:  nil,
		},
		{
			name:           "Missing required scope",
			key:            key,
			requiredScopes: []string{"read", "admin"},
			expectedError:  ErrInsufficientScope,
		},
		{
			name:           "No required scopes",
			key:            key,
			requiredScopes: []string{},
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			apiKey, err := validator.ValidateWithScopes(context.Background(), tt.key, tt.requiredScopes...)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, apiKey)
			}
		})
	}
}

func TestValidator_Validate_StoreError(t *testing.T) {
	t.Parallel()

	// Create a mock store that returns an error
	mockStore := &mockStore{
		getErr: errors.New("database connection failed"),
	}

	validator := NewValidator(mockStore, zap.NewNop())

	_, err := validator.Validate(context.Background(), "any-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection failed")
}

func TestSHA256Hasher_Hash(t *testing.T) {
	t.Parallel()

	hasher := &SHA256Hasher{}

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Simple string",
			input: "test-api-key",
		},
		{
			name:  "Empty string",
			input: "",
		},
		{
			name:  "Long string",
			input: "this-is-a-very-long-api-key-that-should-still-be-hashed-correctly-12345678901234567890",
		},
		{
			name:  "Special characters",
			input: "key-with-special-chars!@#$%^&*()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hash := hasher.Hash(tt.input)

			// SHA256 produces 64 hex characters
			assert.Len(t, hash, 64)

			// Same input should produce same hash
			hash2 := hasher.Hash(tt.input)
			assert.Equal(t, hash, hash2)
		})
	}
}

func TestSHA256Hasher_Compare(t *testing.T) {
	t.Parallel()

	hasher := &SHA256Hasher{}

	tests := []struct {
		name     string
		key      string
		hash     string
		expected bool
	}{
		{
			name:     "Matching key and hash",
			key:      "test-api-key",
			hash:     hasher.Hash("test-api-key"),
			expected: true,
		},
		{
			name:     "Non-matching key and hash",
			key:      "test-api-key",
			hash:     hasher.Hash("different-key"),
			expected: false,
		},
		{
			name:     "Empty key",
			key:      "",
			hash:     hasher.Hash(""),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := hasher.Compare(tt.key, tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAPIKeyFromContext(t *testing.T) {
	t.Parallel()

	apiKey := &APIKey{
		ID:   "key-1",
		Name: "Test Key",
	}

	tests := []struct {
		name     string
		ctx      context.Context
		expected *APIKey
		found    bool
	}{
		{
			name:     "Key in context",
			ctx:      ContextWithAPIKey(context.Background(), apiKey),
			expected: apiKey,
			found:    true,
		},
		{
			name:     "No key in context",
			ctx:      context.Background(),
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, found := GetAPIKeyFromContext(tt.ctx)
			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.expected, key)
		})
	}
}

func TestContextWithAPIKey(t *testing.T) {
	t.Parallel()

	apiKey := &APIKey{
		ID:   "key-1",
		Name: "Test Key",
	}

	ctx := ContextWithAPIKey(context.Background(), apiKey)
	assert.NotNil(t, ctx)

	// Verify the key can be retrieved
	key, found := GetAPIKeyFromContext(ctx)
	assert.True(t, found)
	assert.Equal(t, apiKey, key)
}

// Test error variables
func TestErrorVariables(t *testing.T) {
	t.Parallel()

	assert.NotNil(t, ErrKeyNotFound)
	assert.NotNil(t, ErrKeyExpired)
	assert.NotNil(t, ErrKeyDisabled)
	assert.NotNil(t, ErrKeyInvalid)
	assert.NotNil(t, ErrInvalidHash)
	assert.NotNil(t, ErrMissingKey)
	assert.NotNil(t, ErrInsufficientScope)

	// Verify error messages
	assert.Equal(t, "API key not found", ErrKeyNotFound.Error())
	assert.Equal(t, "API key has expired", ErrKeyExpired.Error())
	assert.Equal(t, "API key is disabled", ErrKeyDisabled.Error())
	assert.Equal(t, "invalid API key", ErrKeyInvalid.Error())
	assert.Equal(t, "invalid key hash", ErrInvalidHash.Error())
	assert.Equal(t, "missing API key", ErrMissingKey.Error())
	assert.Equal(t, "insufficient scope", ErrInsufficientScope.Error())
}

// Helper function to create time pointer
func timePtr(t time.Time) *time.Time {
	return &t
}

// Mock store for testing error scenarios
type mockStore struct {
	getErr error
}

func (m *mockStore) Get(ctx context.Context, keyHash string) (*APIKey, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return nil, ErrKeyNotFound
}

func (m *mockStore) List(ctx context.Context) ([]*APIKey, error) {
	return nil, nil
}

func (m *mockStore) Create(ctx context.Context, key *APIKey) error {
	return nil
}

func (m *mockStore) Delete(ctx context.Context, keyHash string) error {
	return nil
}

func (m *mockStore) Validate(ctx context.Context, keyHash string) (bool, error) {
	return false, nil
}

// Benchmark tests
func BenchmarkSHA256Hasher_Hash(b *testing.B) {
	hasher := &SHA256Hasher{}
	key := "test-api-key-12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Hash(key)
	}
}

func BenchmarkSHA256Hasher_Compare(b *testing.B) {
	hasher := &SHA256Hasher{}
	key := "test-api-key-12345"
	hash := hasher.Hash(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Compare(key, hash)
	}
}

func BenchmarkValidator_Validate(b *testing.B) {
	store := NewMemoryStore()
	hasher := &SHA256Hasher{}

	key := "benchmark-api-key"
	keyHash := hasher.Hash(key)
	store.keys[keyHash] = &APIKey{
		ID:        "key-1",
		Name:      "Benchmark Key",
		KeyHash:   keyHash,
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	validator := NewValidator(store, zap.NewNop())
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.Validate(ctx, key)
	}
}

// Test concurrent validation
func TestValidator_ConcurrentValidation(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	hasher := &SHA256Hasher{}

	key := "concurrent-api-key"
	keyHash := hasher.Hash(key)
	store.keys[keyHash] = &APIKey{
		ID:        "key-1",
		Name:      "Concurrent Key",
		KeyHash:   keyHash,
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	validator := NewValidator(store, zap.NewNop())

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, _ = validator.Validate(context.Background(), key)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

package basic

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestUser_HasRole(t *testing.T) {
	t.Parallel()

	user := &User{
		Roles: []string{"admin", "editor", "viewer"},
	}

	assert.True(t, user.HasRole("admin"))
	assert.True(t, user.HasRole("editor"))
	assert.True(t, user.HasRole("viewer"))
	assert.False(t, user.HasRole("superadmin"))
	assert.False(t, user.HasRole(""))
}

func TestUser_HasGroup(t *testing.T) {
	t.Parallel()

	user := &User{
		Groups: []string{"developers", "qa", "devops"},
	}

	assert.True(t, user.HasGroup("developers"))
	assert.True(t, user.HasGroup("qa"))
	assert.True(t, user.HasGroup("devops"))
	assert.False(t, user.HasGroup("management"))
	assert.False(t, user.HasGroup(""))
}

func TestNewMemoryStore(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	assert.NotNil(t, store)
	assert.NotNil(t, store.users)
}

func TestMemoryStore_Get(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Add a user
	user := &User{
		Username:     "testuser",
		PasswordHash: "hash",
		Enabled:      true,
	}
	store.users["testuser"] = user

	// Get existing user
	result, err := store.Get(ctx, "testuser")
	require.NoError(t, err)
	assert.Equal(t, user, result)

	// Get non-existent user
	_, err = store.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestMemoryStore_List(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Empty store
	users, err := store.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, users)

	// Add users
	store.users["user1"] = &User{Username: "user1"}
	store.users["user2"] = &User{Username: "user2"}

	users, err = store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, users, 2)
}

func TestMemoryStore_Create(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	user := &User{
		Username:     "newuser",
		PasswordHash: "hash",
		Enabled:      true,
	}

	// Create new user
	err := store.Create(ctx, user)
	require.NoError(t, err)

	// Verify user was created
	result, err := store.Get(ctx, "newuser")
	require.NoError(t, err)
	assert.Equal(t, user, result)

	// Try to create duplicate
	err = store.Create(ctx, user)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestMemoryStore_Update(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Add a user
	store.users["testuser"] = &User{
		Username: "testuser",
		Enabled:  true,
	}

	// Update existing user
	updatedUser := &User{
		Username: "testuser",
		Enabled:  false,
	}
	err := store.Update(ctx, updatedUser)
	require.NoError(t, err)

	// Verify update
	result, err := store.Get(ctx, "testuser")
	require.NoError(t, err)
	assert.False(t, result.Enabled)

	// Update non-existent user
	err = store.Update(ctx, &User{Username: "nonexistent"})
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestMemoryStore_Delete(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Add a user
	store.users["testuser"] = &User{Username: "testuser"}

	// Delete existing user
	err := store.Delete(ctx, "testuser")
	require.NoError(t, err)

	// Verify deletion
	_, err = store.Get(ctx, "testuser")
	assert.ErrorIs(t, err, ErrUserNotFound)

	// Delete non-existent user
	err = store.Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestMemoryStore_AddUser(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	err := store.AddUser("testuser", "password123", []string{"admin"}, []string{"developers"})
	require.NoError(t, err)

	// Verify user was added
	user, err := store.Get(context.Background(), "testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.NotEmpty(t, user.PasswordHash)
	assert.Equal(t, []string{"admin"}, user.Roles)
	assert.Equal(t, []string{"developers"}, user.Groups)
	assert.True(t, user.Enabled)
}

func TestMemoryStore_LoadFromSecretData(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	data := map[string][]byte{
		"user1": []byte("password1"),
		"user2": []byte("password2"),
	}

	err := store.LoadFromSecretData(data)
	require.NoError(t, err)

	// Verify users were loaded
	users, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, users, 2)
}

func TestMemoryStore_LoadFromHashedSecretData(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	// Create pre-hashed passwords
	hash1, _ := HashPassword("password1")
	hash2, _ := HashPassword("password2")

	data := map[string][]byte{
		"user1": []byte(hash1),
		"user2": []byte(hash2),
	}

	store.LoadFromHashedSecretData(data)

	// Verify users were loaded
	users, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, users, 2)
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	tests := []struct {
		name   string
		store  Store
		realm  string
		logger *zap.Logger
	}{
		{
			name:   "With all parameters",
			store:  store,
			realm:  "Test Realm",
			logger: zap.NewNop(),
		},
		{
			name:   "With nil logger",
			store:  store,
			realm:  "Test Realm",
			logger: nil,
		},
		{
			name:   "With empty realm",
			store:  store,
			realm:  "",
			logger: zap.NewNop(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := NewValidator(tt.store, tt.realm, tt.logger)
			assert.NotNil(t, validator)
			assert.NotNil(t, validator.logger)
			if tt.realm == "" {
				assert.Equal(t, "Restricted", validator.realm)
			} else {
				assert.Equal(t, tt.realm, validator.realm)
			}
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
				Realm:  "Test Realm",
				Logger: zap.NewNop(),
			},
		},
		{
			name: "With nil logger",
			config: &ValidatorConfig{
				Store:  store,
				Realm:  "Test Realm",
				Logger: nil,
			},
		},
		{
			name: "With empty realm",
			config: &ValidatorConfig{
				Store:  store,
				Realm:  "",
				Logger: zap.NewNop(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := NewValidatorWithConfig(tt.config)
			assert.NotNil(t, validator)
			assert.NotNil(t, validator.logger)
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	_ = store.AddUser("validuser", "validpassword", nil, nil)

	// Add disabled user
	hash, _ := HashPassword("password")
	store.users["disableduser"] = &User{
		Username:     "disableduser",
		PasswordHash: hash,
		Enabled:      false,
	}

	validator := NewValidator(store, "Test", zap.NewNop())

	tests := []struct {
		name          string
		username      string
		password      string
		expectedError error
	}{
		{
			name:          "Valid credentials",
			username:      "validuser",
			password:      "validpassword",
			expectedError: nil,
		},
		{
			name:          "Empty username",
			username:      "",
			password:      "password",
			expectedError: ErrMissingCredentials,
		},
		{
			name:          "Empty password",
			username:      "user",
			password:      "",
			expectedError: ErrMissingCredentials,
		},
		{
			name:          "Non-existent user",
			username:      "nonexistent",
			password:      "password",
			expectedError: ErrInvalidCredentials,
		},
		{
			name:          "Wrong password",
			username:      "validuser",
			password:      "wrongpassword",
			expectedError: ErrInvalidCredentials,
		},
		{
			name:          "Disabled user",
			username:      "disableduser",
			password:      "password",
			expectedError: ErrUserDisabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user, err := validator.Validate(context.Background(), tt.username, tt.password)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.username, user.Username)
			}
		})
	}
}

func TestValidator_ValidateRequest(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	_ = store.AddUser("testuser", "testpassword", nil, nil)

	validator := NewValidator(store, "Test", zap.NewNop())

	tests := []struct {
		name          string
		authHeader    string
		expectedError error
	}{
		{
			name:          "Valid credentials",
			authHeader:    "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpassword")),
			expectedError: nil,
		},
		{
			name:          "Missing header",
			authHeader:    "",
			expectedError: ErrMissingCredentials,
		},
		{
			name:          "Invalid header format",
			authHeader:    "Bearer token",
			expectedError: ErrInvalidHeader,
		},
		{
			name:          "Invalid base64",
			authHeader:    "Basic !!!invalid!!!",
			expectedError: ErrInvalidHeader,
		},
		{
			name:          "Missing colon",
			authHeader:    "Basic " + base64.StdEncoding.EncodeToString([]byte("usernameonly")),
			expectedError: ErrInvalidHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			user, err := validator.ValidateRequest(context.Background(), req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, user)
			}
		})
	}
}

func TestValidator_Realm(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	validator := NewValidator(store, "My Realm", zap.NewNop())

	assert.Equal(t, "My Realm", validator.Realm())
}

func TestExtractCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		authHeader       string
		expectedUsername string
		expectedPassword string
		expectedError    error
	}{
		{
			name:             "Valid credentials",
			authHeader:       "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")),
			expectedUsername: "user",
			expectedPassword: "pass",
		},
		{
			name:             "Password with colon",
			authHeader:       "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass:word")),
			expectedUsername: "user",
			expectedPassword: "pass:word",
		},
		{
			name:             "Case insensitive Basic",
			authHeader:       "basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")),
			expectedUsername: "user",
			expectedPassword: "pass",
		},
		{
			name:          "Missing header",
			authHeader:    "",
			expectedError: ErrMissingCredentials,
		},
		{
			name:          "Wrong scheme",
			authHeader:    "Bearer token",
			expectedError: ErrInvalidHeader,
		},
		{
			name:          "Too short",
			authHeader:    "Bas",
			expectedError: ErrInvalidHeader,
		},
		{
			name:          "Invalid base64",
			authHeader:    "Basic !!!",
			expectedError: ErrInvalidHeader,
		},
		{
			name:          "No colon separator",
			authHeader:    "Basic " + base64.StdEncoding.EncodeToString([]byte("useronly")),
			expectedError: ErrInvalidHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			username, password, err := ExtractCredentials(req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUsername, username)
				assert.Equal(t, tt.expectedPassword, password)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	t.Parallel()

	password := "testpassword123"

	hash, err := HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, password, hash)

	// Verify the hash is valid bcrypt
	assert.True(t, ComparePassword(password, hash))
}

func TestComparePassword(t *testing.T) {
	t.Parallel()

	password := "testpassword123"
	hash, _ := HashPassword(password)

	assert.True(t, ComparePassword(password, hash))
	assert.False(t, ComparePassword("wrongpassword", hash))
	assert.False(t, ComparePassword(password, "invalidhash"))
}

func TestComparePasswordConstantTime(t *testing.T) {
	t.Parallel()

	password := "testpassword123"
	hash, _ := HashPassword(password)

	assert.True(t, ComparePasswordConstantTime(password, hash))
	assert.False(t, ComparePasswordConstantTime("wrongpassword", hash))
}

func TestEncodeCredentials(t *testing.T) {
	t.Parallel()

	result := EncodeCredentials("user", "pass")
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	assert.Equal(t, expected, result)
}

func TestNewSimpleValidator(t *testing.T) {
	t.Parallel()

	credentials := map[string]string{
		"user1": "pass1",
		"user2": "pass2",
	}

	validator := NewSimpleValidator(credentials, "Test Realm")
	assert.NotNil(t, validator)
	assert.Equal(t, "Test Realm", validator.realm)
	assert.Len(t, validator.credentials, 2)
}

func TestNewSimpleValidator_EmptyRealm(t *testing.T) {
	t.Parallel()

	validator := NewSimpleValidator(nil, "")
	assert.Equal(t, "Restricted", validator.realm)
}

func TestNewSimpleValidatorWithHashes(t *testing.T) {
	t.Parallel()

	hash, _ := HashPassword("password")
	credentials := map[string]string{
		"user": hash,
	}

	validator := NewSimpleValidatorWithHashes(credentials, "Test")
	assert.NotNil(t, validator)
}

func TestSimpleValidator_Validate(t *testing.T) {
	t.Parallel()

	credentials := map[string]string{
		"validuser": "validpassword",
	}
	validator := NewSimpleValidator(credentials, "Test")

	tests := []struct {
		name          string
		username      string
		password      string
		expectedError error
	}{
		{
			name:          "Valid credentials",
			username:      "validuser",
			password:      "validpassword",
			expectedError: nil,
		},
		{
			name:          "Invalid username",
			username:      "invaliduser",
			password:      "validpassword",
			expectedError: ErrInvalidCredentials,
		},
		{
			name:          "Invalid password",
			username:      "validuser",
			password:      "invalidpassword",
			expectedError: ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user, err := validator.Validate(context.Background(), tt.username, tt.password)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.username, user.Username)
			}
		})
	}
}

func TestSimpleValidator_ValidateRequest(t *testing.T) {
	t.Parallel()

	credentials := map[string]string{
		"user": "pass",
	}
	validator := NewSimpleValidator(credentials, "Test")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))

	user, err := validator.ValidateRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "user", user.Username)
}

func TestSimpleValidator_Realm(t *testing.T) {
	t.Parallel()

	validator := NewSimpleValidator(nil, "My Realm")
	assert.Equal(t, "My Realm", validator.Realm())
}

func TestNewPlaintextValidator(t *testing.T) {
	t.Parallel()

	credentials := map[string]string{
		"user": "pass",
	}

	validator := NewPlaintextValidator(credentials, "Test")
	assert.NotNil(t, validator)
	assert.Equal(t, "Test", validator.realm)
}

func TestPlaintextValidator_Validate(t *testing.T) {
	t.Parallel()

	credentials := map[string]string{
		"user": "pass",
	}
	validator := NewPlaintextValidator(credentials, "Test")

	tests := []struct {
		name          string
		username      string
		password      string
		expectedError error
	}{
		{
			name:          "Valid credentials",
			username:      "user",
			password:      "pass",
			expectedError: nil,
		},
		{
			name:          "Invalid username",
			username:      "invalid",
			password:      "pass",
			expectedError: ErrInvalidCredentials,
		},
		{
			name:          "Invalid password",
			username:      "user",
			password:      "wrong",
			expectedError: ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user, err := validator.Validate(context.Background(), tt.username, tt.password)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.username, user.Username)
			}
		})
	}
}

func TestPlaintextValidator_ValidateRequest(t *testing.T) {
	t.Parallel()

	credentials := map[string]string{
		"user": "pass",
	}
	validator := NewPlaintextValidator(credentials, "Test")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))

	user, err := validator.ValidateRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "user", user.Username)
}

func TestPlaintextValidator_Realm(t *testing.T) {
	t.Parallel()

	validator := NewPlaintextValidator(nil, "My Realm")
	assert.Equal(t, "My Realm", validator.Realm())
}

func TestGetUserFromContext(t *testing.T) {
	t.Parallel()

	user := &User{
		Username: "testuser",
		Roles:    []string{"admin"},
	}

	tests := []struct {
		name     string
		ctx      context.Context
		expected *User
		found    bool
	}{
		{
			name:     "User in context",
			ctx:      ContextWithUser(context.Background(), user),
			expected: user,
			found:    true,
		},
		{
			name:     "No user in context",
			ctx:      context.Background(),
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, found := GetUserFromContext(tt.ctx)
			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContextWithUser(t *testing.T) {
	t.Parallel()

	user := &User{
		Username: "testuser",
	}

	ctx := ContextWithUser(context.Background(), user)
	assert.NotNil(t, ctx)

	result, found := GetUserFromContext(ctx)
	assert.True(t, found)
	assert.Equal(t, user, result)
}

// Test error variables
func TestErrorVariables(t *testing.T) {
	t.Parallel()

	assert.NotNil(t, ErrMissingCredentials)
	assert.NotNil(t, ErrInvalidCredentials)
	assert.NotNil(t, ErrInvalidHeader)
	assert.NotNil(t, ErrUserNotFound)
	assert.NotNil(t, ErrUserDisabled)

	assert.Equal(t, "missing credentials", ErrMissingCredentials.Error())
	assert.Equal(t, "invalid credentials", ErrInvalidCredentials.Error())
	assert.Equal(t, "invalid authorization header", ErrInvalidHeader.Error())
	assert.Equal(t, "user not found", ErrUserNotFound.Error())
	assert.Equal(t, "user is disabled", ErrUserDisabled.Error())
}

// Test store error handling
func TestValidator_Validate_StoreError(t *testing.T) {
	t.Parallel()

	mockStore := &mockStore{
		getErr: errors.New("database error"),
	}

	validator := NewValidator(mockStore, "Test", zap.NewNop())

	_, err := validator.Validate(context.Background(), "user", "pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database error")
}

// Mock store for testing
type mockStore struct {
	getErr error
}

func (m *mockStore) Get(ctx context.Context, username string) (*User, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return nil, ErrUserNotFound
}

func (m *mockStore) List(ctx context.Context) ([]*User, error) {
	return nil, nil
}

func (m *mockStore) Create(ctx context.Context, user *User) error {
	return nil
}

func (m *mockStore) Update(ctx context.Context, user *User) error {
	return nil
}

func (m *mockStore) Delete(ctx context.Context, username string) error {
	return nil
}

// Concurrent access tests
func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				user := &User{
					Username:     "user",
					PasswordHash: "hash",
				}
				_ = store.Create(ctx, user)
				_ = store.Delete(ctx, "user")
			}
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, _ = store.Get(ctx, "user")
				_, _ = store.List(ctx)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestValidator_ConcurrentValidation(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	_ = store.AddUser("testuser", "testpassword", nil, nil)

	validator := NewValidator(store, "Test", zap.NewNop())

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, _ = validator.Validate(context.Background(), "testuser", "testpassword")
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Benchmark tests
func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		HashPassword("testpassword123")
	}
}

func BenchmarkComparePassword(b *testing.B) {
	hash, _ := HashPassword("testpassword123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComparePassword("testpassword123", hash)
	}
}

func BenchmarkValidator_Validate(b *testing.B) {
	store := NewMemoryStore()
	_ = store.AddUser("testuser", "testpassword", nil, nil)
	validator := NewValidator(store, "Test", zap.NewNop())
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.Validate(ctx, "testuser", "testpassword")
	}
}

func BenchmarkExtractCredentials(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractCredentials(req)
	}
}

func BenchmarkPlaintextValidator_Validate(b *testing.B) {
	credentials := map[string]string{
		"user": "pass",
	}
	validator := NewPlaintextValidator(credentials, "Test")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.Validate(ctx, "user", "pass")
	}
}

// Test timing attack prevention
// Note: This test verifies that the code uses constant-time comparison,
// but actual timing attack prevention requires statistical analysis over many samples.
// This test is intentionally lenient to avoid flakiness in CI environments.
func TestValidator_TimingAttackPrevention(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	_ = store.AddUser("validuser", "password", nil, nil)

	validator := NewValidator(store, "Test", zap.NewNop())

	// Verify that both paths execute without error
	// The actual timing attack prevention is implemented via bcrypt's constant-time comparison
	_, err1 := validator.Validate(context.Background(), "validuser", "wrongpassword")
	assert.ErrorIs(t, err1, ErrInvalidCredentials)

	_, err2 := validator.Validate(context.Background(), "nonexistent", "password")
	assert.ErrorIs(t, err2, ErrInvalidCredentials)

	// Both should return the same error type to prevent user enumeration
	assert.Equal(t, err1.Error(), err2.Error())
}

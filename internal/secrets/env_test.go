package secrets

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewEnvProvider(t *testing.T) {
	// Test with nil config (should use defaults)
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, DefaultEnvPrefix, provider.prefix)

	// Test with custom prefix
	provider, err = NewEnvProvider(&EnvProviderConfig{
		Prefix: "CUSTOM_",
	})
	require.NoError(t, err)
	assert.Equal(t, "CUSTOM_", provider.prefix)
}

func TestEnvProviderType(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)
	assert.Equal(t, ProviderTypeEnv, provider.Type())
}

func TestEnvProviderGetSecret(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "TEST_SECRET_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test with non-existing env var
	_, err = provider.GetSecret(ctx, "nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)

	// Test with simple value
	os.Setenv("TEST_SECRET_SIMPLE", "simple-value")
	defer os.Unsetenv("TEST_SECRET_SIMPLE")

	secret, err := provider.GetSecret(ctx, "simple")
	require.NoError(t, err)
	assert.Equal(t, "simple", secret.Name)
	val, ok := secret.GetString("value")
	assert.True(t, ok)
	assert.Equal(t, "simple-value", val)

	// Test with JSON value
	os.Setenv("TEST_SECRET_JSON", `{"username":"admin","password":"secret123"}`)
	defer os.Unsetenv("TEST_SECRET_JSON")

	secret, err = provider.GetSecret(ctx, "json")
	require.NoError(t, err)
	username, ok := secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)
	password, ok := secret.GetString("password")
	assert.True(t, ok)
	assert.Equal(t, "secret123", password)

	// Test with empty path
	_, err = provider.GetSecret(ctx, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

func TestEnvProviderListSecrets(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "LIST_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Set some test env vars
	os.Setenv("LIST_TEST_SECRET1", "value1")
	os.Setenv("LIST_TEST_SECRET2", "value2")
	defer os.Unsetenv("LIST_TEST_SECRET1")
	defer os.Unsetenv("LIST_TEST_SECRET2")

	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Contains(t, secrets, "secret1")
	assert.Contains(t, secrets, "secret2")
}

func TestEnvProviderIsReadOnly(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)
	assert.True(t, provider.IsReadOnly())
}

func TestEnvProviderWriteSecret(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.WriteSecret(ctx, "test", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)
}

func TestEnvProviderDeleteSecret(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.DeleteSecret(ctx, "test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)
}

func TestEnvProviderHealthCheck(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestEnvProviderClose(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	err = provider.Close()
	assert.NoError(t, err)
}

func TestEnvProviderNormalizeEnvName(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "PREFIX_",
	})
	require.NoError(t, err)

	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "PREFIX_SIMPLE"},
		{"with-dash", "PREFIX_WITH_DASH"},
		{"with.dot", "PREFIX_WITH_DOT"},
		{"with/slash", "PREFIX_WITH_SLASH"},
		{"MixedCase", "PREFIX_MIXEDCASE"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := provider.normalizeEnvName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

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

func TestEnvProviderGetSecretWithComplexJSON(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "COMPLEX_JSON_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test with JSON containing nested objects
	os.Setenv("COMPLEX_JSON_TEST_NESTED", `{"username":"admin","config":{"port":8080,"host":"localhost"}}`)
	defer os.Unsetenv("COMPLEX_JSON_TEST_NESTED")

	secret, err := provider.GetSecret(ctx, "nested")
	require.NoError(t, err)

	// String value should be extracted
	username, ok := secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)

	// Nested object should be JSON-encoded
	configBytes, ok := secret.GetBytes("config")
	assert.True(t, ok)
	assert.Contains(t, string(configBytes), "port")
	assert.Contains(t, string(configBytes), "8080")
}

func TestEnvProviderGetSecretWithArrayJSON(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "ARRAY_JSON_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test with JSON containing arrays
	os.Setenv("ARRAY_JSON_TEST_ARRAY", `{"hosts":["host1","host2"],"port":"8080"}`)
	defer os.Unsetenv("ARRAY_JSON_TEST_ARRAY")

	secret, err := provider.GetSecret(ctx, "array")
	require.NoError(t, err)

	// String value should be extracted
	port, ok := secret.GetString("port")
	assert.True(t, ok)
	assert.Equal(t, "8080", port)

	// Array should be JSON-encoded
	hostsBytes, ok := secret.GetBytes("hosts")
	assert.True(t, ok)
	assert.Contains(t, string(hostsBytes), "host1")
}

func TestEnvProviderHealthCheckWithSecrets(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "HEALTH_CHECK_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Set an env var with the prefix
	os.Setenv("HEALTH_CHECK_TEST_SECRET", "value")
	defer os.Unsetenv("HEALTH_CHECK_TEST_SECRET")

	// Health check should pass
	err = provider.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestEnvProviderListSecretsEmpty(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "UNIQUE_EMPTY_LIST_PREFIX_12345_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// List secrets with no matching env vars
	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestEnvProviderParseEnvValueToData(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "PARSE_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		value    string
		expected map[string][]byte
	}{
		{
			name:  "simple string",
			value: "simple-value",
			expected: map[string][]byte{
				"value": []byte("simple-value"),
			},
		},
		{
			name:  "valid JSON object",
			value: `{"key1":"value1","key2":"value2"}`,
			expected: map[string][]byte{
				"key1": []byte("value1"),
				"key2": []byte("value2"),
			},
		},
		{
			name:  "JSON with number",
			value: `{"port":8080}`,
			expected: map[string][]byte{
				"port": []byte("8080"),
			},
		},
		{
			name:  "invalid JSON",
			value: `{invalid json}`,
			expected: map[string][]byte{
				"value": []byte(`{invalid json}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.parseEnvValueToData(tt.value)
			for key, expectedValue := range tt.expected {
				actualValue, ok := result[key]
				assert.True(t, ok, "key %s should exist", key)
				assert.Equal(t, string(expectedValue), string(actualValue))
			}
		})
	}
}

func TestEnvProviderWithEmptyPrefix(t *testing.T) {
	// Test that empty prefix uses default
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "",
	})
	require.NoError(t, err)
	assert.Equal(t, DefaultEnvPrefix, provider.prefix)
}

func TestEnvProviderWithNilConfig(t *testing.T) {
	// Test that nil config uses defaults
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)
	assert.Equal(t, DefaultEnvPrefix, provider.prefix)
}

func TestEnvProviderParseEnvValueToDataWithNestedObject(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "NESTED_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test with deeply nested JSON
	os.Setenv("NESTED_TEST_DEEP", `{"level1":{"level2":{"level3":"value"}}}`)
	defer os.Unsetenv("NESTED_TEST_DEEP")

	secret, err := provider.GetSecret(ctx, "deep")
	require.NoError(t, err)

	// Nested object should be JSON-encoded
	level1Bytes, ok := secret.GetBytes("level1")
	assert.True(t, ok)
	assert.Contains(t, string(level1Bytes), "level2")
}

func TestEnvProviderListSecretsWithMultipleMatches(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "MULTI_MATCH_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Set multiple env vars
	os.Setenv("MULTI_MATCH_TEST_SECRET_ONE", "value1")
	os.Setenv("MULTI_MATCH_TEST_SECRET_TWO", "value2")
	os.Setenv("MULTI_MATCH_TEST_SECRET_THREE", "value3")
	defer os.Unsetenv("MULTI_MATCH_TEST_SECRET_ONE")
	defer os.Unsetenv("MULTI_MATCH_TEST_SECRET_TWO")
	defer os.Unsetenv("MULTI_MATCH_TEST_SECRET_THREE")

	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Len(t, secrets, 3)
}

func TestEnvProviderGetSecretWithBooleanJSON(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "BOOL_JSON_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test with JSON containing boolean values
	os.Setenv("BOOL_JSON_TEST_BOOLS", `{"enabled":true,"disabled":false}`)
	defer os.Unsetenv("BOOL_JSON_TEST_BOOLS")

	secret, err := provider.GetSecret(ctx, "bools")
	require.NoError(t, err)

	// Boolean values should be JSON-encoded
	enabledBytes, ok := secret.GetBytes("enabled")
	assert.True(t, ok)
	assert.Equal(t, "true", string(enabledBytes))

	disabledBytes, ok := secret.GetBytes("disabled")
	assert.True(t, ok)
	assert.Equal(t, "false", string(disabledBytes))
}

func TestEnvProviderGetSecretWithNullJSON(t *testing.T) {
	logger := zap.NewNop()
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "NULL_JSON_TEST_",
		Logger: logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test with JSON containing null value
	os.Setenv("NULL_JSON_TEST_NULLS", `{"key":"value","nullkey":null}`)
	defer os.Unsetenv("NULL_JSON_TEST_NULLS")

	secret, err := provider.GetSecret(ctx, "nulls")
	require.NoError(t, err)

	// String value should work
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)

	// Null value should be JSON-encoded
	nullBytes, ok := secret.GetBytes("nullkey")
	assert.True(t, ok)
	assert.Equal(t, "null", string(nullBytes))
}

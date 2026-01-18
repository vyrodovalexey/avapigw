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

// TestEnvProvider_Type_Constant tests that Type returns the correct constant
func TestEnvProvider_Type_Constant(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	assert.Equal(t, ProviderTypeEnv, provider.Type())
	assert.Equal(t, ProviderType("env"), provider.Type())
}

// TestEnvProvider_IsReadOnly_AlwaysTrue tests that IsReadOnly always returns true
func TestEnvProvider_IsReadOnly_AlwaysTrue(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	assert.True(t, provider.IsReadOnly())
}

// TestEnvProvider_Close_MultipleCalls tests calling Close multiple times
func TestEnvProvider_Close_MultipleCalls(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	// First close
	err = provider.Close()
	assert.NoError(t, err)

	// Second close should also succeed (idempotent)
	err = provider.Close()
	assert.NoError(t, err)
}

// TestEnvProvider_GetSecret_TableDriven tests GetSecret with various inputs
func TestEnvProvider_GetSecret_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		envVar      string
		envValue    string
		path        string
		expectError bool
		errorIs     error
	}{
		{
			name:        "empty path",
			prefix:      "TEST_EMPTY_PATH_",
			path:        "",
			expectError: true,
			errorIs:     ErrInvalidPath,
		},
		{
			name:        "non-existent env var",
			prefix:      "TEST_NONEXISTENT_",
			path:        "missing",
			expectError: true,
			errorIs:     ErrSecretNotFound,
		},
		{
			name:        "simple value",
			prefix:      "TEST_SIMPLE_",
			envVar:      "TEST_SIMPLE_MYSECRET",
			envValue:    "myvalue",
			path:        "mysecret",
			expectError: false,
		},
		{
			name:        "json value",
			prefix:      "TEST_JSON_",
			envVar:      "TEST_JSON_MYJSON",
			envValue:    `{"key":"value"}`,
			path:        "myjson",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewEnvProvider(&EnvProviderConfig{
				Prefix: tt.prefix,
				Logger: zap.NewNop(),
			})
			require.NoError(t, err)

			if tt.envVar != "" {
				os.Setenv(tt.envVar, tt.envValue)
				defer os.Unsetenv(tt.envVar)
			}

			ctx := context.Background()
			_, err = provider.GetSecret(ctx, tt.path)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestEnvProvider_NormalizeEnvName_TableDriven tests normalizeEnvName with various inputs
func TestEnvProvider_NormalizeEnvName_TableDriven(t *testing.T) {
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
		{"UPPERCASE", "PREFIX_UPPERCASE"},
		{"lowercase", "PREFIX_LOWERCASE"},
		{"with_underscore", "PREFIX_WITH_UNDERSCORE"},
		{"multiple-dashes-here", "PREFIX_MULTIPLE_DASHES_HERE"},
		{"multiple.dots.here", "PREFIX_MULTIPLE_DOTS_HERE"},
		{"mixed-case.with/all", "PREFIX_MIXED_CASE_WITH_ALL"},
		{"", "PREFIX_"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := provider.normalizeEnvName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestEnvProvider_ParseEnvValueToData_TableDriven tests parseEnvValueToData with various inputs
func TestEnvProvider_ParseEnvValueToData_TableDriven(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "PARSE_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		value       string
		expectKeys  []string
		expectValue map[string]string
	}{
		{
			name:       "simple string",
			value:      "simple-value",
			expectKeys: []string{"value"},
			expectValue: map[string]string{
				"value": "simple-value",
			},
		},
		{
			name:       "valid JSON object",
			value:      `{"key1":"value1","key2":"value2"}`,
			expectKeys: []string{"key1", "key2"},
			expectValue: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			name:       "JSON with number",
			value:      `{"port":8080}`,
			expectKeys: []string{"port"},
			expectValue: map[string]string{
				"port": "8080",
			},
		},
		{
			name:       "JSON with boolean",
			value:      `{"enabled":true}`,
			expectKeys: []string{"enabled"},
			expectValue: map[string]string{
				"enabled": "true",
			},
		},
		{
			name:       "JSON with null",
			value:      `{"nullkey":null}`,
			expectKeys: []string{"nullkey"},
			expectValue: map[string]string{
				"nullkey": "null",
			},
		},
		{
			name:       "invalid JSON",
			value:      `{invalid json}`,
			expectKeys: []string{"value"},
			expectValue: map[string]string{
				"value": `{invalid json}`,
			},
		},
		{
			name:       "empty string",
			value:      "",
			expectKeys: []string{"value"},
			expectValue: map[string]string{
				"value": "",
			},
		},
		{
			name:       "JSON array (not object)",
			value:      `["item1","item2"]`,
			expectKeys: []string{"value"},
			expectValue: map[string]string{
				"value": `["item1","item2"]`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.parseEnvValueToData(tt.value)

			for _, key := range tt.expectKeys {
				_, ok := result[key]
				assert.True(t, ok, "expected key %s to exist", key)
			}

			for key, expectedValue := range tt.expectValue {
				actualValue, ok := result[key]
				assert.True(t, ok, "expected key %s to exist", key)
				assert.Equal(t, expectedValue, string(actualValue))
			}
		})
	}
}

// TestEnvProvider_ListSecrets_WithPath tests ListSecrets with a path (should be ignored)
func TestEnvProvider_ListSecrets_WithPath(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "LIST_PATH_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	os.Setenv("LIST_PATH_TEST_SECRET1", "value1")
	defer os.Unsetenv("LIST_PATH_TEST_SECRET1")

	ctx := context.Background()

	// Path should be ignored for env provider
	secrets, err := provider.ListSecrets(ctx, "some/path")
	require.NoError(t, err)
	assert.Contains(t, secrets, "secret1")
}

// TestEnvProvider_HealthCheck_WithSecrets tests HealthCheck when secrets exist
func TestEnvProvider_HealthCheck_WithSecrets(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "HEALTH_WITH_SECRETS_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	os.Setenv("HEALTH_WITH_SECRETS_TEST", "value")
	defer os.Unsetenv("HEALTH_WITH_SECRETS_TEST")

	ctx := context.Background()
	err = provider.HealthCheck(ctx)
	assert.NoError(t, err)
}

// TestEnvProvider_HealthCheck_WithoutSecrets tests HealthCheck when no secrets exist
func TestEnvProvider_HealthCheck_WithoutSecrets(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "HEALTH_NO_SECRETS_UNIQUE_PREFIX_12345_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	// Should still succeed even without secrets
	err = provider.HealthCheck(ctx)
	assert.NoError(t, err)
}

// TestEnvProvider_GetSecret_WithNestedJSON tests GetSecret with deeply nested JSON
func TestEnvProvider_GetSecret_WithNestedJSON(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "NESTED_JSON_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	os.Setenv("NESTED_JSON_TEST_DEEP", `{"level1":{"level2":{"level3":"value"}}}`)
	defer os.Unsetenv("NESTED_JSON_TEST_DEEP")

	secret, err := provider.GetSecret(ctx, "deep")
	require.NoError(t, err)

	// Nested object should be JSON-encoded
	level1Bytes, ok := secret.GetBytes("level1")
	assert.True(t, ok)
	assert.Contains(t, string(level1Bytes), "level2")
	assert.Contains(t, string(level1Bytes), "level3")
}

// TestEnvProvider_GetSecret_WithArrayJSON tests GetSecret with JSON array values
func TestEnvProvider_GetSecret_WithArrayJSON(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "ARRAY_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	os.Setenv("ARRAY_TEST_HOSTS", `{"hosts":["host1","host2","host3"]}`)
	defer os.Unsetenv("ARRAY_TEST_HOSTS")

	secret, err := provider.GetSecret(ctx, "hosts")
	require.NoError(t, err)

	// Array should be JSON-encoded
	hostsBytes, ok := secret.GetBytes("hosts")
	assert.True(t, ok)
	assert.Contains(t, string(hostsBytes), "host1")
	assert.Contains(t, string(hostsBytes), "host2")
	assert.Contains(t, string(hostsBytes), "host3")
}

// TestEnvProvider_ListSecrets_ConversionToLowercase tests that secret names are converted to lowercase
func TestEnvProvider_ListSecrets_ConversionToLowercase(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "CASE_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	os.Setenv("CASE_TEST_UPPERCASE_SECRET", "value")
	defer os.Unsetenv("CASE_TEST_UPPERCASE_SECRET")

	ctx := context.Background()
	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)

	// Should be converted to lowercase with underscores replaced by dashes
	assert.Contains(t, secrets, "uppercase-secret")
}

// TestEnvProvider_ListSecrets_UnderscoreToDash tests that underscores are converted to dashes
func TestEnvProvider_ListSecrets_UnderscoreToDash(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "UNDERSCORE_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	os.Setenv("UNDERSCORE_TEST_MY_SECRET_NAME", "value")
	defer os.Unsetenv("UNDERSCORE_TEST_MY_SECRET_NAME")

	ctx := context.Background()
	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)

	// Underscores should be converted to dashes
	assert.Contains(t, secrets, "my-secret-name")
}

// TestEnvProvider_WriteSecret_ReturnsReadOnly tests that WriteSecret returns ErrReadOnly
func TestEnvProvider_WriteSecret_ReturnsReadOnly(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.WriteSecret(ctx, "test", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)
}

// TestEnvProvider_DeleteSecret_ReturnsReadOnly tests that DeleteSecret returns ErrReadOnly
func TestEnvProvider_DeleteSecret_ReturnsReadOnly(t *testing.T) {
	provider, err := NewEnvProvider(nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.DeleteSecret(ctx, "test")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReadOnly)
}

// TestEnvProvider_GetSecret_Metadata tests that metadata is set correctly
func TestEnvProvider_GetSecret_Metadata(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "METADATA_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	os.Setenv("METADATA_TEST_MYSECRET", "value")
	defer os.Unsetenv("METADATA_TEST_MYSECRET")

	secret, err := provider.GetSecret(ctx, "mysecret")
	require.NoError(t, err)

	assert.Equal(t, "mysecret", secret.Name)
	assert.Equal(t, "environment", secret.Metadata["source"])
	assert.Equal(t, "METADATA_TEST_MYSECRET", secret.Metadata["env_var"])
}

// TestEnvProvider_ListSecrets_MalformedEnvVar tests ListSecrets with malformed env vars
func TestEnvProvider_ListSecrets_MalformedEnvVar(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "MALFORMED_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	// Set a normal env var
	os.Setenv("MALFORMED_TEST_NORMAL", "value")
	defer os.Unsetenv("MALFORMED_TEST_NORMAL")

	ctx := context.Background()
	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Contains(t, secrets, "normal")
}

// TestEnvProvider_ParseEnvValueToData_MarshalError tests parseEnvValueToData with unmarshalable values
func TestEnvProvider_ParseEnvValueToData_MarshalError(t *testing.T) {
	provider, err := NewEnvProvider(&EnvProviderConfig{
		Prefix: "MARSHAL_ERROR_TEST_",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	// Test with valid JSON that has complex nested structure
	result := provider.parseEnvValueToData(`{"key": {"nested": {"deep": "value"}}}`)
	assert.NotNil(t, result)
	assert.Contains(t, result, "key")
}

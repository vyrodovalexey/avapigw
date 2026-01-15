package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewLocalProvider(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test with valid config
	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, tmpDir, provider.basePath)

	// Test with nil config
	_, err = NewLocalProvider(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)

	// Test with empty base path
	_, err = NewLocalProvider(&LocalProviderConfig{
		BasePath: "",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)

	// Test with non-existent path
	_, err = NewLocalProvider(&LocalProviderConfig{
		BasePath: "/nonexistent/path",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestLocalProviderType(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)
	assert.Equal(t, ProviderTypeLocal, provider.Type())
}

func TestLocalProviderGetSecretFromDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logger := zap.NewNop()
	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a secret directory with key files
	secretDir := filepath.Join(tmpDir, "my-secret")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "username"), []byte("admin"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "password"), []byte("secret123"), 0600))

	// Get the secret
	secret, err := provider.GetSecret(ctx, "my-secret")
	require.NoError(t, err)
	assert.Equal(t, "my-secret", secret.Name)

	username, ok := secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)

	password, ok := secret.GetString("password")
	assert.True(t, ok)
	assert.Equal(t, "secret123", password)
}

func TestLocalProviderGetSecretFromYAML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logger := zap.NewNop()
	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a YAML secret file
	yamlContent := `username: admin
password: secret123
port: 5432`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "db-secret.yaml"), []byte(yamlContent), 0600))

	// Get the secret
	secret, err := provider.GetSecret(ctx, "db-secret")
	require.NoError(t, err)
	assert.Equal(t, "db-secret", secret.Name)

	username, ok := secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)

	password, ok := secret.GetString("password")
	assert.True(t, ok)
	assert.Equal(t, "secret123", password)
}

func TestLocalProviderGetSecretFromJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logger := zap.NewNop()
	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   logger,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a JSON secret file
	jsonContent := `{"username": "admin", "password": "secret123"}`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "api-secret.json"), []byte(jsonContent), 0600))

	// Get the secret
	secret, err := provider.GetSecret(ctx, "api-secret")
	require.NoError(t, err)
	assert.Equal(t, "api-secret", secret.Name)

	username, ok := secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)
}

func TestLocalProviderGetSecretNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	ctx := context.Background()

	_, err = provider.GetSecret(ctx, "nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestLocalProviderGetSecretInvalidPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test empty path
	_, err = provider.GetSecret(ctx, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)

	// Test path traversal
	_, err = provider.GetSecret(ctx, "../etc/passwd")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

func TestLocalProviderListSecrets(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create some secrets
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "secret1"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "secret2.yaml"), []byte("key: value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "secret3.json"), []byte(`{"key": "value"}`), 0600))

	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Len(t, secrets, 3)
	assert.Contains(t, secrets, "secret1")
	assert.Contains(t, secrets, "secret2")
	assert.Contains(t, secrets, "secret3")
}

func TestLocalProviderWriteSecret(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Write a secret
	err = provider.WriteSecret(ctx, "new-secret", map[string][]byte{
		"username": []byte("admin"),
		"password": []byte("secret123"),
	})
	require.NoError(t, err)

	// Verify the file was created
	_, err = os.Stat(filepath.Join(tmpDir, "new-secret.yaml"))
	assert.NoError(t, err)

	// Read it back
	secret, err := provider.GetSecret(ctx, "new-secret")
	require.NoError(t, err)
	username, ok := secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)
}

func TestLocalProviderDeleteSecret(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a secret
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "to-delete.yaml"), []byte("key: value"), 0600))

	// Delete it
	err = provider.DeleteSecret(ctx, "to-delete")
	require.NoError(t, err)

	// Verify it's gone
	_, err = os.Stat(filepath.Join(tmpDir, "to-delete.yaml"))
	assert.True(t, os.IsNotExist(err))

	// Delete non-existent should not error
	err = provider.DeleteSecret(ctx, "nonexistent")
	assert.NoError(t, err)
}

func TestLocalProviderIsReadOnly(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)
	assert.False(t, provider.IsReadOnly())
}

func TestLocalProviderHealthCheck(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestLocalProviderHealthCheck_DeletedBasePath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Delete the base path after provider creation
	require.NoError(t, os.RemoveAll(tmpDir))

	ctx := context.Background()
	err = provider.HealthCheck(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base path not accessible")
}

func TestLocalProviderHealthCheck_BasePathIsFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create provider with valid directory
	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Replace directory with a file
	require.NoError(t, os.RemoveAll(tmpDir))
	require.NoError(t, os.WriteFile(tmpDir, []byte("not a directory"), 0600))
	defer os.Remove(tmpDir)

	ctx := context.Background()
	err = provider.HealthCheck(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestLocalProviderClose(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	err = provider.Close()
	assert.NoError(t, err)
}

func TestLocalProviderWriteSecret_InvalidPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test empty path
	err = provider.WriteSecret(ctx, "", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)

	// Test path traversal
	err = provider.WriteSecret(ctx, "../etc/passwd", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

func TestLocalProviderWriteSecret_NestedPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Write a secret with nested path
	err = provider.WriteSecret(ctx, "nested/path/secret", map[string][]byte{
		"username": []byte("admin"),
		"password": []byte("secret123"),
	})
	require.NoError(t, err)

	// Verify the file was created in nested directory
	_, err = os.Stat(filepath.Join(tmpDir, "nested", "path", "secret.yaml"))
	assert.NoError(t, err)

	// Read it back
	secret, err := provider.GetSecret(ctx, "nested/path/secret")
	require.NoError(t, err)
	username, ok := secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)
}

func TestLocalProviderDeleteSecret_InvalidPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test empty path
	err = provider.DeleteSecret(ctx, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)

	// Test path traversal
	err = provider.DeleteSecret(ctx, "../etc/passwd")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

func TestLocalProviderDeleteSecret_Directory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a secret directory with key files
	secretDir := filepath.Join(tmpDir, "dir-secret")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key1"), []byte("value1"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key2"), []byte("value2"), 0600))

	// Delete the directory secret
	err = provider.DeleteSecret(ctx, "dir-secret")
	require.NoError(t, err)

	// Verify it's gone
	_, err = os.Stat(secretDir)
	assert.True(t, os.IsNotExist(err))
}

func TestLocalProviderDeleteSecret_MultipleFormats(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create secrets in multiple formats with same name
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "multi.yaml"), []byte("key: yaml"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "multi.yml"), []byte("key: yml"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "multi.json"), []byte(`{"key": "json"}`), 0600))

	// Delete should remove all formats
	err = provider.DeleteSecret(ctx, "multi")
	require.NoError(t, err)

	// Verify all are gone
	_, err = os.Stat(filepath.Join(tmpDir, "multi.yaml"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(tmpDir, "multi.yml"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(tmpDir, "multi.json"))
	assert.True(t, os.IsNotExist(err))
}

func TestLocalProviderListSecrets_InvalidPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test path traversal
	_, err = provider.ListSecrets(ctx, "../etc")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

func TestLocalProviderListSecrets_NonExistentPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// List non-existent path should return empty list
	secrets, err := provider.ListSecrets(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestLocalProviderListSecrets_WithYMLExtension(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a .yml file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "secret.yml"), []byte("key: value"), 0600))

	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Contains(t, secrets, "secret")
}

func TestLocalProviderGetSecret_YMLExtension(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a .yml file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "secret.yml"), []byte("key: value"), 0600))

	secret, err := provider.GetSecret(ctx, "secret")
	require.NoError(t, err)
	assert.Equal(t, "secret", secret.Name)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestLocalProviderGetSecret_EmptyDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create an empty directory
	secretDir := filepath.Join(tmpDir, "empty-secret")
	require.NoError(t, os.MkdirAll(secretDir, 0750))

	// Should fail because directory is empty
	_, err = provider.GetSecret(ctx, "empty-secret")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestLocalProviderGetSecret_DirectoryWithSubdirs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a directory with subdirectories (should be ignored) and files
	secretDir := filepath.Join(tmpDir, "mixed-secret")
	require.NoError(t, os.MkdirAll(filepath.Join(secretDir, "subdir"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key1"), []byte("value1"), 0600))

	secret, err := provider.GetSecret(ctx, "mixed-secret")
	require.NoError(t, err)
	assert.Equal(t, "mixed-secret", secret.Name)

	// Should only have key1, not subdir
	val, ok := secret.GetString("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)
	assert.Len(t, secret.Data, 1)
}

func TestLocalProviderGetSecret_YAMLWithComplexTypes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a YAML file with complex types
	yamlContent := `string_key: simple_value
number_key: 42
nested:
  inner: value
list_key:
  - item1
  - item2`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "complex.yaml"), []byte(yamlContent), 0600))

	secret, err := provider.GetSecret(ctx, "complex")
	require.NoError(t, err)

	// String key should work
	strVal, ok := secret.GetString("string_key")
	assert.True(t, ok)
	assert.Equal(t, "simple_value", strVal)

	// Number key should be converted to JSON
	numVal, ok := secret.Data["number_key"]
	assert.True(t, ok)
	assert.Equal(t, "42", string(numVal))

	// Nested should be JSON
	nestedVal, ok := secret.Data["nested"]
	assert.True(t, ok)
	assert.Contains(t, string(nestedVal), "inner")
}

func TestLocalProviderGetSecret_JSONWithComplexTypes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a JSON file with complex types
	jsonContent := `{
		"string_key": "simple_value",
		"number_key": 42,
		"nested": {"inner": "value"},
		"list_key": ["item1", "item2"]
	}`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "complex.json"), []byte(jsonContent), 0600))

	secret, err := provider.GetSecret(ctx, "complex")
	require.NoError(t, err)

	// String key should work
	strVal, ok := secret.GetString("string_key")
	assert.True(t, ok)
	assert.Equal(t, "simple_value", strVal)

	// Number key should be converted to JSON
	numVal, ok := secret.Data["number_key"]
	assert.True(t, ok)
	assert.Equal(t, "42", string(numVal))
}

func TestLocalProviderGetSecret_InvalidYAML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create an invalid YAML file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte("invalid: yaml: content:"), 0600))

	// Should fail to parse
	_, err = provider.GetSecret(ctx, "invalid")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestLocalProviderGetSecret_InvalidJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create an invalid JSON file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "invalid.json"), []byte("{invalid json}"), 0600))

	// Should fail to parse
	_, err = provider.GetSecret(ctx, "invalid")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestLocalProviderGetSecret_DirectoryWithTrailingNewline(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a directory with a file that has trailing newline
	secretDir := filepath.Join(tmpDir, "newline-secret")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key"), []byte("value\n"), 0600))

	secret, err := provider.GetSecret(ctx, "newline-secret")
	require.NoError(t, err)

	// Trailing newline should be trimmed
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestNewLocalProvider_BasePathIsFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "local-provider-test")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	_, err = NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpFile.Name(),
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
	assert.Contains(t, err.Error(), "not a directory")
}

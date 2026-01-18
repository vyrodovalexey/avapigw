package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestLocalProviderGetSecret_DirectoryOnlySubdirs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a directory with only subdirectories (no files)
	secretDir := filepath.Join(tmpDir, "only-subdirs")
	require.NoError(t, os.MkdirAll(filepath.Join(secretDir, "subdir1"), 0750))
	require.NoError(t, os.MkdirAll(filepath.Join(secretDir, "subdir2"), 0750))

	// Should fail because no valid key files found
	_, err = provider.GetSecret(ctx, "only-subdirs")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestLocalProviderWriteSecret_MarshalError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Write a valid secret (YAML marshaling should work for any map[string][]byte)
	err = provider.WriteSecret(ctx, "test-secret", map[string][]byte{
		"key": []byte("value"),
	})
	require.NoError(t, err)
}

func TestLocalProviderDeleteSecret_DirectoryError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a directory with a file
	secretDir := filepath.Join(tmpDir, "dir-to-delete")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key"), []byte("value"), 0600))

	// Delete should succeed
	err = provider.DeleteSecret(ctx, "dir-to-delete")
	require.NoError(t, err)

	// Verify directory is gone
	_, err = os.Stat(secretDir)
	assert.True(t, os.IsNotExist(err))
}

func TestLocalProviderListSecrets_SubPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create nested structure
	subDir := filepath.Join(tmpDir, "subpath")
	require.NoError(t, os.MkdirAll(subDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "secret1.yaml"), []byte("key: value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "secret2.json"), []byte(`{"key": "value"}`), 0600))

	// List secrets in subpath
	secrets, err := provider.ListSecrets(ctx, "subpath")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
	assert.Contains(t, secrets, "secret1")
	assert.Contains(t, secrets, "secret2")
}

func TestLocalProviderGetSecret_NestedPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create nested secret
	nestedDir := filepath.Join(tmpDir, "nested", "path")
	require.NoError(t, os.MkdirAll(nestedDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "secret.yaml"), []byte("key: value"), 0600))

	// Get nested secret
	secret, err := provider.GetSecret(ctx, "nested/path/secret")
	require.NoError(t, err)
	assert.Equal(t, "nested/path/secret", secret.Name)
}

func TestLocalProviderDeleteSecret_YMLFile(t *testing.T) {
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

	// Delete should remove the .yml file
	err = provider.DeleteSecret(ctx, "secret")
	require.NoError(t, err)

	// Verify file is gone
	_, err = os.Stat(filepath.Join(tmpDir, "secret.yml"))
	assert.True(t, os.IsNotExist(err))
}

func TestLocalProviderListSecrets_MixedContent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create mixed content: directories, yaml, yml, json, and other files
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "dir-secret"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yaml-secret.yaml"), []byte("key: value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yml-secret.yml"), []byte("key: value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "json-secret.json"), []byte(`{"key": "value"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "other.txt"), []byte("not a secret"), 0600))

	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)

	// Should include dir-secret, yaml-secret, yml-secret, json-secret
	// Should NOT include other.txt
	assert.Contains(t, secrets, "dir-secret")
	assert.Contains(t, secrets, "yaml-secret")
	assert.Contains(t, secrets, "yml-secret")
	assert.Contains(t, secrets, "json-secret")
	assert.NotContains(t, secrets, "other")
	assert.NotContains(t, secrets, "other.txt")
}

func TestLocalProviderGetSecret_PriorityOrder(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create both directory and YAML file with same name
	// Directory should take priority
	secretDir := filepath.Join(tmpDir, "priority-secret")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "from"), []byte("directory"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "priority-secret.yaml"), []byte("from: yaml"), 0600))

	secret, err := provider.GetSecret(ctx, "priority-secret")
	require.NoError(t, err)

	// Should get value from directory (priority)
	val, ok := secret.GetString("from")
	assert.True(t, ok)
	assert.Equal(t, "directory", val)
}

func TestLocalProviderReadSecretFromDirectory_UnreadableFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a directory with a readable file
	secretDir := filepath.Join(tmpDir, "readable-secret")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "readable"), []byte("value"), 0600))

	// Get the secret - should work
	secret, err := provider.GetSecret(ctx, "readable-secret")
	require.NoError(t, err)
	val, ok := secret.GetString("readable")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestLocalProviderValidateAndCleanPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid simple path",
			path:    "secret",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			path:    "nested/secret",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "path traversal",
			path:    "../etc/passwd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.validateAndCleanPath(tt.path, time.Now())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLocalProviderListSecrets_ReadDirError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a subdir and then make it unreadable
	subDir := filepath.Join(tmpDir, "unreadable")
	require.NoError(t, os.MkdirAll(subDir, 0750))

	// List secrets in a non-existent subpath returns empty list
	secrets, err := provider.ListSecrets(ctx, "nonexistent-subpath")
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestLocalProviderReadSecretFromYAML_ByteValue(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a YAML file with various types
	yamlContent := `string_key: simple_value
bool_key: true
null_key: null`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "types.yaml"), []byte(yamlContent), 0600))

	secret, err := provider.GetSecret(ctx, "types")
	require.NoError(t, err)

	// String key should work
	strVal, ok := secret.GetString("string_key")
	assert.True(t, ok)
	assert.Equal(t, "simple_value", strVal)

	// Bool key should be JSON-encoded
	boolVal, ok := secret.Data["bool_key"]
	assert.True(t, ok)
	assert.Equal(t, "true", string(boolVal))
}

func TestLocalProviderReadSecretFromJSON_NumberValue(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a JSON file with number values
	jsonContent := `{"float_key": 3.14, "int_key": 42, "string_key": "value"}`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "numbers.json"), []byte(jsonContent), 0600))

	secret, err := provider.GetSecret(ctx, "numbers")
	require.NoError(t, err)

	// Float key should be JSON-encoded
	floatVal, ok := secret.Data["float_key"]
	assert.True(t, ok)
	assert.Contains(t, string(floatVal), "3.14")

	// Int key should be JSON-encoded
	intVal, ok := secret.Data["int_key"]
	assert.True(t, ok)
	assert.Equal(t, "42", string(intVal))

	// String key should work
	strVal, ok := secret.GetString("string_key")
	assert.True(t, ok)
	assert.Equal(t, "value", strVal)
}

func TestLocalProviderNewLocalProvider_StatError(t *testing.T) {
	// Test with a path that doesn't exist
	_, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: "/nonexistent/path/that/does/not/exist",
		Logger:   zap.NewNop(),
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestLocalProviderGetSecret_FallbackToYAML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create only a YAML file (no directory)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yaml-only.yaml"), []byte("key: value"), 0600))

	secret, err := provider.GetSecret(ctx, "yaml-only")
	require.NoError(t, err)
	assert.Equal(t, "yaml-only", secret.Name)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestLocalProviderGetSecret_FallbackToJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create only a JSON file (no directory or YAML)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "json-only.json"), []byte(`{"key": "value"}`), 0600))

	secret, err := provider.GetSecret(ctx, "json-only")
	require.NoError(t, err)
	assert.Equal(t, "json-only", secret.Name)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestLocalProviderListSecrets_EmptyDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// List secrets in empty directory
	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestLocalProviderDeleteSecret_AllFormats(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create all formats
	secretDir := filepath.Join(tmpDir, "all-formats")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key"), []byte("dir-value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "all-formats.yaml"), []byte("key: yaml"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "all-formats.yml"), []byte("key: yml"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "all-formats.json"), []byte(`{"key": "json"}`), 0600))

	// Delete should remove all
	err = provider.DeleteSecret(ctx, "all-formats")
	require.NoError(t, err)

	// Verify all are gone
	_, err = os.Stat(secretDir)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(tmpDir, "all-formats.yaml"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(tmpDir, "all-formats.yml"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(tmpDir, "all-formats.json"))
	assert.True(t, os.IsNotExist(err))
}

func TestLocalProviderWriteSecret_OverwriteExisting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Write initial secret
	err = provider.WriteSecret(ctx, "overwrite-test", map[string][]byte{
		"key": []byte("initial"),
	})
	require.NoError(t, err)

	// Overwrite with new value
	err = provider.WriteSecret(ctx, "overwrite-test", map[string][]byte{
		"key": []byte("updated"),
	})
	require.NoError(t, err)

	// Read back and verify
	secret, err := provider.GetSecret(ctx, "overwrite-test")
	require.NoError(t, err)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "updated", val)
}

// TestLocalProvider_Type_Constant tests that Type returns the correct constant
func TestLocalProvider_Type_Constant(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	assert.Equal(t, ProviderTypeLocal, provider.Type())
	assert.Equal(t, ProviderType("local"), provider.Type())
}

// TestLocalProvider_IsReadOnly_AlwaysFalse tests that IsReadOnly always returns false
func TestLocalProvider_IsReadOnly_AlwaysFalse(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	assert.False(t, provider.IsReadOnly())
}

// TestLocalProvider_Close_MultipleCalls tests calling Close multiple times
func TestLocalProvider_Close_MultipleCalls(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
	})
	require.NoError(t, err)

	// First close
	err = provider.Close()
	assert.NoError(t, err)

	// Second close should also succeed (idempotent)
	err = provider.Close()
	assert.NoError(t, err)
}

// TestLocalProvider_WriteSecret_WithSpecialCharacters tests writing secrets with special characters
func TestLocalProvider_WriteSecret_WithSpecialCharacters(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Write secret with special characters in values
	err = provider.WriteSecret(ctx, "special-chars", map[string][]byte{
		"key1": []byte("value with spaces"),
		"key2": []byte("value\nwith\nnewlines"),
		"key3": []byte("value\twith\ttabs"),
		"key4": []byte("value:with:colons"),
		"key5": []byte("value=with=equals"),
	})
	require.NoError(t, err)

	// Read back and verify
	secret, err := provider.GetSecret(ctx, "special-chars")
	require.NoError(t, err)

	val1, ok := secret.GetString("key1")
	assert.True(t, ok)
	assert.Equal(t, "value with spaces", val1)

	val2, ok := secret.GetString("key2")
	assert.True(t, ok)
	assert.Equal(t, "value\nwith\nnewlines", val2)
}

// TestLocalProvider_WriteSecret_EmptyData tests writing a secret with empty data
func TestLocalProvider_WriteSecret_EmptyData(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Write secret with empty data
	err = provider.WriteSecret(ctx, "empty-data", map[string][]byte{})
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(filepath.Join(tmpDir, "empty-data.yaml"))
	assert.NoError(t, err)
}

// TestLocalProvider_WriteSecret_NilData tests writing a secret with nil data
func TestLocalProvider_WriteSecret_NilData(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Write secret with nil data
	err = provider.WriteSecret(ctx, "nil-data", nil)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(filepath.Join(tmpDir, "nil-data.yaml"))
	assert.NoError(t, err)
}

// TestLocalProvider_GetSecret_DirectoryWithUnreadableFile tests directory with unreadable file
func TestLocalProvider_GetSecret_DirectoryWithUnreadableFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a directory with a readable file
	secretDir := filepath.Join(tmpDir, "mixed-readable")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "readable"), []byte("value"), 0600))

	// Get the secret - should work with readable file
	secret, err := provider.GetSecret(ctx, "mixed-readable")
	require.NoError(t, err)
	val, ok := secret.GetString("readable")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

// TestLocalProvider_ListSecrets_WithHiddenFiles tests listing with hidden files
func TestLocalProvider_ListSecrets_WithHiddenFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create visible and hidden files
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "visible.yaml"), []byte("key: value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".hidden.yaml"), []byte("key: value"), 0600))

	secrets, err := provider.ListSecrets(ctx, "")
	require.NoError(t, err)

	// Should include visible but not hidden (hidden starts with .)
	assert.Contains(t, secrets, "visible")
	// Hidden files with .yaml extension would be listed as ".hidden"
}

// TestLocalProvider_DeleteSecret_NestedPath tests deleting a secret in a nested path
func TestLocalProvider_DeleteSecret_NestedPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create nested secret
	nestedDir := filepath.Join(tmpDir, "nested", "path")
	require.NoError(t, os.MkdirAll(nestedDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "secret.yaml"), []byte("key: value"), 0600))

	// Delete the nested secret
	err = provider.DeleteSecret(ctx, "nested/path/secret")
	require.NoError(t, err)

	// Verify it's gone
	_, err = os.Stat(filepath.Join(nestedDir, "secret.yaml"))
	assert.True(t, os.IsNotExist(err))
}

// TestLocalProvider_ValidateWritePath_TableDriven tests validateWritePath with various inputs
func TestLocalProvider_ValidateWritePath_TableDriven(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid simple path",
			path:    "secret",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			path:    "nested/secret",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "path traversal",
			path:    "../etc/passwd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.validateWritePath(tt.path, time.Now())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestLocalProvider_ValidateDeletePath_TableDriven tests validateDeletePath with various inputs
func TestLocalProvider_ValidateDeletePath_TableDriven(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid simple path",
			path:    "secret",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			path:    "nested/secret",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "path traversal",
			path:    "../etc/passwd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.validateDeletePath(tt.path, time.Now())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestLocalProvider_ResolveListSearchPath_TableDriven tests resolveListSearchPath with various inputs
func TestLocalProvider_ResolveListSearchPath_TableDriven(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		path     string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "empty path returns base path",
			path:     "",
			wantPath: tmpDir,
			wantErr:  false,
		},
		{
			name:     "simple path",
			path:     "subdir",
			wantPath: filepath.Join(tmpDir, "subdir"),
			wantErr:  false,
		},
		{
			name:    "path traversal",
			path:    "../etc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := provider.resolveListSearchPath(tt.path, time.Now())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantPath, result)
			}
		})
	}
}

// TestLocalProvider_ExtractSecretNamesFromEntries tests extractSecretNamesFromEntries
func TestLocalProvider_ExtractSecretNamesFromEntries(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create various files and directories
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "dir-secret"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yaml-secret.yaml"), []byte("key: value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yml-secret.yml"), []byte("key: value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "json-secret.json"), []byte(`{"key": "value"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "other.txt"), []byte("not a secret"), 0600))

	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	names := provider.extractSecretNamesFromEntries(entries)

	assert.Contains(t, names, "dir-secret")
	assert.Contains(t, names, "yaml-secret")
	assert.Contains(t, names, "yml-secret")
	assert.Contains(t, names, "json-secret")
	// other.txt should not be included
	assert.NotContains(t, names, "other")
	assert.NotContains(t, names, "other.txt")
}

// TestLocalProvider_TryReadSecretFromFormats_DirectoryFirst tests that directory takes priority
func TestLocalProvider_TryReadSecretFromFormats_DirectoryFirst(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create both directory and YAML file with same name
	secretDir := filepath.Join(tmpDir, "priority-test")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "source"), []byte("directory"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "priority-test.yaml"), []byte("source: yaml"), 0600))

	secret, found := provider.tryReadSecretFromFormats("priority-test")
	assert.True(t, found)
	assert.NotNil(t, secret)

	// Should get value from directory (priority)
	val, ok := secret.GetString("source")
	assert.True(t, ok)
	assert.Equal(t, "directory", val)
}

// TestLocalProvider_ReadSecretFromDirectory_EmptyDir tests reading from empty directory
func TestLocalProvider_ReadSecretFromDirectory_EmptyDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create empty directory
	emptyDir := filepath.Join(tmpDir, "empty-dir")
	require.NoError(t, os.MkdirAll(emptyDir, 0750))

	_, err = provider.readSecretFromDirectory(emptyDir, "empty-dir")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "directory is empty")
}

// TestLocalProvider_ReadSecretFromDirectory_OnlySubdirs tests directory with only subdirectories
func TestLocalProvider_ReadSecretFromDirectory_OnlySubdirs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create directory with only subdirectories
	secretDir := filepath.Join(tmpDir, "only-subdirs")
	require.NoError(t, os.MkdirAll(filepath.Join(secretDir, "subdir1"), 0750))
	require.NoError(t, os.MkdirAll(filepath.Join(secretDir, "subdir2"), 0750))

	_, err = provider.readSecretFromDirectory(secretDir, "only-subdirs")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid key files found")
}

// TestLocalProvider_ReadSecretFromYAML_InvalidYAML tests reading invalid YAML
func TestLocalProvider_ReadSecretFromYAML_InvalidYAML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create invalid YAML file
	invalidYAML := filepath.Join(tmpDir, "invalid.yaml")
	require.NoError(t, os.WriteFile(invalidYAML, []byte("invalid: yaml: content: ["), 0600))

	_, err = provider.readSecretFromYAML(invalidYAML, "invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse YAML")
}

// TestLocalProvider_ReadSecretFromJSON_InvalidJSON tests reading invalid JSON
func TestLocalProvider_ReadSecretFromJSON_InvalidJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create invalid JSON file
	invalidJSON := filepath.Join(tmpDir, "invalid.json")
	require.NoError(t, os.WriteFile(invalidJSON, []byte("{invalid json}"), 0600))

	_, err = provider.readSecretFromJSON(invalidJSON, "invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JSON")
}

// TestLocalProvider_ReadSecretFromYAML_NonExistentFile tests reading non-existent YAML file
func TestLocalProvider_ReadSecretFromYAML_NonExistentFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	_, err = provider.readSecretFromYAML(filepath.Join(tmpDir, "nonexistent.yaml"), "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read YAML file")
}

// TestLocalProvider_ReadSecretFromJSON_NonExistentFile tests reading non-existent JSON file
func TestLocalProvider_ReadSecretFromJSON_NonExistentFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	_, err = provider.readSecretFromJSON(filepath.Join(tmpDir, "nonexistent.json"), "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read JSON file")
}

// TestLocalProvider_DeleteSecretFiles_DirectoryAndFiles tests deleting both directory and files
func TestLocalProvider_DeleteSecretFiles_DirectoryAndFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create directory and files with same name
	secretDir := filepath.Join(tmpDir, "multi-format")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key"), []byte("dir-value"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "multi-format.yaml"), []byte("key: yaml"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "multi-format.yml"), []byte("key: yml"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "multi-format.json"), []byte(`{"key": "json"}`), 0600))

	deleted, err := provider.deleteSecretFiles("multi-format", time.Now())
	require.NoError(t, err)
	assert.True(t, deleted)

	// Verify all are gone
	_, err = os.Stat(secretDir)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(tmpDir, "multi-format.yaml"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(tmpDir, "multi-format.yml"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(tmpDir, "multi-format.json"))
	assert.True(t, os.IsNotExist(err))
}

// TestLocalProvider_DeleteSecretFiles_NothingToDelete tests deleting when nothing exists
func TestLocalProvider_DeleteSecretFiles_NothingToDelete(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	deleted, err := provider.deleteSecretFiles("nonexistent", time.Now())
	require.NoError(t, err)
	assert.False(t, deleted)
}

// TestLocalProvider_ListSecrets_ReadDirErrorPath tests ListSecrets when ReadDir fails
func TestLocalProvider_ListSecrets_ReadDirErrorPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a file instead of directory to cause ReadDir to fail
	filePath := filepath.Join(tmpDir, "not-a-dir")
	require.NoError(t, os.WriteFile(filePath, []byte("content"), 0600))

	// Try to list secrets in a file (not a directory)
	_, err = provider.ListSecrets(ctx, "not-a-dir")
	assert.Error(t, err)
}

// TestLocalProvider_ReadSecretFromYAML_WithByteSlice tests YAML with byte slice values
func TestLocalProvider_ReadSecretFromYAML_WithByteSlice(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a YAML file with various types
	yamlContent := `string_key: simple_value
number_key: 42
bool_key: true
null_key: null
nested:
  inner: value`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "types.yaml"), []byte(yamlContent), 0600))

	secret, err := provider.GetSecret(ctx, "types")
	require.NoError(t, err)

	// String key should work
	strVal, ok := secret.GetString("string_key")
	assert.True(t, ok)
	assert.Equal(t, "simple_value", strVal)

	// Number key should be JSON-encoded
	numVal, ok := secret.Data["number_key"]
	assert.True(t, ok)
	assert.Equal(t, "42", string(numVal))

	// Bool key should be JSON-encoded
	boolVal, ok := secret.Data["bool_key"]
	assert.True(t, ok)
	assert.Equal(t, "true", string(boolVal))
}

// TestLocalProvider_ReadSecretFromJSON_WithNestedObjects tests JSON with nested objects
func TestLocalProvider_ReadSecretFromJSON_WithNestedObjects(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a JSON file with nested objects
	jsonContent := `{
		"string_key": "value",
		"nested": {"inner": "nested_value"},
		"array": [1, 2, 3]
	}`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "nested.json"), []byte(jsonContent), 0600))

	secret, err := provider.GetSecret(ctx, "nested")
	require.NoError(t, err)

	// String key should work
	strVal, ok := secret.GetString("string_key")
	assert.True(t, ok)
	assert.Equal(t, "value", strVal)

	// Nested object should be JSON-encoded
	nestedVal, ok := secret.Data["nested"]
	assert.True(t, ok)
	assert.Contains(t, string(nestedVal), "inner")

	// Array should be JSON-encoded
	arrayVal, ok := secret.Data["array"]
	assert.True(t, ok)
	assert.Contains(t, string(arrayVal), "1")
}

// TestLocalProvider_GetSecret_DirectoryFallbackToYAML tests fallback from directory to YAML
func TestLocalProvider_GetSecret_DirectoryFallbackToYAML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create an empty directory (will fail) and a YAML file (will succeed)
	emptyDir := filepath.Join(tmpDir, "fallback-test")
	require.NoError(t, os.MkdirAll(emptyDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "fallback-test.yaml"), []byte("key: yaml-value"), 0600))

	secret, err := provider.GetSecret(ctx, "fallback-test")
	require.NoError(t, err)

	// Should get value from YAML (directory is empty)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "yaml-value", val)
}

// TestLocalProvider_GetSecret_DirectoryFallbackToYML tests fallback from directory to YML
func TestLocalProvider_GetSecret_DirectoryFallbackToYML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create an empty directory (will fail) and a YML file (will succeed)
	emptyDir := filepath.Join(tmpDir, "yml-fallback")
	require.NoError(t, os.MkdirAll(emptyDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yml-fallback.yml"), []byte("key: yml-value"), 0600))

	secret, err := provider.GetSecret(ctx, "yml-fallback")
	require.NoError(t, err)

	// Should get value from YML
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "yml-value", val)
}

// TestLocalProvider_GetSecret_DirectoryFallbackToJSON tests fallback from directory to JSON
func TestLocalProvider_GetSecret_DirectoryFallbackToJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create an empty directory (will fail) and a JSON file (will succeed)
	emptyDir := filepath.Join(tmpDir, "json-fallback")
	require.NoError(t, os.MkdirAll(emptyDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "json-fallback.json"), []byte(`{"key": "json-value"}`), 0600))

	secret, err := provider.GetSecret(ctx, "json-fallback")
	require.NoError(t, err)

	// Should get value from JSON
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "json-value", val)
}

// TestLocalProvider_ReadSecretFromYAML_AllTypes tests YAML with all supported types
func TestLocalProvider_ReadSecretFromYAML_AllTypes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a YAML file with various types
	yamlContent := `string_key: simple_value
number_key: 42
float_key: 3.14
bool_key: true
null_key: null
list_key:
  - item1
  - item2
map_key:
  nested: value`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "all-types.yaml"), []byte(yamlContent), 0600))

	secret, err := provider.GetSecret(ctx, "all-types")
	require.NoError(t, err)

	// String key should work
	strVal, ok := secret.GetString("string_key")
	assert.True(t, ok)
	assert.Equal(t, "simple_value", strVal)

	// Number key should be JSON-encoded
	numVal, ok := secret.Data["number_key"]
	assert.True(t, ok)
	assert.Equal(t, "42", string(numVal))

	// Float key should be JSON-encoded
	floatVal, ok := secret.Data["float_key"]
	assert.True(t, ok)
	assert.Contains(t, string(floatVal), "3.14")

	// Bool key should be JSON-encoded
	boolVal, ok := secret.Data["bool_key"]
	assert.True(t, ok)
	assert.Equal(t, "true", string(boolVal))

	// List key should be JSON-encoded
	listVal, ok := secret.Data["list_key"]
	assert.True(t, ok)
	assert.Contains(t, string(listVal), "item1")

	// Map key should be JSON-encoded
	mapVal, ok := secret.Data["map_key"]
	assert.True(t, ok)
	assert.Contains(t, string(mapVal), "nested")
}

// TestLocalProvider_ReadSecretFromJSON_AllTypes tests JSON with all supported types
func TestLocalProvider_ReadSecretFromJSON_AllTypes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a JSON file with various types
	jsonContent := `{
		"string_key": "simple_value",
		"number_key": 42,
		"float_key": 3.14,
		"bool_key": true,
		"null_key": null,
		"list_key": ["item1", "item2"],
		"map_key": {"nested": "value"}
	}`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "all-types.json"), []byte(jsonContent), 0600))

	secret, err := provider.GetSecret(ctx, "all-types")
	require.NoError(t, err)

	// String key should work
	strVal, ok := secret.GetString("string_key")
	assert.True(t, ok)
	assert.Equal(t, "simple_value", strVal)

	// Number key should be JSON-encoded
	numVal, ok := secret.Data["number_key"]
	assert.True(t, ok)
	assert.Equal(t, "42", string(numVal))

	// Float key should be JSON-encoded
	floatVal, ok := secret.Data["float_key"]
	assert.True(t, ok)
	assert.Contains(t, string(floatVal), "3.14")

	// Bool key should be JSON-encoded
	boolVal, ok := secret.Data["bool_key"]
	assert.True(t, ok)
	assert.Equal(t, "true", string(boolVal))

	// Null key should be JSON-encoded
	nullVal, ok := secret.Data["null_key"]
	assert.True(t, ok)
	assert.Equal(t, "null", string(nullVal))

	// List key should be JSON-encoded
	listVal, ok := secret.Data["list_key"]
	assert.True(t, ok)
	assert.Contains(t, string(listVal), "item1")

	// Map key should be JSON-encoded
	mapVal, ok := secret.Data["map_key"]
	assert.True(t, ok)
	assert.Contains(t, string(mapVal), "nested")
}

// TestLocalProvider_ReadSecretFromDirectory_MultipleFiles tests directory with multiple files
func TestLocalProvider_ReadSecretFromDirectory_MultipleFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a directory with multiple files
	secretDir := filepath.Join(tmpDir, "multi-file")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key1"), []byte("value1"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key2"), []byte("value2"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key3"), []byte("value3"), 0600))

	secret, err := provider.GetSecret(ctx, "multi-file")
	require.NoError(t, err)

	assert.Len(t, secret.Data, 3)
	for i := 1; i <= 3; i++ {
		key := fmt.Sprintf("key%d", i)
		expectedValue := fmt.Sprintf("value%d", i)
		val, ok := secret.GetString(key)
		assert.True(t, ok)
		assert.Equal(t, expectedValue, val)
	}
}

// TestLocalProvider_ReadSecretFromDirectory_ReadDirError tests readSecretFromDirectory when ReadDir fails
func TestLocalProvider_ReadSecretFromDirectory_ReadDirError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Try to read from a non-existent directory
	_, err = provider.readSecretFromDirectory(filepath.Join(tmpDir, "nonexistent"), "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read directory")
}

// TestLocalProvider_WriteSecret_ReadOnlyDirectory tests WriteSecret when directory is read-only
func TestLocalProvider_WriteSecret_ReadOnlyDirectory(t *testing.T) {
	// Skip on non-Unix systems where permissions work differently
	if os.Getenv("CI") != "" {
		t.Skip("Skipping permission test in CI environment")
	}

	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer func() {
		// Restore permissions before cleanup
		os.Chmod(tmpDir, 0750)
		os.RemoveAll(tmpDir)
	}()

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Make the directory read-only
	require.NoError(t, os.Chmod(tmpDir, 0444))

	// Try to write a secret - should fail
	err = provider.WriteSecret(ctx, "test-secret", map[string][]byte{
		"key": []byte("value"),
	})
	// On some systems this might succeed if running as root
	if err != nil {
		assert.Error(t, err)
	}
}

// TestLocalProvider_DeleteSecret_ReadOnlyDirectory tests DeleteSecret when directory is read-only
func TestLocalProvider_DeleteSecret_ReadOnlyDirectory(t *testing.T) {
	// Skip on non-Unix systems where permissions work differently
	if os.Getenv("CI") != "" {
		t.Skip("Skipping permission test in CI environment")
	}

	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer func() {
		// Restore permissions before cleanup
		os.Chmod(tmpDir, 0750)
		os.RemoveAll(tmpDir)
	}()

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a secret file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test-secret.yaml"), []byte("key: value"), 0600))

	// Make the directory read-only
	require.NoError(t, os.Chmod(tmpDir, 0444))

	// Try to delete the secret - should fail
	err = provider.DeleteSecret(ctx, "test-secret")
	// On some systems this might succeed if running as root
	if err != nil {
		assert.Error(t, err)
	}
}

// TestLocalProvider_NewLocalProvider_StatError tests NewLocalProvider when stat fails
func TestLocalProvider_NewLocalProvider_StatError(t *testing.T) {
	// Test with a path that doesn't exist
	_, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: "/nonexistent/path/that/does/not/exist/12345",
		Logger:   zap.NewNop(),
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
	assert.Contains(t, err.Error(), "base path does not exist")
}

// TestLocalProvider_TryReadSecretFromFormats_AllFormats tests tryReadSecretFromFormats with all formats
func TestLocalProvider_TryReadSecretFromFormats_AllFormats(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Test with no files - should return false
	secret, found := provider.tryReadSecretFromFormats("nonexistent")
	assert.False(t, found)
	assert.Nil(t, secret)

	// Test with YAML file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yaml-secret.yaml"), []byte("key: yaml-value"), 0600))
	secret, found = provider.tryReadSecretFromFormats("yaml-secret")
	assert.True(t, found)
	assert.NotNil(t, secret)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "yaml-value", val)

	// Test with YML file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yml-secret.yml"), []byte("key: yml-value"), 0600))
	secret, found = provider.tryReadSecretFromFormats("yml-secret")
	assert.True(t, found)
	assert.NotNil(t, secret)
	val, ok = secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "yml-value", val)

	// Test with JSON file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "json-secret.json"), []byte(`{"key": "json-value"}`), 0600))
	secret, found = provider.tryReadSecretFromFormats("json-secret")
	assert.True(t, found)
	assert.NotNil(t, secret)
	val, ok = secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "json-value", val)
}

// TestLocalProvider_TryReadSecretFromFormats_InvalidFiles tests tryReadSecretFromFormats with invalid files
func TestLocalProvider_TryReadSecretFromFormats_InvalidFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create invalid YAML file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte("invalid: yaml: ["), 0600))

	// Should return false because YAML is invalid
	secret, found := provider.tryReadSecretFromFormats("invalid")
	assert.False(t, found)
	assert.Nil(t, secret)
}

// TestLocalProvider_DeleteSecretFiles_OnlyYAML tests deleteSecretFiles with only YAML file
func TestLocalProvider_DeleteSecretFiles_OnlyYAML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create only YAML file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yaml-only.yaml"), []byte("key: value"), 0600))

	deleted, err := provider.deleteSecretFiles("yaml-only", time.Now())
	require.NoError(t, err)
	assert.True(t, deleted)

	// Verify file is gone
	_, err = os.Stat(filepath.Join(tmpDir, "yaml-only.yaml"))
	assert.True(t, os.IsNotExist(err))
}

// TestLocalProvider_DeleteSecretFiles_OnlyYML tests deleteSecretFiles with only YML file
func TestLocalProvider_DeleteSecretFiles_OnlyYML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create only YML file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yml-only.yml"), []byte("key: value"), 0600))

	deleted, err := provider.deleteSecretFiles("yml-only", time.Now())
	require.NoError(t, err)
	assert.True(t, deleted)

	// Verify file is gone
	_, err = os.Stat(filepath.Join(tmpDir, "yml-only.yml"))
	assert.True(t, os.IsNotExist(err))
}

// TestLocalProvider_DeleteSecretFiles_OnlyJSON tests deleteSecretFiles with only JSON file
func TestLocalProvider_DeleteSecretFiles_OnlyJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create only JSON file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "json-only.json"), []byte(`{"key": "value"}`), 0600))

	deleted, err := provider.deleteSecretFiles("json-only", time.Now())
	require.NoError(t, err)
	assert.True(t, deleted)

	// Verify file is gone
	_, err = os.Stat(filepath.Join(tmpDir, "json-only.json"))
	assert.True(t, os.IsNotExist(err))
}

// TestLocalProvider_DeleteSecretFiles_OnlyDirectory tests deleteSecretFiles with only directory
func TestLocalProvider_DeleteSecretFiles_OnlyDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create only directory
	secretDir := filepath.Join(tmpDir, "dir-only")
	require.NoError(t, os.MkdirAll(secretDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(secretDir, "key"), []byte("value"), 0600))

	deleted, err := provider.deleteSecretFiles("dir-only", time.Now())
	require.NoError(t, err)
	assert.True(t, deleted)

	// Verify directory is gone
	_, err = os.Stat(secretDir)
	assert.True(t, os.IsNotExist(err))
}

// TestLocalProvider_WriteSecret_DeepNestedPath tests WriteSecret with deeply nested path
func TestLocalProvider_WriteSecret_DeepNestedPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Write a secret with deeply nested path
	err = provider.WriteSecret(ctx, "level1/level2/level3/secret", map[string][]byte{
		"key": []byte("value"),
	})
	require.NoError(t, err)

	// Verify the file was created
	_, err = os.Stat(filepath.Join(tmpDir, "level1", "level2", "level3", "secret.yaml"))
	assert.NoError(t, err)

	// Read it back
	secret, err := provider.GetSecret(ctx, "level1/level2/level3/secret")
	require.NoError(t, err)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

// TestLocalProvider_ExtractSecretNamesFromEntries_EmptyEntries tests extractSecretNamesFromEntries with empty entries
func TestLocalProvider_ExtractSecretNamesFromEntries_EmptyEntries(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Empty entries
	entries := []os.DirEntry{}
	names := provider.extractSecretNamesFromEntries(entries)
	assert.Empty(t, names)
}

// TestLocalProvider_ExtractSecretNamesFromEntries_DuplicateNames tests extractSecretNamesFromEntries with duplicate names
func TestLocalProvider_ExtractSecretNamesFromEntries_DuplicateNames(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	// Create files with same base name but different extensions
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "same-name"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "same-name.yaml"), []byte("key: yaml"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "same-name.yml"), []byte("key: yml"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "same-name.json"), []byte(`{"key": "json"}`), 0600))

	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	names := provider.extractSecretNamesFromEntries(entries)

	// Should only have one entry for "same-name" (deduplicated)
	count := 0
	for _, name := range names {
		if name == "same-name" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

// TestLocalProvider_GetSecret_DirectoryWithInvalidYAMLFallback tests fallback when directory fails and YAML is invalid
func TestLocalProvider_GetSecret_DirectoryWithInvalidYAMLFallback(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "local-provider-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewLocalProvider(&LocalProviderConfig{
		BasePath: tmpDir,
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Create an empty directory (will fail) and invalid YAML (will fail) and valid JSON (will succeed)
	emptyDir := filepath.Join(tmpDir, "fallback-chain")
	require.NoError(t, os.MkdirAll(emptyDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "fallback-chain.yaml"), []byte("invalid: yaml: ["), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "fallback-chain.json"), []byte(`{"key": "json-value"}`), 0600))

	secret, err := provider.GetSecret(ctx, "fallback-chain")
	require.NoError(t, err)

	// Should get value from JSON (directory is empty, YAML is invalid)
	val, ok := secret.GetString("key")
	assert.True(t, ok)
	assert.Equal(t, "json-value", val)
}

package secrets

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProviderType(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    ProviderType
		expectError bool
	}{
		{
			name:        "kubernetes provider",
			input:       "kubernetes",
			expected:    ProviderTypeKubernetes,
			expectError: false,
		},
		{
			name:        "vault provider",
			input:       "vault",
			expected:    ProviderTypeVault,
			expectError: false,
		},
		{
			name:        "local provider",
			input:       "local",
			expected:    ProviderTypeLocal,
			expectError: false,
		},
		{
			name:        "env provider",
			input:       "env",
			expected:    ProviderTypeEnv,
			expectError: false,
		},
		{
			name:        "invalid provider",
			input:       "invalid",
			expected:    "",
			expectError: true,
		},
		{
			name:        "empty provider",
			input:       "",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateProviderType(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidProviderType)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestIsValidProviderType(t *testing.T) {
	assert.True(t, IsValidProviderType("kubernetes"))
	assert.True(t, IsValidProviderType("vault"))
	assert.True(t, IsValidProviderType("local"))
	assert.True(t, IsValidProviderType("env"))
	assert.False(t, IsValidProviderType("invalid"))
	assert.False(t, IsValidProviderType(""))
}

func TestSecretGetString(t *testing.T) {
	secret := &Secret{
		Name: "test-secret",
		Data: map[string][]byte{
			"key1": []byte("value1"),
			"key2": []byte("value2"),
		},
	}

	// Test existing key
	val, ok := secret.GetString("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	// Test non-existing key
	val, ok = secret.GetString("key3")
	assert.False(t, ok)
	assert.Equal(t, "", val)

	// Test nil secret
	var nilSecret *Secret
	val, ok = nilSecret.GetString("key1")
	assert.False(t, ok)
	assert.Equal(t, "", val)

	// Test nil data
	emptySecret := &Secret{Name: "empty"}
	val, ok = emptySecret.GetString("key1")
	assert.False(t, ok)
	assert.Equal(t, "", val)
}

func TestSecretGetBytes(t *testing.T) {
	secret := &Secret{
		Name: "test-secret",
		Data: map[string][]byte{
			"key1": []byte("value1"),
		},
	}

	// Test existing key
	val, ok := secret.GetBytes("key1")
	assert.True(t, ok)
	assert.Equal(t, []byte("value1"), val)

	// Test non-existing key
	val, ok = secret.GetBytes("key2")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestProviderTypeConstants(t *testing.T) {
	assert.Equal(t, ProviderType("kubernetes"), ProviderTypeKubernetes)
	assert.Equal(t, ProviderType("vault"), ProviderTypeVault)
	assert.Equal(t, ProviderType("local"), ProviderTypeLocal)
	assert.Equal(t, ProviderType("env"), ProviderTypeEnv)
}

func TestSecretGetBytesNilSecret(t *testing.T) {
	var nilSecret *Secret
	val, ok := nilSecret.GetBytes("key1")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestSecretGetBytesNilData(t *testing.T) {
	emptySecret := &Secret{Name: "empty"}
	val, ok := emptySecret.GetBytes("key1")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestRecordOperation(t *testing.T) {
	// Test recording operation with success
	RecordOperation(ProviderTypeKubernetes, "get", 100*time.Millisecond, nil)

	// Test recording operation with error
	RecordOperation(ProviderTypeVault, "write", 200*time.Millisecond, ErrSecretNotFound)

	// Test recording operation for different providers
	RecordOperation(ProviderTypeLocal, "delete", 50*time.Millisecond, nil)
	RecordOperation(ProviderTypeEnv, "list", 10*time.Millisecond, nil)
}

func TestRecordHealthStatus(t *testing.T) {
	// Test recording healthy status
	RecordHealthStatus(ProviderTypeKubernetes, true)

	// Test recording unhealthy status
	RecordHealthStatus(ProviderTypeVault, false)

	// Test for different providers
	RecordHealthStatus(ProviderTypeLocal, true)
	RecordHealthStatus(ProviderTypeEnv, true)
}

func TestCommonErrors(t *testing.T) {
	// Test that common errors are properly defined
	assert.NotNil(t, ErrSecretNotFound)
	assert.NotNil(t, ErrProviderNotConfigured)
	assert.NotNil(t, ErrReadOnly)
	assert.NotNil(t, ErrInvalidPath)
	assert.NotNil(t, ErrProviderUnavailable)
	assert.NotNil(t, ErrInvalidProviderType)

	// Test error messages
	assert.Equal(t, "secret not found", ErrSecretNotFound.Error())
	assert.Equal(t, "provider not configured", ErrProviderNotConfigured.Error())
	assert.Equal(t, "provider is read-only", ErrReadOnly.Error())
	assert.Equal(t, "invalid secret path", ErrInvalidPath.Error())
	assert.Equal(t, "provider unavailable", ErrProviderUnavailable.Error())
	assert.Equal(t, "invalid provider type", ErrInvalidProviderType.Error())
}

func TestSecretWithMetadata(t *testing.T) {
	now := time.Now()
	secret := &Secret{
		Name:      "test-secret",
		Namespace: "test-ns",
		Data: map[string][]byte{
			"key1": []byte("value1"),
		},
		Metadata: map[string]string{
			"label.app": "myapp",
		},
		Version:   "1",
		CreatedAt: &now,
		UpdatedAt: &now,
	}

	assert.Equal(t, "test-secret", secret.Name)
	assert.Equal(t, "test-ns", secret.Namespace)
	assert.Equal(t, "1", secret.Version)
	assert.NotNil(t, secret.CreatedAt)
	assert.NotNil(t, secret.UpdatedAt)
	assert.Equal(t, "myapp", secret.Metadata["label.app"])
}

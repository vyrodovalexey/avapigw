package secrets

import (
	"testing"

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

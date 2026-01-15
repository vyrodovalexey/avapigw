package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func setupKubernetesProvider(t *testing.T, objects ...runtime.Object) *KubernetesProvider {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objects...).
		Build()

	provider, err := NewKubernetesProvider(&KubernetesProviderConfig{
		Client:           client,
		DefaultNamespace: "default",
		Logger:           zap.NewNop(),
	})
	require.NoError(t, err)
	return provider
}

func TestNewKubernetesProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Test with valid config
	provider, err := NewKubernetesProvider(&KubernetesProviderConfig{
		Client:           client,
		DefaultNamespace: "test-ns",
	})
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "test-ns", provider.defaultNamespace)

	// Test with nil config
	_, err = NewKubernetesProvider(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)

	// Test with nil client
	_, err = NewKubernetesProvider(&KubernetesProviderConfig{
		Client: nil,
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)

	// Test with empty default namespace (should use "default")
	provider, err = NewKubernetesProvider(&KubernetesProviderConfig{
		Client: client,
	})
	require.NoError(t, err)
	assert.Equal(t, "default", provider.defaultNamespace)
}

func TestKubernetesProviderType(t *testing.T) {
	provider := setupKubernetesProvider(t)
	assert.Equal(t, ProviderTypeKubernetes, provider.Type())
}

func TestKubernetesProviderGetSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
			Annotations: map[string]string{
				"description": "test secret",
			},
		},
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("secret123"),
		},
	}

	provider := setupKubernetesProvider(t, secret)
	ctx := context.Background()

	// Test getting secret with just name (uses default namespace)
	result, err := provider.GetSecret(ctx, "test-secret")
	require.NoError(t, err)
	assert.Equal(t, "test-secret", result.Name)
	assert.Equal(t, "default", result.Namespace)

	username, ok := result.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)

	password, ok := result.GetString("password")
	assert.True(t, ok)
	assert.Equal(t, "secret123", password)

	// Check metadata
	assert.Equal(t, "test", result.Metadata["label.app"])
	assert.Equal(t, "test secret", result.Metadata["annotation.description"])

	// Test getting secret with namespace/name format
	result, err = provider.GetSecret(ctx, "default/test-secret")
	require.NoError(t, err)
	assert.Equal(t, "test-secret", result.Name)
	assert.Equal(t, "default", result.Namespace)
}

func TestKubernetesProviderGetSecretNotFound(t *testing.T) {
	provider := setupKubernetesProvider(t)
	ctx := context.Background()

	_, err := provider.GetSecret(ctx, "nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestKubernetesProviderGetSecretInvalidPath(t *testing.T) {
	provider := setupKubernetesProvider(t)
	ctx := context.Background()

	// Empty path
	_, err := provider.GetSecret(ctx, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)

	// Invalid format
	_, err = provider.GetSecret(ctx, "/invalid")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

func TestKubernetesProviderListSecrets(t *testing.T) {
	secret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret1",
			Namespace: "default",
		},
		Data: map[string][]byte{"key": []byte("value")},
	}
	secret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret2",
			Namespace: "default",
		},
		Data: map[string][]byte{"key": []byte("value")},
	}
	secret3 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret3",
			Namespace: "other-ns",
		},
		Data: map[string][]byte{"key": []byte("value")},
	}

	provider := setupKubernetesProvider(t, secret1, secret2, secret3)
	ctx := context.Background()

	// List secrets in default namespace
	secrets, err := provider.ListSecrets(ctx, "default")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
	assert.Contains(t, secrets, "secret1")
	assert.Contains(t, secrets, "secret2")

	// List secrets in other namespace
	secrets, err = provider.ListSecrets(ctx, "other-ns")
	require.NoError(t, err)
	assert.Len(t, secrets, 1)
	assert.Contains(t, secrets, "secret3")

	// List secrets with empty path (uses default namespace)
	secrets, err = provider.ListSecrets(ctx, "")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
}

func TestKubernetesProviderWriteSecret(t *testing.T) {
	provider := setupKubernetesProvider(t)
	ctx := context.Background()

	// Write a new secret
	err := provider.WriteSecret(ctx, "new-secret", map[string][]byte{
		"username": []byte("admin"),
		"password": []byte("secret123"),
	})
	require.NoError(t, err)

	// Read it back
	secret, err := provider.GetSecret(ctx, "new-secret")
	require.NoError(t, err)
	username, ok := secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "admin", username)

	// Update the secret
	err = provider.WriteSecret(ctx, "new-secret", map[string][]byte{
		"username": []byte("newadmin"),
		"password": []byte("newsecret"),
	})
	require.NoError(t, err)

	// Read it back again
	secret, err = provider.GetSecret(ctx, "new-secret")
	require.NoError(t, err)
	username, ok = secret.GetString("username")
	assert.True(t, ok)
	assert.Equal(t, "newadmin", username)
}

func TestKubernetesProviderDeleteSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "to-delete",
			Namespace: "default",
		},
		Data: map[string][]byte{"key": []byte("value")},
	}

	provider := setupKubernetesProvider(t, secret)
	ctx := context.Background()

	// Verify secret exists
	_, err := provider.GetSecret(ctx, "to-delete")
	require.NoError(t, err)

	// Delete the secret
	err = provider.DeleteSecret(ctx, "to-delete")
	require.NoError(t, err)

	// Verify it's gone
	_, err = provider.GetSecret(ctx, "to-delete")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretNotFound)

	// Delete non-existent should not error
	err = provider.DeleteSecret(ctx, "nonexistent")
	assert.NoError(t, err)
}

func TestKubernetesProviderIsReadOnly(t *testing.T) {
	provider := setupKubernetesProvider(t)
	assert.False(t, provider.IsReadOnly())
}

func TestKubernetesProviderHealthCheck(t *testing.T) {
	provider := setupKubernetesProvider(t)
	ctx := context.Background()

	err := provider.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestKubernetesProviderClose(t *testing.T) {
	provider := setupKubernetesProvider(t)
	err := provider.Close()
	assert.NoError(t, err)
}

func TestKubernetesProviderParsePath(t *testing.T) {
	provider := setupKubernetesProvider(t)

	tests := []struct {
		name          string
		path          string
		wantNamespace string
		wantName      string
		wantErr       bool
	}{
		{
			name:          "simple name",
			path:          "my-secret",
			wantNamespace: "default",
			wantName:      "my-secret",
			wantErr:       false,
		},
		{
			name:          "namespace/name",
			path:          "my-ns/my-secret",
			wantNamespace: "my-ns",
			wantName:      "my-secret",
			wantErr:       false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "empty namespace",
			path:    "/my-secret",
			wantErr: true,
		},
		{
			name:    "empty name",
			path:    "my-ns/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, name, err := provider.parsePath(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantNamespace, ns)
				assert.Equal(t, tt.wantName, name)
			}
		})
	}
}

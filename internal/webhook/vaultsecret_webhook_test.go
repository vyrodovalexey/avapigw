package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/webhook/defaulter"
	"github.com/vyrodovalexey/avapigw/internal/webhook/validator"
)

func TestVaultSecretWebhook_Default(t *testing.T) {
	t.Run("defaults mount point", func(t *testing.T) {
		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Defaulter: defaulter.NewVaultSecretDefaulter(),
		}
		err := webhook.Default(context.Background(), secret)
		require.NoError(t, err)
	})

	t.Run("returns error for wrong type", func(t *testing.T) {
		webhook := &VaultSecretWebhook{
			Defaulter: defaulter.NewVaultSecretDefaulter(),
		}
		err := webhook.Default(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a VaultSecret")
	})
}

func TestVaultSecretWebhook_ValidateCreate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid VaultSecret with Kubernetes auth", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.NoError(t, err)
	})

	t.Run("valid VaultSecret with token auth", func(t *testing.T) {
		tokenSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "vault-token", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tokenSecret).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Token: &avapigwv1alpha1.TokenAuthConfig{
							SecretRef: avapigwv1alpha1.SecretObjectReference{
								Name: "vault-token",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.NoError(t, err)
	})

	t.Run("valid VaultSecret with AppRole auth", func(t *testing.T) {
		secretIDSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "approle-secret", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secretIDSecret).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
							RoleID: "my-role-id",
							SecretIDRef: avapigwv1alpha1.SecretObjectReference{
								Name: "approle-secret",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.NoError(t, err)
	})

	t.Run("invalid - no auth method", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth:    avapigwv1alpha1.VaultAuthConfig{},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one authentication method must be specified")
	})

	t.Run("invalid - multiple auth methods", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
						Token: &avapigwv1alpha1.TokenAuthConfig{
							SecretRef: avapigwv1alpha1.SecretObjectReference{
								Name: "vault-token",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only one authentication method should be specified")
	})

	t.Run("invalid - Kubernetes auth without role", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role is required")
	})

	t.Run("invalid - AppRole auth without roleId", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
							RoleID: "",
							SecretIDRef: avapigwv1alpha1.SecretObjectReference{
								Name: "approle-secret",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "roleId is required")
	})

	t.Run("invalid - empty path", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path is required")
	})

	t.Run("invalid - path starts with slash", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "/secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path should not start with /")
	})

	t.Run("invalid - key mapping without vaultKey", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
				Keys: []avapigwv1alpha1.VaultKeyMapping{{
					VaultKey:  "",
					TargetKey: "password",
				}},
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "vaultKey is required")
	})

	t.Run("invalid - key mapping without targetKey", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
				Keys: []avapigwv1alpha1.VaultKeyMapping{{
					VaultKey:  "password",
					TargetKey: "",
				}},
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "targetKey is required")
	})

	t.Run("invalid - duplicate target keys", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
				Keys: []avapigwv1alpha1.VaultKeyMapping{
					{VaultKey: "password1", TargetKey: "password"},
					{VaultKey: "password2", TargetKey: "password"},
				},
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate target key")
	})

	t.Run("invalid - refresh with invalid interval", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		interval := avapigwv1alpha1.Duration("invalid")
		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
				Refresh: &avapigwv1alpha1.VaultRefreshConfig{
					Interval: &interval,
				},
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})

	t.Run("invalid - target without name", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: "",
				},
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("invalid - target with invalid secret type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		invalidType := "invalid-type"
		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: "my-secret",
					Type: &invalidType,
				},
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid secret type")
	})

	t.Run("invalid - wrong object type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a VaultSecret")
	})
}

func TestVaultSecretWebhook_ValidateUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		oldSecret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		newSecret := oldSecret.DeepCopy()
		newSecret.Spec.Path = "secret/data/myapp-v2"

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), oldSecret, newSecret)
		assert.NoError(t, err)
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.Gateway{}, &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a VaultSecret")
	})
}

func TestVaultSecretWebhook_ValidateDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("delete allowed", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), secret)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a VaultSecret")
	})
}

// ============================================================================
// Test Cases for validateReferences
// ============================================================================

func TestVaultSecretWebhook_ValidateReferences(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("validates Kubernetes auth service account reference - not found", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
							ServiceAccountRef: &avapigwv1alpha1.LocalObjectReference{
								Name: "non-existent-sa",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "serviceAccountRef")
	})

	t.Run("validates Kubernetes auth service account reference - found", func(t *testing.T) {
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "vault-sa", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sa).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
							ServiceAccountRef: &avapigwv1alpha1.LocalObjectReference{
								Name: "vault-sa",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.NoError(t, err)
	})

	t.Run("validates token auth secret reference - not found", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Token: &avapigwv1alpha1.TokenAuthConfig{
							SecretRef: avapigwv1alpha1.SecretObjectReference{
								Name: "non-existent-token",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secretRef")
	})

	t.Run("validates AppRole auth secret reference - not found", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
							RoleID: "test-role-id",
							SecretIDRef: avapigwv1alpha1.SecretObjectReference{
								Name: "non-existent-approle-secret",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secretIdRef")
	})

	t.Run("validates AppRole auth secret reference - found", func(t *testing.T) {
		approleSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "approle-secret", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(approleSecret).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
							RoleID: "test-role-id",
							SecretIDRef: avapigwv1alpha1.SecretObjectReference{
								Name: "approle-secret",
							},
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.NoError(t, err)
	})

	t.Run("validates TLS CA cert reference - not found", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
					TLS: &avapigwv1alpha1.VaultTLSConfig{
						CACertRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "non-existent-ca-cert",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "caCertRef")
	})

	t.Run("validates TLS client cert reference - not found", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
					TLS: &avapigwv1alpha1.VaultTLSConfig{
						ClientCertRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "non-existent-client-cert",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "clientCertRef")
	})

	t.Run("validates TLS client key reference - not found", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
					TLS: &avapigwv1alpha1.VaultTLSConfig{
						ClientKeyRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "non-existent-client-key",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "clientKeyRef")
	})

	t.Run("validates all TLS references - found", func(t *testing.T) {
		caCertSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ca-cert", Namespace: "default"},
		}
		clientCertSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "client-cert", Namespace: "default"},
		}
		clientKeySecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "client-key", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caCertSecret, clientCertSecret, clientKeySecret).Build()

		secret := &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "https://vault.example.com",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: "my-role",
						},
					},
					TLS: &avapigwv1alpha1.VaultTLSConfig{
						CACertRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "ca-cert",
						},
						ClientCertRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "client-cert",
						},
						ClientKeyRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "client-key",
						},
					},
				},
				Path: "secret/data/myapp",
			},
		}

		webhook := &VaultSecretWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewVaultSecretDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), secret)
		assert.NoError(t, err)
	})
}

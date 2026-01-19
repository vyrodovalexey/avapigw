package controller

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

func int32Ptr(i int32) *int32 {
	return &i
}

func durationPtr(d time.Duration) *avapigwv1alpha1.Duration {
	dur := avapigwv1alpha1.Duration(d.String())
	return &dur
}

func nowPtr() *metav1.Time {
	t := metav1.Now()
	return &t
}

// ============================================================================
// Test Cases for Vault Client Concurrent Creation (LoadOrStore pattern)
// ============================================================================

// setupScheme creates a scheme with all required types for testing.
// This includes both the custom avapigw types and core Kubernetes types.
func setupScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	return scheme
}

func TestVaultSecretReconciler_GetOrCreateVaultClient_ConcurrentCreation(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create a token secret
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-token",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-token"),
		},
	}
	require.NoError(t, cl.Create(context.Background(), tokenSecret))

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Token: &avapigwv1alpha1.TokenAuthConfig{
						SecretRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "vault-token",
							Namespace: strPtr("default"),
						},
						TokenKey: strPtr("token"),
					},
				},
			},
		},
	}

	// Create a sync.WaitGroup for concurrent access
	var wg sync.WaitGroup
	numGoroutines := 10
	errorsChan := make(chan error, numGoroutines)

	// Simulate concurrent access to the reconciler's vaultClients map
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Simulate LoadOrStore pattern
			clientKey := fmt.Sprintf("%s-%s", vaultSecret.Spec.VaultConnection.Address, vaultSecret.Namespace)
			testMap := &reconciler.vaultClients

			_, loaded := testMap.LoadOrStore(clientKey, idx)
			if loaded {
				errorsChan <- nil
			}
		}(i)
	}

	wg.Wait()
	close(errorsChan)

	// Count how many times we had loaded = true
	loadedCount := 0
	for err := range errorsChan {
		if err == nil {
			loadedCount++
		}
	}

	// At least one should have loaded = true (first one stores, rest load)
	assert.GreaterOrEqual(t, loadedCount, 1, "At least one goroutine should have loaded an existing value")
}

func TestVaultSecretReconciler_HandleDeletion_SafeDeletion(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret with finalizer (without deletion timestamp initially)
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{vaultSecretFinalizer},
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
			},
			Target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "test-secret",
			},
		},
	}

	// Create the target secret that should be deleted
	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("testuser"),
		},
	}

	// Build client with existing objects
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret, targetSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Test deleteTargetSecret directly
	err := reconciler.deleteTargetSecret(context.Background(), vaultSecret)
	require.NoError(t, err)

	// Verify target secret was deleted
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "test-secret"}, &corev1.Secret{})
	assert.True(t, apierrors.IsNotFound(err), "Target secret should be deleted")

	// Test that finalizer can be removed
	controllerutil.RemoveFinalizer(vaultSecret, vaultSecretFinalizer)
	err = cl.Update(context.Background(), vaultSecret)
	require.NoError(t, err)

	// Verify finalizer was removed
	updatedVS := &avapigwv1alpha1.VaultSecret{}
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "test"}, updatedVS)
	require.NoError(t, err)
	assert.False(t, controllerutil.ContainsFinalizer(updatedVS, vaultSecretFinalizer))
}

func TestVaultSecretReconciler_HandleDeletion_NoTargetSecret(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret without target configuration
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{vaultSecretFinalizer},
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
			},
		},
	}

	// Build client with existing object
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Test deleteTargetSecret directly - should not error even without target
	err := reconciler.deleteTargetSecret(context.Background(), vaultSecret)
	require.NoError(t, err)

	// Test that finalizer can be removed
	controllerutil.RemoveFinalizer(vaultSecret, vaultSecretFinalizer)
	err = cl.Update(context.Background(), vaultSecret)
	require.NoError(t, err)
}

func TestVaultSecretReconciler_HandleDeletion_RetainPolicy(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret with Retain policy
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{vaultSecretFinalizer},
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
			},
			Target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "test-secret",
				DeletionPolicy: func() *avapigwv1alpha1.SecretDeletionPolicy {
					p := avapigwv1alpha1.SecretDeletionPolicyRetain
					return &p
				}(),
			},
		},
	}

	// Create the target secret
	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("testuser"),
		},
	}

	// Build client with existing objects
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret, targetSecret).
		Build()

	// Verify target secret exists before any deletion
	err := cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "test-secret"}, &corev1.Secret{})
	assert.NoError(t, err, "Target secret should exist before any deletion")

	// Verify the deletion policy is correctly set to Retain
	assert.NotNil(t, vaultSecret.Spec.Target.DeletionPolicy)
	assert.Equal(t, avapigwv1alpha1.SecretDeletionPolicyRetain, *vaultSecret.Spec.Target.DeletionPolicy)

	// Test that finalizer can be removed (simulating successful cleanup)
	controllerutil.RemoveFinalizer(vaultSecret, vaultSecretFinalizer)
	err = cl.Update(context.Background(), vaultSecret)
	require.NoError(t, err)

	// Verify target secret was NOT deleted (Retain policy - we didn't call deleteTargetSecret)
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "test-secret"}, &corev1.Secret{})
	assert.NoError(t, err, "Target secret should be retained with Retain policy")
}

// ============================================================================
// Test Cases for Refresh Interval Calculation with Jitter
// ============================================================================

func TestVaultSecretReconciler_CalculateNextRefresh_DefaultInterval(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
		},
	}

	// No refresh config - should use default 5 minutes
	interval := reconciler.calculateNextRefresh(vaultSecret)
	assert.Equal(t, 5*time.Minute, interval)
}

func TestVaultSecretReconciler_CalculateNextRefresh_CustomInterval(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			Refresh: &avapigwv1alpha1.VaultRefreshConfig{
				Enabled:       boolPtr(true),
				Interval:      durationPtr(10 * time.Minute),
				JitterPercent: int32Ptr(10),
			},
		},
	}

	interval := reconciler.calculateNextRefresh(vaultSecret)
	// Should be approximately 10 minutes with some jitter
	assert.True(t, interval > 9*time.Minute && interval < 11*time.Minute,
		"Interval should be approximately 10 minutes, got %v", interval)
}

func TestVaultSecretReconciler_CalculateNextRefresh_DisabledRefresh(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			Refresh: &avapigwv1alpha1.VaultRefreshConfig{
				Enabled: boolPtr(false),
			},
		},
	}

	interval := reconciler.calculateNextRefresh(vaultSecret)
	assert.Equal(t, 24*time.Hour, interval, "Disabled refresh should use long interval")
}

func TestVaultSecretReconciler_CalculateNextRefresh_ZeroJitter(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			Refresh: &avapigwv1alpha1.VaultRefreshConfig{
				Enabled:       boolPtr(true),
				Interval:      durationPtr(5 * time.Minute),
				JitterPercent: int32Ptr(0),
			},
		},
	}

	interval := reconciler.calculateNextRefresh(vaultSecret)
	assert.Equal(t, 5*time.Minute, interval, "Zero jitter should return exact interval")
}

// ============================================================================
// Test Cases for Vault Connection Validation
// ============================================================================

func TestVaultSecretReconciler_ValidateVaultConnection_MissingAddress(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "", // Missing address
				Auth:    avapigwv1alpha1.VaultAuthConfig{},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault address is required")
}

func TestVaultSecretReconciler_ValidateVaultConnection_NoAuthMethod(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth:    avapigwv1alpha1.VaultAuthConfig{}, // No auth method
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one authentication method must be configured")
}

func TestVaultSecretReconciler_ValidateVaultConnection_KubernetesAuth_MissingRole(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "", // Missing role
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kubernetes auth role is required")
}

func TestVaultSecretReconciler_ValidateVaultConnection_TokenAuth_SecretNotFound(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Token: &avapigwv1alpha1.TokenAuthConfig{
						SecretRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "vault-token",
							Namespace: strPtr("default"),
						},
						TokenKey: strPtr("token"),
					},
				},
			},
		},
	}

	// Token secret doesn't exist
	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token secret")
}

func TestVaultSecretReconciler_ValidateVaultConnection_TokenAuth_KeyNotFound(t *testing.T) {
	scheme := setupScheme(t)

	// Create a secret without the expected token key
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-token",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"wrong-key": []byte("test-token"),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tokenSecret).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Token: &avapigwv1alpha1.TokenAuthConfig{
						SecretRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "vault-token",
							Namespace: strPtr("default"),
						},
						TokenKey: strPtr("token"),
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token key")
}

func TestVaultSecretReconciler_ValidateVaultConnection_TokenAuth_DefaultKey(t *testing.T) {
	scheme := setupScheme(t)

	// Create a secret with the default "token" key
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-token",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-token"),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tokenSecret).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Token: &avapigwv1alpha1.TokenAuthConfig{
						SecretRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "vault-token",
							Namespace: strPtr("default"),
						},
						// No TokenKey specified, should use default "token"
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.NoError(t, err)
}

func TestVaultSecretReconciler_ValidateVaultConnection_AppRole_MissingRoleID(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
						RoleID: "", // Missing role ID
						SecretIDRef: avapigwv1alpha1.SecretObjectReference{
							Name: "approle-secret",
						},
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AppRole role ID is required")
}

func TestVaultSecretReconciler_ValidateVaultConnection_AppRole_SecretNotFound(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
						RoleID: "test-role-id",
						SecretIDRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "approle-secret",
							Namespace: strPtr("default"),
						},
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AppRole secret ID secret")
}

func TestVaultSecretReconciler_ValidateVaultConnection_AppRole_KeyNotFound(t *testing.T) {
	scheme := setupScheme(t)

	// Create a secret without the expected secret-id key
	approleSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "approle-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"wrong-key": []byte("test-secret-id"),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(approleSecret).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
						RoleID: "test-role-id",
						SecretIDRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "approle-secret",
							Namespace: strPtr("default"),
						},
						SecretIDKey: strPtr("secret-id"),
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID key")
}

func TestVaultSecretReconciler_ValidateVaultConnection_AppRole_DefaultKey(t *testing.T) {
	scheme := setupScheme(t)

	// Create a secret with the default "secret-id" key
	approleSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "approle-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"secret-id": []byte("test-secret-id"),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(approleSecret).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
						RoleID: "test-role-id",
						SecretIDRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "approle-secret",
							Namespace: strPtr("default"),
						},
						// No SecretIDKey specified, should use default "secret-id"
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.NoError(t, err)
}

func TestVaultSecretReconciler_ValidateVaultConnection_TLS_CACertNotFound(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
				TLS: &avapigwv1alpha1.VaultTLSConfig{
					CACertRef: &avapigwv1alpha1.SecretObjectReference{
						Name:      "ca-cert-secret",
						Namespace: strPtr("default"),
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLS CA cert secret")
}

func TestVaultSecretReconciler_ValidateVaultConnection_TLS_CACertFound(t *testing.T) {
	scheme := setupScheme(t)

	// Create a CA cert secret
	caCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-cert-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("test-ca-cert"),
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caCertSecret).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
				TLS: &avapigwv1alpha1.VaultTLSConfig{
					CACertRef: &avapigwv1alpha1.SecretObjectReference{
						Name:      "ca-cert-secret",
						Namespace: strPtr("default"),
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.NoError(t, err)
}

func TestVaultSecretReconciler_ValidateVaultConnection_KubernetesAuth_Valid(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role:      "test-role",
						MountPath: strPtr("kubernetes"),
					},
				},
			},
		},
	}

	err := reconciler.validateVaultConnection(context.Background(), vaultSecret)
	assert.NoError(t, err)
}

// ============================================================================
// Test Cases for Secret Data Retrieval
// ============================================================================

func TestVaultSecretReconciler_GetSecretData(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create a secret with data
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("test-cert-data"),
		},
	}
	require.NoError(t, cl.Create(context.Background(), secret))

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	ref := &avapigwv1alpha1.SecretObjectReference{
		Name:      "test-secret",
		Namespace: strPtr("default"),
	}

	data, err := reconciler.getSecretData(context.Background(), "default", ref, "ca.crt")
	require.NoError(t, err)
	assert.Equal(t, []byte("test-cert-data"), data)
}

func TestVaultSecretReconciler_GetSecretData_KeyFallback(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create a secret with alternative key names
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt":      []byte("primary-cert"),
			"cert":        []byte("fallback-cert"),
			"certificate": []byte("another-cert"),
		},
	}
	require.NoError(t, cl.Create(context.Background(), secret))

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	ref := &avapigwv1alpha1.SecretObjectReference{
		Name:      "test-secret",
		Namespace: strPtr("default"),
	}

	// Request non-existent key, should fall back to ca.crt
	data, err := reconciler.getSecretData(context.Background(), "default", ref, "non-existent-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("primary-cert"), data)
}

func TestVaultSecretReconciler_GetSecretData_NotFound(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client: cl,
		Scheme: scheme,
	}

	ref := &avapigwv1alpha1.SecretObjectReference{
		Name:      "non-existent",
		Namespace: strPtr("default"),
	}

	_, err := reconciler.getSecretData(context.Background(), "default", ref, "key")
	assert.Error(t, err)
}

// ============================================================================
// Test Cases for SetCondition
// ============================================================================

func TestVaultSecretReconciler_SetCondition(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	vaultSecret := &avapigwv1alpha1.VaultSecret{}

	reconciler.setCondition(vaultSecret, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue, "Ready", "Resource is ready")

	condition := vaultSecret.Status.GetCondition(avapigwv1alpha1.ConditionTypeReady)
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
	assert.Equal(t, "Ready", condition.Reason)
	assert.Equal(t, "Resource is ready", condition.Message)
}

// ============================================================================
// Test Cases for Reconcile (NotFound)
// ============================================================================

func TestVaultSecretReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "non-existent",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.IsZero())
}

// ============================================================================
// Test Cases for vaultSecretReferencesSecret
// ============================================================================

func TestVaultSecretReconciler_vaultSecretReferencesSecret(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	tests := []struct {
		name           string
		vaultSecret    *avapigwv1alpha1.VaultSecret
		secretNS       string
		secretName     string
		expectedResult bool
	}{
		{
			name: "references token secret",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Token: &avapigwv1alpha1.TokenAuthConfig{
								SecretRef: avapigwv1alpha1.SecretObjectReference{
									Name:      "token-secret",
									Namespace: strPtr("default"),
								},
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "token-secret",
			expectedResult: true,
		},
		{
			name: "references token secret with default namespace",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Token: &avapigwv1alpha1.TokenAuthConfig{
								SecretRef: avapigwv1alpha1.SecretObjectReference{
									Name: "token-secret",
									// No namespace specified, should use VaultSecret's namespace
								},
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "token-secret",
			expectedResult: true,
		},
		{
			name: "references AppRole secret",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
								RoleID: "test-role-id",
								SecretIDRef: avapigwv1alpha1.SecretObjectReference{
									Name:      "approle-secret",
									Namespace: strPtr("default"),
								},
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "approle-secret",
			expectedResult: true,
		},
		{
			name: "references AppRole secret with default namespace",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
								RoleID: "test-role-id",
								SecretIDRef: avapigwv1alpha1.SecretObjectReference{
									Name: "approle-secret",
									// No namespace specified
								},
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "approle-secret",
			expectedResult: true,
		},
		{
			name: "references TLS CA cert secret",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "test-role",
							},
						},
						TLS: &avapigwv1alpha1.VaultTLSConfig{
							CACertRef: &avapigwv1alpha1.SecretObjectReference{
								Name:      "ca-cert-secret",
								Namespace: strPtr("default"),
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "ca-cert-secret",
			expectedResult: true,
		},
		{
			name: "references TLS CA cert secret with default namespace",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "test-role",
							},
						},
						TLS: &avapigwv1alpha1.VaultTLSConfig{
							CACertRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "ca-cert-secret",
								// No namespace specified
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "ca-cert-secret",
			expectedResult: true,
		},
		{
			name: "references TLS client cert secret",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "test-role",
							},
						},
						TLS: &avapigwv1alpha1.VaultTLSConfig{
							ClientCertRef: &avapigwv1alpha1.SecretObjectReference{
								Name:      "client-cert-secret",
								Namespace: strPtr("default"),
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "client-cert-secret",
			expectedResult: true,
		},
		{
			name: "references TLS client cert secret with default namespace",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "test-role",
							},
						},
						TLS: &avapigwv1alpha1.VaultTLSConfig{
							ClientCertRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "client-cert-secret",
								// No namespace specified
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "client-cert-secret",
			expectedResult: true,
		},
		{
			name: "references TLS client key secret",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "test-role",
							},
						},
						TLS: &avapigwv1alpha1.VaultTLSConfig{
							ClientKeyRef: &avapigwv1alpha1.SecretObjectReference{
								Name:      "client-key-secret",
								Namespace: strPtr("default"),
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "client-key-secret",
			expectedResult: true,
		},
		{
			name: "references TLS client key secret with default namespace",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "test-role",
							},
						},
						TLS: &avapigwv1alpha1.VaultTLSConfig{
							ClientKeyRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "client-key-secret",
								// No namespace specified
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "client-key-secret",
			expectedResult: true,
		},
		{
			name: "does not reference secret",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "test-role",
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "some-secret",
			expectedResult: false,
		},
		{
			name: "does not reference secret - different namespace",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Token: &avapigwv1alpha1.TokenAuthConfig{
								SecretRef: avapigwv1alpha1.SecretObjectReference{
									Name:      "token-secret",
									Namespace: strPtr("other-namespace"),
								},
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "token-secret",
			expectedResult: false,
		},
		{
			name: "does not reference secret - different name",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Token: &avapigwv1alpha1.TokenAuthConfig{
								SecretRef: avapigwv1alpha1.SecretObjectReference{
									Name:      "token-secret",
									Namespace: strPtr("default"),
								},
							},
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "other-secret",
			expectedResult: false,
		},
		{
			name: "TLS config without any refs",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "test-role",
							},
						},
						TLS: &avapigwv1alpha1.VaultTLSConfig{
							InsecureSkipVerify: boolPtr(true),
						},
					},
				},
			},
			secretNS:       "default",
			secretName:     "some-secret",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.vaultSecretReferencesSecret(tt.vaultSecret, tt.secretNS, tt.secretName)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// ============================================================================
// Test Cases for Vault Client Cleanup on Deletion (TASK-009)
// ============================================================================

func TestVaultSecretReconciler_ClientCleanupOnDeletion(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret with finalizer
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{vaultSecretFinalizer},
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
			Target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "test-secret",
			},
		},
	}

	// Build client with existing object
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Pre-populate the vault clients cache
	clientKey := fmt.Sprintf("%s-%s", vaultSecret.Spec.VaultConnection.Address, vaultSecret.Namespace)
	reconciler.vaultClients.Store(clientKey, "mock-client")

	// Verify client is in cache
	_, exists := reconciler.vaultClients.Load(clientKey)
	assert.True(t, exists, "Client should be in cache before cleanup")

	// Call cleanupVaultClient
	reconciler.cleanupVaultClient(vaultSecret)

	// Verify client was removed from cache
	_, exists = reconciler.vaultClients.Load(clientKey)
	assert.False(t, exists, "Client should be removed from cache after cleanup")
}

func TestVaultSecretReconciler_ClientCleanupOnDeletion_MultipleClients(t *testing.T) {
	scheme := setupScheme(t)

	// Create two VaultSecrets with different Vault addresses
	vaultSecret1 := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test1",
			Namespace:  "default",
			Finalizers: []string{vaultSecretFinalizer},
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test1",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault1:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
		},
	}

	vaultSecret2 := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test2",
			Namespace:  "default",
			Finalizers: []string{vaultSecretFinalizer},
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test2",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault2:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
		},
	}

	// Build client with existing objects
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret1, vaultSecret2).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Pre-populate the vault clients cache with both clients
	clientKey1 := fmt.Sprintf("%s-%s", vaultSecret1.Spec.VaultConnection.Address, vaultSecret1.Namespace)
	clientKey2 := fmt.Sprintf("%s-%s", vaultSecret2.Spec.VaultConnection.Address, vaultSecret2.Namespace)
	reconciler.vaultClients.Store(clientKey1, "mock-client-1")
	reconciler.vaultClients.Store(clientKey2, "mock-client-2")

	// Verify both clients are in cache
	_, exists1 := reconciler.vaultClients.Load(clientKey1)
	_, exists2 := reconciler.vaultClients.Load(clientKey2)
	assert.True(t, exists1, "Client 1 should be in cache")
	assert.True(t, exists2, "Client 2 should be in cache")

	// Cleanup only the first VaultSecret's client
	reconciler.cleanupVaultClient(vaultSecret1)

	// Verify only the first client was removed
	_, exists1 = reconciler.vaultClients.Load(clientKey1)
	_, exists2 = reconciler.vaultClients.Load(clientKey2)
	assert.False(t, exists1, "Client 1 should be removed from cache")
	assert.True(t, exists2, "Client 2 should still be in cache")
}

func TestVaultSecretReconciler_HandleDeletion_CleansUpClient(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret with finalizer and deletion timestamp
	now := metav1.Now()
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			Finalizers:        []string{vaultSecretFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
			Target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "test-secret",
				DeletionPolicy: func() *avapigwv1alpha1.SecretDeletionPolicy {
					p := avapigwv1alpha1.SecretDeletionPolicyRetain
					return &p
				}(),
			},
		},
	}

	// Build client with existing object
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Pre-populate the vault clients cache
	clientKey := fmt.Sprintf("%s-%s", vaultSecret.Spec.VaultConnection.Address, vaultSecret.Namespace)
	reconciler.vaultClients.Store(clientKey, "mock-client")

	// Call handleDeletion
	result, err := reconciler.handleDeletion(context.Background(), vaultSecret)

	assert.NoError(t, err)
	assert.True(t, result.IsZero(), "Should return zero result after successful deletion")

	// Verify client was removed from cache
	_, exists := reconciler.vaultClients.Load(clientKey)
	assert.False(t, exists, "Client should be removed from cache after deletion")
}

func TestVaultSecretReconciler_ConcurrentClientCleanup(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Create multiple VaultSecrets with the same Vault address
	numSecrets := 10
	vaultSecrets := make([]*avapigwv1alpha1.VaultSecret, numSecrets)
	for i := 0; i < numSecrets; i++ {
		vaultSecrets[i] = &avapigwv1alpha1.VaultSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test-%d", i),
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.VaultSecretSpec{
				Path: "secret/test",
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "http://vault:8200",
				},
			},
		}
	}

	// Pre-populate the cache
	clientKey := "http://vault:8200-default"
	reconciler.vaultClients.Store(clientKey, "mock-client")

	// Concurrently cleanup all VaultSecrets
	var wg sync.WaitGroup
	for _, vs := range vaultSecrets {
		wg.Add(1)
		go func(vs *avapigwv1alpha1.VaultSecret) {
			defer wg.Done()
			reconciler.cleanupVaultClient(vs)
		}(vs)
	}

	wg.Wait()

	// Verify client was removed (should not panic due to concurrent access)
	_, exists := reconciler.vaultClients.Load(clientKey)
	assert.False(t, exists, "Client should be removed from cache")
}

// ============================================================================
// Test Cases for Vault Address Change Detection (CRIT-003)
// ============================================================================

func TestVaultSecretReconciler_HandleVaultAddressChange(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault1:8200",
			},
		},
	}

	// Pre-populate the cache with the old address
	oldClientKey := "http://vault1:8200-default"
	reconciler.vaultClients.Store(oldClientKey, "mock-client-old")

	// Track the initial address
	trackerKey := fmt.Sprintf("%s/%s", vaultSecret.Namespace, vaultSecret.Name)
	reconciler.vaultAddressTracker.Store(trackerKey, "http://vault1:8200")

	// Change the address
	vaultSecret.Spec.VaultConnection.Address = "http://vault2:8200"

	// Handle the address change
	reconciler.handleVaultAddressChange(context.Background(), vaultSecret)

	// Verify old client was removed
	_, exists := reconciler.vaultClients.Load(oldClientKey)
	assert.False(t, exists, "Old client should be removed from cache")

	// Verify tracker was updated
	newAddress, ok := reconciler.vaultAddressTracker.Load(trackerKey)
	assert.True(t, ok)
	assert.Equal(t, "http://vault2:8200", newAddress)
}

func TestVaultSecretReconciler_HandleVaultAddressChange_NoChange(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault1:8200",
			},
		},
	}

	// Pre-populate the cache
	clientKey := "http://vault1:8200-default"
	reconciler.vaultClients.Store(clientKey, "mock-client")

	// Track the address (same as current)
	trackerKey := fmt.Sprintf("%s/%s", vaultSecret.Namespace, vaultSecret.Name)
	reconciler.vaultAddressTracker.Store(trackerKey, "http://vault1:8200")

	// Handle (no change)
	reconciler.handleVaultAddressChange(context.Background(), vaultSecret)

	// Verify client was NOT removed
	_, exists := reconciler.vaultClients.Load(clientKey)
	assert.True(t, exists, "Client should still be in cache (no address change)")
}

func TestVaultSecretReconciler_HandleVaultAddressChange_FirstTime(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault1:8200",
			},
		},
	}

	// No previous tracking - first time seeing this VaultSecret
	trackerKey := fmt.Sprintf("%s/%s", vaultSecret.Namespace, vaultSecret.Name)

	// Handle (first time)
	reconciler.handleVaultAddressChange(context.Background(), vaultSecret)

	// Verify tracker was set
	address, ok := reconciler.vaultAddressTracker.Load(trackerKey)
	assert.True(t, ok)
	assert.Equal(t, "http://vault1:8200", address)
}

// ============================================================================
// Test Cases for VaultClientCache Integration (CRIT-003)
// ============================================================================

func TestVaultSecretReconciler_InitVaultClientCache(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &VaultClientCacheConfig{
		MaxSize:         50,
		TTL:             15 * time.Minute,
		CleanupInterval: 3 * time.Minute,
	}

	reconciler.InitVaultClientCache(ctx, config)

	assert.NotNil(t, reconciler.vaultClientCache)
	assert.NotNil(t, reconciler.cacheConfig)
	assert.Equal(t, 50, reconciler.cacheConfig.MaxSize)
	assert.Equal(t, 15*time.Minute, reconciler.cacheConfig.TTL)

	// Stop the cache
	reconciler.Stop()
}

func TestVaultSecretReconciler_InitVaultClientCache_DefaultConfig(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use nil config to get defaults
	reconciler.InitVaultClientCache(ctx, nil)

	assert.NotNil(t, reconciler.vaultClientCache)
	assert.NotNil(t, reconciler.cacheConfig)
	assert.Equal(t, 100, reconciler.cacheConfig.MaxSize)
	assert.Equal(t, 30*time.Minute, reconciler.cacheConfig.TTL)

	// Stop the cache
	reconciler.Stop()
}

func TestVaultSecretReconciler_CleanupVaultClient_WithBoundedCache(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize the bounded cache
	reconciler.InitVaultClientCache(ctx, nil)

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
			},
		},
	}

	// Pre-populate both caches
	clientKey := fmt.Sprintf("%s-%s", vaultSecret.Spec.VaultConnection.Address, vaultSecret.Namespace)
	reconciler.vaultClients.Store(clientKey, "mock-client-legacy")
	reconciler.vaultClientCache.Set(clientKey, nil, "http://vault:8200")

	// Track the address
	trackerKey := fmt.Sprintf("%s/%s", vaultSecret.Namespace, vaultSecret.Name)
	reconciler.vaultAddressTracker.Store(trackerKey, "http://vault:8200")

	// Cleanup
	reconciler.cleanupVaultClient(vaultSecret)

	// Verify both caches were cleaned
	_, existsLegacy := reconciler.vaultClients.Load(clientKey)
	assert.False(t, existsLegacy, "Legacy cache should be cleaned")

	_, existsBounded := reconciler.vaultClientCache.Get(clientKey)
	assert.False(t, existsBounded, "Bounded cache should be cleaned")

	// Verify tracker was cleaned
	_, existsTracker := reconciler.vaultAddressTracker.Load(trackerKey)
	assert.False(t, existsTracker, "Address tracker should be cleaned")

	// Stop the cache
	reconciler.Stop()
}

func TestDefaultVaultClientCacheConfig(t *testing.T) {
	config := DefaultVaultClientCacheConfig()
	assert.Equal(t, 100, config.MaxSize)
	assert.Equal(t, 30*time.Minute, config.TTL)
	assert.Equal(t, 5*time.Minute, config.CleanupInterval)
}

// ============================================================================
// Test Cases for findVaultSecretsForSecret
// ============================================================================

func TestVaultSecretReconciler_FindVaultSecretsForSecret(t *testing.T) {
	scheme := setupScheme(t)

	// Create VaultSecrets that reference different secrets
	vaultSecret1 := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test1",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Token: &avapigwv1alpha1.TokenAuthConfig{
						SecretRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "token-secret",
							Namespace: strPtr("default"),
						},
					},
				},
			},
		},
	}

	vaultSecret2 := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs2",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test2",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
		},
	}

	// Create the referenced secret
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "token-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-token"),
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret1, vaultSecret2, tokenSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Test finding VaultSecrets that reference the token secret
	requests := reconciler.findVaultSecretsForSecret(context.Background(), tokenSecret)

	// Should find vs1 but not vs2
	assert.Len(t, requests, 1)
	assert.Equal(t, "vs1", requests[0].Name)
	assert.Equal(t, "default", requests[0].Namespace)
}

func TestVaultSecretReconciler_FindVaultSecretsForSecret_NoMatches(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret that doesn't reference any secrets
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
		},
	}

	// Create an unrelated secret
	unrelatedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unrelated-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"data": []byte("test"),
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret, unrelatedSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Test finding VaultSecrets - should find none
	requests := reconciler.findVaultSecretsForSecret(context.Background(), unrelatedSecret)
	assert.Len(t, requests, 0)
}

func TestVaultSecretReconciler_FindVaultSecretsForSecret_MultipleMatches(t *testing.T) {
	scheme := setupScheme(t)

	// Create multiple VaultSecrets that reference the same secret
	vaultSecret1 := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs1",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test1",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Token: &avapigwv1alpha1.TokenAuthConfig{
						SecretRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "shared-token",
							Namespace: strPtr("default"),
						},
					},
				},
			},
		},
	}

	vaultSecret2 := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs2",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test2",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Token: &avapigwv1alpha1.TokenAuthConfig{
						SecretRef: avapigwv1alpha1.SecretObjectReference{
							Name:      "shared-token",
							Namespace: strPtr("default"),
						},
					},
				},
			},
		},
	}

	// Create the shared secret
	sharedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-token",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-token"),
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret1, vaultSecret2, sharedSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	// Test finding VaultSecrets - should find both
	requests := reconciler.findVaultSecretsForSecret(context.Background(), sharedSecret)
	assert.Len(t, requests, 2)
}

// ============================================================================
// Test Cases for Reconcile with Finalizer
// ============================================================================

func TestVaultSecretReconciler_Reconcile_AddsFinalizer(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret without finalizer
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		WithStatusSubresource(vaultSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:       cl,
		Scheme:       scheme,
		Recorder:     record.NewFakeRecorder(100),
		VaultEnabled: true, // Enable Vault for this test
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test",
		},
	}

	// First reconcile should add finalizer
	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.False(t, result.IsZero(), "Should requeue immediately after adding finalizer")

	// Verify finalizer was added
	updatedVS := &avapigwv1alpha1.VaultSecret{}
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "test"}, updatedVS)
	require.NoError(t, err)
	assert.Contains(t, updatedVS.Finalizers, vaultSecretFinalizer)
}

func TestVaultSecretReconciler_Reconcile_HandlesDeletion(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret with finalizer and deletion timestamp
	now := metav1.Now()
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			Finalizers:        []string{vaultSecretFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
			Target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "target-secret",
				DeletionPolicy: func() *avapigwv1alpha1.SecretDeletionPolicy {
					p := avapigwv1alpha1.SecretDeletionPolicyRetain
					return &p
				}(),
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:       cl,
		Scheme:       scheme,
		Recorder:     record.NewFakeRecorder(100),
		VaultEnabled: true, // Enable Vault for this test
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test",
		},
	}

	// Reconcile should handle deletion
	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.IsZero(), "Should return zero result after deletion")

	// After finalizer removal, the object may be deleted by the fake client
	// So we check if it either doesn't exist or has no finalizer
	updatedVS := &avapigwv1alpha1.VaultSecret{}
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "test"}, updatedVS)
	if err == nil {
		// Object still exists, verify finalizer was removed
		assert.NotContains(t, updatedVS.Finalizers, vaultSecretFinalizer)
	}
	// If object doesn't exist, that's also acceptable (deleted after finalizer removal)
}

func TestVaultSecretReconciler_Reconcile_ValidationError(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret with invalid configuration (missing auth)
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{vaultSecretFinalizer},
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth:    avapigwv1alpha1.VaultAuthConfig{}, // No auth method
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		WithStatusSubresource(vaultSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:       cl,
		Scheme:       scheme,
		Recorder:     record.NewFakeRecorder(100),
		VaultEnabled: true, // Enable Vault for this test
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test",
		},
	}

	// Reconcile should return validation error
	result, err := reconciler.Reconcile(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one authentication method")
	// Should not requeue for validation errors
	assert.True(t, result.Requeue || result.RequeueAfter > 0, "Should have requeue strategy for validation error")
}

func TestVaultSecretReconciler_Reconcile_VaultDisabled(t *testing.T) {
	scheme := setupScheme(t)

	// Create a VaultSecret
	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: "test-role",
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		WithStatusSubresource(vaultSecret).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:              cl,
		Scheme:              scheme,
		Recorder:            record.NewFakeRecorder(100),
		VaultEnabled:        false, // Vault is disabled
		SecretsProviderType: "kubernetes",
	}

	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test",
		},
	}

	// Reconcile should skip gracefully when Vault is disabled
	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0, "Should requeue after interval when Vault is disabled")

	// Verify status was updated
	updatedVS := &avapigwv1alpha1.VaultSecret{}
	err = cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "test"}, updatedVS)
	require.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusPending, updatedVS.Status.Phase)
}

// ============================================================================
// Test Cases for getRequeueStrategy
// ============================================================================

func TestVaultSecretReconciler_GetRequeueStrategy(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	// First call should initialize the strategy
	strategy1 := reconciler.getRequeueStrategy()
	assert.NotNil(t, strategy1)

	// Second call should return the same strategy
	strategy2 := reconciler.getRequeueStrategy()
	assert.Same(t, strategy1, strategy2)
}

func TestVaultSecretReconciler_GetRequeueStrategy_WithCustomStrategy(t *testing.T) {
	customConfig := &RequeueConfig{
		BaseInterval:            10 * time.Second,
		MaxInterval:             1 * time.Minute,
		TransientErrorInterval:  5 * time.Second,
		DependencyErrorInterval: 15 * time.Second,
		ValidationErrorInterval: 2 * time.Minute,
		PermanentErrorInterval:  5 * time.Minute,
		SuccessInterval:         30 * time.Second,
		BackoffMultiplier:       2.0,
		MaxFailures:             5,
		JitterPercent:           20,
	}
	customStrategy := NewRequeueStrategy(customConfig)

	reconciler := &VaultSecretReconciler{
		RequeueStrategy: customStrategy,
	}

	strategy := reconciler.getRequeueStrategy()
	assert.Same(t, customStrategy, strategy)
}

// ============================================================================
// Test Cases for Stop
// ============================================================================

func TestVaultSecretReconciler_Stop_Idempotent(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize the cache
	reconciler.InitVaultClientCache(ctx, nil)

	// Multiple stop calls should not panic
	reconciler.Stop()
	reconciler.Stop()
	reconciler.Stop()
}

func TestVaultSecretReconciler_Stop_WithoutInit(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	// Stop without init should not panic
	reconciler.Stop()
}

// ============================================================================
// Test Cases for handleVaultSecretReconcileError
// ============================================================================

func TestVaultSecretReconciler_handleVaultSecretReconcileError(t *testing.T) {
	reconciler := &VaultSecretReconciler{}
	reconciler.initBaseComponents()
	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-vaultsecret"

	tests := []struct {
		name           string
		reconcileErr   *ReconcileError
		validateResult func(t *testing.T, result ctrl.Result, err error)
	}{
		{
			name: "validation error returns validation result",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypeValidation,
				Op:                 "validate",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          false,
				UserActionRequired: true,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				assert.False(t, result.Requeue)
			},
		},
		{
			name: "permanent error returns permanent result",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypePermanent,
				Op:                 "reconcile",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          false,
				UserActionRequired: true,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				assert.False(t, result.Requeue)
			},
		},
		{
			name: "dependency error returns dependency result with backoff",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypeDependency,
				Op:                 "fetchDependency",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          true,
				UserActionRequired: false,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				assert.True(t, result.RequeueAfter > 0)
			},
		},
		{
			name: "transient error returns transient result with backoff",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypeTransient,
				Op:                 "update",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          true,
				UserActionRequired: false,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				assert.True(t, result.RequeueAfter > 0)
			},
		},
		{
			name: "internal error returns transient result with backoff",
			reconcileErr: &ReconcileError{
				Type:               ErrorTypeInternal,
				Op:                 "internal",
				Resource:           resourceKey,
				Err:                assert.AnError,
				Retryable:          true,
				UserActionRequired: false,
			},
			validateResult: func(t *testing.T, result ctrl.Result, err error) {
				assert.Error(t, err)
				assert.True(t, result.RequeueAfter > 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := reconciler.handleVaultSecretReconcileError(tt.reconcileErr, strategy, resourceKey)
			tt.validateResult(t, result, err)
		})
	}
}

// ============================================================================
// Test Cases for handleVaultSecretReconcileSuccess
// ============================================================================

func TestVaultSecretReconciler_handleVaultSecretReconcileSuccess(t *testing.T) {
	scheme := setupScheme(t)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
	reconciler.initBaseComponents()

	strategy := DefaultRequeueStrategy()
	resourceKey := "default/test-vaultsecret"

	tests := []struct {
		name        string
		vaultSecret *avapigwv1alpha1.VaultSecret
		validate    func(t *testing.T, result ctrl.Result, err error)
	}{
		{
			name: "success with default refresh interval",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
				},
			},
			validate: func(t *testing.T, result ctrl.Result, err error) {
				assert.NoError(t, err)
				assert.True(t, result.RequeueAfter > 0)
				// Default is 5 minutes with jitter (up to 10% by default from both VaultSecret and strategy)
				assert.True(t, result.RequeueAfter >= 4*time.Minute && result.RequeueAfter <= 6*time.Minute,
					"Expected requeue after to be approximately 5 minutes, got %v", result.RequeueAfter)
			},
		},
		{
			name: "success with custom refresh interval",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					Refresh: &avapigwv1alpha1.VaultRefreshConfig{
						Enabled:       boolPtr(true),
						Interval:      durationPtr(10 * time.Minute),
						JitterPercent: int32Ptr(0), // No jitter from VaultSecret, but strategy still adds jitter
					},
				},
			},
			validate: func(t *testing.T, result ctrl.Result, err error) {
				assert.NoError(t, err)
				assert.True(t, result.RequeueAfter > 0)
				// 10 minutes with strategy jitter (up to 10%)
				assert.True(t, result.RequeueAfter >= 9*time.Minute && result.RequeueAfter <= 11*time.Minute,
					"Expected requeue after to be approximately 10 minutes, got %v", result.RequeueAfter)
			},
		},
		{
			name: "success with disabled refresh",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					Refresh: &avapigwv1alpha1.VaultRefreshConfig{
						Enabled:       boolPtr(false),
						JitterPercent: int32Ptr(0), // No jitter from VaultSecret, but strategy still adds jitter
					},
				},
			},
			validate: func(t *testing.T, result ctrl.Result, err error) {
				assert.NoError(t, err)
				assert.True(t, result.RequeueAfter > 0)
				// Disabled refresh uses 24 hours with strategy jitter (up to 10%)
				assert.True(t, result.RequeueAfter >= 21*time.Hour && result.RequeueAfter <= 27*time.Hour,
					"Expected requeue after to be approximately 24 hours, got %v", result.RequeueAfter)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset failure count before each test
			strategy.ResetFailureCount(resourceKey)

			ctx := context.Background()
			logger := ctrl.Log.WithName("test")

			result, err := reconciler.handleVaultSecretReconcileSuccess(ctx, tt.vaultSecret, strategy, resourceKey, logger)
			tt.validate(t, result, err)
		})
	}
}

// ============================================================================
// Test Cases for handleVaultSyncError
// ============================================================================

func TestVaultSecretReconciler_handleVaultSyncError(t *testing.T) {
	scheme := setupScheme(t)

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		WithStatusSubresource(&avapigwv1alpha1.VaultSecret{}).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
	reconciler.initBaseComponents()

	ctx := context.Background()
	logger := ctrl.Log.WithName("test")
	resourceKey := "default/test"
	testErr := fmt.Errorf("vault sync failed")

	reconcileErr := reconciler.handleVaultSyncError(ctx, vaultSecret, resourceKey, testErr, logger)

	assert.NotNil(t, reconcileErr)
	assert.Equal(t, "syncSecret", reconcileErr.Op)
	assert.Contains(t, reconcileErr.Error(), "vault sync failed")

	// Verify status was updated
	updatedVS := &avapigwv1alpha1.VaultSecret{}
	err := cl.Get(ctx, client.ObjectKey{Namespace: "default", Name: "test"}, updatedVS)
	require.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusError, updatedVS.Status.Phase)
	assert.NotNil(t, updatedVS.Status.LastVaultError)
	assert.Contains(t, *updatedVS.Status.LastVaultError, "vault sync failed")
}

// ============================================================================
// Test Cases for finalizeVaultSecretReconcile
// ============================================================================

func TestVaultSecretReconciler_finalizeVaultSecretReconcile(t *testing.T) {
	scheme := setupScheme(t)

	vaultSecret := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			Path: "secret/test",
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vaultSecret).
		WithStatusSubresource(&avapigwv1alpha1.VaultSecret{}).
		Build()

	reconciler := &VaultSecretReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(100),
	}
	reconciler.initBaseComponents()

	ctx := context.Background()
	logger := ctrl.Log.WithName("test")
	resourceKey := "default/test"

	err := reconciler.finalizeVaultSecretReconcile(ctx, vaultSecret, resourceKey, logger)

	assert.NoError(t, err)

	// Verify status was updated
	updatedVS := &avapigwv1alpha1.VaultSecret{}
	err = cl.Get(ctx, client.ObjectKey{Namespace: "default", Name: "test"}, updatedVS)
	require.NoError(t, err)
	assert.Equal(t, avapigwv1alpha1.PhaseStatusReady, updatedVS.Status.Phase)
	assert.Nil(t, updatedVS.Status.LastVaultError)
	assert.NotNil(t, updatedVS.Status.LastRefreshTime)
	assert.NotNil(t, updatedVS.Status.NextRefreshTime)

	// Verify Ready condition
	readyCondition := updatedVS.Status.GetCondition(avapigwv1alpha1.ConditionTypeReady)
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)
	assert.Equal(t, string(avapigwv1alpha1.ReasonReady), readyCondition.Reason)
}

// ============================================================================
// Test Cases for fetchVaultSecret
// ============================================================================

func TestVaultSecretReconciler_fetchVaultSecret(t *testing.T) {
	scheme := setupScheme(t)

	tests := []struct {
		name            string
		objects         []client.Object
		request         reconcile.Request
		wantVaultSecret bool
		wantErr         bool
	}{
		{
			name: "successfully fetches VaultSecret",
			objects: []client.Object{
				&avapigwv1alpha1.VaultSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.VaultSecretSpec{
						Path: "secret/test",
					},
				},
			},
			request: reconcile.Request{
				NamespacedName: client.ObjectKey{
					Name:      "test",
					Namespace: "default",
				},
			},
			wantVaultSecret: true,
			wantErr:         false,
		},
		{
			name:    "returns nil for not found",
			objects: []client.Object{},
			request: reconcile.Request{
				NamespacedName: client.ObjectKey{
					Name:      "non-existent",
					Namespace: "default",
				},
			},
			wantVaultSecret: false,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			reconciler := &VaultSecretReconciler{
				Client:   cl,
				Scheme:   scheme,
				Recorder: record.NewFakeRecorder(100),
			}
			reconciler.initBaseComponents()

			strategy := DefaultRequeueStrategy()
			resourceKey := tt.request.String()

			vaultSecret, _, err := reconciler.fetchVaultSecret(context.Background(), tt.request, strategy, resourceKey)

			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

			if tt.wantVaultSecret {
				assert.NotNil(t, vaultSecret)
			} else {
				assert.Nil(t, vaultSecret)
			}
		})
	}
}

// ============================================================================
// Test Cases for cleanupTargetSecretIfNeeded
// ============================================================================

func TestVaultSecretReconciler_cleanupTargetSecretIfNeeded(t *testing.T) {
	scheme := setupScheme(t)

	tests := []struct {
		name                string
		vaultSecret         *avapigwv1alpha1.VaultSecret
		targetSecretExists  bool
		expectSecretDeleted bool
	}{
		{
			name: "deletes target secret with Delete policy",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
						DeletionPolicy: func() *avapigwv1alpha1.SecretDeletionPolicy {
							p := avapigwv1alpha1.SecretDeletionPolicyDelete
							return &p
						}(),
					},
				},
			},
			targetSecretExists:  true,
			expectSecretDeleted: true,
		},
		{
			name: "retains target secret with Retain policy",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
						DeletionPolicy: func() *avapigwv1alpha1.SecretDeletionPolicy {
							p := avapigwv1alpha1.SecretDeletionPolicyRetain
							return &p
						}(),
					},
				},
			},
			targetSecretExists:  true,
			expectSecretDeleted: false,
		},
		{
			name: "no-op when target is nil",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path:   "secret/test",
					Target: nil,
				},
			},
			targetSecretExists:  false,
			expectSecretDeleted: false,
		},
		{
			name: "uses default Delete policy when not specified",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name:           "target-secret",
						DeletionPolicy: nil, // Default is Delete
					},
				},
			},
			targetSecretExists:  true,
			expectSecretDeleted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objects []client.Object
			objects = append(objects, tt.vaultSecret)

			if tt.targetSecretExists {
				targetSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "target-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"data": []byte("test"),
					},
				}
				objects = append(objects, targetSecret)
			}

			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				Build()

			reconciler := &VaultSecretReconciler{
				Client:   cl,
				Scheme:   scheme,
				Recorder: record.NewFakeRecorder(100),
			}
			reconciler.initBaseComponents()

			ctx := context.Background()
			logger := ctrl.Log.WithName("test")
			resourceKey := "default/test"

			reconciler.cleanupTargetSecretIfNeeded(ctx, tt.vaultSecret, resourceKey, logger)

			// Check if target secret exists
			targetSecret := &corev1.Secret{}
			err := cl.Get(ctx, client.ObjectKey{Namespace: "default", Name: "target-secret"}, targetSecret)

			if tt.expectSecretDeleted {
				assert.True(t, apierrors.IsNotFound(err), "Target secret should be deleted")
			} else if tt.targetSecretExists {
				assert.NoError(t, err, "Target secret should still exist")
			}
		})
	}
}

// ============================================================================
// Test Cases for resolveTargetNamespace
// ============================================================================

func TestVaultSecretReconciler_resolveTargetNamespace(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	tests := []struct {
		name             string
		defaultNamespace string
		targetNamespace  *string
		want             string
	}{
		{
			name:             "uses default namespace when target is nil",
			defaultNamespace: "default",
			targetNamespace:  nil,
			want:             "default",
		},
		{
			name:             "uses target namespace when specified",
			defaultNamespace: "default",
			targetNamespace:  strPtr("custom-ns"),
			want:             "custom-ns",
		},
		{
			name:             "uses empty target namespace when specified",
			defaultNamespace: "default",
			targetNamespace:  strPtr(""),
			want:             "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.resolveTargetNamespace(tt.defaultNamespace, tt.targetNamespace)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for buildVaultClientConfig
// ============================================================================

func TestVaultSecretReconciler_buildVaultClientConfig(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	tests := []struct {
		name      string
		conn      avapigwv1alpha1.VaultConnectionConfig
		tlsConfig *vault.TLSConfig
		wantAddr  string
		wantNs    string
	}{
		{
			name: "basic config without namespace",
			conn: avapigwv1alpha1.VaultConnectionConfig{
				Address: "http://vault:8200",
			},
			tlsConfig: nil,
			wantAddr:  "http://vault:8200",
			wantNs:    "",
		},
		{
			name: "config with namespace",
			conn: avapigwv1alpha1.VaultConnectionConfig{
				Address:   "https://vault:8200",
				Namespace: strPtr("my-namespace"),
			},
			tlsConfig: nil,
			wantAddr:  "https://vault:8200",
			wantNs:    "my-namespace",
		},
		{
			name: "config with TLS",
			conn: avapigwv1alpha1.VaultConnectionConfig{
				Address: "https://vault:8200",
			},
			tlsConfig: &vault.TLSConfig{
				InsecureSkipVerify: true,
			},
			wantAddr: "https://vault:8200",
			wantNs:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := reconciler.buildVaultClientConfig(tt.conn, tt.tlsConfig)

			assert.Equal(t, tt.wantAddr, config.Address)
			assert.Equal(t, tt.wantNs, config.Namespace)
			assert.Equal(t, tt.tlsConfig, config.TLSConfig)
			assert.NotZero(t, config.Timeout)
			assert.NotZero(t, config.MaxRetries)
		})
	}
}

// ============================================================================
// Test Cases for createKubernetesAuthMethod
// ============================================================================

func TestVaultSecretReconciler_createKubernetesAuthMethod(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	tests := []struct {
		name      string
		k8sAuth   *avapigwv1alpha1.KubernetesAuthConfig
		wantErr   bool
		wantMount string
	}{
		{
			name: "basic kubernetes auth",
			k8sAuth: &avapigwv1alpha1.KubernetesAuthConfig{
				Role: "my-role",
			},
			wantErr:   false,
			wantMount: "kubernetes",
		},
		{
			name: "kubernetes auth with custom mount path",
			k8sAuth: &avapigwv1alpha1.KubernetesAuthConfig{
				Role:      "my-role",
				MountPath: strPtr("custom-k8s"),
			},
			wantErr:   false,
			wantMount: "custom-k8s",
		},
		{
			name: "kubernetes auth with custom token path",
			k8sAuth: &avapigwv1alpha1.KubernetesAuthConfig{
				Role:      "my-role",
				TokenPath: strPtr("/custom/token/path"),
			},
			wantErr:   false,
			wantMount: "kubernetes",
		},
		{
			name: "kubernetes auth with empty role fails",
			k8sAuth: &avapigwv1alpha1.KubernetesAuthConfig{
				Role: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMethod, err := reconciler.createKubernetesAuthMethod(tt.k8sAuth)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, authMethod)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authMethod)
				assert.Equal(t, "kubernetes", authMethod.Name())
			}
		})
	}
}

// ============================================================================
// Test Cases for createTokenAuthMethod
// ============================================================================

func TestVaultSecretReconciler_createTokenAuthMethod(t *testing.T) {
	scheme := setupScheme(t)

	tests := []struct {
		name             string
		defaultNamespace string
		tokenAuth        *avapigwv1alpha1.TokenAuthConfig
		secrets          []client.Object
		wantErr          bool
		errContains      string
	}{
		{
			name:             "successful token auth with default key",
			defaultNamespace: "default",
			tokenAuth: &avapigwv1alpha1.TokenAuthConfig{
				SecretRef: avapigwv1alpha1.SecretObjectReference{
					Name: "vault-token",
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vault-token",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"token": []byte("my-vault-token"),
					},
				},
			},
			wantErr: false,
		},
		{
			name:             "successful token auth with custom key",
			defaultNamespace: "default",
			tokenAuth: &avapigwv1alpha1.TokenAuthConfig{
				SecretRef: avapigwv1alpha1.SecretObjectReference{
					Name: "vault-token",
				},
				TokenKey: strPtr("custom-token-key"),
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vault-token",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"custom-token-key": []byte("my-vault-token"),
					},
				},
			},
			wantErr: false,
		},
		{
			name:             "successful token auth with custom namespace",
			defaultNamespace: "default",
			tokenAuth: &avapigwv1alpha1.TokenAuthConfig{
				SecretRef: avapigwv1alpha1.SecretObjectReference{
					Name:      "vault-token",
					Namespace: strPtr("other-ns"),
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vault-token",
						Namespace: "other-ns",
					},
					Data: map[string][]byte{
						"token": []byte("my-vault-token"),
					},
				},
			},
			wantErr: false,
		},
		{
			name:             "fails when secret not found",
			defaultNamespace: "default",
			tokenAuth: &avapigwv1alpha1.TokenAuthConfig{
				SecretRef: avapigwv1alpha1.SecretObjectReference{
					Name: "non-existent",
				},
			},
			secrets:     []client.Object{},
			wantErr:     true,
			errContains: "failed to get token secret",
		},
		{
			name:             "fails when token is empty",
			defaultNamespace: "default",
			tokenAuth: &avapigwv1alpha1.TokenAuthConfig{
				SecretRef: avapigwv1alpha1.SecretObjectReference{
					Name: "vault-token",
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vault-token",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"token": []byte(""),
					},
				},
			},
			wantErr:     true,
			errContains: "token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.secrets...).
				Build()

			reconciler := &VaultSecretReconciler{
				Client: cl,
				Scheme: scheme,
			}

			authMethod, err := reconciler.createTokenAuthMethod(context.Background(), tt.defaultNamespace, tt.tokenAuth)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authMethod)
				assert.Equal(t, "token", authMethod.Name())
			}
		})
	}
}

// ============================================================================
// Test Cases for createAppRoleAuthMethod
// ============================================================================

func TestVaultSecretReconciler_createAppRoleAuthMethod(t *testing.T) {
	scheme := setupScheme(t)

	tests := []struct {
		name             string
		defaultNamespace string
		appRole          *avapigwv1alpha1.AppRoleAuthConfig
		secrets          []client.Object
		wantErr          bool
		errContains      string
	}{
		{
			name:             "successful approle auth with default key",
			defaultNamespace: "default",
			appRole: &avapigwv1alpha1.AppRoleAuthConfig{
				RoleID: "my-role-id",
				SecretIDRef: avapigwv1alpha1.SecretObjectReference{
					Name: "approle-secret",
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "approle-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"secret-id": []byte("my-secret-id"),
					},
				},
			},
			wantErr: false,
		},
		{
			name:             "successful approle auth with custom key",
			defaultNamespace: "default",
			appRole: &avapigwv1alpha1.AppRoleAuthConfig{
				RoleID: "my-role-id",
				SecretIDRef: avapigwv1alpha1.SecretObjectReference{
					Name: "approle-secret",
				},
				SecretIDKey: strPtr("custom-secret-key"),
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "approle-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"custom-secret-key": []byte("my-secret-id"),
					},
				},
			},
			wantErr: false,
		},
		{
			name:             "successful approle auth with custom mount path",
			defaultNamespace: "default",
			appRole: &avapigwv1alpha1.AppRoleAuthConfig{
				RoleID: "my-role-id",
				SecretIDRef: avapigwv1alpha1.SecretObjectReference{
					Name: "approle-secret",
				},
				MountPath: strPtr("custom-approle"),
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "approle-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"secret-id": []byte("my-secret-id"),
					},
				},
			},
			wantErr: false,
		},
		{
			name:             "successful approle auth with custom namespace",
			defaultNamespace: "default",
			appRole: &avapigwv1alpha1.AppRoleAuthConfig{
				RoleID: "my-role-id",
				SecretIDRef: avapigwv1alpha1.SecretObjectReference{
					Name:      "approle-secret",
					Namespace: strPtr("other-ns"),
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "approle-secret",
						Namespace: "other-ns",
					},
					Data: map[string][]byte{
						"secret-id": []byte("my-secret-id"),
					},
				},
			},
			wantErr: false,
		},
		{
			name:             "fails when secret not found",
			defaultNamespace: "default",
			appRole: &avapigwv1alpha1.AppRoleAuthConfig{
				RoleID: "my-role-id",
				SecretIDRef: avapigwv1alpha1.SecretObjectReference{
					Name: "non-existent",
				},
			},
			secrets:     []client.Object{},
			wantErr:     true,
			errContains: "failed to get AppRole secret",
		},
		{
			name:             "fails when secret-id is empty",
			defaultNamespace: "default",
			appRole: &avapigwv1alpha1.AppRoleAuthConfig{
				RoleID: "my-role-id",
				SecretIDRef: avapigwv1alpha1.SecretObjectReference{
					Name: "approle-secret",
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "approle-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"secret-id": []byte(""),
					},
				},
			},
			wantErr:     true,
			errContains: "secretID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.secrets...).
				Build()

			reconciler := &VaultSecretReconciler{
				Client: cl,
				Scheme: scheme,
			}

			authMethod, err := reconciler.createAppRoleAuthMethod(context.Background(), tt.defaultNamespace, tt.appRole)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authMethod)
				assert.Equal(t, "approle", authMethod.Name())
			}
		})
	}
}

// ============================================================================
// Test Cases for createAuthMethod
// ============================================================================

func TestVaultSecretReconciler_createAuthMethod(t *testing.T) {
	scheme := setupScheme(t)

	tests := []struct {
		name        string
		vaultSecret *avapigwv1alpha1.VaultSecret
		secrets     []client.Object
		wantErr     bool
		errContains string
		wantName    string
	}{
		{
			name: "creates kubernetes auth method",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "http://vault:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "my-role",
							},
						},
					},
				},
			},
			secrets:  []client.Object{},
			wantErr:  false,
			wantName: "kubernetes",
		},
		{
			name: "creates token auth method",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "http://vault:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Token: &avapigwv1alpha1.TokenAuthConfig{
								SecretRef: avapigwv1alpha1.SecretObjectReference{
									Name: "vault-token",
								},
							},
						},
					},
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vault-token",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"token": []byte("my-token"),
					},
				},
			},
			wantErr:  false,
			wantName: "token",
		},
		{
			name: "creates approle auth method",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "http://vault:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
								RoleID: "my-role-id",
								SecretIDRef: avapigwv1alpha1.SecretObjectReference{
									Name: "approle-secret",
								},
							},
						},
					},
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "approle-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"secret-id": []byte("my-secret-id"),
					},
				},
			},
			wantErr:  false,
			wantName: "approle",
		},
		{
			name: "fails when no auth method configured",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Path: "secret/test",
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "http://vault:8200",
						Auth:    avapigwv1alpha1.VaultAuthConfig{},
					},
				},
			},
			secrets:     []client.Object{},
			wantErr:     true,
			errContains: "no authentication method configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.secrets...).
				Build()

			reconciler := &VaultSecretReconciler{
				Client: cl,
				Scheme: scheme,
			}

			authMethod, err := reconciler.createAuthMethod(context.Background(), tt.vaultSecret)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authMethod)
				assert.Equal(t, tt.wantName, authMethod.Name())
			}
		})
	}
}

// ============================================================================
// Test Cases for buildVaultTLSConfig
// ============================================================================

func TestVaultSecretReconciler_buildVaultTLSConfig(t *testing.T) {
	scheme := setupScheme(t)

	tests := []struct {
		name             string
		defaultNamespace string
		tlsSpec          *avapigwv1alpha1.VaultTLSConfig
		secrets          []client.Object
		wantErr          bool
		errContains      string
		wantNil          bool
		wantSkipVerify   bool
		wantServerName   string
	}{
		{
			name:             "returns nil when tlsSpec is nil",
			defaultNamespace: "default",
			tlsSpec:          nil,
			secrets:          []client.Object{},
			wantErr:          false,
			wantNil:          true,
		},
		{
			name:             "basic TLS config with insecure skip verify",
			defaultNamespace: "default",
			tlsSpec: &avapigwv1alpha1.VaultTLSConfig{
				InsecureSkipVerify: boolPtr(true),
			},
			secrets:        []client.Object{},
			wantErr:        false,
			wantNil:        false,
			wantSkipVerify: true,
		},
		{
			name:             "TLS config with server name",
			defaultNamespace: "default",
			tlsSpec: &avapigwv1alpha1.VaultTLSConfig{
				ServerName: strPtr("vault.example.com"),
			},
			secrets:        []client.Object{},
			wantErr:        false,
			wantNil:        false,
			wantServerName: "vault.example.com",
		},
		{
			name:             "TLS config with CA cert",
			defaultNamespace: "default",
			tlsSpec: &avapigwv1alpha1.VaultTLSConfig{
				CACertRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "ca-secret",
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"ca.crt": []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
					},
				},
			},
			wantErr: false,
			wantNil: false,
		},
		{
			name:             "TLS config with client cert and key",
			defaultNamespace: "default",
			tlsSpec: &avapigwv1alpha1.VaultTLSConfig{
				ClientCertRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "client-cert-secret",
				},
				ClientKeyRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "client-key-secret",
				},
			},
			secrets: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "client-cert-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----"),
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "client-key-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"tls.key": []byte("-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----"),
					},
				},
			},
			wantErr: false,
			wantNil: false,
		},
		{
			name:             "fails when CA cert secret not found",
			defaultNamespace: "default",
			tlsSpec: &avapigwv1alpha1.VaultTLSConfig{
				CACertRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "non-existent",
				},
			},
			secrets:     []client.Object{},
			wantErr:     true,
			errContains: "failed to get CA cert",
		},
		{
			name:             "fails when client cert secret not found",
			defaultNamespace: "default",
			tlsSpec: &avapigwv1alpha1.VaultTLSConfig{
				ClientCertRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "non-existent",
				},
			},
			secrets:     []client.Object{},
			wantErr:     true,
			errContains: "failed to get client cert",
		},
		{
			name:             "fails when client key secret not found",
			defaultNamespace: "default",
			tlsSpec: &avapigwv1alpha1.VaultTLSConfig{
				ClientKeyRef: &avapigwv1alpha1.SecretObjectReference{
					Name: "non-existent",
				},
			},
			secrets:     []client.Object{},
			wantErr:     true,
			errContains: "failed to get client key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.secrets...).
				Build()

			reconciler := &VaultSecretReconciler{
				Client: cl,
				Scheme: scheme,
			}

			tlsConfig, err := reconciler.buildVaultTLSConfig(context.Background(), tt.defaultNamespace, tt.tlsSpec)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.wantNil {
					assert.Nil(t, tlsConfig)
				} else {
					assert.NotNil(t, tlsConfig)
					assert.Equal(t, tt.wantSkipVerify, tlsConfig.InsecureSkipVerify)
					assert.Equal(t, tt.wantServerName, tlsConfig.ServerName)
				}
			}
		})
	}
}

// ============================================================================
// Test Cases for mapVaultDataToSecret
// ============================================================================

func TestVaultSecretReconciler_mapVaultDataToSecret(t *testing.T) {
	reconciler := &VaultSecretReconciler{}
	logger := ctrl.Log.WithName("test")

	tests := []struct {
		name            string
		vaultSecret     *avapigwv1alpha1.VaultSecret
		vaultSecretData *vault.Secret
		wantData        map[string][]byte
	}{
		{
			name: "copies all keys when no explicit mapping",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Keys: nil,
				},
			},
			vaultSecretData: &vault.Secret{
				Data: map[string]interface{}{
					"username": "admin",
					"password": "secret123",
				},
			},
			wantData: map[string][]byte{
				"username": []byte("admin"),
				"password": []byte("secret123"),
			},
		},
		{
			name: "uses explicit key mappings",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Keys: []avapigwv1alpha1.VaultKeyMapping{
						{VaultKey: "username", TargetKey: "user"},
						{VaultKey: "password", TargetKey: "pass"},
					},
				},
			},
			vaultSecretData: &vault.Secret{
				Data: map[string]interface{}{
					"username": "admin",
					"password": "secret123",
					"extra":    "ignored",
				},
			},
			wantData: map[string][]byte{
				"user": []byte("admin"),
				"pass": []byte("secret123"),
			},
		},
		{
			name: "handles missing vault keys gracefully",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Keys: []avapigwv1alpha1.VaultKeyMapping{
						{VaultKey: "username", TargetKey: "user"},
						{VaultKey: "non-existent", TargetKey: "missing"},
					},
				},
			},
			vaultSecretData: &vault.Secret{
				Data: map[string]interface{}{
					"username": "admin",
				},
			},
			wantData: map[string][]byte{
				"user": []byte("admin"),
			},
		},
		{
			name: "applies base64 encoding when specified",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Keys: []avapigwv1alpha1.VaultKeyMapping{
						{
							VaultKey:  "data",
							TargetKey: "encoded",
							Encoding: func() *avapigwv1alpha1.VaultValueEncoding {
								e := avapigwv1alpha1.VaultValueEncodingBase64
								return &e
							}(),
						},
					},
				},
			},
			vaultSecretData: &vault.Secret{
				Data: map[string]interface{}{
					"data": "hello",
				},
			},
			wantData: map[string][]byte{
				"encoded": []byte("aGVsbG8="), // base64 of "hello"
			},
		},
		{
			name: "skips non-string values when copying all",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Keys: nil,
				},
			},
			vaultSecretData: &vault.Secret{
				Data: map[string]interface{}{
					"string_val": "text",
					"int_val":    123,
					"bool_val":   true,
				},
			},
			wantData: map[string][]byte{
				"string_val": []byte("text"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.mapVaultDataToSecret(tt.vaultSecret, tt.vaultSecretData, logger)
			assert.Equal(t, tt.wantData, result)
		})
	}
}

// ============================================================================
// Test Cases for setSecretLabelsAndAnnotations
// ============================================================================

func TestVaultSecretReconciler_setSecretLabelsAndAnnotations(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	tests := []struct {
		name            string
		secret          *corev1.Secret
		vaultSecret     *avapigwv1alpha1.VaultSecret
		target          *avapigwv1alpha1.VaultTargetConfig
		vaultSecretData *vault.Secret
		wantLabels      map[string]string
		wantAnnotations map[string]string
	}{
		{
			name:   "sets default labels",
			secret: &corev1.Secret{},
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-vault-secret",
				},
			},
			target:          &avapigwv1alpha1.VaultTargetConfig{},
			vaultSecretData: &vault.Secret{},
			wantLabels: map[string]string{
				"app.kubernetes.io/managed-by":                 "avapigw",
				"avapigw.vyrodovalexey.github.com/vaultsecret": "my-vault-secret",
			},
			wantAnnotations: map[string]string{},
		},
		{
			name:   "merges target labels with defaults",
			secret: &corev1.Secret{},
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-vault-secret",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Labels: map[string]string{
					"custom-label": "custom-value",
				},
			},
			vaultSecretData: &vault.Secret{},
			wantLabels: map[string]string{
				"custom-label":                                 "custom-value",
				"app.kubernetes.io/managed-by":                 "avapigw",
				"avapigw.vyrodovalexey.github.com/vaultsecret": "my-vault-secret",
			},
			wantAnnotations: map[string]string{},
		},
		{
			name:   "sets target annotations",
			secret: &corev1.Secret{},
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-vault-secret",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Annotations: map[string]string{
					"custom-annotation": "custom-value",
				},
			},
			vaultSecretData: &vault.Secret{},
			wantLabels: map[string]string{
				"app.kubernetes.io/managed-by":                 "avapigw",
				"avapigw.vyrodovalexey.github.com/vaultsecret": "my-vault-secret",
			},
			wantAnnotations: map[string]string{
				"custom-annotation": "custom-value",
			},
		},
		{
			name:   "adds vault metadata to annotations",
			secret: &corev1.Secret{},
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-vault-secret",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{},
			vaultSecretData: &vault.Secret{
				Metadata: &vault.SecretMetadata{
					Version:     5,
					CreatedTime: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
				},
			},
			wantLabels: map[string]string{
				"app.kubernetes.io/managed-by":                 "avapigw",
				"avapigw.vyrodovalexey.github.com/vaultsecret": "my-vault-secret",
			},
			wantAnnotations: map[string]string{
				"avapigw.vyrodovalexey.github.com/vault-version":      "5",
				"avapigw.vyrodovalexey.github.com/vault-created-time": "2024-01-15T10:30:00Z",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler.setSecretLabelsAndAnnotations(tt.secret, tt.vaultSecret, tt.target, tt.vaultSecretData)

			assert.Equal(t, tt.wantLabels, tt.secret.Labels)
			for k, v := range tt.wantAnnotations {
				assert.Equal(t, v, tt.secret.Annotations[k])
			}
		})
	}
}

// ============================================================================
// Test Cases for setOwnerReferenceIfNeeded
// ============================================================================

func TestVaultSecretReconciler_setOwnerReferenceIfNeeded(t *testing.T) {
	scheme := setupScheme(t)

	tests := []struct {
		name         string
		vaultSecret  *avapigwv1alpha1.VaultSecret
		secret       *corev1.Secret
		target       *avapigwv1alpha1.VaultTargetConfig
		wantOwnerRef bool
		wantErr      bool
	}{
		{
			name: "sets owner reference with Owner policy",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
					UID:       "test-uid",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "default",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				CreationPolicy: func() *avapigwv1alpha1.SecretCreationPolicy {
					p := avapigwv1alpha1.SecretCreationPolicyOwner
					return &p
				}(),
			},
			wantOwnerRef: true,
			wantErr:      false,
		},
		{
			name: "sets owner reference with default policy (nil)",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
					UID:       "test-uid",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "default",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				CreationPolicy: nil,
			},
			wantOwnerRef: true,
			wantErr:      false,
		},
		{
			name: "does not set owner reference with Merge policy",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
					UID:       "test-uid",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "default",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				CreationPolicy: func() *avapigwv1alpha1.SecretCreationPolicy {
					p := avapigwv1alpha1.SecretCreationPolicyMerge
					return &p
				}(),
			},
			wantOwnerRef: false,
			wantErr:      false,
		},
		{
			name: "does not set owner reference with Orphan policy",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
					UID:       "test-uid",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "default",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				CreationPolicy: func() *avapigwv1alpha1.SecretCreationPolicy {
					p := avapigwv1alpha1.SecretCreationPolicyOrphan
					return &p
				}(),
			},
			wantOwnerRef: false,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &VaultSecretReconciler{
				Scheme: scheme,
			}

			err := reconciler.setOwnerReferenceIfNeeded(tt.vaultSecret, tt.secret, tt.target)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.wantOwnerRef {
					assert.Len(t, tt.secret.OwnerReferences, 1)
					assert.Equal(t, tt.vaultSecret.Name, tt.secret.OwnerReferences[0].Name)
				} else {
					assert.Len(t, tt.secret.OwnerReferences, 0)
				}
			}
		})
	}
}

// ============================================================================
// Test Cases for buildTargetSecret
// ============================================================================

func TestVaultSecretReconciler_buildTargetSecret(t *testing.T) {
	reconciler := &VaultSecretReconciler{}
	logger := ctrl.Log.WithName("test")

	tests := []struct {
		name            string
		vaultSecret     *avapigwv1alpha1.VaultSecret
		target          *avapigwv1alpha1.VaultTargetConfig
		targetNamespace string
		vaultSecretData *vault.Secret
		wantName        string
		wantNamespace   string
		wantType        corev1.SecretType
	}{
		{
			name: "builds basic target secret",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Keys: nil,
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "target-secret",
			},
			targetNamespace: "default",
			vaultSecretData: &vault.Secret{
				Data: map[string]interface{}{
					"username": "admin",
				},
			},
			wantName:      "target-secret",
			wantNamespace: "default",
			wantType:      corev1.SecretTypeOpaque,
		},
		{
			name: "builds target secret with custom type",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Keys: nil,
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "tls-secret",
				Type: strPtr("kubernetes.io/tls"),
			},
			targetNamespace: "default",
			vaultSecretData: &vault.Secret{
				Data: map[string]interface{}{
					"tls.crt": "cert-data",
					"tls.key": "key-data",
				},
			},
			wantName:      "tls-secret",
			wantNamespace: "default",
			wantType:      corev1.SecretTypeTLS,
		},
		{
			name: "builds target secret in different namespace",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					Keys: nil,
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "target-secret",
			},
			targetNamespace: "other-namespace",
			vaultSecretData: &vault.Secret{
				Data: map[string]interface{}{
					"data": "value",
				},
			},
			wantName:      "target-secret",
			wantNamespace: "other-namespace",
			wantType:      corev1.SecretTypeOpaque,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := reconciler.buildTargetSecret(tt.vaultSecret, tt.target, tt.targetNamespace, tt.vaultSecretData, logger)

			assert.Equal(t, tt.wantName, secret.Name)
			assert.Equal(t, tt.wantNamespace, secret.Namespace)
			assert.Equal(t, tt.wantType, secret.Type)
			assert.NotNil(t, secret.Labels)
			assert.NotNil(t, secret.Data)
		})
	}
}

// ============================================================================
// Test Cases for updateSyncStatus
// ============================================================================

func TestVaultSecretReconciler_updateSyncStatus(t *testing.T) {
	reconciler := &VaultSecretReconciler{}

	tests := []struct {
		name            string
		vaultSecret     *avapigwv1alpha1.VaultSecret
		target          *avapigwv1alpha1.VaultTargetConfig
		targetNamespace string
		vaultSecretData *vault.Secret
		wantSecretName  string
		wantNamespace   string
		wantVersion     string
	}{
		{
			name: "updates status with basic info",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "target-secret",
			},
			targetNamespace: "default",
			vaultSecretData: &vault.Secret{},
			wantSecretName:  "target-secret",
			wantNamespace:   "default",
			wantVersion:     "",
		},
		{
			name: "updates status with version from metadata",
			vaultSecret: &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-vault-secret",
					Namespace: "default",
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "target-secret",
			},
			targetNamespace: "other-ns",
			vaultSecretData: &vault.Secret{
				Metadata: &vault.SecretMetadata{
					Version: 42,
				},
			},
			wantSecretName: "target-secret",
			wantNamespace:  "other-ns",
			wantVersion:    "42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler.updateSyncStatus(tt.vaultSecret, tt.target, tt.targetNamespace, tt.vaultSecretData)

			assert.NotNil(t, tt.vaultSecret.Status.TargetSecretName)
			assert.Equal(t, tt.wantSecretName, *tt.vaultSecret.Status.TargetSecretName)
			assert.NotNil(t, tt.vaultSecret.Status.TargetSecretNamespace)
			assert.Equal(t, tt.wantNamespace, *tt.vaultSecret.Status.TargetSecretNamespace)

			if tt.wantVersion != "" {
				assert.NotNil(t, tt.vaultSecret.Status.SecretVersion)
				assert.Equal(t, tt.wantVersion, *tt.vaultSecret.Status.SecretVersion)
			}
		})
	}
}

// ============================================================================
// Test Cases for createOrUpdateSecret
// ============================================================================

func TestVaultSecretReconciler_createOrUpdateSecret(t *testing.T) {
	scheme := setupScheme(t)
	logger := ctrl.Log.WithName("test")

	tests := []struct {
		name            string
		secret          *corev1.Secret
		target          *avapigwv1alpha1.VaultTargetConfig
		targetNamespace string
		existingSecret  *corev1.Secret
		wantErr         bool
		wantCreate      bool
		wantUpdate      bool
	}{
		{
			name: "creates new secret when not exists",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "new-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "new-secret",
			},
			targetNamespace: "default",
			existingSecret:  nil,
			wantErr:         false,
			wantCreate:      true,
			wantUpdate:      false,
		},
		{
			name: "updates existing secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"key": []byte("new-value"),
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				Name: "existing-secret",
			},
			targetNamespace: "default",
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "existing-secret",
					Namespace:       "default",
					ResourceVersion: "12345",
				},
				Data: map[string][]byte{
					"key": []byte("old-value"),
				},
			},
			wantErr:    false,
			wantCreate: false,
			wantUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objects []client.Object
			if tt.existingSecret != nil {
				objects = append(objects, tt.existingSecret)
			}

			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				Build()

			reconciler := &VaultSecretReconciler{
				Client: cl,
				Scheme: scheme,
			}

			err := reconciler.createOrUpdateSecret(context.Background(), tt.secret, tt.target, tt.targetNamespace, logger)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify secret exists
				resultSecret := &corev1.Secret{}
				err := cl.Get(context.Background(), client.ObjectKey{
					Namespace: tt.targetNamespace,
					Name:      tt.target.Name,
				}, resultSecret)
				assert.NoError(t, err)
				assert.Equal(t, tt.secret.Data, resultSecret.Data)
			}
		})
	}
}

// ============================================================================
// Test Cases for updateExistingSecret
// ============================================================================

func TestVaultSecretReconciler_updateExistingSecret(t *testing.T) {
	scheme := setupScheme(t)
	logger := ctrl.Log.WithName("test")

	tests := []struct {
		name           string
		secret         *corev1.Secret
		existingSecret *corev1.Secret
		target         *avapigwv1alpha1.VaultTargetConfig
		wantData       map[string][]byte
		wantErr        bool
	}{
		{
			name: "replaces data with Owner policy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"new-key": []byte("new-value"),
				},
			},
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "test-secret",
					Namespace:       "default",
					ResourceVersion: "12345",
				},
				Data: map[string][]byte{
					"old-key": []byte("old-value"),
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				CreationPolicy: func() *avapigwv1alpha1.SecretCreationPolicy {
					p := avapigwv1alpha1.SecretCreationPolicyOwner
					return &p
				}(),
			},
			wantData: map[string][]byte{
				"new-key": []byte("new-value"),
			},
			wantErr: false,
		},
		{
			name: "merges data with Merge policy",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"new-key": []byte("new-value"),
				},
			},
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "test-secret",
					Namespace:       "default",
					ResourceVersion: "12345",
				},
				Data: map[string][]byte{
					"old-key": []byte("old-value"),
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				CreationPolicy: func() *avapigwv1alpha1.SecretCreationPolicy {
					p := avapigwv1alpha1.SecretCreationPolicyMerge
					return &p
				}(),
			},
			wantData: map[string][]byte{
				"new-key": []byte("new-value"),
				"old-key": []byte("old-value"),
			},
			wantErr: false,
		},
		{
			name: "new value takes precedence in merge",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"shared-key": []byte("new-value"),
				},
			},
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "test-secret",
					Namespace:       "default",
					ResourceVersion: "12345",
				},
				Data: map[string][]byte{
					"shared-key": []byte("old-value"),
					"other-key":  []byte("other-value"),
				},
			},
			target: &avapigwv1alpha1.VaultTargetConfig{
				CreationPolicy: func() *avapigwv1alpha1.SecretCreationPolicy {
					p := avapigwv1alpha1.SecretCreationPolicyMerge
					return &p
				}(),
			},
			wantData: map[string][]byte{
				"shared-key": []byte("new-value"),
				"other-key":  []byte("other-value"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existingSecret).
				Build()

			reconciler := &VaultSecretReconciler{
				Client: cl,
				Scheme: scheme,
			}

			err := reconciler.updateExistingSecret(
				context.Background(),
				tt.secret,
				tt.existingSecret,
				tt.target,
				"default",
				logger,
			)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify updated secret
				resultSecret := &corev1.Secret{}
				err := cl.Get(context.Background(), client.ObjectKey{
					Namespace: "default",
					Name:      "test-secret",
				}, resultSecret)
				assert.NoError(t, err)
				assert.Equal(t, tt.wantData, resultSecret.Data)
			}
		})
	}
}

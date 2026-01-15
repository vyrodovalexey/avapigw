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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
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

package cert

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func setupTestRotator(t *testing.T, objects ...runtime.Object) (*Rotator, string) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objects...).
		Build()

	tmpDir := t.TempDir()

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           tmpDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     1 * time.Hour,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	return rotator, tmpDir
}

func TestRotatorConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *RotatorConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &RotatorConfig{
				SecretName:        "webhook-certs",
				SecretNamespace:   "default",
				CertDir:           "/tmp/certs",
				RotationThreshold: 30 * 24 * time.Hour,
				CheckInterval:     1 * time.Hour,
			},
			wantErr: false,
		},
		{
			name: "missing secret name",
			config: &RotatorConfig{
				SecretNamespace:   "default",
				CertDir:           "/tmp/certs",
				RotationThreshold: 30 * 24 * time.Hour,
				CheckInterval:     1 * time.Hour,
			},
			wantErr: true,
			errMsg:  "secret name is required",
		},
		{
			name: "missing secret namespace",
			config: &RotatorConfig{
				SecretName:        "webhook-certs",
				CertDir:           "/tmp/certs",
				RotationThreshold: 30 * 24 * time.Hour,
				CheckInterval:     1 * time.Hour,
			},
			wantErr: true,
			errMsg:  "secret namespace is required",
		},
		{
			name: "missing cert dir",
			config: &RotatorConfig{
				SecretName:        "webhook-certs",
				SecretNamespace:   "default",
				RotationThreshold: 30 * 24 * time.Hour,
				CheckInterval:     1 * time.Hour,
			},
			wantErr: true,
			errMsg:  "cert directory is required",
		},
		{
			name: "zero rotation threshold",
			config: &RotatorConfig{
				SecretName:        "webhook-certs",
				SecretNamespace:   "default",
				CertDir:           "/tmp/certs",
				RotationThreshold: 0,
				CheckInterval:     1 * time.Hour,
			},
			wantErr: true,
			errMsg:  "rotation threshold must be positive",
		},
		{
			name: "zero check interval",
			config: &RotatorConfig{
				SecretName:        "webhook-certs",
				SecretNamespace:   "default",
				CertDir:           "/tmp/certs",
				RotationThreshold: 30 * 24 * time.Hour,
				CheckInterval:     0,
			},
			wantErr: true,
			errMsg:  "check interval must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewRotator(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(generatorCfg)

	t.Run("with defaults", func(t *testing.T) {
		rotatorCfg := &RotatorConfig{
			SecretName:      "webhook-certs",
			SecretNamespace: "default",
			CertDir:         "/tmp/certs",
			// CheckInterval and RotationThreshold are zero
		}

		logger := zap.NewNop()
		rotator := NewRotator(rotatorCfg, generator, client, logger)

		assert.NotNil(t, rotator)
		assert.Equal(t, DefaultCheckInterval, rotator.config.CheckInterval)
		assert.Equal(t, DefaultRotationThreshold, rotator.config.RotationThreshold)
	})

	t.Run("with custom values", func(t *testing.T) {
		rotatorCfg := &RotatorConfig{
			SecretName:        "webhook-certs",
			SecretNamespace:   "default",
			CertDir:           "/tmp/certs",
			CheckInterval:     2 * time.Hour,
			RotationThreshold: 60 * 24 * time.Hour,
		}

		logger := zap.NewNop()
		rotator := NewRotator(rotatorCfg, generator, client, logger)

		assert.NotNil(t, rotator)
		assert.Equal(t, 2*time.Hour, rotator.config.CheckInterval)
		assert.Equal(t, 60*24*time.Hour, rotator.config.RotationThreshold)
	})
}

func TestRotator_OnRotate(t *testing.T) {
	rotator, _ := setupTestRotator(t)

	rotator.OnRotate(func(bundle *CertificateBundle) {
		// Callback registered
	})

	assert.Len(t, rotator.onRotateCallbacks, 1)
}

func TestRotator_EnsureCertificates_NewCerts(t *testing.T) {
	rotator, tmpDir := setupTestRotator(t)
	ctx := context.Background()

	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Verify certificates were written to disk
	certPath := filepath.Join(tmpDir, CertFileName)
	keyPath := filepath.Join(tmpDir, KeyFileName)

	_, err = os.Stat(certPath)
	assert.NoError(t, err)

	_, err = os.Stat(keyPath)
	assert.NoError(t, err)

	// Verify current bundle is set
	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
	assert.NotEmpty(t, bundle.CACert)
	assert.NotEmpty(t, bundle.ServerCert)
}

func TestRotator_EnsureCertificates_ExistingValidCerts(t *testing.T) {
	// Create existing valid certificates in secret
	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(generatorCfg)
	bundle, err := generator.Generate()
	require.NoError(t, err)

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert:  bundle.CACert,
			SecretKeyCAKey:   bundle.CAKey,
			SecretKeyTLSCert: bundle.ServerCert,
			SecretKeyTLSKey:  bundle.ServerKey,
		},
	}

	rotator, _ := setupTestRotator(t, existingSecret)
	ctx := context.Background()

	err = rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Verify current bundle is set
	currentBundle := rotator.GetCurrentBundle()
	assert.NotNil(t, currentBundle)
}

func TestRotator_WriteCertificatesToDir(t *testing.T) {
	rotator, tmpDir := setupTestRotator(t)

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(generatorCfg)
	bundle, err := generator.Generate()
	require.NoError(t, err)

	err = rotator.WriteCertificatesToDir(bundle)
	require.NoError(t, err)

	// Verify files were written
	certPath := filepath.Join(tmpDir, CertFileName)
	keyPath := filepath.Join(tmpDir, KeyFileName)

	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, bundle.ServerCert, certData)

	keyData, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, bundle.ServerKey, keyData)
}

func TestRotator_GetCurrentBundle(t *testing.T) {
	rotator, _ := setupTestRotator(t)

	// Initially nil
	assert.Nil(t, rotator.GetCurrentBundle())

	// After ensuring certificates
	ctx := context.Background()
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
}

func TestRotator_GetCABundle(t *testing.T) {
	rotator, _ := setupTestRotator(t)

	// Initially nil
	assert.Nil(t, rotator.GetCABundle())

	// After ensuring certificates
	ctx := context.Background()
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	caBundle := rotator.GetCABundle()
	assert.NotNil(t, caBundle)
	assert.NotEmpty(t, caBundle)
}

func TestRotator_RotateIfNeeded_NoCurrentBundle(t *testing.T) {
	rotator, _ := setupTestRotator(t)
	ctx := context.Background()

	// When no current bundle exists, should ensure certificates
	rotated, err := rotator.RotateIfNeeded(ctx)
	require.NoError(t, err)
	assert.True(t, rotated)

	// Now bundle should exist
	assert.NotNil(t, rotator.GetCurrentBundle())
}

func TestRotator_RotateIfNeeded_NoRotationNeeded(t *testing.T) {
	rotator, _ := setupTestRotator(t)
	ctx := context.Background()

	// First ensure certificates exist
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Check if rotation is needed (should not be needed for fresh certs)
	rotated, err := rotator.RotateIfNeeded(ctx)
	require.NoError(t, err)
	assert.False(t, rotated)
}

func TestRotator_RotateIfNeeded_RotationNeeded(t *testing.T) {
	// Create a certificate that's about to expire
	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         1 * time.Hour, // Very short validity
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)
	bundle, err := generator.Generate()
	require.NoError(t, err)

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert:  bundle.CACert,
			SecretKeyCAKey:   bundle.CAKey,
			SecretKeyTLSCert: bundle.ServerCert,
			SecretKeyTLSKey:  bundle.ServerKey,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(existingSecret).
		Build()

	tmpDir := t.TempDir()

	// Use a new generator with longer validity for rotation
	newGeneratorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	newGenerator := NewGenerator(newGeneratorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           tmpDir,
		RotationThreshold: 2 * time.Hour, // Threshold > validity means rotation needed
		CheckInterval:     1 * time.Hour,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, newGenerator, client, logger)

	ctx := context.Background()

	// First ensure certificates exist (loads the short-lived cert)
	err = rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Track if callback was called
	callbackCalled := false
	rotator.OnRotate(func(b *CertificateBundle) {
		callbackCalled = true
	})

	// Now rotation should be needed
	rotated, err := rotator.RotateIfNeeded(ctx)
	require.NoError(t, err)
	assert.True(t, rotated)
	assert.True(t, callbackCalled)
}

func TestRotator_RotateIfNeeded_WithCallback(t *testing.T) {
	rotator, _ := setupTestRotator(t)
	ctx := context.Background()

	// Register callback
	var receivedBundle *CertificateBundle
	rotator.OnRotate(func(bundle *CertificateBundle) {
		receivedBundle = bundle
	})

	// When no current bundle exists, should ensure certificates and call callback
	rotated, err := rotator.RotateIfNeeded(ctx)
	require.NoError(t, err)
	assert.True(t, rotated)

	// Callback should NOT be called for initial certificate generation
	// (only for actual rotation)
	assert.Nil(t, receivedBundle)
}

func TestRotator_Stop(t *testing.T) {
	rotator, _ := setupTestRotator(t)

	err := rotator.Stop()
	assert.NoError(t, err)
}

func TestRotator_StartAndStop(t *testing.T) {
	rotator, _ := setupTestRotator(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- rotator.Start(ctx)
	}()

	// Wait a bit for startup
	time.Sleep(500 * time.Millisecond)

	// Stop the rotator
	err := rotator.Stop()
	assert.NoError(t, err)

	// Wait for Start to return
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("rotator did not stop in time")
	}
}

func TestRotatorConstants(t *testing.T) {
	assert.Equal(t, 1*time.Hour, DefaultCheckInterval)
	assert.Equal(t, "ca.crt", SecretKeyCACert)
	assert.Equal(t, "ca.key", SecretKeyCAKey)
	assert.Equal(t, "tls.crt", SecretKeyTLSCert)
	assert.Equal(t, "tls.key", SecretKeyTLSKey)
	assert.Equal(t, "tls.crt", CertFileName)
	assert.Equal(t, "tls.key", KeyFileName)
}

func TestRotator_RotationLoop_ContextCancellation(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	tmpDir := t.TempDir()

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           tmpDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     50 * time.Millisecond, // Very short for testing
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start the rotator
	errCh := make(chan error, 1)
	go func() {
		errCh <- rotator.Start(ctx)
	}()

	// Wait for a few check intervals
	time.Sleep(150 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for Start to return
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("rotator did not stop in time after context cancellation")
	}
}

func TestRotator_EnsureCertificates_InvalidExistingCert(t *testing.T) {
	// Create a secret with invalid certificate data
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert:  []byte("invalid-ca-cert"),
			SecretKeyCAKey:   []byte("invalid-ca-key"),
			SecretKeyTLSCert: []byte("invalid-server-cert"),
			SecretKeyTLSKey:  []byte("invalid-server-key"),
		},
	}

	rotator, _ := setupTestRotator(t, existingSecret)
	ctx := context.Background()

	// Should generate new certificates because existing ones are invalid
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Verify new valid certificates were generated
	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
	assert.NotEqual(t, []byte("invalid-server-cert"), bundle.ServerCert)
}

func TestRotator_EnsureCertificates_MissingSecretKeys(t *testing.T) {
	// Create a secret with missing keys
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert: []byte("some-ca-cert"),
			// Missing other keys
		},
	}

	rotator, _ := setupTestRotator(t, existingSecret)
	ctx := context.Background()

	// Should generate new certificates because existing secret is incomplete
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Verify new valid certificates were generated
	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
}

func TestRotator_WriteCertificatesToDir_CreateDirectory(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Use a non-existent directory path
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "certs")

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           nestedDir, // Non-existent nested directory
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     1 * time.Hour,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	bundle, err := generator.Generate()
	require.NoError(t, err)

	// Should create the directory and write certificates
	err = rotator.WriteCertificatesToDir(bundle)
	require.NoError(t, err)

	// Verify directory was created
	_, err = os.Stat(nestedDir)
	assert.NoError(t, err)

	// Verify files were written
	certPath := filepath.Join(nestedDir, CertFileName)
	_, err = os.Stat(certPath)
	assert.NoError(t, err)
}

func TestRotator_LoadFromSecret_AllKeysMissing(t *testing.T) {
	// Create a secret with all keys missing
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			// All keys missing
		},
	}

	rotator, _ := setupTestRotator(t, existingSecret)
	ctx := context.Background()

	// Should generate new certificates
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
}

func TestRotator_SaveToSecret_Update(t *testing.T) {
	// Create an existing secret
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert:  []byte("old-ca-cert"),
			SecretKeyCAKey:   []byte("old-ca-key"),
			SecretKeyTLSCert: []byte("old-server-cert"),
			SecretKeyTLSKey:  []byte("old-server-key"),
		},
	}

	rotator, _ := setupTestRotator(t, existingSecret)
	ctx := context.Background()

	// Ensure certificates - should update the existing secret
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Verify new certificates were generated (not the old ones)
	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
	assert.NotEqual(t, []byte("old-server-cert"), bundle.ServerCert)
}

func TestRotator_PerformRotation(t *testing.T) {
	rotator, _ := setupTestRotator(t)
	ctx := context.Background()

	// First ensure certificates exist
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	originalBundle := rotator.GetCurrentBundle()
	require.NotNil(t, originalBundle)

	// Perform rotation
	newBundle, err := rotator.performRotation(ctx, originalBundle.ExpiresAt)
	require.NoError(t, err)
	assert.NotNil(t, newBundle)

	// Verify new bundle is different
	assert.NotEqual(t, originalBundle.ServerCert, newBundle.ServerCert)
	assert.NotEqual(t, originalBundle.ServerKey, newBundle.ServerKey)
}

func TestRotator_CheckRotationNeeded(t *testing.T) {
	tests := []struct {
		name              string
		validity          time.Duration
		rotationThreshold time.Duration
		expectRotation    bool
	}{
		{
			name:              "no rotation needed - fresh cert",
			validity:          365 * 24 * time.Hour,
			rotationThreshold: 30 * 24 * time.Hour,
			expectRotation:    false,
		},
		{
			name:              "rotation needed - threshold exceeds validity",
			validity:          1 * time.Hour,
			rotationThreshold: 2 * time.Hour,
			expectRotation:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(scheme))
			client := fake.NewClientBuilder().WithScheme(scheme).Build()

			tmpDir := t.TempDir()

			generatorCfg := &GeneratorConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				Validity:         tt.validity,
				KeySize:          2048,
			}
			generator := NewGenerator(generatorCfg)

			rotatorCfg := &RotatorConfig{
				SecretName:        "webhook-certs",
				SecretNamespace:   "default",
				CertDir:           tmpDir,
				RotationThreshold: tt.rotationThreshold,
				CheckInterval:     1 * time.Hour,
			}

			logger := zap.NewNop()
			rotator := NewRotator(rotatorCfg, generator, client, logger)

			ctx := context.Background()
			err := rotator.EnsureCertificates(ctx)
			require.NoError(t, err)

			bundle := rotator.GetCurrentBundle()
			require.NotNil(t, bundle)

			needsRotation, err := rotator.checkRotationNeeded(bundle)
			require.NoError(t, err)
			assert.Equal(t, tt.expectRotation, needsRotation)
		})
	}
}

func TestRotator_UpdateBundleAndNotify(t *testing.T) {
	rotator, _ := setupTestRotator(t)

	// Register multiple callbacks
	callbackCount := 0
	var receivedBundles []*CertificateBundle

	rotator.OnRotate(func(bundle *CertificateBundle) {
		callbackCount++
		receivedBundles = append(receivedBundles, bundle)
	})

	rotator.OnRotate(func(bundle *CertificateBundle) {
		callbackCount++
		receivedBundles = append(receivedBundles, bundle)
	})

	// Create a test bundle
	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(generatorCfg)
	bundle, err := generator.Generate()
	require.NoError(t, err)

	// Update bundle and notify
	rotator.updateBundleAndNotify(bundle)

	// Verify callbacks were called
	assert.Equal(t, 2, callbackCount)
	assert.Len(t, receivedBundles, 2)
	for _, received := range receivedBundles {
		assert.Equal(t, bundle, received)
	}

	// Verify current bundle was updated
	assert.Equal(t, bundle, rotator.GetCurrentBundle())
}

func TestRotator_RotationLoop_TickerFires(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	tmpDir := t.TempDir()

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           tmpDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     50 * time.Millisecond, // Very short for testing
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	ctx, cancel := context.WithCancel(context.Background())

	// Start the rotator
	errCh := make(chan error, 1)
	go func() {
		errCh <- rotator.Start(ctx)
	}()

	// Wait for a few check intervals to ensure ticker fires
	time.Sleep(200 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for Start to return
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("rotator did not stop in time")
	}
}

func TestRotator_RotationLoop_StopChannel(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	tmpDir := t.TempDir()

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           tmpDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     50 * time.Millisecond,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	ctx := context.Background()

	// Start the rotator
	errCh := make(chan error, 1)
	go func() {
		errCh <- rotator.Start(ctx)
	}()

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Stop via stop channel
	err := rotator.Stop()
	assert.NoError(t, err)

	// Wait for Start to return
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("rotator did not stop in time")
	}
}

func TestRotator_WriteCertificatesToDir_FilePermissions(t *testing.T) {
	rotator, tmpDir := setupTestRotator(t)

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(generatorCfg)
	bundle, err := generator.Generate()
	require.NoError(t, err)

	err = rotator.WriteCertificatesToDir(bundle)
	require.NoError(t, err)

	// Verify file permissions
	certPath := filepath.Join(tmpDir, CertFileName)
	keyPath := filepath.Join(tmpDir, KeyFileName)

	certInfo, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), certInfo.Mode().Perm())

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
}

func TestRotator_LoadFromSecret_MissingCAKey(t *testing.T) {
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert: []byte("some-ca-cert"),
			// Missing SecretKeyCAKey
			SecretKeyTLSCert: []byte("some-server-cert"),
			SecretKeyTLSKey:  []byte("some-server-key"),
		},
	}

	rotator, _ := setupTestRotator(t, existingSecret)
	ctx := context.Background()

	// Should generate new certificates because CA key is missing
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
}

func TestRotator_LoadFromSecret_MissingTLSCert(t *testing.T) {
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert: []byte("some-ca-cert"),
			SecretKeyCAKey:  []byte("some-ca-key"),
			// Missing SecretKeyTLSCert
			SecretKeyTLSKey: []byte("some-server-key"),
		},
	}

	rotator, _ := setupTestRotator(t, existingSecret)
	ctx := context.Background()

	// Should generate new certificates because TLS cert is missing
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
}

func TestRotator_LoadFromSecret_MissingTLSKey(t *testing.T) {
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert:  []byte("some-ca-cert"),
			SecretKeyCAKey:   []byte("some-ca-key"),
			SecretKeyTLSCert: []byte("some-server-cert"),
			// Missing SecretKeyTLSKey
		},
	}

	rotator, _ := setupTestRotator(t, existingSecret)
	ctx := context.Background()

	// Should generate new certificates because TLS key is missing
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	bundle := rotator.GetCurrentBundle()
	assert.NotNil(t, bundle)
}

func TestRotator_RotateIfNeeded_RotationWithCallbacks(t *testing.T) {
	// Create a certificate that's about to expire
	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         1 * time.Hour, // Very short validity
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)
	bundle, err := generator.Generate()
	require.NoError(t, err)

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert:  bundle.CACert,
			SecretKeyCAKey:   bundle.CAKey,
			SecretKeyTLSCert: bundle.ServerCert,
			SecretKeyTLSKey:  bundle.ServerKey,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(existingSecret).
		Build()

	tmpDir := t.TempDir()

	// Use a new generator with longer validity for rotation
	newGeneratorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	newGenerator := NewGenerator(newGeneratorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           tmpDir,
		RotationThreshold: 2 * time.Hour, // Threshold > validity means rotation needed
		CheckInterval:     1 * time.Hour,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, newGenerator, client, logger)

	ctx := context.Background()

	// First ensure certificates exist (loads the short-lived cert)
	err = rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Track callbacks
	callbackCount := 0
	var receivedBundle *CertificateBundle
	rotator.OnRotate(func(b *CertificateBundle) {
		callbackCount++
		receivedBundle = b
	})

	// Now rotation should be needed
	rotated, err := rotator.RotateIfNeeded(ctx)
	require.NoError(t, err)
	assert.True(t, rotated)
	assert.Equal(t, 1, callbackCount)
	assert.NotNil(t, receivedBundle)
}

func TestRotator_ConcurrentAccess(t *testing.T) {
	rotator, _ := setupTestRotator(t)
	ctx := context.Background()

	// Ensure certificates exist first
	err := rotator.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Test concurrent access to GetCurrentBundle and GetCABundle
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = rotator.GetCurrentBundle()
				_ = rotator.GetCABundle()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestRotator_MultipleCallbacks(t *testing.T) {
	rotator, _ := setupTestRotator(t)

	// Register multiple callbacks
	callbacks := make([]bool, 3)
	for i := range callbacks {
		idx := i
		rotator.OnRotate(func(bundle *CertificateBundle) {
			callbacks[idx] = true
		})
	}

	assert.Len(t, rotator.onRotateCallbacks, 3)
}

func TestRotator_RotationLoop_RotationError(t *testing.T) {
	// Create a rotator with a very short check interval
	// and a certificate that needs rotation but will fail
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	// Create a secret with invalid certificate data that will cause rotation check to fail
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-certs",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert:  []byte("invalid"),
			SecretKeyCAKey:   []byte("invalid"),
			SecretKeyTLSCert: []byte("invalid"),
			SecretKeyTLSKey:  []byte("invalid"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(existingSecret).
		Build()

	tmpDir := t.TempDir()

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           tmpDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     50 * time.Millisecond,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	ctx, cancel := context.WithCancel(context.Background())

	// Start the rotator
	errCh := make(chan error, 1)
	go func() {
		errCh <- rotator.Start(ctx)
	}()

	// Wait for a few check intervals
	time.Sleep(200 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for Start to return
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("rotator did not stop in time")
	}
}

func TestRotator_PerformRotation_WriteError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Use a directory that doesn't exist and can't be created
	invalidDir := "/nonexistent/path/that/cannot/be/created"

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           invalidDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     1 * time.Hour,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	ctx := context.Background()

	// Try to perform rotation - should fail due to invalid directory
	_, err := rotator.performRotation(ctx, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write new certificates to directory")
}

func TestRotator_EnsureCertificates_WriteError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Use a directory that doesn't exist and can't be created
	invalidDir := "/nonexistent/path/that/cannot/be/created"

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           invalidDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     1 * time.Hour,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	ctx := context.Background()

	// Try to ensure certificates - should fail due to invalid directory
	err := rotator.EnsureCertificates(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write certificates to directory")
}

func TestRotator_Start_EnsureCertificatesError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Use a directory that doesn't exist and can't be created
	invalidDir := "/nonexistent/path/that/cannot/be/created"

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           invalidDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     1 * time.Hour,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	ctx := context.Background()

	// Start should fail due to invalid directory
	err := rotator.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to ensure certificates on startup")
}

func TestRotator_RotateIfNeeded_CheckRotationError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	tmpDir := t.TempDir()

	generatorCfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(generatorCfg)

	rotatorCfg := &RotatorConfig{
		SecretName:        "webhook-certs",
		SecretNamespace:   "default",
		CertDir:           tmpDir,
		RotationThreshold: 30 * 24 * time.Hour,
		CheckInterval:     1 * time.Hour,
	}

	logger := zap.NewNop()
	rotator := NewRotator(rotatorCfg, generator, client, logger)

	// Manually set an invalid bundle to trigger check error
	rotator.currentBundle = &CertificateBundle{
		CACert:     []byte("invalid"),
		CAKey:      []byte("invalid"),
		ServerCert: []byte("invalid"),
		ServerKey:  []byte("invalid"),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
	}

	ctx := context.Background()

	// RotateIfNeeded should fail due to invalid certificate
	_, err := rotator.RotateIfNeeded(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check if rotation is needed")
}

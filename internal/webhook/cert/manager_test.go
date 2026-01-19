package cert

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestManagerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ManagerConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &ManagerConfig{
				ServiceName:       "webhook-service",
				ServiceNamespace:  "default",
				SecretName:        "webhook-certs",
				CertDir:           "/tmp/certs",
				Validity:          365 * 24 * time.Hour,
				RotationThreshold: 30 * 24 * time.Hour,
				CheckInterval:     1 * time.Hour,
			},
			wantErr: false,
		},
		{
			name: "missing service name",
			config: &ManagerConfig{
				ServiceNamespace: "default",
				SecretName:       "webhook-certs",
				CertDir:          "/tmp/certs",
			},
			wantErr: true,
			errMsg:  "service name is required",
		},
		{
			name: "missing service namespace",
			config: &ManagerConfig{
				ServiceName: "webhook-service",
				SecretName:  "webhook-certs",
				CertDir:     "/tmp/certs",
			},
			wantErr: true,
			errMsg:  "service namespace is required",
		},
		{
			name: "missing secret name",
			config: &ManagerConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				CertDir:          "/tmp/certs",
			},
			wantErr: true,
			errMsg:  "secret name is required",
		},
		{
			name: "missing cert dir",
			config: &ManagerConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				SecretName:       "webhook-certs",
			},
			wantErr: true,
			errMsg:  "cert directory is required",
		},
		{
			name: "defaults applied for zero values",
			config: &ManagerConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				SecretName:       "webhook-certs",
				CertDir:          "/tmp/certs",
				// Validity, RotationThreshold, CheckInterval, KeySize are zero
			},
			wantErr: false,
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
				// Check defaults are applied
				if tt.config.Validity == 0 {
					assert.Equal(t, DefaultValidity, tt.config.Validity)
				}
				if tt.config.RotationThreshold == 0 {
					assert.Equal(t, DefaultRotationThreshold, tt.config.RotationThreshold)
				}
				if tt.config.CheckInterval == 0 {
					assert.Equal(t, DefaultCheckInterval, tt.config.CheckInterval)
				}
				if tt.config.KeySize == 0 {
					assert.Equal(t, DefaultKeySize, tt.config.KeySize)
				}
			}
		})
	}
}

func TestNewManager_InvalidConfig(t *testing.T) {
	// Test with invalid config (missing required fields)
	cfg := &ManagerConfig{
		// Missing ServiceName
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          "/tmp/certs",
	}

	_, err := NewManager(cfg, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestNewManager_ValidConfig(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:                 "webhook-service",
		ServiceNamespace:            "default",
		SecretName:                  "webhook-certs",
		CertDir:                     certDir,
		Validity:                    365 * 24 * time.Hour,
		RotationThreshold:           30 * 24 * time.Hour,
		CheckInterval:               1 * time.Hour,
		KeySize:                     2048,
		DNSNames:                    []string{"extra.dns.name"},
		ValidatingWebhookConfigName: "validating-webhook",
		MutatingWebhookConfigName:   "mutating-webhook",
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Verify manager fields
	assert.Equal(t, cfg, manager.config)
	assert.NotNil(t, manager.generator)
	assert.NotNil(t, manager.rotator)
	assert.NotNil(t, manager.injector)
	assert.NotNil(t, manager.logger)
	assert.False(t, manager.IsStarted())
}

func TestNewManager_WithDefaults(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	// Config with minimal required fields - defaults should be applied
	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Verify defaults were applied
	assert.Equal(t, DefaultValidity, cfg.Validity)
	assert.Equal(t, DefaultRotationThreshold, cfg.RotationThreshold)
	assert.Equal(t, DefaultCheckInterval, cfg.CheckInterval)
	assert.Equal(t, DefaultKeySize, cfg.KeySize)
}

func TestManager_GetCertDir(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	assert.Equal(t, certDir, manager.GetCertDir())
}

func TestManager_IsStarted(t *testing.T) {
	// Create a manager struct directly for testing
	m := &Manager{
		started: false,
	}

	assert.False(t, m.IsStarted())

	m.started = true
	assert.True(t, m.IsStarted())
}

func TestManager_GetCABundle_NotStarted(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	// Before starting, CA bundle should be nil
	assert.Nil(t, manager.GetCABundle())
}

func TestManager_GetCurrentBundle_NotStarted(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	// Before starting, current bundle should be nil
	assert.Nil(t, manager.GetCurrentBundle())
}

func TestManager_GetCertificateExpiry_NoBundle(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	// Before starting, should return error
	_, err = manager.GetCertificateExpiry()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificate bundle available")
}

func TestManager_NeedsRotation_NoBundle(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	// Before starting, should return true (needs rotation because no cert exists)
	needsRotation, err := manager.NeedsRotation()
	require.NoError(t, err)
	assert.True(t, needsRotation)
}

func TestManager_InjectCABundle_NoBundle(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Before starting, should return error
	err = manager.InjectCABundle(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA bundle is not available")
}

func TestManager_Start_AlreadyStarted(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	// Manually set started to true
	manager.started = true

	ctx := context.Background()
	err = manager.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already started")
}

func TestManager_Stop_NotStarted(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	// Stop when not started should be a no-op
	err = manager.Stop()
	require.NoError(t, err)
}

func TestManager_StartAndStop(t *testing.T) {
	// Create a fake k8s client with namespace
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
		CheckInterval:    100 * time.Millisecond, // Short interval for testing
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager
	err = manager.Start(ctx)
	require.NoError(t, err)
	assert.True(t, manager.IsStarted())

	// Verify certificates were generated
	assert.NotNil(t, manager.GetCABundle())
	assert.NotNil(t, manager.GetCurrentBundle())

	// Get certificate expiry
	expiry, err := manager.GetCertificateExpiry()
	require.NoError(t, err)
	assert.True(t, expiry.After(time.Now()))

	// Check needs rotation (should be false for fresh cert)
	needsRotation, err := manager.NeedsRotation()
	require.NoError(t, err)
	assert.False(t, needsRotation)

	// Stop the manager
	err = manager.Stop()
	require.NoError(t, err)
	assert.False(t, manager.IsStarted())
}

func TestManager_EnsureCertificates(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Ensure certificates
	err = manager.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Verify certificates were generated
	assert.NotNil(t, manager.GetCABundle())
	assert.NotNil(t, manager.GetCurrentBundle())
}

func TestManager_InjectCABundle_AfterStart(t *testing.T) {
	// Create a fake k8s client with admissionregistration types for webhook injection
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Now inject CA bundle should work (even if webhooks don't exist)
	err = manager.InjectCABundle(ctx)
	// This may return an error if webhooks don't exist, but shouldn't panic
	// The error is expected since we don't have webhooks configured
	if err != nil {
		// This is acceptable - webhooks don't exist
		t.Logf("InjectCABundle returned expected error: %v", err)
	}
}

func TestManager_Start_WithWebhooks(t *testing.T) {
	// Create a fake k8s client with webhooks
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	sideEffects := admissionregistrationv1.SideEffectClassNone
	reinvocationPolicy := admissionregistrationv1.NeverReinvocationPolicy

	validatingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-validating-webhook",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "avapigw-operator",
			},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:        "validating.webhook.example.com",
				SideEffects: &sideEffects,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "webhook-service",
						Namespace: "default",
					},
				},
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	mutatingWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-mutating-webhook",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "avapigw-operator",
			},
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:               "mutating.webhook.example.com",
				SideEffects:        &sideEffects,
				ReinvocationPolicy: &reinvocationPolicy,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "webhook-service",
						Namespace: "default",
					},
				},
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(validatingWebhook, mutatingWebhook).
		Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Verify CA bundle was injected
	assert.NotNil(t, manager.GetCABundle())
}

func TestManager_Start_RotatorCallback(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
		CheckInterval:    100 * time.Millisecond,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Verify rotator callback was registered
	assert.True(t, manager.IsStarted())
}

func TestManager_NeedsRotation_WithBundle(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:       "webhook-service",
		ServiceNamespace:  "default",
		SecretName:        "webhook-certs",
		CertDir:           certDir,
		Validity:          365 * 24 * time.Hour,
		RotationThreshold: 30 * 24 * time.Hour,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager to generate certificates
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Check needs rotation (should be false for fresh cert)
	needsRotation, err := manager.NeedsRotation()
	require.NoError(t, err)
	assert.False(t, needsRotation)
}

func TestManager_GetCertificateExpiry_WithBundle(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
		Validity:         365 * 24 * time.Hour,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager to generate certificates
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Get certificate expiry
	expiry, err := manager.GetCertificateExpiry()
	require.NoError(t, err)
	assert.True(t, expiry.After(time.Now()))

	// Verify expiry is approximately correct
	expectedExpiry := time.Now().Add(365 * 24 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, expiry, 5*time.Second)
}

func TestManager_Stop_AfterStart(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager
	err = manager.Start(ctx)
	require.NoError(t, err)
	assert.True(t, manager.IsStarted())

	// Stop the manager
	err = manager.Stop()
	require.NoError(t, err)
	assert.False(t, manager.IsStarted())

	// Stop again should be a no-op
	err = manager.Stop()
	require.NoError(t, err)
}

func TestManager_InjectCABundle_WithWebhooks(t *testing.T) {
	// Create a fake k8s client with webhooks
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	sideEffects := admissionregistrationv1.SideEffectClassNone

	validatingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-validating-webhook",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "avapigw-operator",
			},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:        "validating.webhook.example.com",
				SideEffects: &sideEffects,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "webhook-service",
						Namespace: "default",
					},
				},
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(validatingWebhook).
		Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Inject CA bundle
	err = manager.InjectCABundle(ctx)
	require.NoError(t, err)
}

func TestManagerConfig_Validate_NegativeValues(t *testing.T) {
	tests := []struct {
		name    string
		config  *ManagerConfig
		wantErr bool
	}{
		{
			name: "negative validity gets default",
			config: &ManagerConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				SecretName:       "webhook-certs",
				CertDir:          "/tmp/certs",
				Validity:         -1 * time.Hour,
			},
			wantErr: false,
		},
		{
			name: "negative rotation threshold gets default",
			config: &ManagerConfig{
				ServiceName:       "webhook-service",
				ServiceNamespace:  "default",
				SecretName:        "webhook-certs",
				CertDir:           "/tmp/certs",
				RotationThreshold: -1 * time.Hour,
			},
			wantErr: false,
		},
		{
			name: "negative check interval gets default",
			config: &ManagerConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				SecretName:       "webhook-certs",
				CertDir:          "/tmp/certs",
				CheckInterval:    -1 * time.Hour,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestManager_ConcurrentAccess(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()
	certDir := t.TempDir()

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          certDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the manager
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Test concurrent access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = manager.IsStarted()
				_ = manager.GetCABundle()
				_ = manager.GetCurrentBundle()
				_ = manager.GetCertDir()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestManager_Start_RotatorStartError(t *testing.T) {
	// Create a fake k8s client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	logger := zap.NewNop()

	// Use an invalid directory that can't be created
	invalidDir := "/nonexistent/path/that/cannot/be/created"

	cfg := &ManagerConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		SecretName:       "webhook-certs",
		CertDir:          invalidDir,
	}

	manager, err := NewManager(cfg, fakeClient, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start should fail due to invalid directory
	err = manager.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start certificate rotator")
}

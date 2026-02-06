// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ============================================================================
// InjectCABundle Tests - Cover more paths
// ============================================================================

func TestWebhookCAInjector_InjectCABundle_CAChainPath(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	// Create a test webhook configuration
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook-cachain",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.webhook.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte(""),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(webhookConfig).
		Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer certManager.Close()

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook-cachain",
		CertManager:       certManager,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = injector.InjectCABundle(ctx)
	require.NoError(t, err)

	// Verify the CA bundle was updated
	caBundle := injector.GetCABundle()
	assert.NotEmpty(t, caBundle)
}

// ============================================================================
// refreshLoop Tests - Cover context cancellation
// ============================================================================

func TestWebhookCAInjector_RefreshLoop_ContextCancel(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook-refresh",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.webhook.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte(""),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(webhookConfig).
		Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer certManager.Close()

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook-refresh",
		CertManager:       certManager,
		Client:            fakeClient,
		RefreshInterval:   50 * time.Millisecond,
	})
	require.NoError(t, err)

	// Start with a context that will be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err = injector.Start(ctx)
	require.NoError(t, err)

	// Wait for context to be cancelled
	<-ctx.Done()

	// Give refresh loop time to exit
	time.Sleep(100 * time.Millisecond)
}

// ============================================================================
// refreshLoop Tests - Cover stop channel
// ============================================================================

func TestWebhookCAInjector_RefreshLoop_StopChannel(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook-stop",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.webhook.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte(""),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(webhookConfig).
		Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer certManager.Close()

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook-stop",
		CertManager:       certManager,
		Client:            fakeClient,
		RefreshInterval:   50 * time.Millisecond,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = injector.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for refresh loop to start
	time.Sleep(100 * time.Millisecond)

	// Stop the injector
	injector.Stop()

	// Give refresh loop time to exit
	time.Sleep(100 * time.Millisecond)
}

// ============================================================================
// refreshLoop Tests - Cover ticker refresh
// ============================================================================

func TestWebhookCAInjector_RefreshLoop_TickerRefresh(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook-ticker",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.webhook.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte(""),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(webhookConfig).
		Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer certManager.Close()

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook-ticker",
		CertManager:       certManager,
		Client:            fakeClient,
		RefreshInterval:   50 * time.Millisecond, // Short interval for testing
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = injector.Start(ctx)
	require.NoError(t, err)

	// Wait for at least one refresh cycle
	time.Sleep(150 * time.Millisecond)

	// Stop the injector
	injector.Stop()

	// Verify CA bundle was refreshed
	caBundle := injector.GetCABundle()
	assert.NotEmpty(t, caBundle)
}

// ============================================================================
// updateWebhookConfiguration Tests - Cover no update needed
// ============================================================================

func TestWebhookCAInjector_UpdateWebhookConfiguration_NoUpdateNeeded(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	// Create a webhook configuration with existing CA bundle
	existingCABundle := []byte("existing-ca-bundle")
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook-noupdate",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.webhook.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: existingCABundle,
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(webhookConfig).
		Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer certManager.Close()

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook-noupdate",
		CertManager:       certManager,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	// First injection
	ctx := context.Background()
	err = injector.InjectCABundle(ctx)
	require.NoError(t, err)

	// Second injection with same CA bundle should not update
	err = injector.InjectCABundle(ctx)
	require.NoError(t, err)
}

// ============================================================================
// Stop Tests - Cover double stop
// ============================================================================

func TestWebhookCAInjector_Stop_DoubleStop(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer certManager.Close()

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
		CertManager:       certManager,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	// Stop twice - should not panic
	injector.Stop()
	injector.Stop()
}

// ============================================================================
// Start Tests - Cover already stopped
// ============================================================================

func TestWebhookCAInjector_Start_AlreadyStopped(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer certManager.Close()

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
		CertManager:       certManager,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	// Stop first
	injector.Stop()

	// Try to start - should fail
	ctx := context.Background()
	err = injector.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has been stopped")
}

// ============================================================================
// InjectCABundle Tests - Cover error paths
// ============================================================================

func TestWebhookCAInjector_InjectCABundle_GetCAError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create a mock cert manager that returns an error
	mockMgr := &mockCertManagerForInjector{
		getCAErr: assert.AnError,
	}

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
		CertManager:       mockMgr,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = injector.InjectCABundle(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get CA")
}

func TestWebhookCAInjector_InjectCABundle_GetCertError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create a mock cert manager that returns an error on GetCertificate
	mockMgr := &mockCertManagerForInjector{
		getCertErr: assert.AnError,
	}

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
		CertManager:       mockMgr,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = injector.InjectCABundle(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get certificate")
}

// ============================================================================
// Start Tests - Cover initial injection failure
// ============================================================================

func TestWebhookCAInjector_Start_InitialInjectionFailure(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	// No webhook config exists - injection will fail
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)
	defer certManager.Close()

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "non-existent-webhook",
		CertManager:       certManager,
		Client:            fakeClient,
		RefreshInterval:   100 * time.Millisecond,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Start should not return error even if initial injection fails
	err = injector.Start(ctx)
	require.NoError(t, err)

	// Wait for context to be cancelled
	<-ctx.Done()

	// Stop the injector
	injector.Stop()
}

// ============================================================================
// Mock cert manager for testing
// ============================================================================

type mockCertManagerForInjector struct {
	getCertErr error
	getCAErr   error
}

func (m *mockCertManagerForInjector) GetCertificate(_ context.Context, _ *CertificateRequest) (*Certificate, error) {
	if m.getCertErr != nil {
		return nil, m.getCertErr
	}
	return &Certificate{
		CertificatePEM: []byte("test-cert"),
		PrivateKeyPEM:  []byte("test-key"),
		CAChainPEM:     []byte("test-ca-chain"),
	}, nil
}

func (m *mockCertManagerForInjector) GetCA(_ context.Context) (*x509.CertPool, error) {
	if m.getCAErr != nil {
		return nil, m.getCAErr
	}
	return x509.NewCertPool(), nil
}

func (m *mockCertManagerForInjector) RotateCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	return m.GetCertificate(ctx, req)
}

func (m *mockCertManagerForInjector) Close() error {
	return nil
}

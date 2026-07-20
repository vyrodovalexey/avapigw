// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/x509"
	"sync"
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

// TestWebhookCAInjector_InjectCABundle_GetCertError verifies that CA
// injection does NOT depend on leaf certificate issuance: a certificate
// manager whose GetCertificate fails (e.g. a restrictive Vault PKI role
// rejecting the probe common name) must still inject the CA bundle
// obtained from GetCAPEM.
func TestWebhookCAInjector_InjectCABundle_GetCertError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-webhook"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:                    "test.webhook.io",
				ClientConfig:            admissionregistrationv1.WebhookClientConfig{},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(webhookConfig).Build()

	// Cert manager with failing issuance (restrictive PKI role) but a
	// readable CA PEM.
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
	require.NoError(t, err,
		"CA injection must not require leaf certificate issuance")
	assert.Equal(t, []byte("test-ca-chain"), injector.GetCABundle(),
		"CA bundle must come from GetCAPEM")
}

// flakyCertManagerForInjector fails GetCAPEM for the first N calls, then
// succeeds — simulating the manager-client "cache is not started" window at
// operator startup.
type flakyCertManagerForInjector struct {
	mockCertManagerForInjector
	mu        sync.Mutex
	failures  int
	pemCalls  int
	succeeded bool
}

func (m *flakyCertManagerForInjector) GetCAPEM(_ context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pemCalls++
	if m.pemCalls <= m.failures {
		return nil, assert.AnError
	}
	m.succeeded = true
	return []byte("late-ca-chain"), nil
}

// TestWebhookCAInjector_Start_RetriesInitialInjection verifies the initial
// injection is retried with backoff until it succeeds, so webhooks work as
// soon as the manager cache starts instead of waiting a full
// RefreshInterval with a placeholder caBundle.
func TestWebhookCAInjector_Start_RetriesInitialInjection(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "retry-webhook"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:                    "retry.webhook.io",
				ClientConfig:            admissionregistrationv1.WebhookClientConfig{},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(webhookConfig).Build()

	mockMgr := &flakyCertManagerForInjector{failures: 2}

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "retry-webhook",
		CertManager:       mockMgr,
		Client:            fakeClient,
		RefreshInterval:   time.Hour,
	})
	require.NoError(t, err)
	defer injector.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, injector.Start(ctx))

	require.Eventually(t, func() bool {
		return len(injector.GetCABundle()) > 0
	}, 20*time.Second, 100*time.Millisecond,
		"initial injection must succeed after transient failures without waiting for the refresh interval")

	assert.Equal(t, []byte("late-ca-chain"), injector.GetCABundle())
}

// TestWebhookCAInjector_InjectWithRetry_StopsOnStop verifies Stop unparks
// the retry loop.
func TestWebhookCAInjector_InjectWithRetry_StopsOnStop(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Permanently failing manager: retry loop must exit via Stop.
	mockMgr := &mockCertManagerForInjector{getCAErr: assert.AnError}

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "never-succeeds",
		CertManager:       mockMgr,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, injector.Start(ctx))

	done := make(chan struct{})
	go func() {
		injector.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not complete while retry loop was active")
	}
}

// TestWebhookCAInjector_InjectCABundle_GetCAPEMError verifies injection
// fails cleanly when the CA PEM is unavailable.
func TestWebhookCAInjector_InjectCABundle_GetCAPEMError(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	mockMgr := &mockCertManagerForInjector{
		getCAErr: assert.AnError,
	}

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
		CertManager:       mockMgr,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	err = injector.InjectCABundle(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get CA PEM")
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

func (m *mockCertManagerForInjector) GetCAPEM(_ context.Context) ([]byte, error) {
	if m.getCAErr != nil {
		return nil, m.getCAErr
	}
	return []byte("test-ca-chain"), nil
}

func (m *mockCertManagerForInjector) RotateCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	return m.GetCertificate(ctx, req)
}

func (m *mockCertManagerForInjector) Close() error {
	return nil
}

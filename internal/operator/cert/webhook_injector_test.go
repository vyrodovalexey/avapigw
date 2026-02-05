// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewWebhookCAInjector(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)

	tests := []struct {
		name    string
		config  *WebhookInjectorConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is required",
		},
		{
			name: "missing webhook config name",
			config: &WebhookInjectorConfig{
				CertManager: certManager,
				Client:      fakeClient,
			},
			wantErr: true,
			errMsg:  "webhook config name is required",
		},
		{
			name: "missing certificate manager",
			config: &WebhookInjectorConfig{
				WebhookConfigName: "test-webhook",
				Client:            fakeClient,
			},
			wantErr: true,
			errMsg:  "certificate manager is required",
		},
		{
			name: "missing kubernetes client",
			config: &WebhookInjectorConfig{
				WebhookConfigName: "test-webhook",
				CertManager:       certManager,
			},
			wantErr: true,
			errMsg:  "kubernetes client is required",
		},
		{
			name: "valid config",
			config: &WebhookInjectorConfig{
				WebhookConfigName: "test-webhook",
				CertManager:       certManager,
				Client:            fakeClient,
			},
			wantErr: false,
		},
		{
			name: "valid config with custom refresh interval",
			config: &WebhookInjectorConfig{
				WebhookConfigName: "test-webhook",
				CertManager:       certManager,
				Client:            fakeClient,
				RefreshInterval:   30 * time.Minute,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injector, err := NewWebhookCAInjector(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, injector)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, injector)
			}
		})
	}
}

func TestWebhookCAInjector_InjectCABundle(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	// Create a test webhook configuration
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.webhook.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte("old-ca-bundle"),
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

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
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

	// Verify base64 encoding works
	caBase64 := injector.GetCABundleBase64()
	assert.NotEmpty(t, caBase64)
}

func TestWebhookCAInjector_InjectCABundle_WebhookNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "non-existent-webhook",
		CertManager:       certManager,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = injector.InjectCABundle(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update webhook configuration")
}

func TestWebhookCAInjector_StartStop(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook",
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

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
		CertManager:       certManager,
		Client:            fakeClient,
		RefreshInterval:   100 * time.Millisecond,
	})
	require.NoError(t, err)

	// Use a longer timeout to ensure certificate generation completes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = injector.Start(ctx)
	require.NoError(t, err)

	// Use polling with timeout instead of fixed sleep to handle race conditions
	// This ensures we wait for the CA bundle to be populated
	var caBundle []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		caBundle = injector.GetCABundle()
		if len(caBundle) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify CA bundle was injected
	assert.NotEmpty(t, caBundle, "CA bundle should be populated after Start()")

	// Stop the injector
	injector.Stop()

	// Verify it can't be started again
	err = injector.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has been stopped")
}

func TestWebhookCAInjector_GetCABundle_Empty(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	certManager, err := NewSelfSignedProvider(nil)
	require.NoError(t, err)

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
		CertManager:       certManager,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	// Before injection, CA bundle should be empty
	caBundle := injector.GetCABundle()
	assert.Empty(t, caBundle)

	caBase64 := injector.GetCABundleBase64()
	assert.Empty(t, caBase64)
}

func TestWebhookCAInjector_MultipleWebhooks(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	// Create a webhook configuration with multiple webhooks
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "webhook1.test.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte(""),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
			{
				Name: "webhook2.test.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte(""),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			},
			{
				Name: "webhook3.test.io",
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

	injector, err := NewWebhookCAInjector(&WebhookInjectorConfig{
		WebhookConfigName: "test-webhook",
		CertManager:       certManager,
		Client:            fakeClient,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = injector.InjectCABundle(ctx)
	require.NoError(t, err)

	// Verify the CA bundle was set
	caBundle := injector.GetCABundle()
	assert.NotEmpty(t, caBundle)
}

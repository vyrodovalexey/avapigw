package cert

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func setupTestInjector(t *testing.T, objects ...runtime.Object) *Injector {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objects...).
		Build()

	cfg := &InjectorConfig{
		Namespace: "default",
	}

	logger := zap.NewNop()
	return NewInjector(cfg, k8sClient, logger)
}

func TestInjectorConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *InjectorConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &InjectorConfig{
				Namespace: "default",
			},
			wantErr: false,
		},
		{
			name: "valid config with webhook names",
			config: &InjectorConfig{
				Namespace:                   "default",
				ValidatingWebhookConfigName: "validating-webhook",
				MutatingWebhookConfigName:   "mutating-webhook",
			},
			wantErr: false,
		},
		{
			name: "missing namespace",
			config: &InjectorConfig{
				Namespace: "",
			},
			wantErr: true,
			errMsg:  "namespace is required",
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

func TestNewInjector(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	cfg := &InjectorConfig{
		Namespace:                   "default",
		ValidatingWebhookConfigName: "validating-webhook",
		MutatingWebhookConfigName:   "mutating-webhook",
	}

	logger := zap.NewNop()
	injector := NewInjector(cfg, k8sClient, logger)

	assert.NotNil(t, injector)
	assert.Equal(t, cfg, injector.config)
}

func TestInjector_SetCABundle(t *testing.T) {
	injector := setupTestInjector(t)

	caBundle := []byte("test-ca-bundle")
	injector.SetCABundle(caBundle)

	assert.Equal(t, caBundle, injector.caBundle)
}

func TestInjector_InjectIntoValidatingWebhooks_NoCABundle(t *testing.T) {
	injector := setupTestInjector(t)
	ctx := context.Background()

	err := injector.InjectIntoValidatingWebhooks(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA bundle is not set")
}

func TestInjector_InjectIntoValidatingWebhooks_SpecificName(t *testing.T) {
	sideEffects := admissionregistrationv1.SideEffectClassNone
	webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-validating-webhook",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:        "test.webhook.example.com",
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

	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(webhook).
		Build()

	cfg := &InjectorConfig{
		Namespace:                   "default",
		ValidatingWebhookConfigName: "test-validating-webhook",
	}

	logger := zap.NewNop()
	injector := NewInjector(cfg, k8sClient, logger)

	caBundle := []byte("test-ca-bundle")
	injector.SetCABundle(caBundle)

	ctx := context.Background()
	err := injector.InjectIntoValidatingWebhooks(ctx)
	require.NoError(t, err)

	// Verify CA bundle was injected
	updatedWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	err = k8sClient.Get(ctx, client.ObjectKey{Name: "test-validating-webhook"}, updatedWebhook)
	require.NoError(t, err)
	assert.Equal(t, caBundle, updatedWebhook.Webhooks[0].ClientConfig.CABundle)
}

func TestInjector_InjectIntoValidatingWebhooks_ManagedLabel(t *testing.T) {
	sideEffects := admissionregistrationv1.SideEffectClassNone
	managedWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "managed-validating-webhook",
			Labels: map[string]string{
				WebhookConfigLabelKey: WebhookConfigLabelValue,
			},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:        "managed.webhook.example.com",
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

	unmanagedWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "unmanaged-validating-webhook",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:        "unmanaged.webhook.example.com",
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

	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(managedWebhook, unmanagedWebhook).
		Build()

	cfg := &InjectorConfig{
		Namespace: "default",
		// No specific name, should inject into all managed webhooks
	}

	logger := zap.NewNop()
	injector := NewInjector(cfg, k8sClient, logger)

	caBundle := []byte("test-ca-bundle")
	injector.SetCABundle(caBundle)

	ctx := context.Background()
	err := injector.InjectIntoValidatingWebhooks(ctx)
	require.NoError(t, err)

	// Verify CA bundle was injected into managed webhook
	updatedManaged := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	err = k8sClient.Get(ctx, client.ObjectKey{Name: "managed-validating-webhook"}, updatedManaged)
	require.NoError(t, err)
	assert.Equal(t, caBundle, updatedManaged.Webhooks[0].ClientConfig.CABundle)

	// Verify unmanaged webhook was not modified
	updatedUnmanaged := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	err = k8sClient.Get(ctx, client.ObjectKey{Name: "unmanaged-validating-webhook"}, updatedUnmanaged)
	require.NoError(t, err)
	assert.Nil(t, updatedUnmanaged.Webhooks[0].ClientConfig.CABundle)
}

func TestInjector_InjectIntoMutatingWebhooks_NoCABundle(t *testing.T) {
	injector := setupTestInjector(t)
	ctx := context.Background()

	err := injector.InjectIntoMutatingWebhooks(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA bundle is not set")
}

func TestInjector_InjectIntoMutatingWebhooks_SpecificName(t *testing.T) {
	sideEffects := admissionregistrationv1.SideEffectClassNone
	reinvocationPolicy := admissionregistrationv1.NeverReinvocationPolicy
	webhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-mutating-webhook",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:               "test.webhook.example.com",
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

	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(webhook).
		Build()

	cfg := &InjectorConfig{
		Namespace:                 "default",
		MutatingWebhookConfigName: "test-mutating-webhook",
	}

	logger := zap.NewNop()
	injector := NewInjector(cfg, k8sClient, logger)

	caBundle := []byte("test-ca-bundle")
	injector.SetCABundle(caBundle)

	ctx := context.Background()
	err := injector.InjectIntoMutatingWebhooks(ctx)
	require.NoError(t, err)

	// Verify CA bundle was injected
	updatedWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{}
	err = k8sClient.Get(ctx, client.ObjectKey{Name: "test-mutating-webhook"}, updatedWebhook)
	require.NoError(t, err)
	assert.Equal(t, caBundle, updatedWebhook.Webhooks[0].ClientConfig.CABundle)
}

func TestInjector_InjectIntoMutatingWebhooks_ManagedLabel(t *testing.T) {
	sideEffects := admissionregistrationv1.SideEffectClassNone
	reinvocationPolicy := admissionregistrationv1.NeverReinvocationPolicy
	managedWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "managed-mutating-webhook",
			Labels: map[string]string{
				"app.kubernetes.io/name": "avapigw",
			},
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:               "managed.webhook.example.com",
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

	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(managedWebhook).
		Build()

	cfg := &InjectorConfig{
		Namespace: "default",
	}

	logger := zap.NewNop()
	injector := NewInjector(cfg, k8sClient, logger)

	caBundle := []byte("test-ca-bundle")
	injector.SetCABundle(caBundle)

	ctx := context.Background()
	err := injector.InjectIntoMutatingWebhooks(ctx)
	require.NoError(t, err)

	// Verify CA bundle was injected
	updatedWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{}
	err = k8sClient.Get(ctx, client.ObjectKey{Name: "managed-mutating-webhook"}, updatedWebhook)
	require.NoError(t, err)
	assert.Equal(t, caBundle, updatedWebhook.Webhooks[0].ClientConfig.CABundle)
}

func TestInjector_InjectAll(t *testing.T) {
	sideEffects := admissionregistrationv1.SideEffectClassNone
	reinvocationPolicy := admissionregistrationv1.NeverReinvocationPolicy

	validatingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "validating-webhook",
			Labels: map[string]string{
				WebhookConfigLabelKey: WebhookConfigLabelValue,
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
			Name: "mutating-webhook",
			Labels: map[string]string{
				WebhookConfigLabelKey: WebhookConfigLabelValue,
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

	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(validatingWebhook, mutatingWebhook).
		Build()

	cfg := &InjectorConfig{
		Namespace: "default",
	}

	logger := zap.NewNop()
	injector := NewInjector(cfg, k8sClient, logger)

	caBundle := []byte("test-ca-bundle")
	injector.SetCABundle(caBundle)

	ctx := context.Background()
	err := injector.InjectAll(ctx)
	require.NoError(t, err)

	// Verify both webhooks were updated
	updatedValidating := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	err = k8sClient.Get(ctx, client.ObjectKey{Name: "validating-webhook"}, updatedValidating)
	require.NoError(t, err)
	assert.Equal(t, caBundle, updatedValidating.Webhooks[0].ClientConfig.CABundle)

	updatedMutating := &admissionregistrationv1.MutatingWebhookConfiguration{}
	err = k8sClient.Get(ctx, client.ObjectKey{Name: "mutating-webhook"}, updatedMutating)
	require.NoError(t, err)
	assert.Equal(t, caBundle, updatedMutating.Webhooks[0].ClientConfig.CABundle)
}

func TestInjector_InjectAll_NoCABundle(t *testing.T) {
	injector := setupTestInjector(t)
	ctx := context.Background()

	err := injector.InjectAll(ctx)
	assert.Error(t, err)
}

func TestInjector_AlreadyHasCorrectCABundle(t *testing.T) {
	sideEffects := admissionregistrationv1.SideEffectClassNone
	caBundle := []byte("test-ca-bundle")

	webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-validating-webhook",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:        "test.webhook.example.com",
				SideEffects: &sideEffects,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "webhook-service",
						Namespace: "default",
					},
					CABundle: caBundle, // Already has the correct CA bundle
				},
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, admissionregistrationv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(webhook).
		Build()

	cfg := &InjectorConfig{
		Namespace:                   "default",
		ValidatingWebhookConfigName: "test-validating-webhook",
	}

	logger := zap.NewNop()
	injector := NewInjector(cfg, k8sClient, logger)
	injector.SetCABundle(caBundle)

	ctx := context.Background()
	err := injector.InjectIntoValidatingWebhooks(ctx)
	require.NoError(t, err)
}

func TestInjectorConstants(t *testing.T) {
	assert.Equal(t, "app.kubernetes.io/managed-by", WebhookConfigLabelKey)
	assert.Equal(t, "avapigw-operator", WebhookConfigLabelValue)
}

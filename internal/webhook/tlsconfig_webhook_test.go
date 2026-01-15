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

func TestTLSConfigWebhook_Default(t *testing.T) {
	t.Run("defaults TLS versions", func(t *testing.T) {
		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
			},
		}

		webhook := &TLSConfigWebhook{
			Defaulter: defaulter.NewTLSConfigDefaulter(),
		}
		err := webhook.Default(context.Background(), config)
		require.NoError(t, err)
	})

	t.Run("returns error for wrong type", func(t *testing.T) {
		webhook := &TLSConfigWebhook{
			Defaulter: defaulter.NewTLSConfigDefaulter(),
		}
		err := webhook.Default(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a TLSConfig")
	})
}

func TestTLSConfigWebhook_ValidateCreate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid TLSConfig with secret source", func(t *testing.T) {
		tlsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-cert", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tlsSecret).Build()

		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.NoError(t, err)
	})

	t.Run("valid TLSConfig with vault source", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Vault: &avapigwv1alpha1.VaultCertificateSource{
						Path: "pki/issue/my-role",
					},
				},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.NoError(t, err)
	})

	t.Run("invalid - no certificate source", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either secret or vault must be specified")
	})

	t.Run("invalid - both secret and vault sources", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
					Vault: &avapigwv1alpha1.VaultCertificateSource{
						Path: "pki/issue/my-role",
					},
				},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("invalid - minVersion greater than maxVersion", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		minVersion := avapigwv1alpha1.TLSVersion13
		maxVersion := avapigwv1alpha1.TLSVersion12
		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
				MinVersion: &minVersion,
				MaxVersion: &maxVersion,
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "minVersion cannot be greater than maxVersion")
	})

	t.Run("invalid - unknown cipher suite", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
				CipherSuites: []string{"UNKNOWN_CIPHER_SUITE"},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown cipher suite")
	})

	t.Run("invalid - unknown ALPN protocol", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
				ALPNProtocols: []string{"unknown-protocol"},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown ALPN protocol")
	})

	t.Run("invalid - client validation enabled without CA", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		enabled := true
		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
				ClientValidation: &avapigwv1alpha1.ClientValidationConfig{
					Enabled: &enabled,
				},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "caCertificateRef or trustedCAs is required")
	})

	t.Run("invalid - rotation with invalid check interval", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		checkInterval := avapigwv1alpha1.Duration("invalid")
		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
				Rotation: &avapigwv1alpha1.CertificateRotationConfig{
					CheckInterval: &checkInterval,
				},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})

	t.Run("invalid - wrong object type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a TLSConfig")
	})
}

func TestTLSConfigWebhook_ValidateUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		tlsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-cert", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tlsSecret).Build()

		oldConfig := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
			},
		}

		newConfig := oldConfig.DeepCopy()

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), oldConfig, newConfig)
		assert.NoError(t, err)
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.Gateway{}, &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a TLSConfig")
	})
}

func TestTLSConfigWebhook_ValidateDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("delete allowed - no references", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), config)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("delete blocked - has references", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{{
							Name: "test-config",
						}},
					},
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		config := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
			},
		}

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateDelete(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "referenced by one or more Gateways")
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &TLSConfigWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTLSConfigDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a TLSConfig")
	})
}

func TestTLSVersionToInt(t *testing.T) {
	tests := []struct {
		name     string
		version  avapigwv1alpha1.TLSVersion
		expected int
	}{
		{"TLS 1.0", avapigwv1alpha1.TLSVersion10, 10},
		{"TLS 1.1", avapigwv1alpha1.TLSVersion11, 11},
		{"TLS 1.2", avapigwv1alpha1.TLSVersion12, 12},
		{"TLS 1.3", avapigwv1alpha1.TLSVersion13, 13},
		{"Unknown", avapigwv1alpha1.TLSVersion("unknown"), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tlsVersionToInt(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

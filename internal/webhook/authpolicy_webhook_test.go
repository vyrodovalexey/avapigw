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

func TestAuthPolicyWebhook_Default(t *testing.T) {
	t.Run("defaults policy values", func(t *testing.T) {
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Defaulter: defaulter.NewAuthPolicyDefaulter(),
		}
		err := webhook.Default(context.Background(), policy)
		require.NoError(t, err)
	})

	t.Run("returns error for wrong type", func(t *testing.T) {
		webhook := &AuthPolicyWebhook{
			Defaulter: defaulter.NewAuthPolicyDefaulter(),
		}
		err := webhook.Default(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected an AuthPolicy")
	})
}

func TestAuthPolicyWebhook_ValidateCreate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid AuthPolicy targeting Gateway", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.NoError(t, err)
	})

	t.Run("valid AuthPolicy targeting HTTPRoute", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(route).Build()

		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "HTTPRoute",
					Name:  "test-route",
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.NoError(t, err)
	})

	t.Run("invalid - unsupported target kind", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "TCPRoute",
					Name:  "test-route",
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid target kind")
	})

	t.Run("invalid - JWT enabled without JWKS", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		enabled := true
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					JWT: &avapigwv1alpha1.JWTAuthConfig{
						Enabled: &enabled,
					},
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either jwksUri or jwks must be specified")
	})

	t.Run("valid - JWT with JWKS URI", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		enabled := true
		jwksUri := "https://auth.example.com/.well-known/jwks.json"
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					JWT: &avapigwv1alpha1.JWTAuthConfig{
						Enabled: &enabled,
						JWKSUri: &jwksUri,
					},
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.NoError(t, err)
	})

	t.Run("invalid - API key Secret validation without secretRef", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		enabled := true
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
						Enabled: &enabled,
						Validation: &avapigwv1alpha1.APIKeyValidationConfig{
							Type: avapigwv1alpha1.APIKeyValidationSecret,
						},
					},
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secretRef is required")
	})

	t.Run("invalid - API key External validation without external config", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		enabled := true
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
						Enabled: &enabled,
						Validation: &avapigwv1alpha1.APIKeyValidationConfig{
							Type: avapigwv1alpha1.APIKeyValidationExternal,
						},
					},
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "external configuration is required")
	})

	t.Run("invalid - API key External validation without URL", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		enabled := true
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
						Enabled: &enabled,
						Validation: &avapigwv1alpha1.APIKeyValidationConfig{
							Type: avapigwv1alpha1.APIKeyValidationExternal,
							External: &avapigwv1alpha1.ExternalValidationConfig{
								URL: "",
							},
						},
					},
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "URL is required")
	})

	t.Run("invalid - authorization rule without name", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authorization: &avapigwv1alpha1.AuthorizationConfig{
					Rules: []avapigwv1alpha1.AuthorizationRule{{
						Name: "",
					}},
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("invalid - wrong object type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected an AuthPolicy")
	})
}

func TestAuthPolicyWebhook_ValidateUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		oldPolicy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
			},
		}

		newPolicy := oldPolicy.DeepCopy()

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
		assert.NoError(t, err)
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.Gateway{}, &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected an AuthPolicy")
	})
}

func TestAuthPolicyWebhook_ValidateDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("delete allowed", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
			},
		}

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), policy)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &AuthPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewAuthPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected an AuthPolicy")
	})
}

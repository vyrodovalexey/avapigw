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

// ============================================================================
// Additional AuthPolicy Webhook Tests for Coverage
// ============================================================================

func TestAuthPolicyWebhook_ValidateOAuth2Syntax(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid OAuth2 with token endpoint", func(t *testing.T) {
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
		tokenEndpoint := "https://auth.example.com/oauth/token"
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					OAuth2: &avapigwv1alpha1.OAuth2Config{
						Enabled:       &enabled,
						TokenEndpoint: &tokenEndpoint,
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

	t.Run("OAuth2 with empty token endpoint is valid", func(t *testing.T) {
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
		emptyEndpoint := ""
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					OAuth2: &avapigwv1alpha1.OAuth2Config{
						Enabled:       &enabled,
						TokenEndpoint: &emptyEndpoint,
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
}

func TestAuthPolicyWebhook_ValidateCORSSyntax(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid CORS with allow origins", func(t *testing.T) {
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

		origin := "https://example.com"
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				SecurityHeaders: &avapigwv1alpha1.SecurityHeadersConfig{
					CORS: &avapigwv1alpha1.CORSConfig{
						AllowOrigins: []avapigwv1alpha1.CORSOrigin{{
							Exact: &origin,
						}},
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

	t.Run("CORS with empty origin is skipped", func(t *testing.T) {
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

		emptyOrigin := ""
		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				SecurityHeaders: &avapigwv1alpha1.SecurityHeadersConfig{
					CORS: &avapigwv1alpha1.CORSConfig{
						AllowOrigins: []avapigwv1alpha1.CORSOrigin{{
							Exact: &emptyOrigin,
						}},
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

	t.Run("CORS with nil origin exact is skipped", func(t *testing.T) {
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
				SecurityHeaders: &avapigwv1alpha1.SecurityHeadersConfig{
					CORS: &avapigwv1alpha1.CORSConfig{
						AllowOrigins: []avapigwv1alpha1.CORSOrigin{{
							Exact: nil,
						}},
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
}

func TestAuthPolicyWebhook_ValidateAuthenticationReferences(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid JWT with JWKS secret reference", func(t *testing.T) {
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

		jwksSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "jwks-secret", Namespace: "default"},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway, jwksSecret).Build()

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
						JWKS: &avapigwv1alpha1.SecretObjectReference{
							Name: "jwks-secret",
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
		assert.NoError(t, err)
	})

	t.Run("invalid JWT with missing JWKS secret", func(t *testing.T) {
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
						JWKS: &avapigwv1alpha1.SecretObjectReference{
							Name: "missing-jwks-secret",
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
		assert.Contains(t, err.Error(), "spec.authentication.jwt.jwks")
	})

	t.Run("valid basic auth with secret reference", func(t *testing.T) {
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

		basicSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "basic-auth-secret", Namespace: "default"},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway, basicSecret).Build()

		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					Basic: &avapigwv1alpha1.BasicAuthConfig{
						SecretRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "basic-auth-secret",
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
		assert.NoError(t, err)
	})

	t.Run("invalid basic auth with missing secret", func(t *testing.T) {
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
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					Basic: &avapigwv1alpha1.BasicAuthConfig{
						SecretRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "missing-basic-secret",
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
		assert.Contains(t, err.Error(), "spec.authentication.basic.secretRef")
	})

	t.Run("valid OAuth2 with client secret reference", func(t *testing.T) {
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

		clientSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "oauth2-client-secret", Namespace: "default"},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway, clientSecret).Build()

		policy := &avapigwv1alpha1.AuthPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.AuthPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					OAuth2: &avapigwv1alpha1.OAuth2Config{
						ClientSecretRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "oauth2-client-secret",
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
		assert.NoError(t, err)
	})

	t.Run("invalid OAuth2 with missing client secret", func(t *testing.T) {
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
				Authentication: &avapigwv1alpha1.AuthenticationConfig{
					OAuth2: &avapigwv1alpha1.OAuth2Config{
						ClientSecretRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "missing-oauth2-secret",
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
		assert.Contains(t, err.Error(), "spec.authentication.oauth2.clientSecretRef")
	})

	t.Run("valid API key with secret reference", func(t *testing.T) {
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

		apiKeySecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "api-key-secret", Namespace: "default"},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway, apiKeySecret).Build()

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
							SecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "api-key-secret",
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
		assert.NoError(t, err)
	})

	t.Run("invalid API key with missing secret", func(t *testing.T) {
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
							SecretRef: &avapigwv1alpha1.SecretObjectReference{
								Name: "missing-api-key-secret",
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
		assert.Contains(t, err.Error(), "spec.authentication.apiKey.validation.secretRef")
	})
}

func TestAuthPolicyWebhook_ValidateAPIKeyExternalURL(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid API key external validation with URL", func(t *testing.T) {
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
								URL: "https://api.example.com/validate",
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
		assert.NoError(t, err)
	})
}

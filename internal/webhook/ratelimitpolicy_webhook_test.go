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

func TestRateLimitPolicyWebhook_Default(t *testing.T) {
	t.Run("defaults policy values", func(t *testing.T) {
		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Defaulter: defaulter.NewRateLimitPolicyDefaulter(),
		}
		err := webhook.Default(context.Background(), policy)
		require.NoError(t, err)
	})

	t.Run("returns error for wrong type", func(t *testing.T) {
		webhook := &RateLimitPolicyWebhook{
			Defaulter: defaulter.NewRateLimitPolicyDefaulter(),
		}
		err := webhook.Default(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a RateLimitPolicy")
	})
}

func TestRateLimitPolicyWebhook_ValidateCreate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid RateLimitPolicy targeting Gateway", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.NoError(t, err)
	})

	t.Run("valid RateLimitPolicy targeting HTTPRoute", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(route).Build()

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "HTTPRoute",
					Name:  "test-route",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.NoError(t, err)
	})

	t.Run("invalid - unsupported target kind", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "TCPRoute",
					Name:  "test-route",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid target kind")
	})

	t.Run("invalid - no rules", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one rule is required")
	})

	t.Run("invalid - rule with zero requests", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 0,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "requests must be at least 1")
	})

	t.Run("invalid - token bucket with zero tokens", func(t *testing.T) {
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

		algorithm := avapigwv1alpha1.RateLimitAlgorithmTokenBucket
		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
					Algorithm: &algorithm,
					TokenBucket: &avapigwv1alpha1.TokenBucketConfig{
						Tokens: 0,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tokens must be at least 1")
	})

	t.Run("invalid - client identifier Header without header name", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
					ClientIdentifier: &avapigwv1alpha1.ClientIdentifierConfig{
						Type: avapigwv1alpha1.ClientIdentifierHeader,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "header is required")
	})

	t.Run("invalid - client identifier JWTClaim without claim name", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
					ClientIdentifier: &avapigwv1alpha1.ClientIdentifierConfig{
						Type: avapigwv1alpha1.ClientIdentifierJWTClaim,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "claim is required")
	})

	t.Run("invalid - client identifier Cookie without cookie name", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
					ClientIdentifier: &avapigwv1alpha1.ClientIdentifierConfig{
						Type: avapigwv1alpha1.ClientIdentifierCookie,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cookie is required")
	})

	t.Run("invalid - tier with zero requests", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
					Tiers: []avapigwv1alpha1.RateLimitTier{{
						Name:  "premium",
						Match: avapigwv1alpha1.RateLimitTierMatch{},
						Limit: avapigwv1alpha1.RateLimitValue{
							Requests: 0,
							Unit:     avapigwv1alpha1.RateLimitUnitMinute,
						},
					}},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "requests must be at least 1")
	})

	t.Run("invalid - Redis storage without config", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
				Storage: &avapigwv1alpha1.RateLimitStorageConfig{
					Type: avapigwv1alpha1.RateLimitStorageRedis,
				},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis configuration is required")
	})

	t.Run("invalid - Redis storage without address", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
				Storage: &avapigwv1alpha1.RateLimitStorageConfig{
					Type: avapigwv1alpha1.RateLimitStorageRedis,
					Redis: &avapigwv1alpha1.RedisStorageConfig{
						Address: "",
					},
				},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "address is required")
	})

	t.Run("invalid - wrong object type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a RateLimitPolicy")
	})
}

func TestRateLimitPolicyWebhook_ValidateUpdate(t *testing.T) {
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

		oldPolicy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
			},
		}

		newPolicy := oldPolicy.DeepCopy()
		newPolicy.Spec.Rules[0].Limit.Requests = 200

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
		assert.NoError(t, err)
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.Gateway{}, &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a RateLimitPolicy")
	})
}

func TestRateLimitPolicyWebhook_ValidateDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("delete allowed", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), policy)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a RateLimitPolicy")
	})
}

// ============================================================================
// Additional RateLimitPolicy Webhook Tests for Coverage
// ============================================================================

func TestRateLimitPolicyWebhook_ValidateReferences(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid RateLimitPolicy with Redis secret reference", func(t *testing.T) {
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

		redisSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "redis-secret", Namespace: "default"},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway, redisSecret).Build()

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
				Storage: &avapigwv1alpha1.RateLimitStorageConfig{
					Type: avapigwv1alpha1.RateLimitStorageRedis,
					Redis: &avapigwv1alpha1.RedisStorageConfig{
						Address: "redis:6379",
						SecretRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "redis-secret",
						},
					},
				},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.NoError(t, err)
	})

	t.Run("invalid RateLimitPolicy with missing Redis secret", func(t *testing.T) {
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

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "Gateway",
					Name:  "test-gateway",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
				Storage: &avapigwv1alpha1.RateLimitStorageConfig{
					Type: avapigwv1alpha1.RateLimitStorageRedis,
					Redis: &avapigwv1alpha1.RedisStorageConfig{
						Address: "redis:6379",
						SecretRef: &avapigwv1alpha1.SecretObjectReference{
							Name: "missing-redis-secret",
						},
					},
				},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "spec.storage.redis.secretRef")
	})

	t.Run("valid RateLimitPolicy targeting GRPCRoute", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(route).Build()

		policy := &avapigwv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
			Spec: avapigwv1alpha1.RateLimitPolicySpec{
				TargetRef: avapigwv1alpha1.TargetRef{
					Group: avapigwv1alpha1.GroupVersion.Group,
					Kind:  "GRPCRoute",
					Name:  "test-route",
				},
				Rules: []avapigwv1alpha1.RateLimitRule{{
					Name: "default",
					Limit: avapigwv1alpha1.RateLimitValue{
						Requests: 100,
						Unit:     avapigwv1alpha1.RateLimitUnitMinute,
					},
				}},
			},
		}

		webhook := &RateLimitPolicyWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewRateLimitPolicyDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), policy)
		assert.NoError(t, err)
	})
}

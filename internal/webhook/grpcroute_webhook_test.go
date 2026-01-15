package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/webhook/defaulter"
	"github.com/vyrodovalexey/avapigw/internal/webhook/validator"
)

func TestGRPCRouteWebhook_Default(t *testing.T) {
	t.Run("defaults parent ref group and kind", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
			},
		}

		webhook := &GRPCRouteWebhook{
			Defaulter: defaulter.NewGRPCRouteDefaulter(),
		}
		err := webhook.Default(context.Background(), route)
		require.NoError(t, err)

		// Group and Kind should be defaulted
		assert.NotNil(t, route.Spec.ParentRefs[0].Group)
		assert.Equal(t, avapigwv1alpha1.GroupVersion.Group, *route.Spec.ParentRefs[0].Group)
		assert.NotNil(t, route.Spec.ParentRefs[0].Kind)
		assert.Equal(t, "Gateway", *route.Spec.ParentRefs[0].Kind)
	})

	t.Run("defaults backend ref group, kind and weight", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					BackendRefs: []avapigwv1alpha1.GRPCBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
				}},
			},
		}

		webhook := &GRPCRouteWebhook{
			Defaulter: defaulter.NewGRPCRouteDefaulter(),
		}
		err := webhook.Default(context.Background(), route)
		require.NoError(t, err)

		// Group, Kind and Weight should be defaulted
		assert.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Group)
		assert.Equal(t, "", *route.Spec.Rules[0].BackendRefs[0].Group)
		assert.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Kind)
		assert.Equal(t, "Service", *route.Spec.Rules[0].BackendRefs[0].Kind)
		assert.NotNil(t, route.Spec.Rules[0].BackendRefs[0].Weight)
		assert.Equal(t, int32(1), *route.Spec.Rules[0].BackendRefs[0].Weight)
	})

	t.Run("defaults retry policy values", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					RetryPolicy: &avapigwv1alpha1.GRPCRetryPolicy{},
				}},
			},
		}

		webhook := &GRPCRouteWebhook{
			Defaulter: defaulter.NewGRPCRouteDefaulter(),
		}
		err := webhook.Default(context.Background(), route)
		require.NoError(t, err)

		// Retry policy should have defaults
		assert.NotNil(t, route.Spec.Rules[0].RetryPolicy.NumRetries)
		assert.Equal(t, int32(1), *route.Spec.Rules[0].RetryPolicy.NumRetries)
		assert.NotNil(t, route.Spec.Rules[0].RetryPolicy.Backoff)
		assert.NotNil(t, route.Spec.Rules[0].RetryPolicy.Backoff.BaseInterval)
		assert.Equal(t, "100ms", *route.Spec.Rules[0].RetryPolicy.Backoff.BaseInterval)
		assert.NotNil(t, route.Spec.Rules[0].RetryPolicy.Backoff.MaxInterval)
		assert.Equal(t, "10s", *route.Spec.Rules[0].RetryPolicy.Backoff.MaxInterval)
	})
}

func TestGRPCRouteWebhook_ValidateSyntax(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	webhook := &GRPCRouteWebhook{
		Client:             cl,
		Defaulter:          defaulter.NewGRPCRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(cl),
		ReferenceValidator: validator.NewReferenceValidator(cl),
	}

	t.Run("invalid - negative retry count", func(t *testing.T) {
		numRetries := int32(-1)

		route := &avapigwv1alpha1.GRPCRoute{}
		route.Name = "test"
		route.Namespace = "default"
		route.Spec.Rules = []avapigwv1alpha1.GRPCRouteRule{{
			RetryPolicy: &avapigwv1alpha1.GRPCRetryPolicy{
				NumRetries: &numRetries,
			},
		}}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "numRetries must be non-negative")
	})

	t.Run("invalid - regex method match with invalid pattern", func(t *testing.T) {
		methodType := avapigwv1alpha1.GRPCMethodMatchRegularExpression
		service := "[invalid regex"

		route := &avapigwv1alpha1.GRPCRoute{}
		route.Name = "test"
		route.Namespace = "default"
		route.Spec.Rules = []avapigwv1alpha1.GRPCRouteRule{{
			Matches: []avapigwv1alpha1.GRPCRouteMatch{{
				Method: &avapigwv1alpha1.GRPCMethodMatch{
					Type:    &methodType,
					Service: &service,
				},
			}},
		}}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("invalid - regex header match with invalid pattern", func(t *testing.T) {
		headerType := avapigwv1alpha1.HeaderMatchRegularExpression

		route := &avapigwv1alpha1.GRPCRoute{}
		route.Name = "test"
		route.Namespace = "default"
		route.Spec.Rules = []avapigwv1alpha1.GRPCRouteRule{{
			Matches: []avapigwv1alpha1.GRPCRouteMatch{{
				Headers: []avapigwv1alpha1.GRPCHeaderMatch{{
					Type:  &headerType,
					Name:  "X-Custom",
					Value: "[invalid regex",
				}},
			}},
		}}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})
}

func TestGRPCRouteWebhook_ValidateCreate(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("valid route", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "grpc",
					Port:     50051,
					Protocol: avapigwv1alpha1.ProtocolGRPC,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
			},
		}

		webhook := &GRPCRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGRPCRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
	})

	t.Run("invalid - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &GRPCRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGRPCRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a GRPCRoute")
	})
}

func TestGRPCRouteWebhook_ValidateUpdate(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "grpc",
					Port:     50051,
					Protocol: avapigwv1alpha1.ProtocolGRPC,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		oldRoute := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
			},
		}

		newRoute := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
			},
		}

		webhook := &GRPCRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGRPCRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateUpdate(context.Background(), oldRoute, newRoute)
		assert.NoError(t, err)
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &GRPCRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGRPCRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.Gateway{}, &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a GRPCRoute")
	})
}

func TestGRPCRouteWebhook_ValidateDelete(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("delete allowed", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
		}

		webhook := &GRPCRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGRPCRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateDelete(context.Background(), route)
		assert.NoError(t, err)
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &GRPCRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGRPCRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a GRPCRoute")
	})
}

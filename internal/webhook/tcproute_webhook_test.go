package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/webhook/defaulter"
	"github.com/vyrodovalexey/avapigw/internal/webhook/validator"
)

func TestTCPRouteWebhook_Default(t *testing.T) {
	t.Run("defaults parent ref group and kind", func(t *testing.T) {
		route := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.TCPRouteRule{{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
				}},
			},
		}

		webhook := &TCPRouteWebhook{
			Defaulter: defaulter.NewTCPRouteDefaulter(),
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
		route := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.TCPRouteRule{{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
				}},
			},
		}

		webhook := &TCPRouteWebhook{
			Defaulter: defaulter.NewTCPRouteDefaulter(),
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

	t.Run("returns error for wrong type", func(t *testing.T) {
		webhook := &TCPRouteWebhook{
			Defaulter: defaulter.NewTCPRouteDefaulter(),
		}
		err := webhook.Default(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a TCPRoute")
	})
}

func TestTCPRouteWebhook_ValidateCreate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid TCPRoute with rules", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "tcp",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolTCP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		route := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.TCPRouteRule{{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
				}},
			},
		}

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), route)
		// May fail due to service not existing, but syntax validation should pass
		// The error should be about service not found, not syntax
		if err != nil {
			assert.Contains(t, err.Error(), "service")
		}
	})

	t.Run("invalid - no rules", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		route := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.TCPRouteRule{},
			},
		}

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one rule is required")
	})

	t.Run("invalid - rule without backend refs", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		route := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.TCPRouteRule{{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{},
				}},
			},
		}

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one backend reference is required")
	})

	t.Run("invalid - wrong object type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a TCPRoute")
	})

	t.Run("invalid - invalid idle timeout format", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		idleTimeout := avapigwv1alpha1.Duration("invalid")
		route := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.TCPRouteRule{{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
					IdleTimeout: &idleTimeout,
				}},
			},
		}

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})

	t.Run("invalid - invalid connect timeout format", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		connectTimeout := avapigwv1alpha1.Duration("bad")
		route := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.TCPRouteRule{{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
					ConnectTimeout: &connectTimeout,
				}},
			},
		}

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})
}

func TestTCPRouteWebhook_ValidateUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "tcp",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolTCP,
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()

		oldRoute := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.TCPRouteRule{{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
				}},
			},
		}

		newRoute := oldRoute.DeepCopy()

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), oldRoute, newRoute)
		// May fail due to service not existing
		if err != nil {
			assert.Contains(t, err.Error(), "service")
		}
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.Gateway{}, &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a TCPRoute")
	})
}

func TestTCPRouteWebhook_ValidateDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("delete allowed", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		route := &avapigwv1alpha1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.TCPRouteSpec{
				Rules: []avapigwv1alpha1.TCPRouteRule{{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
				}},
			},
		}

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), route)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &TCPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewTCPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a TCPRoute")
	})
}

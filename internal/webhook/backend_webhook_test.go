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

func TestBackendWebhook_Default(t *testing.T) {
	t.Run("defaults load balancing algorithm", func(t *testing.T) {
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
			},
		}

		webhook := &BackendWebhook{
			Defaulter: defaulter.NewBackendDefaulter(),
		}
		err := webhook.Default(context.Background(), backend)
		require.NoError(t, err)
	})

	t.Run("returns error for wrong type", func(t *testing.T) {
		webhook := &BackendWebhook{
			Defaulter: defaulter.NewBackendDefaulter(),
		}
		err := webhook.Default(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a Backend")
	})
}

func TestBackendWebhook_ValidateCreate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid backend with endpoints", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("valid backend with service reference", func(t *testing.T) {
		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "my-service", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(service).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "my-service",
					Port: 8080,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid - no service or endpoints", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec:       avapigwv1alpha1.BackendSpec{},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either service or endpoints must be specified")
	})

	t.Run("invalid - both service and endpoints", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "my-service",
					Port: 8080,
				},
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("invalid - service port out of range", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "my-service",
					Port: 70000,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid - endpoint port out of range", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    0,
				}},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})

	t.Run("invalid - endpoint invalid address", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "invalid_address",
					Port:    8080,
				}},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "address must be a valid IP address or hostname")
	})

	t.Run("valid - endpoint with valid hostname", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "backend.example.com",
					Port:    8080,
				}},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid - consistent hash without config", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		algorithm := avapigwv1alpha1.LoadBalancingConsistentHash
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				LoadBalancing: &avapigwv1alpha1.LoadBalancingConfig{
					Algorithm: &algorithm,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "consistentHash configuration is required")
	})

	t.Run("invalid - consistent hash header type without header", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		algorithm := avapigwv1alpha1.LoadBalancingConsistentHash
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				LoadBalancing: &avapigwv1alpha1.LoadBalancingConfig{
					Algorithm: &algorithm,
					ConsistentHash: &avapigwv1alpha1.ConsistentHashConfig{
						Type: avapigwv1alpha1.ConsistentHashHeader,
					},
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "header is required")
	})

	t.Run("invalid - consistent hash cookie type without cookie", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		algorithm := avapigwv1alpha1.LoadBalancingConsistentHash
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				LoadBalancing: &avapigwv1alpha1.LoadBalancingConfig{
					Algorithm: &algorithm,
					ConsistentHash: &avapigwv1alpha1.ConsistentHashConfig{
						Type: avapigwv1alpha1.ConsistentHashCookie,
					},
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cookie is required")
	})

	t.Run("invalid - health check with invalid interval", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		interval := avapigwv1alpha1.Duration("invalid")
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					Interval: &interval,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})

	t.Run("invalid - health check HTTP without path", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					HTTP: &avapigwv1alpha1.HTTPHealthCheckConfig{
						Path: "",
					},
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path is required")
	})

	t.Run("invalid - health check HTTP with invalid status code", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					HTTP: &avapigwv1alpha1.HTTPHealthCheckConfig{
						Path:             "/health",
						ExpectedStatuses: []int32{99, 600},
					},
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status code must be between 100 and 599")
	})

	t.Run("invalid - mutual TLS without certificate ref", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		mode := avapigwv1alpha1.BackendTLSModeMutual
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				TLS: &avapigwv1alpha1.BackendTLSConfig{
					Mode: &mode,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificateRef is required for Mutual TLS mode")
	})

	t.Run("invalid - wrong object type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a Backend")
	})
}

func TestBackendWebhook_ValidateUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		oldBackend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
			},
		}

		newBackend := oldBackend.DeepCopy()
		newBackend.Spec.Endpoints[0].Port = 9090

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), oldBackend, newBackend)
		assert.NoError(t, err)
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.Gateway{}, &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a Backend")
	})
}

func TestBackendWebhook_ValidateDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("delete allowed - no references", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), backend)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("delete with warning - has references", func(t *testing.T) {
		backendGroup := avapigwv1alpha1.GroupVersion.Group
		backendKind := "Backend"
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Group: &backendGroup,
							Kind:  &backendKind,
							Name:  "test-backend",
						},
					}},
				}},
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(route).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), backend)
		assert.NoError(t, err)
		assert.NotEmpty(t, warnings)
		assert.Contains(t, warnings[0], "referenced by routes")
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a Backend")
	})
}

// ============================================================================
// Additional Backend Webhook Tests for Coverage
// ============================================================================

func TestBackendWebhook_ValidateCircuitBreakerConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid circuit breaker with interval", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		interval := avapigwv1alpha1.Duration("10s")
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
					Interval: &interval,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid circuit breaker with invalid interval", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		interval := avapigwv1alpha1.Duration("invalid")
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
					Interval: &interval,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})

	t.Run("valid circuit breaker with base ejection time", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		baseEjectionTime := avapigwv1alpha1.Duration("30s")
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
					BaseEjectionTime: &baseEjectionTime,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid circuit breaker with invalid base ejection time", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		baseEjectionTime := avapigwv1alpha1.Duration("bad")
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
					BaseEjectionTime: &baseEjectionTime,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})
}

func TestBackendWebhook_ValidateTLSReferences(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid TLS with certificate reference", func(t *testing.T) {
		tlsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-cert", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tlsSecret).Build()

		mode := avapigwv1alpha1.BackendTLSModeMutual
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				TLS: &avapigwv1alpha1.BackendTLSConfig{
					Mode: &mode,
					CertificateRef: &avapigwv1alpha1.SecretObjectReference{
						Name: "tls-cert",
					},
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid TLS with missing certificate reference", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		mode := avapigwv1alpha1.BackendTLSModeMutual
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				TLS: &avapigwv1alpha1.BackendTLSConfig{
					Mode: &mode,
					CertificateRef: &avapigwv1alpha1.SecretObjectReference{
						Name: "missing-tls-cert",
					},
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "spec.tls.certificateRef")
	})

	t.Run("valid TLS with CA certificate reference", func(t *testing.T) {
		caSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ca-cert", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caSecret).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				TLS: &avapigwv1alpha1.BackendTLSConfig{
					CACertificateRef: &avapigwv1alpha1.SecretObjectReference{
						Name: "ca-cert",
					},
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid TLS with missing CA certificate reference", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				TLS: &avapigwv1alpha1.BackendTLSConfig{
					CACertificateRef: &avapigwv1alpha1.SecretObjectReference{
						Name: "missing-ca-cert",
					},
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "spec.tls.caCertificateRef")
	})
}

func TestBackendWebhook_ValidateServiceWithNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid service reference with explicit namespace", func(t *testing.T) {
		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "my-service", Namespace: "other-ns"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(service).Build()

		otherNs := "other-ns"
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name:      "my-service",
					Namespace: &otherNs,
					Port:      8080,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid service reference with missing service in namespace", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		otherNs := "other-ns"
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name:      "missing-service",
					Namespace: &otherNs,
					Port:      8080,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "spec.service")
	})
}

func TestBackendWebhook_ValidateHealthCheckTimeout(t *testing.T) {
	scheme := runtime.NewScheme()
	err := avapigwv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid health check with timeout", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		timeout := avapigwv1alpha1.Duration("5s")
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					Timeout: &timeout,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.NoError(t, err)
	})

	t.Run("invalid health check with invalid timeout", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		timeout := avapigwv1alpha1.Duration("invalid")
		backend := &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: "test-backend", Namespace: "default"},
			Spec: avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{{
					Address: "10.0.0.1",
					Port:    8080,
				}},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					Timeout: &timeout,
				},
			},
		}

		webhook := &BackendWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewBackendDefaulter(),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err := webhook.ValidateCreate(context.Background(), backend)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})
}

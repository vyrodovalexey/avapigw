package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

// ============================================================================
// GRPCRouteWebhook Default Wrong Type Tests
// ============================================================================

func TestGRPCRouteWebhook_Default_WrongType(t *testing.T) {
	webhook := &GRPCRouteWebhook{
		Defaulter: defaulter.NewGRPCRouteDefaulter(),
	}

	err := webhook.Default(context.Background(), &avapigwv1alpha1.Gateway{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected a GRPCRoute")
}

// ============================================================================
// GRPCRouteWebhook validateBackendRefs Tests
// ============================================================================

func TestGRPCRouteWebhook_validateBackendRefs(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	tests := []struct {
		name        string
		objects     []client.Object
		route       *avapigwv1alpha1.GRPCRoute
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid - Service backend exists",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "my-service", Namespace: "default"},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{{
						BackendRefs: []avapigwv1alpha1.GRPCBackendRef{{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name: "my-service",
							},
						}},
					}},
				},
			},
			expectError: false,
		},
		{
			name:    "invalid - Service backend does not exist",
			objects: []client.Object{},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{{
						BackendRefs: []avapigwv1alpha1.GRPCBackendRef{{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name: "missing-service",
							},
						}},
					}},
				},
			},
			expectError: true,
			errorMsg:    "not found",
		},
		{
			name: "valid - Backend CRD exists",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{Name: "my-backend", Namespace: "default"},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{{
						BackendRefs: []avapigwv1alpha1.GRPCBackendRef{{
							BackendRef: avapigwv1alpha1.BackendRef{
								Group: strPtr(avapigwv1alpha1.GroupVersion.Group),
								Kind:  strPtr("Backend"),
								Name:  "my-backend",
							},
						}},
					}},
				},
			},
			expectError: false,
		},
		{
			name:    "invalid - Backend CRD does not exist",
			objects: []client.Object{},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{{
						BackendRefs: []avapigwv1alpha1.GRPCBackendRef{{
							BackendRef: avapigwv1alpha1.BackendRef{
								Group: strPtr(avapigwv1alpha1.GroupVersion.Group),
								Kind:  strPtr("Backend"),
								Name:  "missing-backend",
							},
						}},
					}},
				},
			},
			expectError: true,
			errorMsg:    "not found",
		},
		{
			name: "valid - Service in different namespace",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "my-service", Namespace: "other-ns"},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{{
						BackendRefs: []avapigwv1alpha1.GRPCBackendRef{{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name:      "my-service",
								Namespace: strPtr("other-ns"),
							},
						}},
					}},
				},
			},
			expectError: false,
		},
		{
			name:    "valid - no backend refs (empty rules)",
			objects: []client.Object{},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					Rules: []avapigwv1alpha1.GRPCRouteRule{{}},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			webhook := &GRPCRouteWebhook{
				Client:             cl,
				Defaulter:          defaulter.NewGRPCRouteDefaulter(),
				DuplicateChecker:   validator.NewDuplicateChecker(cl),
				ReferenceValidator: validator.NewReferenceValidator(cl),
			}

			err := webhook.validateBackendRefs(context.Background(), tt.route)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// GRPCRouteWebhook validateParentProtocols Tests
// ============================================================================

func TestGRPCRouteWebhook_validateParentProtocols(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	tests := []struct {
		name        string
		objects     []client.Object
		route       *avapigwv1alpha1.GRPCRoute
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid - GRPC listener",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{{
							Name:     "grpc",
							Port:     50051,
							Protocol: avapigwv1alpha1.ProtocolGRPC,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						SectionName: strPtr("grpc"),
					}},
				},
			},
			expectError: false,
		},
		{
			name: "valid - GRPCS listener",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{{
							Name:     "grpcs",
							Port:     50052,
							Protocol: avapigwv1alpha1.ProtocolGRPCS,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						SectionName: strPtr("grpcs"),
					}},
				},
			},
			expectError: false,
		},
		{
			name: "invalid - HTTP listener for GRPCRoute",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{{
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						SectionName: strPtr("http"),
					}},
				},
			},
			expectError: true,
			errorMsg:    "protocol",
		},
		{
			name: "invalid - TCP listener for GRPCRoute",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{{
							Name:     "tcp",
							Port:     9000,
							Protocol: avapigwv1alpha1.ProtocolTCP,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						SectionName: strPtr("tcp"),
					}},
				},
			},
			expectError: true,
			errorMsg:    "protocol",
		},
		{
			name: "valid - no section name (any listener)",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{{
							Name:     "grpc",
							Port:     50051,
							Protocol: avapigwv1alpha1.ProtocolGRPC,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name: "test-gateway",
						// No SectionName - should not validate protocol
					}},
				},
			},
			expectError: false,
		},
		{
			name: "valid - parent in different namespace",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "other-ns"},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{{
							Name:     "grpc",
							Port:     50051,
							Protocol: avapigwv1alpha1.ProtocolGRPC,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						Namespace:   strPtr("other-ns"),
						SectionName: strPtr("grpc"),
					}},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			webhook := &GRPCRouteWebhook{
				Client:             cl,
				Defaulter:          defaulter.NewGRPCRouteDefaulter(),
				DuplicateChecker:   validator.NewDuplicateChecker(cl),
				ReferenceValidator: validator.NewReferenceValidator(cl),
			}

			err := webhook.validateParentProtocols(context.Background(), tt.route)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// GRPCRouteWebhook validateSyntax with Session Affinity Tests
// ============================================================================

func TestGRPCRouteWebhook_validateSyntax_SessionAffinity(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	webhook := &GRPCRouteWebhook{
		Client:             cl,
		Defaulter:          defaulter.NewGRPCRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(cl),
		ReferenceValidator: validator.NewReferenceValidator(cl),
	}

	t.Run("invalid - Header session affinity without header config", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					SessionAffinity: &avapigwv1alpha1.GRPCSessionAffinityConfig{
						Type: avapigwv1alpha1.GRPCSessionAffinityTypeHeader,
						// Missing Header config
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "header configuration is required")
	})

	t.Run("invalid - Cookie session affinity without cookie config", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					SessionAffinity: &avapigwv1alpha1.GRPCSessionAffinityConfig{
						Type: avapigwv1alpha1.GRPCSessionAffinityTypeCookie,
						// Missing Cookie config
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cookie configuration is required")
	})

	t.Run("valid - Header session affinity with header config", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					SessionAffinity: &avapigwv1alpha1.GRPCSessionAffinityConfig{
						Type: avapigwv1alpha1.GRPCSessionAffinityTypeHeader,
						Header: &avapigwv1alpha1.GRPCSessionAffinityHeaderConfig{
							Name: "X-Session-ID",
						},
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})

	t.Run("valid - Cookie session affinity with cookie config", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					SessionAffinity: &avapigwv1alpha1.GRPCSessionAffinityConfig{
						Type: avapigwv1alpha1.GRPCSessionAffinityTypeCookie,
						Cookie: &avapigwv1alpha1.GRPCSessionAffinityCookieConfig{
							Name: "session-cookie",
						},
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})
}

// ============================================================================
// GRPCRouteWebhook validateSyntax with Invalid Hostname Tests
// ============================================================================

func TestGRPCRouteWebhook_validateSyntax_InvalidHostname(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	webhook := &GRPCRouteWebhook{
		Client:             cl,
		Defaulter:          defaulter.NewGRPCRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(cl),
		ReferenceValidator: validator.NewReferenceValidator(cl),
	}

	t.Run("invalid hostname format", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Hostnames: []avapigwv1alpha1.Hostname{"invalid_hostname"},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid hostname")
	})

	t.Run("valid hostname", func(t *testing.T) {
		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Hostnames: []avapigwv1alpha1.Hostname{"example.com", "*.example.com"},
			},
		}

		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})
}

// ============================================================================
// GRPCRouteWebhook validateSyntax with Invalid Retry Timeout Tests
// ============================================================================

func TestGRPCRouteWebhook_validateSyntax_InvalidRetryTimeout(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	webhook := &GRPCRouteWebhook{
		Client:             cl,
		Defaulter:          defaulter.NewGRPCRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(cl),
		ReferenceValidator: validator.NewReferenceValidator(cl),
	}

	t.Run("invalid perTryTimeout format", func(t *testing.T) {
		perTryTimeout := avapigwv1alpha1.Duration("invalid")

		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					RetryPolicy: &avapigwv1alpha1.GRPCRetryPolicy{
						PerTryTimeout: &perTryTimeout,
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})

	t.Run("valid perTryTimeout format", func(t *testing.T) {
		perTryTimeout := avapigwv1alpha1.Duration("5s")

		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					RetryPolicy: &avapigwv1alpha1.GRPCRetryPolicy{
						PerTryTimeout: &perTryTimeout,
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})
}

// ============================================================================
// GRPCRouteWebhook validateSyntax with Invalid Method Regex Tests
// ============================================================================

func TestGRPCRouteWebhook_validateSyntax_InvalidMethodRegex(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	webhook := &GRPCRouteWebhook{
		Client:             cl,
		Defaulter:          defaulter.NewGRPCRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(cl),
		ReferenceValidator: validator.NewReferenceValidator(cl),
	}

	t.Run("invalid method regex pattern", func(t *testing.T) {
		methodType := avapigwv1alpha1.GRPCMethodMatchRegularExpression
		method := "[invalid regex"

		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					Matches: []avapigwv1alpha1.GRPCRouteMatch{{
						Method: &avapigwv1alpha1.GRPCMethodMatch{
							Type:   &methodType,
							Method: &method,
						},
					}},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("valid method regex pattern", func(t *testing.T) {
		methodType := avapigwv1alpha1.GRPCMethodMatchRegularExpression
		method := "^Get.*$"

		route := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Rules: []avapigwv1alpha1.GRPCRouteRule{{
					Matches: []avapigwv1alpha1.GRPCRouteMatch{{
						Method: &avapigwv1alpha1.GRPCMethodMatch{
							Type:   &methodType,
							Method: &method,
						},
					}},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})
}

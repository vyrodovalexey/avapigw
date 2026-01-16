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

func TestHTTPRouteWebhook_Default(t *testing.T) {
	t.Run("defaults parent ref group and kind", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
			},
		}

		webhook := &HTTPRouteWebhook{
			Defaulter: defaulter.NewHTTPRouteDefaulter(),
		}
		err := webhook.Default(context.Background(), route)
		require.NoError(t, err)

		// Group and Kind should be defaulted
		assert.NotNil(t, route.Spec.ParentRefs[0].Group)
		assert.Equal(t, avapigwv1alpha1.GroupVersion.Group, *route.Spec.ParentRefs[0].Group)
		assert.NotNil(t, route.Spec.ParentRefs[0].Kind)
		assert.Equal(t, "Gateway", *route.Spec.ParentRefs[0].Kind)
	})

	t.Run("defaults path match type and value", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					Matches: []avapigwv1alpha1.HTTPRouteMatch{{}},
				}},
			},
		}

		webhook := &HTTPRouteWebhook{
			Defaulter: defaulter.NewHTTPRouteDefaulter(),
		}
		err := webhook.Default(context.Background(), route)
		require.NoError(t, err)

		// Path type and value should be defaulted
		assert.NotNil(t, route.Spec.Rules[0].Matches[0].Path)
		assert.NotNil(t, route.Spec.Rules[0].Matches[0].Path.Type)
		assert.Equal(t, avapigwv1alpha1.PathMatchPathPrefix, *route.Spec.Rules[0].Matches[0].Path.Type)
		assert.NotNil(t, route.Spec.Rules[0].Matches[0].Path.Value)
		assert.Equal(t, "/", *route.Spec.Rules[0].Matches[0].Path.Value)
	})

	t.Run("defaults backend ref group, kind and weight", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{{
						BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-service",
						},
					}},
				}},
			},
		}

		webhook := &HTTPRouteWebhook{
			Defaulter: defaulter.NewHTTPRouteDefaulter(),
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
}

func TestHTTPRouteWebhook_ValidateSyntax(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	webhook := &HTTPRouteWebhook{
		Client:             cl,
		Defaulter:          defaulter.NewHTTPRouteDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(cl),
		ReferenceValidator: validator.NewReferenceValidator(cl),
	}

	t.Run("valid route - no error", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{}
		route.Name = "test"
		route.Namespace = "default"

		// Test syntax validation without parent refs validation
		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})

	t.Run("invalid - regex path match with invalid pattern", func(t *testing.T) {
		pathType := avapigwv1alpha1.PathMatchRegularExpression
		pathValue := "[invalid regex"

		route := &avapigwv1alpha1.HTTPRoute{}
		route.Name = "test"
		route.Namespace = "default"
		route.Spec.Rules = []avapigwv1alpha1.HTTPRouteRule{{
			Matches: []avapigwv1alpha1.HTTPRouteMatch{{
				Path: &avapigwv1alpha1.HTTPPathMatch{
					Type:  &pathType,
					Value: &pathValue,
				},
			}},
		}}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("invalid - regex header match with invalid pattern", func(t *testing.T) {
		headerType := avapigwv1alpha1.HeaderMatchRegularExpression

		route := &avapigwv1alpha1.HTTPRoute{}
		route.Name = "test"
		route.Namespace = "default"
		route.Spec.Rules = []avapigwv1alpha1.HTTPRouteRule{{
			Matches: []avapigwv1alpha1.HTTPRouteMatch{{
				Headers: []avapigwv1alpha1.HTTPHeaderMatch{{
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

func TestHTTPRouteWebhook_ValidateCreate(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("valid route", func(t *testing.T) {
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

		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
			},
		}

		webhook := &HTTPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewHTTPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateCreate(context.Background(), route)
		assert.NoError(t, err)
	})

	t.Run("invalid - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &HTTPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewHTTPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected an HTTPRoute")
	})
}

func TestHTTPRouteWebhook_ValidateUpdate(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
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

		oldRoute := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
			},
		}

		newRoute := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{
					Name: "test-gateway",
				}},
				Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
			},
		}

		webhook := &HTTPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewHTTPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateUpdate(context.Background(), oldRoute, newRoute)
		assert.NoError(t, err)
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &HTTPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewHTTPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.Gateway{}, &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected an HTTPRoute")
	})
}

func TestHTTPRouteWebhook_ValidateDelete(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("delete allowed", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
		}

		webhook := &HTTPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewHTTPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateDelete(context.Background(), route)
		assert.NoError(t, err)
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &HTTPRouteWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewHTTPRouteDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.Gateway{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected an HTTPRoute")
	})
}

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name        string
		duration    string
		expectError bool
	}{
		{"valid duration - seconds", "30s", false},
		{"valid duration - minutes", "5m", false},
		{"valid duration - hours", "1h", false},
		{"valid duration - milliseconds", "100ms", false},
		{"empty duration is valid", "", false},
		{"invalid - no unit", "30", true},
		{"invalid - wrong unit", "30x", true},
		{"invalid - negative number", "-5s", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDuration(tt.duration)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// HTTPRouteWebhook validateFilter Tests
// ============================================================================

func TestHTTPRouteWebhook_validateFilter(t *testing.T) {
	webhook := &HTTPRouteWebhook{}

	tests := []struct {
		name        string
		filter      avapigwv1alpha1.HTTPRouteFilter
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid RequestHeaderModifier filter",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterRequestHeaderModifier,
				RequestHeaderModifier: &avapigwv1alpha1.HTTPHeaderFilter{
					Set: []avapigwv1alpha1.HTTPHeader{{Name: "X-Custom", Value: "value"}},
				},
			},
			expectError: false,
		},
		{
			name: "invalid RequestHeaderModifier - missing config",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterRequestHeaderModifier,
			},
			expectError: true,
			errorMsg:    "requestHeaderModifier is required",
		},
		{
			name: "valid ResponseHeaderModifier filter",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterResponseHeaderModifier,
				ResponseHeaderModifier: &avapigwv1alpha1.HTTPHeaderFilter{
					Set: []avapigwv1alpha1.HTTPHeader{{Name: "X-Custom", Value: "value"}},
				},
			},
			expectError: false,
		},
		{
			name: "invalid ResponseHeaderModifier - missing config",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterResponseHeaderModifier,
			},
			expectError: true,
			errorMsg:    "responseHeaderModifier is required",
		},
		{
			name: "valid RequestMirror filter",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterRequestMirror,
				RequestMirror: &avapigwv1alpha1.HTTPRequestMirrorFilter{
					BackendRef: avapigwv1alpha1.BackendRef{Name: "mirror-backend"},
				},
			},
			expectError: false,
		},
		{
			name: "invalid RequestMirror - missing config",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterRequestMirror,
			},
			expectError: true,
			errorMsg:    "requestMirror is required",
		},
		{
			name: "valid RequestRedirect filter",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterRequestRedirect,
				RequestRedirect: &avapigwv1alpha1.HTTPRequestRedirectFilter{
					Hostname: (*avapigwv1alpha1.PreciseHostname)(strPtr("example.com")),
				},
			},
			expectError: false,
		},
		{
			name: "invalid RequestRedirect - missing config",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterRequestRedirect,
			},
			expectError: true,
			errorMsg:    "requestRedirect is required",
		},
		{
			name: "valid URLRewrite filter",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterURLRewrite,
				URLRewrite: &avapigwv1alpha1.HTTPURLRewriteFilter{
					Hostname: (*avapigwv1alpha1.PreciseHostname)(strPtr("example.com")),
				},
			},
			expectError: false,
		},
		{
			name: "invalid URLRewrite - missing config",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterURLRewrite,
			},
			expectError: true,
			errorMsg:    "urlRewrite is required",
		},
		{
			name: "valid DirectResponse filter",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterDirectResponse,
				DirectResponse: &avapigwv1alpha1.HTTPDirectResponseFilter{
					StatusCode: 200,
				},
			},
			expectError: false,
		},
		{
			name: "invalid DirectResponse - missing config",
			filter: avapigwv1alpha1.HTTPRouteFilter{
				Type: avapigwv1alpha1.HTTPRouteFilterDirectResponse,
			},
			expectError: true,
			errorMsg:    "directResponse is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := webhook.validateFilter(tt.filter, "spec.rules[0].filters[0]")
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
// HTTPRouteWebhook validateSyntax with Timeouts Tests
// ============================================================================

func TestHTTPRouteWebhook_validateSyntax_Timeouts(t *testing.T) {
	webhook := &HTTPRouteWebhook{}

	t.Run("valid timeouts", func(t *testing.T) {
		requestTimeout := avapigwv1alpha1.Duration("30s")
		backendTimeout := avapigwv1alpha1.Duration("5s")

		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					Timeouts: &avapigwv1alpha1.HTTPRouteTimeouts{
						Request:        &requestTimeout,
						BackendRequest: &backendTimeout,
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})

	t.Run("invalid request timeout", func(t *testing.T) {
		requestTimeout := avapigwv1alpha1.Duration("invalid")

		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					Timeouts: &avapigwv1alpha1.HTTPRouteTimeouts{
						Request: &requestTimeout,
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})

	t.Run("invalid backend request timeout", func(t *testing.T) {
		backendTimeout := avapigwv1alpha1.Duration("invalid")

		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					Timeouts: &avapigwv1alpha1.HTTPRouteTimeouts{
						BackendRequest: &backendTimeout,
					},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration format")
	})
}

// ============================================================================
// HTTPRouteWebhook validateSyntax with QueryParams Tests
// ============================================================================

func TestHTTPRouteWebhook_validateSyntax_QueryParams(t *testing.T) {
	webhook := &HTTPRouteWebhook{}

	t.Run("invalid regex query param", func(t *testing.T) {
		queryType := avapigwv1alpha1.QueryParamMatchRegularExpression

		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					Matches: []avapigwv1alpha1.HTTPRouteMatch{{
						QueryParams: []avapigwv1alpha1.HTTPQueryParamMatch{{
							Type:  &queryType,
							Name:  "param",
							Value: "[invalid regex",
						}},
					}},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("valid regex query param", func(t *testing.T) {
		queryType := avapigwv1alpha1.QueryParamMatchRegularExpression

		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					Matches: []avapigwv1alpha1.HTTPRouteMatch{{
						QueryParams: []avapigwv1alpha1.HTTPQueryParamMatch{{
							Type:  &queryType,
							Name:  "param",
							Value: "^[a-z]+$",
						}},
					}},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})
}

// ============================================================================
// HTTPRouteWebhook Default Wrong Type Tests
// ============================================================================

func TestHTTPRouteWebhook_Default_WrongType(t *testing.T) {
	webhook := &HTTPRouteWebhook{
		Defaulter: defaulter.NewHTTPRouteDefaulter(),
	}

	err := webhook.Default(context.Background(), &avapigwv1alpha1.Gateway{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected an HTTPRoute")
}

// ============================================================================
// HTTPRouteWebhook validateSyntax with Invalid Hostname Tests
// ============================================================================

func TestHTTPRouteWebhook_validateSyntax_InvalidHostname(t *testing.T) {
	webhook := &HTTPRouteWebhook{}

	t.Run("invalid hostname format", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Hostnames: []avapigwv1alpha1.Hostname{"invalid_hostname"},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid hostname")
	})

	t.Run("valid hostname", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Hostnames: []avapigwv1alpha1.Hostname{"example.com", "*.example.com"},
			},
		}

		err := webhook.validateSyntax(route)
		assert.NoError(t, err)
	})
}

// ============================================================================
// HTTPRouteWebhook validateSyntax with Filters Tests
// ============================================================================

func TestHTTPRouteWebhook_validateSyntax_Filters(t *testing.T) {
	webhook := &HTTPRouteWebhook{}

	t.Run("invalid filter - missing required config", func(t *testing.T) {
		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				Rules: []avapigwv1alpha1.HTTPRouteRule{{
					Filters: []avapigwv1alpha1.HTTPRouteFilter{{
						Type: avapigwv1alpha1.HTTPRouteFilterRequestHeaderModifier,
						// Missing RequestHeaderModifier
					}},
				}},
			},
		}

		err := webhook.validateSyntax(route)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "requestHeaderModifier is required")
	})
}

// ============================================================================
// HTTPRouteWebhook validateBackendRefs Tests
// ============================================================================

func TestHTTPRouteWebhook_validateBackendRefs(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))

	tests := []struct {
		name        string
		objects     []client.Object
		route       *avapigwv1alpha1.HTTPRoute
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
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{{
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
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{{
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
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{{
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
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{{
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
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{{
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
			name: "valid - multiple backend refs",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "service-1", Namespace: "default"},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "service-2", Namespace: "default"},
				},
			},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{BackendRef: avapigwv1alpha1.BackendRef{Name: "service-1"}},
							{BackendRef: avapigwv1alpha1.BackendRef{Name: "service-2"}},
						},
					}},
				},
			},
			expectError: false,
		},
		{
			name: "invalid - one of multiple backend refs missing",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "service-1", Namespace: "default"},
				},
			},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{BackendRef: avapigwv1alpha1.BackendRef{Name: "service-1"}},
							{BackendRef: avapigwv1alpha1.BackendRef{Name: "missing-service"}},
						},
					}},
				},
			},
			expectError: true,
			errorMsg:    "not found",
		},
		{
			name:    "valid - no backend refs (empty rules)",
			objects: []client.Object{},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					Rules: []avapigwv1alpha1.HTTPRouteRule{{}},
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

			webhook := &HTTPRouteWebhook{
				Client:             cl,
				Defaulter:          defaulter.NewHTTPRouteDefaulter(),
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
// HTTPRouteWebhook validateParentProtocols Tests
// ============================================================================

func TestHTTPRouteWebhook_validateParentProtocols(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	tests := []struct {
		name        string
		objects     []client.Object
		route       *avapigwv1alpha1.HTTPRoute
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid - HTTP listener",
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
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						SectionName: strPtr("http"),
					}},
				},
			},
			expectError: false,
		},
		{
			name: "valid - HTTPS listener",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{{
							Name:     "https",
							Port:     443,
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						SectionName: strPtr("https"),
					}},
				},
			},
			expectError: false,
		},
		{
			name: "invalid - TCP listener for HTTPRoute",
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
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
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
			name: "invalid - GRPC listener for HTTPRoute",
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
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						SectionName: strPtr("grpc"),
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
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
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
							Name:     "http",
							Port:     80,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
						}},
					},
				},
			},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{{
						Name:        "test-gateway",
						Namespace:   strPtr("other-ns"),
						SectionName: strPtr("http"),
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

			webhook := &HTTPRouteWebhook{
				Client:             cl,
				Defaulter:          defaulter.NewHTTPRouteDefaulter(),
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
